// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the transport-level batch COMPRESSION wrap (`transport-compression`)
//! — the wz mirror of zenoh's per-batch lz4 codec
//! (`io/zenoh-transport/src/common/batch.rs`).
//!
//! Once a session negotiates compression (the `session-extcompression`
//! Z_EXT_COMPRESSION handshake), EVERY post-establishment outbound batch carries
//! a 1-byte `BatchHeader` whose bit 0 (`COMPRESSION`) signals whether the payload
//! that follows is lz4-compressed. zenoh compresses the serialized batch payload
//! and keeps the compressed form ONLY when it is smaller than the original
//! (`batch.rs:347-351`); otherwise it clears the bit and ships the payload raw —
//! so incompressible data never grows. The receiver reads the header and
//! `lz4_flex::block::decompress_into`s into an mtu-bounded buffer
//! (`batch.rs:457-500`).
//!
//! wz applies this at the `crate::session_actions::SessionLinkActions::send_wire`
//! seam (the single pre-link emit point — the wz analogue of zenoh's "finalize
//! the batch then write to the link"): `compress_batch` produces the
//! `[BatchHeader][payload]` the link layer then length-frames (the
//! StreamEnvelope on a streamed link, exactly zenoh's `[length][header][payload]`
//! wire). The RX un-wrap (`decompress_batch`) runs at the
//! [`crate::drive::dispatch_link_event`] entry, BEFORE the universal / lowlatency
//! dispatch — compression is the OUTERMOST wire layer.
//!
//! The lz4 codec is the SAME crate zenoh uses (`lz4_flex`, the block format),
//! so a future wz<->zenohd cross-impl session that negotiates compression is
//! byte-compatible. The block API is `no_std + alloc` (the `safe-encode` /
//! `safe-decode` pure-Rust impls), matching this crate's profile.

use alloc::vec;
use alloc::vec::Vec;

use sce_forge_runtime::codec::{Bounded, SceCursor, VecSink};
use wz_codecs::compressed_batch::{CompressedBatchParts, CompressedBatchView, CompressedBatchWire};

/// The `BatchHeader` COMPRESSION bit (zenoh `batch.rs:127` `COMPRESSION = 1`):
/// bit 0 of the 1-byte header set => the payload that follows is lz4-compressed.
pub const BATCH_HEADER_COMPRESSION: u8 = 0x01;

/// The size of the `BatchHeader` [`compress_batch`] puts in front of a batch's
/// payload. It is counted inside the batch size, as the streamed length is
/// ([`crate::link::STREAM_BATCH_LENGTH_BYTES`]): zenoh writes it into the same
/// mtu-sized buffer, right after the length (`io/zenoh-transport/src/common/batch.rs`
/// @ `let _ = writer.write_u8(h.as_u8());`).
pub const BATCH_HEADER_BYTES: usize = 1;

/// Wrap a serialized batch payload for a compression-negotiated session: prepend
/// the 1-byte `BatchHeader` and lz4-compress the payload, keeping the compressed
/// form ONLY when it is strictly smaller than the original and within the batch's
/// bound. Otherwise the original payload ships uncompressed, the COMPRESSION bit
/// clear, which is what zenoh 1.10.2 does: it compresses into a support buffer and
/// keeps the original batch with the bit cleared when the result is not smaller
/// (`io/zenoh-transport/src/common/batch.rs` @
/// `lz4_flex::block::compress_into(payload, b).unwrap_or(0)` writes nothing on a failed
/// compression, and `io/zenoh-transport/src/common/batch.rs` @
/// `if support.len() < self.buffer.len() {` compares and falls back). The returned
/// `[BatchHeader][payload]` is what the link layer then length-frames.
///
/// The header and the payload are written by the batch's document
/// (`sources/codecs/compressed_batch.scxml`); the LZ4 block is the transform this
/// function owns. Every batch is answered, so each sender (a session's send, a
/// multicast group's datagram, its beacon) takes this one fallback.
pub fn compress_batch(payload: &[u8]) -> Vec<u8> {
    match compressed(payload) {
        Some(batch) => batch,
        None => uncompressed(payload),
    }
}

/// The batch of `payload` lz4-compressed, when that is strictly smaller than
/// `payload` and within the batch's bound; `None` when the compressor declines or
/// the compressed form is not smaller.
fn compressed(payload: &[u8]) -> Option<Vec<u8>> {
    let mut scratch = vec![0u8; lz4_flex::block::get_maximum_output_size(payload.len())];
    let n = lz4_flex::block::compress_into(payload, &mut scratch).ok()?;
    let body = scratch
        .get(..n)
        .filter(|body| !body.is_empty() && body.len() < payload.len())?;
    encoded(BATCH_HEADER_COMPRESSION, body)
}

/// The batch of `payload` as it is, the COMPRESSION bit clear. A payload past the
/// document's bound is still the header byte followed by the payload: the
/// uncompressed batch is the payload with no transform, whatever its length.
fn uncompressed(payload: &[u8]) -> Vec<u8> {
    encoded(0x00, payload).unwrap_or_else(|| {
        let mut out = Vec::with_capacity(payload.len().saturating_add(BATCH_HEADER_BYTES));
        out.push(0x00);
        out.extend_from_slice(payload);
        out
    })
}

/// The batch `[header][body]` as its document writes it; `None` for a body past
/// the document's bound.
fn encoded(header: u8, body: &[u8]) -> Option<Vec<u8>> {
    let batch = CompressedBatchParts {
        header,
        payload: Bounded::new(body)?,
    };
    let mut out = Vec::with_capacity(CompressedBatchWire::measure(&batch).len());
    match CompressedBatchWire::encode_source(&batch, &mut VecSink::new(&mut out)) {
        Ok(()) => {}
        Err(never) => match never {},
    }
    Some(out)
}

/// Un-wrap a `[BatchHeader][payload]` batch from a compression-negotiated
/// session: read the header, and if the COMPRESSION bit is set decompress into an
/// `max_decompressed`-bounded buffer (the negotiated batch mtu — the original
/// payload was <= mtu, so a peer cannot force an unbounded allocation; a blob
/// that decompresses past the bound is rejected as malformed). Returns `None`
/// when the wire is empty or lz4 decompression fails (a malformed peer — the
/// caller maps this to a framing error). The bit-clear case copies the raw
/// payload out verbatim.
pub fn decompress_batch(wire: &[u8], max_decompressed: usize) -> Option<Vec<u8>> {
    // The header and the payload as the batch's document reads them; the payload
    // is the rest of the unit.
    let batch = CompressedBatchView::decode(&mut SceCursor::new(wire)).ok()?;
    let payload = batch.payload.into_inner();
    if batch.compression() {
        let mut out = vec![0u8; max_decompressed];
        let n = lz4_flex::block::decompress_into(payload, &mut out).ok()?;
        out.truncate(n);
        Some(out)
    } else {
        Some(payload.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A compressible payload round-trips and the header bit is SET — the
    /// compressed form is strictly smaller, so it is kept.
    #[test]
    fn compressible_payload_round_trips_with_the_bit_set() {
        let payload = vec![0xABu8; 4096]; // highly compressible
        let wire = compress_batch(&payload);
        assert_eq!(wire[0] & BATCH_HEADER_COMPRESSION, BATCH_HEADER_COMPRESSION);
        assert!(wire.len() < payload.len(), "compression shrank the payload");
        assert_eq!(decompress_batch(&wire, 65536), Some(payload));
    }

    /// An incompressible payload ships RAW with the bit CLEAR (zenoh's
    /// "never grow" rule) and still round-trips.
    #[test]
    fn incompressible_payload_ships_raw_with_the_bit_clear() {
        // A short, high-entropy-ish payload lz4 cannot shrink below original.
        let payload: Vec<u8> = (0u8..=63).collect();
        let wire = compress_batch(&payload);
        assert_eq!(wire[0] & BATCH_HEADER_COMPRESSION, 0, "bit clear = raw");
        assert_eq!(&wire[1..], &payload[..], "payload shipped verbatim");
        assert_eq!(decompress_batch(&wire, 65536), Some(payload));
    }

    /// Every batch `compress_batch` writes, compressed or shipped as it is, is
    /// read whole by its document (`sources/codecs/compressed_batch.scxml`) and
    /// written back byte for byte, with the flag and the payload
    /// `decompress_batch` reads.
    #[test]
    fn every_batch_written_here_is_the_batch_the_document_reads() {
        use sce_forge_runtime::codec::SceCursor;
        use wz_codecs::compressed_batch::CompressedBatchView;
        let payloads: [Vec<u8>; 3] = [Vec::new(), (0u8..=63).collect(), vec![0xAB; 4096]];
        let mut compressed = 0usize;
        for payload in payloads {
            let wire = compress_batch(&payload);
            let mut cursor = SceCursor::new(&wire);
            let view = CompressedBatchView::decode(&mut cursor).expect("the document reads it");
            assert_eq!(cursor.remaining(), 0, "read whole");
            assert_eq!(view.compression(), wire[0] & BATCH_HEADER_COMPRESSION != 0);
            assert_eq!(view.payload.into_inner(), &wire[1..]);
            assert_eq!(view.encode_to_vec(), wire, "written back");
            compressed += usize::from(view.compression());
            assert_eq!(decompress_batch(&wire, 65536), Some(payload));
        }
        assert_eq!(compressed, 1, "one batch of the three is kept compressed");
    }

    /// A payload lz4 would grow ships uncompressed, the bit clear, past the
    /// document's bound as within it; a compressible one past the bound is kept
    /// compressed where its compressed form fits.
    #[test]
    fn a_payload_compression_would_grow_ships_uncompressed() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let noise: Vec<u8> = (0..70_000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        let wire = compress_batch(&noise);
        assert_eq!(wire[0], 0x00, "the original batch, the bit clear");
        assert_eq!(&wire[1..], &noise[..], "its payload as it is");

        let small: Vec<u8> = (0u8..=63).collect();
        let wire = compress_batch(&small);
        assert_eq!(wire[0], 0x00);
        assert_eq!(decompress_batch(&wire, 65536), Some(small));

        let zeros = vec![0u8; 70_000];
        let wire = compress_batch(&zeros);
        assert_eq!(wire[0] & BATCH_HEADER_COMPRESSION, BATCH_HEADER_COMPRESSION);
        assert_eq!(decompress_batch(&wire, 70_000), Some(zeros));
    }

    /// An empty wire (no header byte) is rejected as malformed.
    #[test]
    fn empty_wire_is_rejected() {
        assert_eq!(decompress_batch(&[], 65536), None);
    }

    /// A compressed blob whose claimed expansion exceeds the bound is rejected
    /// (the decompression-bomb guard) rather than allocating unboundedly.
    #[test]
    fn over_bound_decompression_is_rejected() {
        let payload = vec![0x5Au8; 8192];
        let wire = compress_batch(&payload);
        assert_eq!(wire[0] & BATCH_HEADER_COMPRESSION, BATCH_HEADER_COMPRESSION);
        // Bound below the true decompressed size => decompress_into errors.
        assert_eq!(decompress_batch(&wire, 1024), None);
    }

    /// R2707 (open-debt item 784) — THE FIELD WALKER INVENTS NO RECORD OUT OF
    /// GENUINELY COMPRESSED BYTES.
    ///
    /// # The half this closes
    ///
    /// A consuming surface asked what a dissector does with a `Frame` on a
    /// compression-negotiated session, and named the outcome it wanted ruled
    /// out rather than discovered: "it walks the compressed bytes and reports
    /// whatever records fall out of them", which is worse than silence because
    /// a reader cannot tell an invented record from a real one.
    ///
    /// R2706 answered the first half — the row now says `undecompressible`,
    /// from the session that negotiated the compression and knows — and
    /// measured the walk over `wz-capture`'s fixture, whose body is a four-byte
    /// marker. That measured "the walk halts on bytes it cannot read". It did
    /// NOT measure "no lz4 frame decodes into something", because those four
    /// bytes are not a compressor's output.
    ///
    /// # Why the witness lives HERE
    ///
    /// This module is the only place that holds both halves at once. The
    /// compressor is `compress_batch` beside it, and the walker is this crate's
    /// `dissect`. `wz-capture` cannot host it: its whole compressed fixture
    /// rests on that crate NOT carrying `transport-compression`, so enabling
    /// the feature there to produce real lz4 would let `batch_of` open the body
    /// and the fixture would lose its subject. Hand-writing lz4 bytes in a
    /// fixture would be this workspace's other recorded defect — a constant
    /// copied out of a format, drifting silently.
    ///
    /// # The control, and why it is the whole test
    ///
    /// The SAME records, walked UNCOMPRESSED, must come back. Without it this
    /// asserts nothing: a walker that returned no record for any input would
    /// satisfy the compressed arm and be useless.
    #[cfg(all(feature = "dissect", feature = "codec-push"))]
    #[test]
    fn a_genuinely_compressed_body_yields_no_invented_record() {
        // A real batch: one `Push` the walker knows, encoded by the codec
        // rather than written out by hand, repeated so lz4 has something to
        // shrink. The repetition is load-bearing twice -- the wrap ships RAW
        // when it cannot compress, which would quietly make this test about the
        // uncompressed path, and the assertion below catches that.
        // NO keyexpr suffix: the subject here is the WALK, and a suffix needs
        // the header's `N` flag, which would make this fixture a statement
        // about the codec's flag derivation instead. An id-only `WireexprLocal`
        // is a record the walker names in full, which is all this needs.
        let record = wz_codecs::lent::Push {
            keyexpr: wz_codecs::lent::Wireexpr {
                body: wz_codecs::lent::WireexprVariant::WireexprLocal(
                    wz_codecs::lent::WireexprLocal {
                        id: 0,
                        suffix_len: None,
                        suffix: None,
                    },
                ),
            },
            body: wz_codecs::lent::PushVariant::CodecZenohMsgPut(wz_codecs::lent::MsgPut {
                payload_len: Some(8),
                extensions_has_0x12: wz_codecs::msg_put::MsgPutExtensionsHas0x12::NotHas0x12 {
                    extensions: None,
                    payload: wz_codecs::Bounded::new(&[0u8; 8] as &[u8]).unwrap(),
                },
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec();
        // Repeated enough that lz4 has something to shrink: the wrap ships RAW
        // when it cannot, and the header assertion below is what stops this
        // test from quietly becoming the control twice.
        let mut payload = Vec::new();
        for _ in 0..32 {
            payload.extend_from_slice(&record);
        }

        // THE CONTROL FIRST, so a walker that answers nothing to everything
        // fails here rather than passing the claim below.
        let plain = crate::dissect::dissect_batch(&payload, 0);
        assert_eq!(
            plain.records.len(),
            32,
            "the control must walk every record: {plain:?}"
        );

        let wire = compress_batch(&payload);
        assert_eq!(
            wire[0] & BATCH_HEADER_COMPRESSION,
            BATCH_HEADER_COMPRESSION,
            "the fixture must actually be compressed, or it is the control twice"
        );
        // What a dissector without lz4 sees: the body as it lies on the wire.
        let walked = crate::dissect::dissect_batch(&wire[1..], 0);
        assert!(
            walked.records.is_empty(),
            "the walk invented {} record(s) out of compressed bytes, which is \
             the outcome the reporting consumer asked to have ruled out: {walked:?}",
            walked.records.len()
        );
        assert!(
            walked.halt.is_some(),
            "and it must SAY where it stopped rather than report a clean empty \
             batch, which reads as 'this frame carried nothing': {walked:?}"
        );
    }
}
