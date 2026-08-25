// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! wz applies this at the [`crate::session_actions::SessionLinkActions::send_wire`]
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

/// The `BatchHeader` COMPRESSION bit (zenoh `batch.rs:127` `COMPRESSION = 1`):
/// bit 0 of the 1-byte header set => the payload that follows is lz4-compressed.
pub const BATCH_HEADER_COMPRESSION: u8 = 0x01;

/// Wrap a serialized batch payload for a compression-negotiated session: prepend
/// the 1-byte `BatchHeader` and lz4-compress the payload, keeping the compressed
/// form ONLY when it is strictly smaller than the original (zenoh
/// `batch.rs:347-351` — incompressible data ships raw with the COMPRESSION bit
/// clear, never growing). The returned `[BatchHeader][payload]` is what the link
/// layer then length-frames.
pub fn compress_batch(payload: &[u8]) -> Vec<u8> {
    let max = lz4_flex::block::get_maximum_output_size(payload.len());
    let mut scratch = vec![0u8; max];
    let n = lz4_flex::block::compress_into(payload, &mut scratch).unwrap_or(0);
    if n > 0 && n < payload.len() {
        let mut out = Vec::with_capacity(1 + n);
        out.push(BATCH_HEADER_COMPRESSION);
        out.extend_from_slice(&scratch[..n]);
        out
    } else {
        // Incompressible (or the compressor declined): ship raw, bit 0 clear.
        let mut out = Vec::with_capacity(1 + payload.len());
        out.push(0x00);
        out.extend_from_slice(payload);
        out
    }
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
    let (&header, payload) = wire.split_first()?;
    if header & BATCH_HEADER_COMPRESSION != 0 {
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
}
