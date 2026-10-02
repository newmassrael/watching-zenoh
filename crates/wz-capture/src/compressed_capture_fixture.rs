// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R3012 (open-debt item 809) — the tracked capture of a compression-negotiated
//! session whose last batch the compressor's decoder REFUSES, and the oracle that
//! keeps it a function of the encoders that emitted it.
//!
//! # What the word means, and what a sample has to be
//!
//! `carried_state: "undecompressible"` is a narrow claim. The session NEGOTIATED
//! compression (both Inits carry the offer, so the BatchHeader is on the wire),
//! the batch's header says the body is lz4, and the lz4 decoder refused the
//! body. It is not "this build has no lz4" in a build that has one, and it is not
//! "compressed traffic": a healthy compressed session reads `batch`. So a sample
//! that is only a header and some bytes somebody typed proves nothing, and the
//! one this crate had until now (`compressed_session_dissection`, four literal
//! bytes after a header) was exactly that: a consumer could not tell a reader that
//! recognised a refused body from one that said `undecompressible` to anything
//! after a compression offer.
//!
//! So this file carries TWO batches of one session, built the same way, of which
//! only one is damaged:
//!
//! * the first is the compressor's output for a real `Frame` carrying a real
//!   `Push`, unchanged. It OPENS: `batch`.
//! * the second is the same construction for the next sequence number, with ONE
//!   field of the encoder's own bytes overwritten: the match offset of the
//!   block's first sequence, set to 0xFFFF. An offset that reaches back past
//!   everything decoded so far cannot be satisfied by any lz4 decoder, so it is
//!   refused for a reason that is a property of the format and not of this
//!   crate's decoder. `undecompressible`.
//!
//! The twin is the control. Without it, a reader that said `undecompressible`
//! to every compressed batch would pass; with it, only one that opens the good
//! block and refuses the damaged one does.
//!
//! # How the bytes are made, and how that is CHECKED
//!
//! * the handshake is the four Init/Open datagrams `datagram_tests` builds from
//!   the codecs' own types, with the compression offer on both Inits;
//! * each batch is `wz_session_core::compression::compress_batch` over
//!   `frame_encode::encode_frame_with_push` of `push_build::build_push_literal`;
//! * the damage is applied to the compressor's output at a position FOUND by
//!   reading the lz4 block's first sequence, not at a constant;
//! * the container is `crate::pcap::write`.
//!
//! `the_tracked_compressed_capture_is_byte_identical_to_what_wz_emits` rebuilds
//! all of it and compares the whole file. `..._breaks_exactly_one_named_spot`
//! compares the two batches byte by byte and names the spot. Code spans and not
//! intra-doc links throughout, as in `raweth_capture_fixture`: the module is
//! `#[cfg(test)]`.

use alloc::vec::Vec;

use crate::link::LINKTYPE_ETHERNET;

/// The tracked capture, read at COMPILE time, as `raweth_capture_fixture` reads
/// its own, and for the same reason.
const TRACKED: &[u8] = include_bytes!("../../../captures/compressed-session-refused-body.pcap");

/// Where it lives, for the refusals below to name.
const TRACKED_PATH: &str = "captures/compressed-session-refused-body.pcap";

/// Microseconds between packets: a deterministic timeline, no wall clock.
const PACKET_SPACING_MICROS: u32 = 1_000;

/// What the damaged field is overwritten with. An offset is the distance back
/// into the output decoded so far, so 0xFFFF reaches before the start of any
/// block this payload compresses to; no decoder can satisfy it.
const DAMAGED_OFFSET: [u8; 2] = [0xFF, 0xFF];

/// The payload of both batches: one literal key, a value long enough to compress
/// and repetitive enough that the compressor keeps the compressed form (it ships
/// raw, header bit clear, when compression does not shrink the batch).
const KEYEXPR: &str = "demo/compressed";
const VALUE_LEN: usize = 240;

/// The position, in an lz4 BLOCK, of the first sequence's 2-byte little-endian
/// match offset.
///
/// A block is a run of sequences: a token (literal length in the high nibble,
/// match length in the low), the literal length's extension bytes when the nibble
/// is 15 (each 255 adds 255, the first smaller byte ends it), the literals, then
/// the offset. Read from the block itself so the damage lands on the field that
/// is meant, whatever the compressor chose for the literals.
fn first_match_offset_at(block: &[u8]) -> usize {
    let token = block[0];
    let mut at = 1usize;
    let mut literals = usize::from(token >> 4);
    if literals == 15 {
        loop {
            let more = block[at];
            at += 1;
            literals += usize::from(more);
            if more != 255 {
                break;
            }
        }
    }
    at + literals
}

/// One batch exactly as the sender put it on the wire: the `BatchHeader` (bit 0
/// set, the body is lz4) then the compressor's block for a `Frame` carrying a
/// `Push` at sequence number `sn`.
fn compressed_batch(sn: u64) -> Vec<u8> {
    let value = alloc::vec![b'z'; VALUE_LEN];
    let push = wz_session_core::push_build::build_push_literal(KEYEXPR, &value)
        .expect("a literal put builds");
    let frame = wz_session_core::frame_encode::encode_frame_with_push(sn, push, true);
    let wire = wz_session_core::compression::compress_batch(&frame);
    assert_eq!(
        wire[0],
        wz_session_core::compression::BATCH_HEADER_COMPRESSION,
        "the premise: this payload compresses, so the header says lz4"
    );
    wire
}

/// The same batch with the first sequence's match offset overwritten.
fn damaged_batch(sn: u64) -> Vec<u8> {
    let mut wire = compressed_batch(sn);
    let at = 1 + first_match_offset_at(&wire[1..]);
    assert_ne!(
        wire[at..at + 2],
        DAMAGED_OFFSET,
        "the premise: the compressor did not already emit the damaged value"
    );
    wire[at..at + 2].copy_from_slice(&DAMAGED_OFFSET);
    wire
}

/// Rebuild the whole file from the encoders: handshake, the intact batch, the
/// damaged batch, and the container.
fn rebuild() -> Vec<u8> {
    use crate::datagram_tests::{compression_offer, init_datagram, open_datagram, udp_packet};

    let offer = compression_offer();
    let messages: [(bool, Vec<u8>); 6] = [
        (true, init_datagram(false, &offer)),
        (false, init_datagram(true, &offer)),
        (true, open_datagram(false)),
        (false, open_datagram(true)),
        (true, compressed_batch(0)),
        (true, damaged_batch(1)),
    ];
    let packets: Vec<Vec<u8>> = messages
        .iter()
        .map(|(from_low, message)| {
            if *from_low {
                udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, message)
            } else {
                udp_packet([10, 0, 0, 2], 7447, [10, 0, 0, 1], 43210, message)
            }
        })
        .collect();
    let refs: Vec<(u32, u32, &[u8])> = packets
        .iter()
        .enumerate()
        .map(|(i, p)| (0u32, i as u32 * PACKET_SPACING_MICROS, p.as_slice()))
        .collect();
    crate::pcap::write(LINKTYPE_ETHERNET, &refs)
}

/// Rewrite the tracked file from `rebuild`. `#[ignore]`d: the REFRESHER, not a
/// check.
///
/// ```text
/// cargo test -p wz-capture --features compression,dissect --lib \
///   refresh_the_tracked_compressed_capture -- --ignored
/// ```
///
/// then run the suite again: `include_bytes!` recompiles the oracle against the
/// new file, so the refresh is only believed once it has been re-graded.
#[test]
#[ignore = "REFRESHER, not a check: rewrites the tracked capture"]
fn refresh_the_tracked_compressed_capture() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(TRACKED_PATH);
    let bytes = rebuild();
    std::fs::write(&path, &bytes).unwrap_or_else(|e| panic!("writing {path:?}: {e}"));
    std::println!(
        "wrote {} byte(s) to {} — now re-run the suite to grade it",
        bytes.len(),
        TRACKED_PATH
    );
}

/// The tracked file IS what the encoders emit, byte for byte.
#[test]
fn the_tracked_compressed_capture_is_byte_identical_to_what_wz_emits() {
    let rebuilt = rebuild();
    assert_eq!(
        TRACKED.len(),
        rebuilt.len(),
        "{TRACKED_PATH} is {} byte(s) and the encoders emit {} — refresh it with \
         `cargo test -p wz-capture --features compression,dissect --lib \
         refresh_the_tracked_compressed_capture -- --ignored` if the compressor \
         or a codec changed on purpose",
        TRACKED.len(),
        rebuilt.len()
    );
    if let Some(at) = TRACKED.iter().zip(rebuilt.iter()).position(|(a, b)| a != b) {
        panic!(
            "{TRACKED_PATH} first differs from what the encoders emit at byte {at}: \
             tracked {:#04x}, emitted {:#04x}. The file has been hand-edited, or an \
             encoder changed and the fixture was not refreshed.",
            TRACKED[at], rebuilt[at]
        );
    }
}

/// The two batches differ at ONE named field, and only the damaged one is
/// refused.
///
/// Read off the tracked bytes rather than the rebuild, so a hand-edited file
/// cannot satisfy it by agreeing with the encoders' idea of itself. The intact
/// batch must open to exactly the frame the encoder produced (so the control is
/// a control and not a second refusal), and the damaged one must differ from it
/// in the two offset bytes and nowhere else. The decoder that refuses it is the
/// one a compression-negotiated link runs.
#[test]
fn the_tracked_compressed_capture_breaks_exactly_one_named_spot() {
    let file = crate::pcap::parse(TRACKED).expect("the tracked capture parses");
    assert_eq!(
        file.packets.len(),
        6,
        "four handshake datagrams, two batches"
    );
    // A UDP datagram's payload is the last `len` bytes of the packet; read the
    // two batches back as the sender's units.
    let unit = |index: usize| -> Vec<u8> {
        let want = if index == 4 {
            compressed_batch(0)
        } else {
            damaged_batch(1)
        };
        let data = &file.packets[index].data;
        assert!(
            data.ends_with(&want),
            "packet {index} must carry the sender's batch as its datagram payload"
        );
        want
    };
    let first = unit(4);
    let damaged = unit(5);
    // The damaged batch's UNDAMAGED TWIN: the same construction at the same
    // sequence number. Comparing it with the first batch instead would differ in
    // the sequence number too, which says nothing about the damage.
    let intact = compressed_batch(1);

    let frame = {
        let value = alloc::vec![b'z'; VALUE_LEN];
        let push = wz_session_core::push_build::build_push_literal(KEYEXPR, &value).unwrap();
        wz_session_core::frame_encode::encode_frame_with_push(0, push, true)
    };
    assert_eq!(
        wz_session_core::compression::decompress_batch(&first, 65_536),
        Some(frame),
        "the control must OPEN, to exactly the frame the encoder produced"
    );
    assert!(
        wz_session_core::compression::decompress_batch(&intact, 65_536).is_some(),
        "and so must the damaged batch's undamaged twin"
    );

    let at = 1 + first_match_offset_at(&intact[1..]);
    let differing: Vec<usize> = intact
        .iter()
        .zip(damaged.iter())
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .map(|(i, _)| i)
        .collect();
    assert!(
        !differing.is_empty() && differing.iter().all(|i| (at..at + 2).contains(i)),
        "the batches may differ only inside the first sequence's match offset \
         (bytes {at}..{}), and differ at {differing:?}",
        at + 2
    );
    assert_eq!(&damaged[at..at + 2], &DAMAGED_OFFSET);
    assert_eq!(
        wz_session_core::compression::decompress_batch(&damaged, 65_536),
        None,
        "the damaged batch must be REFUSED by the lz4 decoder"
    );
}

/// The tracked file reaches the surface a consumer reads, and the two batches
/// come out as the two different words.
///
/// This is also the third question a consumer asks: the census's
/// `undecompressible_batches` counts the same thing the field rows' `carried_state`
/// says, here one of each, derived from the documents and not from a number
/// written beside them.
#[cfg(feature = "dissect")]
#[test]
fn the_tracked_compressed_capture_reaches_the_consumer_surface() {
    use wz_session_core::passive::Carried;

    let d = crate::Dissection::from_capture(TRACKED).expect("the tracked capture dissects");
    let flows = d.datagram_flows();
    assert_eq!(flows.len(), 1, "one sender and one receiver, so one flow");
    let carried: Vec<&Carried> = flows[0]
        .frames
        .iter()
        .filter(|f| !matches!(f.carried, Carried::Nothing))
        .map(|f| &f.carried)
        .collect();
    assert!(
        matches!(
            carried.as_slice(),
            [Carried::Batch(_), Carried::Undecompressible]
        ),
        "the intact batch opens and the damaged one does not, in that order: {carried:?}"
    );

    // The refused batch is accounted as bytes the reader could not locate any
    // message in: exactly the damaged datagram's payload, and nothing of the
    // intact one.
    assert_eq!(
        d.framing_health().unaccounted_batch_bytes,
        damaged_batch(1).len() as u64,
        "the unlocatable bytes are the damaged batch and only it"
    );

    let file = TRACKED;
    let doc = crate::fields_json::fields_json(&d, file, None, None);
    let rows_refused = doc
        .matches("\"carried_state\":\"undecompressible\"")
        .count();
    let rows_opened = doc.matches("\"carried_state\":\"batch\"").count();
    assert_eq!((rows_opened, rows_refused), (1, 1), "{doc}");

    let census = crate::census_json::census_json(&d);
    assert!(
        census.contains(&alloc::format!(
            "\"undecompressible_batches\":{rows_refused}"
        )),
        "the census counts the same refusal the rows name ({rows_refused}): {census}"
    );
    // The framing group sits in the page that carries the throughput plane.
    let table = crate::agg::aggregate(&d);
    let summary = crate::report::CaptureReport::of(&d)
        .with_throughput(&table)
        .to_json();
    assert!(
        summary.contains(&alloc::format!(
            "\"undecompressible_batches\":{rows_refused}"
        )),
        "and so does the summary: {summary}"
    );
}
