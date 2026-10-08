// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R3012 (open-debt item 809) — the tracked capture of one fragmented message
//! seen two ways, and the oracle that keeps it a function of the encoders.
//!
//! # What a capture that began after the handshake reads, and what a sample has to be
//!
//! A reader that never saw the session's InitAck does not know the size of the
//! sequence-number ring, and will not guess a mask: a wrap and a gap look the
//! same without it. The ring decides one thing about a fragment chain, whether a
//! step from one fragment to the next is consecutive across a wrap, and a step of
//! plain `+1` is consecutive on every ring. So that reader follows a chain whose
//! steps are all `+1` and reassembles it; only a step it cannot judge ends the
//! chain, with `carried_state: "fragment_without_resolution"` on the fragment that
//! showed it (the `unresolved_chain_tests` module builds those). Until the router
//! was told the ring was unknown, this file's flow A read `fragment_without_resolution`
//! on both fragments, and it was the specimen of that word.
//!
//! The file carries ONE message in two flows, and the fragments are the same
//! bytes in both:
//!
//! * flow A (`10.0.0.1:43210` to `10.0.0.2:7447`) has the two fragments and no
//!   handshake at all: the first reads `fragment` (a chain begun) and the second
//!   `reassembled`, and the sequence-number verdict on both is
//!   `without_resolution`, the ring being unknown;
//! * flow B (`10.0.0.3:43211` to `10.0.0.4:7447`) has the four handshake
//!   datagrams and then the same two fragments: the first reads `fragment` (a
//!   chain still open) and the second `reassembled` (the chain completed and its
//!   message was read), with a verdict read on the ring the InitAck fixed.
//!
//! The two flows differ in exactly one fact, the handshake, and in what follows
//! from it and nothing else: the sequence-number verdict, which a reader that
//! missed the handshake may not claim.
//!
//! # How the bytes are made, and how that is CHECKED
//!
//! * the message is `push_build::build_push_literal` encoded by its own codec,
//!   split in two at the middle;
//! * each fragment is the transport header byte (from `wire_const`, with the
//!   reliable and more flags) and a one-byte sequence number, then its piece.
//!   A Fragment is hand-walked by `parse_inbound` and has no body codec, as the
//!   MID vocabulary in `datagram_tests` records; the sequence numbers 0 and 1 are
//!   their own one-byte VLE;
//! * the handshake is the four Init and Open datagrams `datagram_tests` builds
//!   from the codecs' own types;
//! * the container is `crate::pcap::write`.
//!
//! `the_tracked_midsession_capture_is_byte_identical_to_what_wz_emits` rebuilds
//! all of it and compares the whole file. Code spans and not intra-doc links, as
//! in the sibling fixtures: the module is `#[cfg(test)]`.

use alloc::vec::Vec;

use crate::link::LINKTYPE_ETHERNET;

/// The tracked capture, read at COMPILE time, as the sibling oracles read theirs.
const TRACKED: &[u8] =
    include_bytes!("../../../captures/fragmented-push-midsession-and-established.pcap");

/// Where it lives, for the refusals below to name.
const TRACKED_PATH: &str = "captures/fragmented-push-midsession-and-established.pcap";

/// Microseconds between packets: a deterministic timeline, no wall clock.
const PACKET_SPACING_MICROS: u32 = 1_000;

const KEYEXPR: &str = "demo/fragmented";
const VALUE_LEN: usize = 120;

/// The message both flows carry, as the codec writes it.
fn message() -> Vec<u8> {
    let value = alloc::vec![b'f'; VALUE_LEN];
    wz_session_core::push_build::build_push_literal(KEYEXPR, &value)
        .expect("a literal put builds")
        .try_as_borrowed()
        .expect("a built push re-borrows")
        .encode_to_vec()
}

/// One Fragment datagram: reliable, `more` as asked, sequence number `sn` (below
/// 128, so its VLE is one byte), then `piece`.
fn fragment(sn: u8, more: bool, piece: &[u8]) -> Vec<u8> {
    assert!(sn < 0x80, "a one-byte VLE sequence number");
    let mut wire = alloc::vec![
        wz_session_core::wire_const::T_MID_FRAGMENT
            | wz_codecs::wire_const::FLAG_T_FRAGMENT_R
            | if more {
                wz_codecs::wire_const::FLAG_T_FRAGMENT_M
            } else {
                0
            },
        sn,
    ];
    wire.extend_from_slice(piece);
    wire
}

/// The two fragments of [`message`], split at its middle.
fn fragments() -> [Vec<u8>; 2] {
    let message = message();
    let split = message.len() / 2;
    [
        fragment(0, true, &message[..split]),
        fragment(1, false, &message[split..]),
    ]
}

/// Rebuild the whole file from the encoders: flow A, flow B, and the container.
fn rebuild() -> Vec<u8> {
    use crate::datagram_tests::{init_datagram, open_datagram, udp_packet};

    let [first, second] = fragments();
    let a = |m: &[u8]| udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, m);
    let b_out = |m: &[u8]| udp_packet([10, 0, 0, 3], 43211, [10, 0, 0, 4], 7447, m);
    let b_back = |m: &[u8]| udp_packet([10, 0, 0, 4], 7447, [10, 0, 0, 3], 43211, m);
    let packets: Vec<Vec<u8>> = alloc::vec![
        a(&first),
        a(&second),
        b_out(&init_datagram(false, &[])),
        b_back(&init_datagram(true, &[])),
        b_out(&open_datagram(false)),
        b_back(&open_datagram(true)),
        b_out(&first),
        b_out(&second),
    ];
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
/// cargo test -p wz-capture --features dissect --lib \
///   refresh_the_tracked_midsession_capture -- --ignored
/// ```
#[test]
#[ignore = "REFRESHER, not a check: rewrites the tracked capture"]
fn refresh_the_tracked_midsession_capture() {
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
fn the_tracked_midsession_capture_is_byte_identical_to_what_wz_emits() {
    let rebuilt = rebuild();
    assert_eq!(
        TRACKED.len(),
        rebuilt.len(),
        "{TRACKED_PATH} is {} byte(s) and the encoders emit {} — refresh it with \
         `cargo test -p wz-capture --features dissect --lib \
         refresh_the_tracked_midsession_capture -- --ignored` if an encoder \
         changed on purpose",
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

/// The two flows differ in the handshake and in nothing else.
///
/// Read off the tracked bytes: the fragments of flow A and of flow B are the same
/// datagram payloads, flow A has no establishment message before them, and flow B
/// has the four before its own. The two pieces, joined, are the message the codec
/// wrote, so a reader that reassembles flow B reads a real `Push`.
#[test]
fn the_tracked_midsession_capture_differs_between_its_flows_only_in_the_handshake() {
    let file = crate::pcap::parse(TRACKED).expect("the tracked capture parses");
    assert_eq!(
        file.packets.len(),
        8,
        "two fragments, then four handshake datagrams and two fragments"
    );
    let [first, second] = fragments();
    // A packet's UDP datagram payload: after the 14-byte Ethernet header, the
    // 20-byte IPv4 header and the 8-byte UDP header, for as long as the IP header
    // says. The frame itself can be PADDED past that (a short datagram rides in
    // an Ethernet frame of at least 60 bytes), so the tail of the frame is not
    // the datagram.
    let datagram = |index: usize| -> &[u8] {
        let data = &file.packets[index].data;
        let ip_total = usize::from(u16::from_be_bytes([data[16], data[17]]));
        &data[14 + 20 + 8..14 + ip_total]
    };
    let carries = |index: usize, want: &[u8]| datagram(index) == want;
    assert!(
        carries(0, &first) && carries(1, &second),
        "flow A's fragments"
    );
    assert!(
        carries(6, &first) && carries(7, &second),
        "flow B's fragments"
    );

    // Which flow each packet belongs to, read from the IPv4 source address
    // (Ethernet header 14 bytes, the source address at offset 12 of the IP
    // header). Flow A is the first two packets and nothing else: no
    // establishment message of any kind is among them.
    let source = |index: usize| -> [u8; 4] {
        file.packets[index].data[26..30]
            .try_into()
            .expect("an IPv4 source address is four bytes")
    };
    assert_eq!(
        [source(0), source(1)],
        [[10, 0, 0, 1]; 2],
        "flow A is 10.0.0.1"
    );
    for index in 2..8 {
        assert!(
            [[10, 0, 0, 3], [10, 0, 0, 4]].contains(&source(index)),
            "packet {index} belongs to flow B, so flow A is exactly the two fragments"
        );
    }
    // Flow B's four datagrams before its fragments are the handshake, in order.
    use crate::datagram_tests::{init_datagram, open_datagram};
    assert!(
        carries(2, &init_datagram(false, &[])),
        "flow B opens with an Init"
    );
    assert!(
        carries(3, &init_datagram(true, &[])),
        "answered by an InitAck"
    );
    assert!(carries(4, &open_datagram(false)), "then an Open");
    assert!(carries(5, &open_datagram(true)), "answered by an OpenAck");

    let mut joined = first[2..].to_vec();
    joined.extend_from_slice(&second[2..]);
    assert_eq!(
        joined,
        message(),
        "the pieces are the message, split in two"
    );
}

/// The tracked file reaches the surface a consumer reads, and the same two
/// fragments read alike in both flows, but for the sequence-number verdict.
///
/// Both flows read a chain begun and then a `Push` reassembled, the flow with no
/// handshake included. What differs is the ring: the flow with the handshake has
/// one, and the verdicts on its fragments are read on it, while the flow without
/// has none and says `without_resolution` on both. No fragment is unplaceable, and
/// the census's `unresolvable_fragments` agrees with the field rows' own word
/// rather than with a number written beside it.
#[cfg(feature = "dissect")]
#[test]
fn the_tracked_midsession_capture_reaches_the_consumer_surface() {
    use wz_session_core::network_message::NetworkMessage;
    use wz_session_core::passive::Carried;
    use wz_session_core::reassembly_dispatch::IngestOutcome;

    let d = crate::Dissection::from_capture(TRACKED).expect("the tracked capture dissects");
    let flows = d.datagram_flows();
    assert_eq!(
        flows.len(),
        2,
        "two flows: one without a handshake, one with"
    );
    let mut flows_without_a_ring = 0;
    let mut flows_with_a_ring = 0;
    for flow in flows {
        let carried: Vec<&Carried> = flow
            .frames
            .iter()
            .filter(|f| !matches!(f.carried, Carried::Nothing))
            .map(|f| &f.carried)
            .collect();
        match carried.as_slice() {
            [Carried::Fragment(IngestOutcome::Begun), Carried::Reassembled { batch, .. }] => {
                if flow.session.context().sn_mask().is_some() {
                    flows_with_a_ring += 1;
                } else {
                    flows_without_a_ring += 1;
                }
                let messages: Vec<&NetworkMessage> = batch.records().map(|(m, _)| m).collect();
                assert!(
                    matches!(messages.as_slice(), [NetworkMessage::Push(_)]),
                    "the joined fragments read as the one Push they were cut from: {messages:?}"
                );
            }
            other => panic!("a flow carried an unexpected sequence of states: {other:?}"),
        }
    }
    assert_eq!(
        (flows_without_a_ring, flows_with_a_ring),
        (1, 1),
        "one flow of each kind"
    );

    let doc = crate::fields_json::fields_json(&d, TRACKED, None, None);
    let rows = |word: &str| {
        doc.matches(&alloc::format!("\"carried_state\":\"{word}\""))
            .count()
    };
    assert_eq!(
        (
            rows("fragment_without_resolution"),
            rows("fragment"),
            rows("reassembled")
        ),
        (0, 2, 2),
        "{doc}"
    );
    let verdicts = |word: &str| {
        doc.matches(&alloc::format!("\"verdict\":\"{word}\""))
            .count()
    };
    assert_eq!(
        (
            verdicts("without_resolution"),
            verdicts("baseline"),
            verdicts("continuous")
        ),
        (2, 1, 1),
        "the flow with no ring claims no verdict, the flow with one reads its own: {doc}"
    );

    let census = crate::census_json::census_json(&d);
    assert!(
        census.contains("\"unresolvable_fragments\":0"),
        "the census counts the fragments the rows name, which are none: {census}"
    );
    let puts: usize = crate::agg::aggregate(&d)
        .rows()
        .iter()
        .map(|r| r.totals().puts)
        .sum();
    assert_eq!(
        puts, 2,
        "both flows carried the Push, the one with no ring too"
    );
}
