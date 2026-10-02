// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R3012 (open-debt item 809) — the tracked capture of one fragmented message
//! seen two ways, and the oracle that keeps it a function of the encoders.
//!
//! # What the word means, and what a sample has to be
//!
//! `carried_state: "fragment_without_resolution"` says a Fragment was seen before
//! this reader saw the session's InitAck, so the sequence-number resolution is
//! unknown and the reader will not guess a mask: a wrap and a gap look the same
//! without it. It is the state of a capture that started in the middle of a
//! session. It is not "a fragment", and a consumer that has never been shown the
//! same fragments read WITH a resolution cannot tell the word from the ordinary
//! `fragment`.
//!
//! So the file carries ONE message in two flows, and the fragments are the same
//! bytes in both:
//!
//! * flow A (`10.0.0.1:43210` to `10.0.0.2:7447`) has the two fragments and no
//!   handshake at all: both read `fragment_without_resolution`;
//! * flow B (`10.0.0.3:43211` to `10.0.0.4:7447`) has the four handshake
//!   datagrams and then the same two fragments: the first reads `fragment` (a
//!   chain still open) and the second `reassembled` (the chain completed and its
//!   message was read).
//!
//! The two flows differ in exactly one fact, the handshake, which is the
//! condition the word names.
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
/// fragments come out as the two different states.
///
/// The census's `unresolvable_fragments` counts the fragments that read
/// `fragment_without_resolution`, and is checked against the field rows' own word
/// rather than against a number written beside it.
#[cfg(feature = "dissect")]
#[test]
fn the_tracked_midsession_capture_reaches_the_consumer_surface() {
    use wz_session_core::network_message::NetworkMessage;
    use wz_session_core::passive::Carried;

    let d = crate::Dissection::from_capture(TRACKED).expect("the tracked capture dissects");
    let flows = d.datagram_flows();
    assert_eq!(
        flows.len(),
        2,
        "two flows: one without a handshake, one with"
    );
    let mut unresolved_flows = 0;
    let mut established_flows = 0;
    for flow in flows {
        let carried: Vec<&Carried> = flow
            .frames
            .iter()
            .filter(|f| !matches!(f.carried, Carried::Nothing))
            .map(|f| &f.carried)
            .collect();
        match carried.as_slice() {
            [Carried::FragmentWithoutResolution, Carried::FragmentWithoutResolution] => {
                unresolved_flows += 1;
            }
            [Carried::Fragment(_), Carried::Reassembled { batch, .. }] => {
                established_flows += 1;
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
        (unresolved_flows, established_flows),
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
        (2, 1, 1),
        "{doc}"
    );

    let census = crate::census_json::census_json(&d);
    assert!(
        census.contains("\"unresolvable_fragments\":2"),
        "the census counts the two fragments the rows name: {census}"
    );
}
