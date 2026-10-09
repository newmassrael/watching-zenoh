// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt item 811 — the tracked capture of a publisher that SETS what the
//! demo never sets, and the oracle that keeps it a function of the encoders.
//!
//! # What none of the other tracked captures can say
//!
//! A publish through the library surface can carry three things the two-node demo
//! never asks for, and a consumer that reads them has no sample to read:
//!
//! * a transport PRIORITY, the `ext_qos` of the Frame the Push rides in. It means
//!   something only on a session whose Inits both offered QoS: without that the
//!   priority lives in the link layer alone and the Frame has no conduit to name;
//! * the body's ENCODING, the `E` bit of the Put and the encoding field behind it;
//! * the body's TIMESTAMP, the `T` bit of the Put and the timestamp behind it.
//!
//! The QoS byte of the Push itself (priority, congestion control, express) rides
//! with them, because `PublishOptions::with_priority` sets one value that drives
//! the Frame's conduit and that byte together.
//!
//! A reader that drops any of these branches reads every other capture here
//! exactly as before, which is why deleting the branch left the whole census
//! green: no capture had the material.
//!
//! # What the file holds, and its control
//!
//! One UDP flow, one session:
//!
//! * the four establishment datagrams, both Inits carrying the QoS offer;
//! * a `Frame` on the default conduit (no `ext_qos`, which is how a Frame at
//!   `Data` is written) carrying a Push with NONE of the three set. It is the
//!   control: a reader that reports a priority, an encoding or a timestamp where
//!   there is none, or that cannot tell the two Pushes apart, fails on it;
//! * a `Frame` on the `InteractiveHigh` conduit carrying a Push with all three
//!   set, and the matching QoS byte.
//!
//! # How the bytes are made, and how that is CHECKED
//!
//! * both Pushes are `push_build::build_push_literal_with_meta`, the function
//!   `Session::publish` calls with the `PushMetadata` its `PublishOptions`
//!   projects into. The oracle fills that metadata directly: `PublishOptions`
//!   lives in the runtime crate, which depends on this one, so reaching it from
//!   here would be a dependency cycle, and the projection is graded where it is
//!   (`push_metadata_drops_qos_when_feature_off` and its siblings);
//! * each Frame is `frame_encode::encode_frame_with_push_qos`, which writes the
//!   `ext_qos` the unicast batch writer writes for the same priority;
//! * the QoS offer is `extqos::encode_qos_ext`, the entry a QoS session puts on
//!   its Init, written by the ext codec;
//! * the container is `crate::pcap::write`.
//!
//! `the_tracked_publisher_fields_capture_is_byte_identical_to_what_wz_emits`
//! rebuilds all of it and compares the whole file. Code spans and not intra-doc
//! links, as in the sibling fixtures: the module is `#[cfg(test)]`.

use alloc::vec::Vec;

use wz_session_core::metadata::PushMetadata;
use wz_session_core::qos::Priority;
use wz_session_core::sample::{EncodingHint, QosLevel, TimestampHint};

use crate::link::LINKTYPE_ETHERNET;

/// The tracked capture, read at COMPILE time, as the sibling oracles read theirs.
const TRACKED: &[u8] =
    include_bytes!("../../../captures/publisher-priority-encoding-timestamp.pcap");

/// Where it lives, for the refusals below to name.
const TRACKED_PATH: &str = "captures/publisher-priority-encoding-timestamp.pcap";

/// Microseconds between packets: a deterministic timeline, no wall clock.
const PACKET_SPACING_MICROS: u32 = 1_000;

/// The key both Pushes are published on.
const KEYEXPR: &str = "demo/publisher/fields";

/// The conduit the second Frame rides: not the default, and not the highest, so a
/// reader that reports the band by position (first, last) and not by value fails.
const PRIORITY: Priority = Priority::InteractiveHigh;

/// An NTP64 word with every byte distinct, so a reader that reports it truncated or
/// byte-swapped reports a different number.
const TIMESTAMP_TIME: u64 = 0x0123_4567_89AB_CDEF;

/// The timestamp's source identifier. Not the Init's `0xAA` bytes, so a reader that
/// takes the timestamp's zid from the session reports the wrong one.
const TIMESTAMP_ZID: [u8; 4] = [0x7E, 0x57, 0x42, 0x11];

/// The MIME name of the encoding the second Push declares; the table id is looked
/// up by it so the fixture says what it means and not the number it sits at.
const ENCODING_NAME: &str = "application/json";

/// A body that IS what the encoding declares, so no payload judgement is in play.
const VALUE: &[u8] = br#"{"t":21.5}"#;

/// The table id of [`ENCODING_NAME`].
fn encoding_id() -> u16 {
    wz_codecs::encoding_ids::ENCODING_ID_TO_STR
        .iter()
        .position(|name| *name == ENCODING_NAME)
        .unwrap_or_else(|| panic!("the encoding table holds no `{ENCODING_NAME}`")) as u16
}

/// What `PublishOptions` would project for the publish with all three set:
/// `with_priority`, `with_encoding`, `with_timestamp`.
fn full_metadata() -> PushMetadata {
    PushMetadata {
        timestamp: Some(TimestampHint {
            time: TIMESTAMP_TIME,
            zid: TIMESTAMP_ZID.to_vec(),
        }),
        encoding: Some(EncodingHint {
            packed_id: u32::from(encoding_id()) << 1,
            schema: None,
        }),
        qos: Some(QosLevel::DEFAULT.with_priority(PRIORITY)),
        ..PushMetadata::default()
    }
}

/// One Frame: reliable, sequence number 0, `priority` as its `ext_qos` when it is
/// not the default conduit, carrying the Push built from `meta`.
///
/// Sequence number 0 on both: zenoh numbers each (priority, reliability) pair
/// separately, so the two Frames are the first of their own conduits and neither
/// reads as a gap or a duplicate of the other.
fn frame(meta: &PushMetadata, priority: Option<Priority>) -> Vec<u8> {
    let push = wz_session_core::push_build::build_push_literal_with_meta(KEYEXPR, VALUE, meta)
        .expect("a literal put with metadata builds");
    wz_session_core::frame_encode::encode_frame_with_push_qos(0, push, true, priority)
}

/// The control: a plain publish, no priority, no encoding, no timestamp.
fn control_frame() -> Vec<u8> {
    frame(&PushMetadata::default(), None)
}

/// The publish with all three set, on the non-default conduit.
fn full_frame() -> Vec<u8> {
    frame(&full_metadata(), Some(PRIORITY))
}

/// The establishment ext chain that OFFERS QoS: the unit entry the ext codec
/// writes at the id `extqos` names.
fn qos_offer() -> Vec<u8> {
    wz_session_core::extqos::encode_qos_ext()
        .as_borrowed()
        .encode_to_vec()
}

/// Rebuild the whole file from the encoders: the QoS handshake, the control, the
/// publish with the three fields, and the container.
fn rebuild() -> Vec<u8> {
    use crate::datagram_tests::{init_datagram, open_datagram, udp_packet};

    let offer = qos_offer();
    let out = |m: &[u8]| udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, m);
    let back = |m: &[u8]| udp_packet([10, 0, 0, 2], 7447, [10, 0, 0, 1], 43210, m);
    let packets: Vec<Vec<u8>> = alloc::vec![
        out(&init_datagram(false, &offer)),
        back(&init_datagram(true, &offer)),
        out(&open_datagram(false)),
        back(&open_datagram(true)),
        out(&control_frame()),
        out(&full_frame()),
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
///   refresh_the_tracked_publisher_fields_capture -- --ignored
/// ```
#[test]
#[ignore = "REFRESHER, not a check: rewrites the tracked capture"]
fn refresh_the_tracked_publisher_fields_capture() {
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
fn the_tracked_publisher_fields_capture_is_byte_identical_to_what_wz_emits() {
    let rebuilt = rebuild();
    assert_eq!(
        TRACKED.len(),
        rebuilt.len(),
        "{TRACKED_PATH} is {} byte(s) and the encoders emit {} — refresh it with \
         `cargo test -p wz-capture --features dissect --lib \
         refresh_the_tracked_publisher_fields_capture -- --ignored` if an encoder \
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

/// A packet's UDP datagram payload: after the 14-byte Ethernet header, the
/// 20-byte IPv4 header and the 8-byte UDP header, for as long as the IP header
/// says. The frame can be PADDED past that (a short datagram rides in an Ethernet
/// frame of at least 60 bytes), so the tail of the frame is not the datagram.
fn datagram(file: &crate::pcap::PcapFile, index: usize) -> &[u8] {
    let data = &file.packets[index].data;
    let ip_total = usize::from(u16::from_be_bytes([data[16], data[17]]));
    &data[14 + 20 + 8..14 + ip_total]
}

/// The file is the session the module doc describes, in order, and its two Frames
/// differ in what a publish that sets the three fields adds.
///
/// Read off the tracked bytes and not off the encoders' output: the QoS offer is on
/// both Inits (the only reason a priority means anything here), the control Frame
/// has no extension chain, and the second Frame has exactly one, the `ext_qos`
/// whose body is the conduit.
#[test]
fn the_tracked_publisher_fields_capture_is_a_qos_session_with_a_control_and_a_full_publish() {
    use crate::datagram_tests::{init_datagram, open_datagram};

    let file = crate::pcap::parse(TRACKED).expect("the tracked capture parses");
    assert_eq!(
        file.packets.len(),
        6,
        "four establishment datagrams, the control Frame, the full Frame"
    );
    let offer = qos_offer();
    assert_eq!(
        offer,
        [wz_session_core::extqos::QOS_EXT_ID],
        "the offer is the presence-only unit entry, one header byte"
    );
    assert_eq!(datagram(&file, 0), init_datagram(false, &offer), "Init");
    assert_eq!(datagram(&file, 1), init_datagram(true, &offer), "InitAck");
    assert_eq!(datagram(&file, 2), open_datagram(false), "Open");
    assert_eq!(datagram(&file, 3), open_datagram(true), "OpenAck");

    let (control, full) = (datagram(&file, 4), datagram(&file, 5));
    assert_eq!(control, control_frame(), "the control Frame");
    assert_eq!(full, full_frame(), "the full Frame");

    // Both are reliable Frames of sequence number 0; the Z flag, which says an
    // extension chain follows the sequence number, is the only header difference.
    let frame_header =
        wz_session_core::wire_const::T_MID_FRAME | wz_codecs::wire_const::FLAG_T_FRAME_R;
    assert_eq!(control[0], frame_header, "control: no extension chain");
    assert_eq!(
        full[0],
        frame_header | wz_codecs::wire_const::FLAG_T_Z,
        "full: an extension chain"
    );
    assert_eq!((control[1], full[1]), (0, 0), "sequence number 0 on both");
    // The chain is the one `ext_qos` entry (id 1) with the conduit as its body,
    // and the Push follows it at byte 4; the control's Push follows the sequence
    // number at byte 2. The tail of each is the Push its metadata built.
    assert_eq!(
        full[2] & 0x0F,
        wz_session_core::extqos::QOS_EXT_ID,
        "the chain's one entry is the QoS extension"
    );
    assert_eq!(full[3], PRIORITY.wire_byte(), "and its body is the conduit");
    let push = |meta: &PushMetadata| {
        wz_session_core::push_build::build_push_literal_with_meta(KEYEXPR, VALUE, meta)
            .expect("a literal put with metadata builds")
            .try_as_borrowed()
            .expect("a built push re-borrows")
            .encode_to_vec()
    };
    assert_eq!(
        &control[2..],
        push(&PushMetadata::default()),
        "the control's Push is the plain one"
    );
    assert_eq!(
        &full[4..],
        push(&full_metadata()),
        "the full Frame's Push carries the metadata"
    );
}

/// The text of the document's row for `packet`: from its opening to the next
/// row's, or to the end of the list for the last one.
#[cfg(feature = "dissect")]
fn row(doc: &str, packet: u32) -> &str {
    let key = alloc::format!("\"offset_space\":\"packet\",\"packet\":{packet},");
    let at = doc
        .find(&key)
        .unwrap_or_else(|| panic!("the document has no row for packet {packet}: {doc}"));
    let rest = &doc[at + key.len()..];
    let end = rest
        // A row opens with `{"direction":` and follows the previous row's `}` and
        // a comma; the row's own `conduit` also holds a `"direction":` key, but
        // after a colon, which is what tells the two apart.
        .find("},{\"direction\":\"")
        .or_else(|| rest.find("],\"shown\":"))
        .unwrap_or(rest.len());
    &rest[..end]
}

/// Whether `text` holds a field named `name`, of any kind.
#[cfg(feature = "dissect")]
fn has_field(text: &str, name: &str) -> bool {
    text.contains(&alloc::format!("{{\"name\":\"{name}\","))
}

/// The `value` of every LEAF field named `name` in `text`, as the document writes
/// it (a string keeps its quotes), in document order. A nested field has no value
/// of its own and is skipped; its children are found by their own names.
#[cfg(feature = "dissect")]
fn values_of<'a>(text: &'a str, name: &str) -> Vec<&'a str> {
    const VALUE: &str = "\"value\":";
    let key = alloc::format!("{{\"name\":\"{name}\",");
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(at) = text[from..].find(&key) {
        let start = from + at;
        let end = text[start..]
            .find('}')
            .map_or(text.len(), |close| start + close);
        let object = &text[start..end];
        if !object.contains("\"kind\":\"nested\"") {
            if let Some(v) = object.find(VALUE) {
                found.push(&object[v + VALUE.len()..]);
            }
        }
        from = start + key.len();
    }
    found
}

/// A zenoh id as zenoh prints it: the bytes in reverse, as lower-case hex with the
/// leading zeros dropped (`ZenohId`'s `Display`).
#[cfg(feature = "dissect")]
fn zid_text(bytes: &[u8]) -> alloc::string::String {
    let hex: alloc::string::String = bytes
        .iter()
        .rev()
        .map(|b| alloc::format!("{b:02x}"))
        .collect();
    hex.trim_start_matches('0').into()
}

/// The tracked file reaches the surface a consumer reads, and the three fields are
/// reported where they were set and ONLY there.
///
/// Both the document and the decoded records are read, because they are two paths
/// from the same bytes: a document that dropped a branch while the decoder kept it
/// (or the reverse) is a disagreement the control row is there to expose. Row 4,
/// the control, must carry no priority, no encoding and no timestamp; row 5 must
/// carry all three with the values the encoder was handed.
#[cfg(feature = "dissect")]
#[test]
fn the_tracked_publisher_fields_capture_reaches_the_consumer_surface() {
    use wz_session_core::inbound::InboundFrame;
    use wz_session_core::network_message::NetworkMessage;
    use wz_session_core::passive::Carried;
    use wz_session_core::push_build::read_push_timestamp;

    let d = crate::Dissection::from_capture(TRACKED).expect("the tracked capture dissects");
    let doc = crate::fields_json::fields_json(&d, TRACKED, None, None);

    // The session negotiated QoS: both Inits offered it.
    assert!(
        doc.contains("\"negotiated\":true,\"lowlatency\":false,\"compression\":false,\"qos\":true"),
        "the session must read as QoS-negotiated: {doc}"
    );

    // --- the document: the control row ---------------------------------------
    let control = row(&doc, 4);
    assert!(
        control.contains(&alloc::format!(
            "\"conduit\":{{\"direction\":\"a\",\"priority\":\"{}\",\"reliable\":true}}",
            Priority::DEFAULT.name()
        )),
        "the control rides the default conduit: {control}"
    );
    for absent in ["extensions", "priority", "timestamp", "encoding"] {
        assert!(
            !has_field(control, absent),
            "the control carries no `{absent}` field: {control}"
        );
    }
    assert_eq!(
        (values_of(control, "t"), values_of(control, "e")),
        (alloc::vec!["false"], alloc::vec!["false"]),
        "the control's Put sets neither the timestamp bit nor the encoding bit: {control}"
    );
    assert!(
        control.contains("\"encoding\":null,\"shm_descriptor\":false"),
        "the control's payload declares no encoding: {control}"
    );

    // --- the document: the full row -------------------------------------------
    let full = row(&doc, 5);
    let conduit = alloc::format!("\"{}\"", PRIORITY.name());
    assert!(
        full.contains(&alloc::format!(
            "\"conduit\":{{\"direction\":\"a\",\"priority\":{conduit},\"reliable\":true}}"
        )),
        "the full Frame rides the conduit it was sent on: {full}"
    );
    assert_eq!(
        values_of(full, "priority"),
        [conduit.as_str(), conduit.as_str()],
        "the Frame's `ext_qos` and the Push's QoS byte both name the priority: {full}"
    );
    let qos_raw = QosLevel::DEFAULT.with_priority(PRIORITY).raw;
    assert_eq!(
        values_of(full, "value"),
        [
            alloc::format!("{}", PRIORITY.wire_byte()),
            alloc::format!("{qos_raw}")
        ],
        "the two QoS bodies are the conduit and the Push's whole QoS byte: {full}"
    );
    assert_eq!(
        (values_of(full, "congestion"), values_of(full, "express")),
        (alloc::vec!["\"Drop\""], alloc::vec!["false"]),
        "the QoS byte keeps the default congestion control and no express: {full}"
    );
    assert_eq!(
        (values_of(full, "t"), values_of(full, "e")),
        (alloc::vec!["true"], alloc::vec!["true"]),
        "the Put sets the timestamp bit and the encoding bit: {full}"
    );
    assert!(
        has_field(full, "timestamp"),
        "the Put's timestamp is reported as a group of its own: {full}"
    );
    assert_eq!(
        (
            values_of(full, "time"),
            values_of(full, "zid_len"),
            values_of(full, "zid")
        ),
        (
            // An NTP64 word past 2^53 is written as a string, so no consumer
            // rounds it through a double.
            alloc::vec![alloc::format!("\"{TIMESTAMP_TIME}\"").as_str()],
            alloc::vec!["4"],
            alloc::vec![alloc::format!("\"{}\"", zid_text(&TIMESTAMP_ZID)).as_str()],
        ),
        "the timestamp is the one the encoder was handed: {full}"
    );
    assert_eq!(
        (values_of(full, "packed_id"), values_of(full, "has_schema")),
        (
            alloc::vec![alloc::format!("{}", u32::from(encoding_id()) << 1).as_str()],
            alloc::vec!["false"]
        ),
        "the Put's encoding field is the id the encoder was handed: {full}"
    );
    // The last `id` in the row is the encoding's (the keyexpr's comes first).
    assert_eq!(
        values_of(full, "id").last().copied(),
        Some(alloc::format!("{}", encoding_id()).as_str()),
        "and the id is split out of the packed word: {full}"
    );
    assert!(
        full.contains(&alloc::format!(
            "\"encoding\":\"{ENCODING_NAME}\",\"shm_descriptor\":false"
        )),
        "and the entry names it as zenoh prints it: {full}"
    );

    // --- the decoder: the same two messages, read without the document --------
    let flows = d.datagram_flows();
    assert_eq!(flows.len(), 1, "one session");
    let mut seen = Vec::new();
    for frame in flows[0].frames.iter() {
        let Carried::Batch(batch) = &frame.carried else {
            continue;
        };
        let Ok(InboundFrame::Frame { priority, .. }) = &frame.frame else {
            panic!(
                "a batch rode something that is not a Frame: {:?}",
                frame.frame
            );
        };
        let pushes: Vec<_> = batch
            .records()
            .filter_map(|(m, _)| match m {
                NetworkMessage::Push(push) => Some(push),
                _ => None,
            })
            .collect();
        let [push] = pushes.as_slice() else {
            panic!("a Frame of this capture carries exactly one Push");
        };
        let wz_session_core::wire::PushOwnedVariant::CodecZenohMsgPut(put) = &push.body else {
            panic!("the Push is a Put");
        };
        seen.push((
            *priority,
            read_push_timestamp(push),
            put.encoding.as_ref().map(EncodingHint::from_codec),
        ));
    }
    assert_eq!(
        seen,
        [
            (Priority::DEFAULT, None, None),
            (
                PRIORITY,
                full_metadata().timestamp,
                full_metadata().encoding
            ),
        ],
        "the control decodes bare and the full publish with what it was handed"
    );

    // --- the census agrees with the rows --------------------------------------
    let census = crate::census_json::census_json(&d);
    for declared in [
        alloc::format!("\"declared\":\"{ENCODING_NAME}\",\"payloads\":1"),
        alloc::string::String::from("\"declared\":\"zenoh/bytes (undeclared)\",\"payloads\":1"),
    ] {
        assert!(
            census.contains(&declared),
            "the payload plane counts one declared and one undeclared body: {census}"
        );
    }
}
