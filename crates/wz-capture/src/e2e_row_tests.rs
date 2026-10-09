// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `e2e` block of the field document, over captures built packet by
//! packet.
//!
//! What the ledger tests (`e2e_slot_tests`) cannot show is that the frames
//! REACH it: that the pipeline finds a Push's key, the sender of its direction
//! and the instant of its packet, and hands them over in the order the frames
//! were sent, for a frame in a batch, in a chain of fragments and in a row the
//! since-door passes over. Every capture here is synthetic, the profiles are
//! the shape `e2e_slot_tests` and `e2e_tests` use, and the expected numbers are
//! written out by hand from the frames' counters.
//!
//! Every test runs over BOTH link kinds. A stream flow and a datagram flow are
//! two row producers in the field document, with their own loops, their own
//! cursor handling and their own way of finding a row's bytes, and a test over
//! one would leave the other's wiring unwatched.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use wz_session_core::json5::{self, Json5Value};

use crate::datagram_tests::{
    frame_carrying, push, sender_space, tcp_packet, tcp_packet_reverse, udp_packet,
};
use crate::e2e_frame::{build, Values};
use crate::e2e_profile::Profile;
use crate::fields_json::{fields_json, fields_json_since_coordinated, RowCoordinates, Since};
use crate::link::{FlowKey, LINKTYPE_ETHERNET};
use crate::node::tests::init_wire;
use crate::payload::formats::FormatMap;
use crate::payload_decode::Declarations;
use crate::Dissection;

const LOW: [u8; 4] = [10, 0, 0, 1];
const HIGH: [u8; 4] = [10, 0, 0, 2];

/// The sender zids, and the spelling zenoh prints them in: the little-endian
/// id read as a number, so the LAST wire byte comes first.
const ZID_LOW: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
const ZID_HIGH: [u8; 4] = [0x55, 0x66, 0x77, 0x88];
const HEX_LOW: &str = "44332211";
const HEX_HIGH: &str = "88776655";

/// The two kinds of link a row is produced for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Link {
    Udp,
    Tcp,
}

const LINKS: [Link; 2] = [Link::Udp, Link::Tcp];

/// A one-line profile: CRC first, a 2-byte counter that wraps at 65536, an
/// identifier whose wire value is XORed and split, and a slot keyed on the
/// whole identifier. `name` and `max_gap` vary between uses.
fn profile_text(name: &str, max_gap: u32) -> String {
    format!(
        r#"{{"name": "{name}", "fields": [{{"name": "crc", "bytes": 4}}, {{"name": "length", "bytes": 2}}, {{"name": "counter", "bytes": 2}}, {{"name": "ident", "bytes": 4, "xor": "0x00FF00FF", "split": [{{"name": "domain", "lsb": 24, "width": 8}}, {{"name": "msg", "lsb": 0, "width": 16}}]}}], "crc": {{"field": "crc", "width": 32, "poly": "0xF4ACFB13", "init": "0xFFFFFFFF", "refin": true, "refout": true, "xorout": "0xFFFFFFFF", "cover": ["length", "ident", "@payload", "counter"]}}, "length": {{"field": "length", "counts": "frame"}}, "counter": {{"field": "counter", "max_gap": {max_gap}, "timeout_ms": 100}}, "slot": {{"message": ["ident"]}}}}"#
    )
}

/// A second layout: CRC LAST and 8 bytes wide, so a frame read at the first
/// profile's offsets is damaged.
fn profile_b_text() -> String {
    String::from(
        r#"{"name": "prof-b", "fields": [{"name": "length", "bytes": 4}, {"name": "counter", "bytes": 4}, {"name": "tag", "bytes": 2}, {"name": "crc", "bytes": 8}], "crc": {"field": "crc", "width": 64, "poly": "0x42F0E1EBA9EA3693", "init": "0xFFFFFFFFFFFFFFFF", "refin": true, "refout": true, "xorout": "0xFFFFFFFFFFFFFFFF", "cover": ["counter", "@payload", "tag", "length"]}, "length": {"field": "length", "counts": "frame"}, "counter": {"field": "counter", "max_gap": 5, "timeout_ms": 50}}"#,
    )
}

fn prof() -> Profile {
    Profile::parse(&profile_text("prof", 3)).expect("reads")
}

/// A `prof` frame carrying `body`, with this counter.
fn frame(counter: u64, body: &[u8]) -> Vec<u8> {
    build(
        &prof(),
        &Values::new()
            .whole("counter", counter)
            .parts("ident", &[("domain", 2), ("msg", 700)]),
        body,
    )
    .expect("builds")
    .bytes
}

/// The same frame with a body bit flipped.
fn damaged(mut bytes: Vec<u8>) -> Vec<u8> {
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    bytes
}

/// A capture of one conversation, built packet by packet.
struct Wire {
    d: Dissection,
    packets: Vec<Vec<u8>>,
    link: Link,
    /// The next TCP sequence number of each end, low then high.
    next_seq: [u32; 2],
}

impl Wire {
    /// A conversation whose two ends have named themselves, when `named`.
    fn new(link: Link, named: bool) -> Self {
        let mut wire = Self {
            d: Dissection::new(),
            packets: Vec::new(),
            link,
            next_seq: [1000, 5000],
        };
        if named {
            wire.send(true, None, &init_wire(&ZID_LOW));
            wire.send(false, None, &init_wire(&ZID_HIGH));
        }
        wire
    }

    /// One message from the low end (`from_low`) or the high end, taken at
    /// `ns`. On a stream it is length-prefixed, as the stream reader needs.
    fn send(&mut self, from_low: bool, ns: Option<u64>, message: &[u8]) {
        let packet = match self.link {
            Link::Udp => {
                if from_low {
                    udp_packet(LOW, 43210, HIGH, 7447, message)
                } else {
                    udp_packet(HIGH, 7447, LOW, 43210, message)
                }
            }
            Link::Tcp => {
                let mut framed = (message.len() as u16).to_le_bytes().to_vec();
                framed.extend_from_slice(message);
                let end = usize::from(!from_low);
                let seq = self.next_seq[end];
                self.next_seq[end] += framed.len() as u32;
                if from_low {
                    tcp_packet(seq, &framed)
                } else {
                    tcp_packet_reverse(seq, &framed)
                }
            }
        };
        let index = self.packets.len();
        self.d
            .push_packet_at_nanos(LINKTYPE_ETHERNET, index, ns, &packet);
        self.packets.push(packet);
    }

    /// A Push of `payload` under `key`, alone in a Frame.
    fn put(&mut self, from_low: bool, ns: Option<u64>, key: &'static str, payload: &[u8]) {
        let record = push(sender_space(0, Some(key)), payload);
        self.send(from_low, ns, &frame_carrying(&record));
    }

    fn file(&self) -> Vec<u8> {
        let rows: Vec<(u32, u32, &[u8])> = self
            .packets
            .iter()
            .enumerate()
            .map(|(i, p)| (0u32, i as u32, p.as_slice()))
            .collect();
        crate::pcap::write(LINKTYPE_ETHERNET, &rows)
    }

    fn document(&mut self, declarations: &str) -> String {
        self.d.finish();
        let mut map = FormatMap::new();
        map.declare_all(declarations).expect("declarations install");
        let run = Declarations::new(&map);
        fields_json(&self.d, &self.file(), None, Some(&run))
    }
}

/// The documents and renderings the field document's pins read to reach every
/// key and every arm of the `e2e` block: a named sender with timestamps, a
/// sender the capture never named, a payload shorter than the header, and a
/// payload that is not bytes at all (which no capture here can make, so it is
/// rendered from the type).
///
/// Stream captures, and that is a choice: the pins this feeds are built over
/// stream captures, and a datagram flow's document carries keys of its own
/// (`disagreements`) that those pins have never held.
pub(crate) fn pin_documents() -> Vec<String> {
    const MS: u64 = 1_000_000;
    let declarations = format!(
        "#prof={}\ndemo/e2e/**=prof@pkg.Pose\n",
        profile_text("prof", 3)
    );
    let mut named = Wire::new(Link::Tcp, true);
    named.put(true, Some(MS), "demo/e2e/a", &frame(1, b"first"));
    named.put(true, Some(300 * MS), "demo/e2e/a", &frame(1, b"again"));
    named.put(
        true,
        Some(900 * MS),
        "demo/e2e/a",
        &damaged(frame(2, b"late")),
    );
    named.put(true, Some(901 * MS), "demo/e2e/a", b"short");
    let mut unnamed = Wire::new(Link::Tcp, false);
    unnamed.put(true, None, "demo/e2e/a", &frame(1, b"first"));

    let mut map = FormatMap::new();
    map.declare_all(&declarations).expect("installs");
    let run = Declarations::new(&map);
    let unreadable = run
        .judge_e2e("demo/e2e/a", None, None, None)
        .expect("a profile key");
    let mut block = String::new();
    crate::e2e_row::push_block(&unreadable, &mut block);
    alloc::vec![
        named.document(&declarations),
        unnamed.document(&declarations),
        block,
    ]
}

// ----------------------------------------------------------------- reading

fn parse(doc: &str) -> Json5Value {
    json5::parse(doc).expect("the document is JSON")
}

fn get<'a>(value: &'a Json5Value, key: &str) -> Option<&'a Json5Value> {
    match value {
        Json5Value::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

/// Every value held under the key `e2e`, at any depth, in document order.
fn blocks_of(value: &Json5Value, out: &mut Vec<Json5Value>) {
    match value {
        Json5Value::Object(entries) => {
            for (key, inner) in entries {
                if key == "e2e" {
                    out.push(inner.clone());
                } else {
                    blocks_of(inner, out);
                }
            }
        }
        Json5Value::Array(items) => {
            for item in items {
                blocks_of(item, out);
            }
        }
        _ => {}
    }
}

fn e2e_blocks(doc: &str) -> Vec<Json5Value> {
    let mut out = Vec::new();
    blocks_of(&parse(doc), &mut out);
    out
}

/// The blocks that sit under an `above_transport` key, which is where a message
/// that arrived in fragments is judged.
fn blocks_above_transport(value: &Json5Value, out: &mut Vec<Json5Value>) {
    match value {
        Json5Value::Object(entries) => {
            for (key, inner) in entries {
                if key == "above_transport" {
                    blocks_of(inner, out);
                } else {
                    blocks_above_transport(inner, out);
                }
            }
        }
        Json5Value::Array(items) => {
            for item in items {
                blocks_above_transport(item, out);
            }
        }
        _ => {}
    }
}

fn text(value: &Json5Value, key: &str) -> Option<String> {
    match get(value, key)? {
        Json5Value::String(s) => Some(s.clone()),
        Json5Value::Number(n) => Some(n.clone()),
        Json5Value::Bool(b) => Some(b.to_string()),
        Json5Value::Null => Some(String::from("null")),
        _ => None,
    }
}

/// `(counter_error, counter_reason)` of a block.
fn counter_verdict(block: &Json5Value) -> (String, String) {
    (
        text(block, "counter_error").expect("counter_error"),
        text(block, "counter_reason").expect("counter_reason"),
    )
}

const FINE: (&str, &str) = ("false", "none");
const REPEAT: (&str, &str) = ("true", "repeat");
const JUMP: (&str, &str) = ("true", "out_of_range");

fn verdicts(doc: &str) -> Vec<(String, String)> {
    e2e_blocks(doc).iter().map(counter_verdict).collect()
}

fn expect(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect()
}

fn strings(values: &[&str]) -> Vec<Option<String>> {
    values.iter().map(|v| Some(v.to_string())).collect()
}

fn rules(extra: &str) -> String {
    format!("#prof={}\n{extra}", profile_text("prof", 3))
}

// ------------------------------------------------------------------- rules

#[test]
fn only_the_entries_a_profile_rule_covers_carry_an_e2e_block() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        wire.put(true, None, "demo/e2e/a", &frame(1, b"\x08\x96\x01"));
        wire.put(true, None, "demo/plain/b", b"not a frame");
        let doc = wire.document(&rules("demo/e2e/**=prof@pkg.Pose\ndemo/**=json\n"));

        let blocks = e2e_blocks(&doc);
        assert_eq!(
            blocks.len(),
            1,
            "{link:?}: one covered Push, one uncovered: {doc}"
        );
        let block = &blocks[0];
        assert_eq!(text(block, "profile").as_deref(), Some("prof"));
        assert_eq!(text(block, "body_schema").as_deref(), Some("pkg.Pose"));
        let rule = get(block, "matched_rule").expect("matched_rule");
        assert_eq!(text(rule, "index").as_deref(), Some("0"));
        assert_eq!(text(rule, "pattern").as_deref(), Some("demo/e2e/**"));
        assert_eq!(text(block, "opened").as_deref(), Some("true"));
        assert_eq!(text(block, "payload_offset").as_deref(), Some("12"));
        assert_eq!(text(block, "payload_bytes").as_deref(), Some("3"));
        assert_eq!(text(block, "crc_error").as_deref(), Some("false"));
        assert_eq!(text(block, "counter").as_deref(), Some("1"));
        assert_eq!(text(block, "length_field").as_deref(), Some("15"));
        assert_eq!(text(block, "length_expected").as_deref(), Some("15"));
        assert_eq!(text(block, "length_matches_frame").as_deref(), Some("true"));
        // No packet carried a time, so no timeout was judged: `null`, and not
        // false.
        assert_eq!(text(block, "timeout_error").as_deref(), Some("null"));
        assert_eq!(text(block, "silence_ms").as_deref(), Some("null"));
        assert_eq!(
            counter_verdict(block),
            (String::from("false"), String::from("none"))
        );

        let slot = get(block, "slot").expect("slot");
        assert_eq!(text(slot, "keyexpr").as_deref(), Some("demo/e2e/a"));
        assert_eq!(text(slot, "zid").as_deref(), Some(HEX_LOW));
        // The identifier is the logical value (700 in the low 16 bits, 2 in the
        // top byte, with the wire's XOR undone), under the profile's own name.
        let Some(Json5Value::Array(identity)) = get(slot, "identity") else {
            panic!("identity: {doc}");
        };
        assert_eq!(identity.len(), 1);
        assert_eq!(text(&identity[0], "name").as_deref(), Some("ident"));
        assert_eq!(text(&identity[0], "value").as_deref(), Some("33555132"));

        // The body is read beside the verdict, in payload coordinates.
        assert!(doc.contains("\"format\":\"prof\""), "{doc}");
        assert!(doc.contains("\"state\":\"decoded\""), "{doc}");
    }
}

#[test]
fn a_rule_ahead_of_the_profile_rule_keeps_its_keys_out_of_the_block() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        wire.put(true, None, "demo/e2e/a", &frame(1, b"x"));
        let doc = wire.document(&rules("demo/e2e/**=json\ndemo/e2e/a=prof\n"));
        assert!(e2e_blocks(&doc).is_empty(), "{link:?}: {doc}");
        assert!(!doc.contains("\"e2e\""), "{link:?}: {doc}");
    }
}

#[test]
fn a_profile_that_no_rule_names_adds_nothing_to_the_document() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        wire.put(true, None, "demo/e2e/a", &frame(1, b"x"));
        let with = wire.document(&rules("demo/**=json\n"));
        let without = wire.document("demo/**=json\n");
        assert!(!with.contains("\"e2e\""), "{link:?}: {with}");
        assert_eq!(with, without, "{link:?}");
    }
}

// ----------------------------------------------------------------- slots

#[test]
fn a_counter_is_judged_across_the_rows_of_the_document_in_order() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        for counter in [65534u64, 65535, 0, 0, 3, 7, 8] {
            wire.put(true, None, "demo/e2e/a", &frame(counter, b"body"));
        }
        let doc = wire.document(&rules("demo/e2e/**=prof\n"));
        assert_eq!(
            verdicts(&doc),
            expect(&[FINE, FINE, FINE, REPEAT, FINE, JUMP, FINE]),
            "{link:?}"
        );
    }
}

#[test]
fn the_two_senders_of_a_conversation_keep_their_own_counters() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        // The low end counts from 1 and the high end from 100, on one key,
        // interleaved. Keyed by the key alone, each would be a jump from the
        // other.
        for (from_low, counter) in [
            (true, 1u64),
            (false, 100),
            (true, 2),
            (false, 101),
            (true, 3),
            (false, 102),
        ] {
            wire.put(from_low, None, "demo/e2e/a", &frame(counter, b"body"));
        }
        let doc = wire.document(&rules("demo/e2e/**=prof\n"));
        assert_eq!(verdicts(&doc), expect(&[FINE; 6]), "{link:?}");
        let zids: Vec<String> = e2e_blocks(&doc)
            .iter()
            .map(|b| text(get(b, "slot").expect("slot"), "zid").expect("zid"))
            .collect();
        assert_eq!(
            zids,
            [HEX_LOW, HEX_HIGH, HEX_LOW, HEX_HIGH, HEX_LOW, HEX_HIGH],
            "{link:?}"
        );
    }
}

#[test]
fn a_sender_the_capture_never_named_gets_a_crc_verdict_and_no_counter_verdict() {
    for link in LINKS {
        let mut wire = Wire::new(link, false);
        wire.put(true, None, "demo/e2e/a", &frame(1, b"body"));
        wire.put(true, None, "demo/e2e/a", &frame(1, b"body"));
        wire.put(true, None, "demo/e2e/a", &damaged(frame(2, b"body")));
        let doc = wire.document(&rules("demo/e2e/**=prof\n"));
        let blocks = e2e_blocks(&doc);
        assert_eq!(blocks.len(), 3, "{link:?}");
        for block in &blocks {
            assert_eq!(text(block, "counter_error").as_deref(), Some("null"));
            assert_eq!(text(block, "timeout_error").as_deref(), Some("null"));
            assert_eq!(text(block, "counter_reason").as_deref(), Some("null"));
            assert_eq!(
                text(get(block, "slot").expect("slot"), "zid").as_deref(),
                Some("null")
            );
        }
        // The CRC needs no slot.
        let crc: Vec<_> = blocks.iter().map(|b| text(b, "crc_error")).collect();
        assert_eq!(crc, strings(&["false", "false", "true"]), "{link:?}");
    }
}

#[test]
fn the_timeout_is_judged_against_the_instants_the_capture_took_the_packets_at() {
    const MS: u64 = 1_000_000;
    // Sub-millisecond digits on every instant, so the silence is the
    // difference of whole milliseconds and not of the raw nanoseconds.
    let at = |ms: u64| Some(1_700_000_000_000_000_000 + ms * MS + 7);
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        wire.put(true, at(0), "demo/e2e/a", &frame(1, b"body"));
        wire.put(true, at(50), "demo/e2e/a", &frame(2, b"body"));
        wire.put(true, at(250), "demo/e2e/a", &frame(3, b"body"));
        wire.put(true, at(500), "demo/e2e/a", &damaged(frame(4, b"body")));
        let doc = wire.document(&rules("demo/e2e/**=prof\n"));
        let blocks = e2e_blocks(&doc);
        let timeouts: Vec<_> = blocks.iter().map(|b| text(b, "timeout_error")).collect();
        let silences: Vec<_> = blocks.iter().map(|b| text(b, "silence_ms")).collect();
        // A valid frame ends its silence however long it was; the damaged one
        // moves nothing, so it is judged against the valid frame at 250 and is
        // late.
        assert_eq!(
            timeouts,
            strings(&["false", "false", "false", "true"]),
            "{link:?}"
        );
        assert_eq!(silences, strings(&["null", "50", "200", "250"]), "{link:?}");
    }
}

#[test]
fn each_profile_is_read_at_its_own_offsets() {
    let b = Profile::parse(&profile_b_text()).expect("reads");
    let frame_b = build(
        &b,
        &Values::new().whole("counter", 9).whole("tag", 5),
        b"second-profile-body",
    )
    .expect("builds")
    .bytes;
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        wire.put(true, None, "demo/a/x", &frame(1, b"first-profile-body"));
        wire.put(true, None, "demo/b/x", &frame_b);
        let declarations = format!(
            "#prof={}\n#prof-b={}\ndemo/a/**=prof\ndemo/b/**=prof-b\n",
            profile_text("prof", 3),
            profile_b_text()
        );
        let doc = wire.document(&declarations);
        let blocks = e2e_blocks(&doc);
        assert_eq!(blocks.len(), 2, "{link:?}");
        assert_eq!(text(&blocks[0], "profile").as_deref(), Some("prof"));
        assert_eq!(text(&blocks[1], "profile").as_deref(), Some("prof-b"));
        for block in &blocks {
            assert_eq!(text(block, "crc_error").as_deref(), Some("false"), "{doc}");
        }
        assert_eq!(text(&blocks[1], "counter").as_deref(), Some("9"));
        assert_eq!(text(&blocks[1], "payload_offset").as_deref(), Some("18"));
    }
}

#[test]
fn a_batch_is_judged_in_the_order_its_frames_were_batched() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        let first = push(sender_space(0, Some("demo/e2e/a")), &frame(1, b"one"));
        let second = push(sender_space(0, Some("demo/e2e/a")), &frame(1, b"two"));
        let other = push(sender_space(0, Some("demo/e2e/b")), &frame(1, b"three"));
        let batch: Vec<u8> = [first, second, other].concat();
        wire.send(true, None, &frame_carrying(&batch));
        let doc = wire.document(&rules("demo/e2e/**=prof\n"));
        // The second record repeats the first's counter on the SAME key, and
        // the third carries the same counter on ANOTHER key, which is its own
        // slot.
        assert_eq!(
            verdicts(&doc),
            expect(&[FINE, REPEAT, FINE]),
            "{link:?}: {doc}"
        );
    }
}

/// One `Fragment` message: reliable, `more` as asked, sequence number `sn`.
fn fragment(sn: u8, more: bool, piece: &[u8]) -> Vec<u8> {
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

#[test]
fn a_frame_that_arrived_in_fragments_is_judged_where_its_chain_completed() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        // 150 body bytes: a message cut in two, as a frame too big for a batch
        // is.
        let message = push(sender_space(0, Some("demo/e2e/a")), &frame(5, &[0xAB; 150]));
        let (head, tail) = message.split_at(message.len() / 2);
        wire.send(true, None, &fragment(0, true, head));
        wire.send(true, None, &fragment(1, false, tail));
        // And a frame that was not fragmented, with the SAME counter: the two
        // routes share one slot, so this is a repetition.
        wire.put(true, None, "demo/e2e/a", &frame(5, b"direct"));
        wire.put(true, None, "demo/e2e/a", &frame(6, b"direct"));
        let doc = wire.document(&rules("demo/e2e/**=prof\n"));

        assert!(
            doc.contains("\"carried_state\":\"reassembled\""),
            "{link:?}: the chain completed: {doc}"
        );
        assert_eq!(
            verdicts(&doc),
            expect(&[FINE, REPEAT, FINE]),
            "{link:?}: {doc}"
        );
        // The first block is the one inside the completed chain's record, and
        // the fragment row that began the chain carries none.
        let mut inside = Vec::new();
        blocks_above_transport(&parse(&doc), &mut inside);
        assert_eq!(
            inside.len(),
            1,
            "{link:?}: one block under above_transport: {doc}"
        );
        assert_eq!(text(&inside[0], "payload_bytes").as_deref(), Some("150"));
    }
}

/// A numbering that numbers every list and every row by its produced-index
/// plus one, as a handle's would.
struct Numbered;

impl RowCoordinates for Numbered {
    fn list_id(&self, list: usize) -> Option<u64> {
        Some(list as u64)
    }

    fn scouting_list_id(&self, _flow: &FlowKey) -> Option<u64> {
        Some(u64::MAX)
    }

    fn row_seq(&self, _list: usize, produced: u64) -> Option<u64> {
        Some(produced + 1)
    }

    fn scouting_row_seq(&self, _flow: &FlowKey, produced: u64) -> Option<u64> {
        Some(produced + 1)
    }
}

#[test]
fn a_row_the_cursor_passes_over_still_moves_the_counter_of_the_rows_after_it() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        // Rows 1 and 2 are the two handshakes; the frames are rows 3, 4 and 5.
        // The fifth repeats the fourth.
        wire.put(true, None, "demo/e2e/a", &frame(10, b"body"));
        wire.put(true, None, "demo/e2e/a", &frame(11, b"body"));
        wire.put(true, None, "demo/e2e/a", &frame(11, b"body"));
        wire.d.finish();
        let mut map = FormatMap::new();
        map.declare_all(&rules("demo/e2e/**=prof\n"))
            .expect("installs");
        let run = Declarations::new(&map);
        let doc = fields_json_since_coordinated(
            &wire.d,
            &wire.file(),
            Some(&run),
            &Numbered,
            Since {
                after_seq: 4,
                through_seq: 5,
            },
        );
        // Only the fifth row is written, and it is judged as the repetition it
        // is: had the rows before it not been judged, it would be the first
        // frame its slot ever received.
        assert_eq!(verdicts(&doc), expect(&[REPEAT]), "{link:?}: {doc}");
        assert!(
            doc.contains("\"payload_mapping_counts_exact\":false"),
            "{link:?}: the passed rows are still reported as not walked: {doc}"
        );
    }
}

#[test]
fn a_cursor_with_no_profile_rule_does_not_walk_the_rows_it_passes_over() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        wire.put(true, None, "demo/e2e/a", &frame(10, b"body"));
        wire.d.finish();
        let mut map = FormatMap::new();
        map.declare_all("demo/**=json\n").expect("installs");
        let run = Declarations::new(&map);
        let doc = fields_json_since_coordinated(
            &wire.d,
            &wire.file(),
            Some(&run),
            &Numbered,
            Since {
                after_seq: 3,
                through_seq: 3,
            },
        );
        assert!(!doc.contains("\"e2e\""), "{link:?}: {doc}");
        assert_eq!(run.e2e_slots(), 0, "{link:?}");
    }
}
