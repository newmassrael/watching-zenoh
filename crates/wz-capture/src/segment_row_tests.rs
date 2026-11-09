// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `segment` block of the field document (revision 59), over captures
//! built packet by packet.
//!
//! What the ledger tests (`segment_chain_tests`) cannot show is that the
//! pieces REACH it: that the pipeline finds a Push's key (resolved, or the id
//! and suffix of a reference it cannot resolve), the direction it travelled
//! and its payload, hands the pieces over in the order they were sent, writes
//! the verdict beside the entry, and reads the joined message by the key's own
//! rule. The profile is the synthetic one of `segment_profile_tests`, and every
//! test runs over both link kinds, whose row producers are separate loops.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use wz_session_core::json5::{self, Json5Value};

use crate::datagram_tests::{frame_carrying, push, sender_space};
use crate::e2e_row_tests::{Link, Wire, LINKS};
use crate::fields_json::fields_json;
use crate::payload::formats::FormatMap;
use crate::payload_decode::Declarations;
use crate::segment_profile_tests::{demo_piece, DEMO};

/// The message the senders split: JSON, so a `json` rule can read it joined.
const MESSAGE: &[u8] = br#"{"temp":21}"#;

/// `text` on one line, as a declaration needs it.
fn one_line(text: &str) -> String {
    text.split('\n').map(str::trim).collect::<Vec<_>>().join("")
}

/// The demo profile under a second name, without its CRC: recognised by its
/// mark alone, so its pieces carry no CRC verdict.
fn plain_profile() -> String {
    let text = one_line(DEMO).replacen("demo-split", "demo-plain", 1);
    let start = text.find(r#""crc":"#).expect("a crc");
    let end = text.find(r#""stream""#).expect("a stream");
    format!("{}{}", &text[..start], &text[end..])
}

/// The two profiles, a segment rule for each (the narrower first), and
/// `extra` rules after them.
fn declarations(extra: &str) -> String {
    format!(
        "#demo-split={}\n#demo-plain={}\ndemo/plain/**=demo-plain\n**=demo-split\n{extra}",
        one_line(DEMO),
        plain_profile()
    )
}

/// A key as a reference writes it: an id, and the suffix after it.
type Key = (u64, Option<&'static str>);

/// A literal key, written as id 0 and the key as its suffix.
fn literal(key: &'static str) -> Key {
    (0, Some(key))
}

/// One Push of `payload` under `key`, alone in a Frame, from the low end.
fn put(wire: &mut Wire, key: Key, payload: &[u8]) {
    let (id, suffix) = key;
    wire.send(
        true,
        None,
        &frame_carrying(&push(sender_space(id, suffix), payload)),
    );
}

/// Piece `range` of [`MESSAGE`], on stream `origin`, transfer `number`.
fn piece(origin: u16, number: u8, range: core::ops::Range<usize>) -> Vec<u8> {
    demo_piece(
        origin,
        number,
        MESSAGE.len() as u32,
        range.start as u32,
        &MESSAGE[range],
    )
}

fn document(wire: &mut Wire, text: &str) -> String {
    wire.d.finish();
    let mut map = FormatMap::new();
    map.declare_all(text).expect("declarations install");
    fields_json(&wire.d, &wire.file(), None, Some(&Declarations::new(&map)))
}

fn member<'v>(value: &'v Json5Value, key: &str) -> Option<&'v Json5Value> {
    match value {
        Json5Value::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn word(value: Option<&Json5Value>) -> Option<&str> {
    match value {
        Some(Json5Value::String(s)) => Some(s),
        _ => None,
    }
}

/// Every `key` member anywhere in `value`, in document order.
fn collect<'v>(value: &'v Json5Value, key: &str, out: &mut Vec<&'v Json5Value>) {
    match value {
        Json5Value::Object(entries) => {
            for (k, v) in entries {
                if k == key {
                    out.push(v);
                }
                collect(v, key, out);
            }
        }
        Json5Value::Array(items) => items.iter().for_each(|v| collect(v, key, out)),
        _ => {}
    }
}

/// Every `segment` block of the document, in order.
fn segments(doc: &str) -> Vec<Json5Value> {
    let tree = json5::parse(doc).expect("the document is JSON");
    let mut found = Vec::new();
    collect(&tree, "segment", &mut found);
    found.into_iter().cloned().collect()
}

/// The `place` of every segment block, in order (`-` for `null`).
fn places(doc: &str) -> Vec<String> {
    segments(doc)
        .iter()
        .map(|s| String::from(word(member(s, "place")).unwrap_or("-")))
        .collect()
}

/// The row-level `payload_decode.state` words, in order.
fn row_states(doc: &str) -> Vec<String> {
    let tree = json5::parse(doc).expect("the document is JSON");
    let mut found = Vec::new();
    collect(&tree, "payload_decode", &mut found);
    found
        .iter()
        .filter_map(|d| word(member(d, "state")))
        .map(String::from)
        .collect()
}

#[test]
fn pieces_on_a_resolved_key_join_and_the_message_is_read_by_the_keys_rule() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        put(&mut wire, literal("demo/large"), &piece(1, 1, 0..4));
        put(&mut wire, literal("demo/large"), &piece(1, 1, 4..8));
        put(&mut wire, literal("demo/large"), &piece(1, 1, 8..11));
        // An ordinary payload on the same key is no piece.
        put(&mut wire, literal("demo/large"), MESSAGE);
        let doc = document(&mut wire, &declarations("demo/**=json"));
        assert_eq!(
            places(&doc),
            ["first", "continuing", "closing"],
            "{link:?}: {doc}"
        );
        let blocks = segments(&doc);
        let joined = member(&blocks[2], "joined").expect("a joined key");
        assert!(
            matches!(member(&blocks[0], "joined"), Some(Json5Value::Null)),
            "{link:?}: only the closing piece carries the message"
        );
        assert!(
            matches!(member(joined, "whole_bytes"), Some(Json5Value::Number(n)) if n == "11"),
            "{link:?}: {doc}"
        );
        let decode = member(joined, "payload_decode").expect("the message is decoded");
        assert_eq!(
            word(member(decode, "state")),
            Some("decoded"),
            "{link:?}: {doc}"
        );
        assert_eq!(word(member(decode, "format")), Some("json"), "{link:?}");
        // The rows of the pieces say so; the ordinary payload decodes.
        let states = row_states(&doc);
        assert_eq!(
            states.iter().filter(|s| *s == "segment_piece").count(),
            3,
            "{link:?}: {states:?}"
        );
        assert!(
            states.iter().any(|s| s == "decoded"),
            "{link:?}: {states:?}"
        );
        // The header is reported field by field, the roles beside it.
        assert_eq!(word(member(&blocks[0], "profile")), Some("demo-split"));
        assert!(
            matches!(member(&blocks[1], "chunk_offset"), Some(Json5Value::Number(n)) if n == "4")
        );
    }
}

#[test]
fn pieces_under_an_unresolved_id_join_per_suffix_under_the_rule_for_every_key() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        // Two streams under one id, told apart by the suffix alone.
        put(&mut wire, (7, None), &piece(1, 1, 0..6));
        put(&mut wire, (7, Some("/@history")), &piece(1, 1, 0..6));
        put(&mut wire, (7, None), &piece(1, 1, 6..11));
        put(&mut wire, (7, Some("/@history")), &piece(1, 1, 6..11));
        let doc = document(&mut wire, &declarations(""));
        assert_eq!(
            places(&doc),
            ["first", "first", "closing", "closing"],
            "{link:?}: {doc}"
        );
        let blocks = segments(&doc);
        for closing in &blocks[2..] {
            let joined = member(closing, "joined").expect("joined");
            let decode = member(joined, "payload_decode").expect("decoded");
            assert_eq!(
                word(member(decode, "state")),
                Some("keyexpr_unresolved"),
                "{link:?}: no rule can be tested against a key nobody knows"
            );
        }
    }
}

#[test]
fn a_rule_narrower_than_every_key_does_not_cover_an_unresolved_reference() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        put(&mut wire, (7, None), &piece(1, 1, 0..11));
        let narrow = format!("#demo-split={}\ndemo/**=demo-split", one_line(DEMO));
        let doc = document(&mut wire, &narrow);
        assert!(segments(&doc).is_empty(), "{link:?}: {doc}");
    }
}

#[test]
fn a_new_transfer_ends_the_unjoined_one_and_a_damaged_piece_joins_nothing() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        put(&mut wire, literal("demo/large"), &piece(1, 1, 0..4));
        let mut damaged = piece(1, 1, 4..8);
        *damaged.last_mut().expect("a chunk") ^= 0x01;
        put(&mut wire, literal("demo/large"), &damaged);
        put(&mut wire, literal("demo/large"), &piece(1, 2, 0..11));
        let doc = document(&mut wire, &declarations(""));
        let blocks = segments(&doc);
        assert_eq!(places(&doc), ["first", "-", "whole"], "{link:?}: {doc}");
        assert_eq!(word(member(&blocks[1], "unjoined")), Some("crc_mismatch"));
        assert!(matches!(
            member(&blocks[1], "crc_error"),
            Some(Json5Value::Bool(true))
        ));
        let ended = match member(&blocks[2], "ended_transfers") {
            Some(Json5Value::Array(items)) => items.clone(),
            other => panic!("{link:?}: {other:?}"),
        };
        assert_eq!(ended.len(), 1, "{link:?}: {doc}");
        assert!(matches!(
            member(&ended[0], "received_bytes"),
            Some(Json5Value::Number(n)) if n == "4"
        ));
    }
}

/// The documents the field document's pins read to reach every key of the
/// `segment` block and every word of its two families and of `segment_piece`:
/// every place, every reason a piece joins nothing, a CRC verdict and a profile
/// with none, a missing range, an ended transfer, and a joined message with its
/// decode.
///
/// Stream captures, for the reason `e2e_row_tests::pin_documents` gives: the
/// pins this feeds are built over stream captures, and a datagram flow's
/// document carries keys of its own (`disagreements`) those pins never held.
/// The tests above run both links.
pub(crate) fn pin_documents() -> Vec<String> {
    {
        let mut wire = Wire::new(Link::Tcp, true);
        let key = || literal("demo/large");
        // first, continuing (out of order, with a gap), closing.
        put(&mut wire, key(), &piece(1, 1, 0..4));
        put(&mut wire, key(), &piece(1, 1, 8..11));
        put(&mut wire, key(), &piece(1, 1, 4..8));
        // after_closing.
        put(&mut wire, key(), &piece(1, 1, 4..8));
        // whole, on another stream.
        put(&mut wire, key(), &piece(2, 1, 0..11));
        // An open transfer, then a piece disagreeing on its total, then a new
        // transfer ending it unjoined.
        put(&mut wire, key(), &piece(3, 1, 0..4));
        put(&mut wire, key(), &demo_piece(3, 1, 40, 4, b"abcd"));
        put(&mut wire, key(), &piece(3, 2, 0..4));
        // Every other reason a piece joins nothing.
        let mut damaged = piece(4, 1, 0..4);
        *damaged.last_mut().expect("a chunk") ^= 0x01;
        put(&mut wire, key(), &damaged);
        put(&mut wire, key(), &demo_piece(4, 1, 0, 0, b"abc"));
        put(&mut wire, key(), &demo_piece(4, 1, 5000, 0, b"abc"));
        put(&mut wire, key(), &demo_piece(4, 1, 10, 0, b""));
        put(&mut wire, key(), &demo_piece(4, 1, 4, 2, b"abc"));
        // A profile with no CRC.
        put(&mut wire, literal("demo/plain/x"), &piece(5, 1, 0..11));
        // An id the wire never declared and a declaration fixed, so an entry's
        // `keyexpr_source` says `fixed_id` (every other says `wire` or null).
        // No format rule covers the fixed key: it adds the word and no state.
        put(&mut wire, (7, None), MESSAGE);
        // `protobuf` reads the joined message: a decoder the other pins already
        // render, so these documents add the `segment` keys and nothing else.
        alloc::vec![document(
            &mut wire,
            &declarations("demo/**=protobuf\n#%7=other/fixed")
        )]
    }
}

#[test]
fn the_pin_documents_reach_every_place_and_every_reason() {
    for doc in pin_documents() {
        let blocks = segments(&doc);
        let mut seen: Vec<&str> = blocks
            .iter()
            .filter_map(|b| word(member(b, "place")).or(word(member(b, "unjoined"))))
            .collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            seen,
            [
                "after_closing",
                "closing",
                "continuing",
                "crc_mismatch",
                "empty_chunk",
                "empty_total",
                "first",
                "past_total",
                "total_disagrees",
                "total_past_max",
                "whole"
            ],
            "{doc}"
        );
        assert!(
            blocks
                .iter()
                .any(|b| matches!(member(b, "crc_error"), Some(Json5Value::Null))),
            "a profile with no CRC writes null"
        );
    }
}
