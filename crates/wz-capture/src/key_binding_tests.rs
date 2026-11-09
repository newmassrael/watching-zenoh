// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Fixed key ids (`#%<id>=<keyexpr>`) and the values of messages a sender split
//! into pieces.
//!
//! A sender whose key ids are fixed in advance never declares them on the wire,
//! so every reference it writes is one the wire's tables cannot answer. These
//! tests hold what a declaration fixing the id changes: the key the field
//! document reads such a reference under (and says it read it under), every rule
//! that then applies, a reference the wire DOES answer staying the wire's, and
//! the values door reading the message the pieces join to.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use wz_session_core::json5::{self, Json5Value};

use crate::datagram_tests::{frame_carrying, push, sender_space};
use crate::e2e_row_tests::{Wire, LINKS};
use crate::field_values::{field_values_since, ValuesAsk, ValuesMemory};
use crate::field_values_tests::Numbered;
use crate::fields_json::fields_json;
use crate::payload::formats::{
    declaration_text, parse_declaration, DeclarationKind, DeclarationText, FormatMap,
    FormatMapError,
};
use crate::payload_decode::Declarations;
use crate::segment_profile_tests::{demo_piece, DEMO};

/// The message the senders split: JSON, so a `json` rule reads it joined.
const MESSAGE: &[u8] = br#"{"temp":21}"#;

/// `text` on one line, as a declaration needs it.
fn one_line(text: &str) -> String {
    text.split('\n').map(str::trim).collect::<Vec<_>>().join("")
}

/// One Push of `payload` under the id `id` with `suffix`, alone in a Frame,
/// from the low end.
fn put(wire: &mut Wire, id: u64, suffix: Option<&'static str>, payload: &[u8]) {
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

/// Every `carried` entry of the document that names a key or a miss: the
/// records a Push carries, in document order.
fn records(doc: &str) -> Vec<Json5Value> {
    fn walk(value: &Json5Value, out: &mut Vec<Json5Value>) {
        match value {
            Json5Value::Object(entries) => {
                for (k, v) in entries {
                    if k == "carried" {
                        if let Json5Value::Array(items) = v {
                            out.extend(
                                items
                                    .iter()
                                    .filter(|e| word(member(e, "message")) == Some("Push"))
                                    .cloned(),
                            );
                        }
                    }
                    walk(v, out);
                }
            }
            Json5Value::Array(items) => items.iter().for_each(|v| walk(v, out)),
            _ => {}
        }
    }
    let tree = json5::parse(doc).expect("the document is JSON");
    let mut out = Vec::new();
    walk(&tree, &mut out);
    out
}

#[test]
fn a_key_binding_line_reads_back_as_itself_and_is_its_own_kind() {
    let line = "#%7=demo/sensor/temp";
    assert_eq!(
        parse_declaration(line),
        Ok(DeclarationText::KeyBinding {
            id: 7,
            keyexpr: "demo/sensor/temp"
        })
    );
    assert_eq!(
        declaration_text(&parse_declaration(line).expect("a binding")),
        line
    );
    let mut map = FormatMap::new();
    let read = map.declare_described(line).expect("installed");
    assert_eq!(read.kind, DeclarationKind::KeyBinding);
    assert_eq!(read.pattern.as_deref(), Some("demo/sensor/temp"));
    assert_eq!(read.rule_index, None);
    let listed = map.declarations();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].kind, DeclarationKind::KeyBinding);
    assert_eq!(listed[0].text, line);
    assert_eq!(
        map.key_bindings().collect::<Vec<_>>(),
        [(7, "demo/sensor/temp")]
    );
    assert!(!map.is_empty(), "a binding alone is a declaration");
}

#[test]
fn a_name_that_is_not_the_mark_and_digits_alone_stays_a_definition() {
    // `%` followed by anything but digits only is a definition's name, as it
    // was before the binding existed.
    assert!(matches!(
        parse_declaration("#%7x=u8 a"),
        Ok(DeclarationText::Definition { name: "%7x", .. })
    ));
    assert!(matches!(
        parse_declaration("#%=u8 a"),
        Ok(DeclarationText::Definition { name: "%", .. })
    ));
}

#[test]
fn an_id_zero_an_id_bound_twice_and_a_key_that_is_none_are_refused() {
    let mut map = FormatMap::new();
    assert_eq!(
        map.declare("#%0=demo/a"),
        Err(FormatMapError::KeyIdZero(String::from("demo/a")))
    );
    map.declare("#%7=demo/a").expect("the first binding of 7");
    assert_eq!(
        map.declare("#%7=demo/b"),
        Err(FormatMapError::KeyIdBound(7))
    );
    assert!(matches!(
        map.declare("#%8=demo//b"),
        Err(FormatMapError::NotAKeyexpr(..))
    ));
    // An id past the largest a reference can write names no id.
    assert!(matches!(
        map.declare("#%99999999999999999999=demo/a"),
        Err(FormatMapError::NotADeclaration(_))
    ));
    // Each refusal names itself in a sentence.
    let why = format!("{}", FormatMapError::KeyIdBound(7));
    assert!(why.contains("already bound"), "{why}");
}

#[test]
fn a_reference_the_wire_does_not_answer_is_read_under_the_fixed_key() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        put(&mut wire, 7, None, MESSAGE);
        put(&mut wire, 7, Some("/@history"), MESSAGE);
        put(&mut wire, 9, None, MESSAGE);
        let doc = document(&mut wire, "#%7=demo/sensor\ndemo/**=json");
        let entries = records(&doc);
        assert_eq!(entries.len(), 3, "{link:?}: {doc}");
        // The fixed key, its suffix appended, and the wire's miss still said.
        assert_eq!(word(member(&entries[0], "keyexpr")), Some("demo/sensor"));
        assert_eq!(
            word(member(&entries[1], "keyexpr")),
            Some("demo/sensor/@history"),
            "{link:?}: {doc}"
        );
        for entry in &entries[..2] {
            assert_eq!(
                word(member(entry, "keyexpr_source")),
                Some("fixed_id"),
                "{link:?}"
            );
            assert!(
                word(member(entry, "keyexpr_cause")).is_some(),
                "{link:?}: the wire still did not answer it"
            );
            assert!(matches!(
                member(entry, "keyexpr_id"),
                Some(Json5Value::Number(n)) if n == "7"
            ));
        }
        assert!(matches!(
            member(&entries[1], "keyexpr_suffix"),
            Some(Json5Value::String(s)) if s == "/@history"
        ));
        // An id no declaration fixed stays unresolved.
        assert!(matches!(
            member(&entries[2], "keyexpr"),
            Some(Json5Value::Null)
        ));
        assert!(matches!(
            member(&entries[2], "keyexpr_source"),
            Some(Json5Value::Null)
        ));
        // The rule for the fixed key reads the payload. `demo/**` does not
        // cover `demo/sensor/@history`: `**` matches no chunk that opens with
        // `@`, which is a fact about the key and not about where it came from.
        // The rows that carry no payload (the session's own) are left out.
        let tree = json5::parse(&doc).expect("JSON");
        let mut decodes = Vec::new();
        collect_states(&tree, &mut decodes);
        decodes.retain(|s| s != "no_payload");
        assert_eq!(
            decodes,
            ["decoded", "no_rule", "keyexpr_unresolved"],
            "{link:?}: {doc}"
        );
    }
}

/// The `payload_decode.state` words of the rows, in order.
fn collect_states(value: &Json5Value, out: &mut Vec<String>) {
    match value {
        Json5Value::Object(entries) => {
            for (k, v) in entries {
                if k == "payload_decode" {
                    if let Some(state) = word(member(v, "state")) {
                        out.push(String::from(state));
                    }
                }
                collect_states(v, out);
            }
        }
        Json5Value::Array(items) => items.iter().for_each(|v| collect_states(v, out)),
        _ => {}
    }
}

#[test]
fn a_reference_the_wire_answers_is_the_wires_and_says_so() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        // A literal key, as most references are written.
        put(&mut wire, 0, Some("demo/literal"), MESSAGE);
        let doc = document(&mut wire, "#%7=demo/sensor\ndemo/**=json");
        let entries = records(&doc);
        assert_eq!(word(member(&entries[0], "keyexpr")), Some("demo/literal"));
        assert_eq!(
            word(member(&entries[0], "keyexpr_source")),
            Some("wire"),
            "{link:?}: {doc}"
        );
        assert!(matches!(
            member(&entries[0], "keyexpr_cause"),
            Some(Json5Value::Null)
        ));
    }
}

#[test]
fn without_a_binding_every_entry_says_where_its_key_came_from() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        put(&mut wire, 7, None, MESSAGE);
        let doc = document(&mut wire, "demo/**=json");
        let entries = records(&doc);
        assert!(matches!(
            member(&entries[0], "keyexpr_source"),
            Some(Json5Value::Null)
        ));
    }
}

/// The two segment declarations of `segment_row_tests`: the synthetic profile
/// and a rule covering every key, then `extra`.
fn split_declarations(extra: &str) -> String {
    format!("#demo-split={}\n**=demo-split\n{extra}", one_line(DEMO))
}

#[test]
fn pieces_under_a_fixed_id_join_and_the_message_is_read_by_its_keys_rule() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        put(&mut wire, 7, None, &piece(1, 1, 0..6));
        put(&mut wire, 7, None, &piece(1, 1, 6..11));
        let doc = document(
            &mut wire,
            &split_declarations("#%7=demo/large\ndemo/**=json"),
        );
        let entries = records(&doc);
        let closing = member(&entries[1], "segment").expect("a segment block");
        assert_eq!(word(member(closing, "place")), Some("closing"));
        let joined = member(closing, "joined").expect("joined");
        let decode = member(joined, "payload_decode").expect("decoded");
        assert_eq!(
            word(member(decode, "state")),
            Some("decoded"),
            "{link:?}: the joined message is read under the fixed key: {doc}"
        );
        assert_eq!(word(member(decode, "keyexpr")), Some("demo/large"));
    }
}

/// The values document over `wire` for `paths`, every row.
fn values(wire: &mut Wire, text: &str, paths: &str) -> Json5Value {
    wire.d.finish();
    let any = crate::filter::Filter::any();
    let doc = field_values_since(
        &wire.d,
        &Numbered,
        ValuesAsk {
            declarations: text,
            selector: "",
            filter: &any,
            paths,
            after_seq: 0,
            through_seq: u64::MAX,
        },
        &mut ValuesMemory::new(),
        None,
    )
    .expect("a document");
    json5::parse(&doc).expect("the values document is JSON")
}

fn value_records(doc: &Json5Value) -> Vec<Json5Value> {
    match member(doc, "records") {
        Some(Json5Value::Array(items)) => items.clone(),
        other => panic!("records: {other:?}"),
    }
}

#[test]
fn the_values_door_reads_the_message_the_pieces_join_to() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        put(&mut wire, 0, Some("demo/large"), &piece(1, 1, 0..4));
        put(&mut wire, 0, Some("demo/large"), &piece(1, 1, 4..8));
        put(&mut wire, 0, Some("demo/large"), &piece(1, 1, 8..11));
        // A whole message on the same key is a record as it always was.
        put(&mut wire, 0, Some("demo/large"), MESSAGE);
        let doc = values(&mut wire, &split_declarations("demo/**=json"), "$.temp");
        let recs = value_records(&doc);
        let states: Vec<&str> = recs
            .iter()
            .map(|r| word(member(r, "state")).unwrap_or("-"))
            .collect();
        assert_eq!(
            states,
            ["segment_piece", "segment_piece", "decoded", "decoded"],
            "{link:?}: {doc:?}"
        );
        // The first two say why they have no value: still missing bytes.
        let first = member(&recs[0], "segment").expect("a segment");
        assert_eq!(word(member(first, "place")), Some("first"));
        assert!(matches!(
            member(first, "whole_bytes"),
            Some(Json5Value::Number(n)) if n == "11"
        ));
        // The closing piece carries the joined message's value.
        let closing = member(&recs[2], "segment").expect("a segment");
        assert_eq!(word(member(closing, "place")), Some("closing"));
        let values = match member(&recs[2], "values") {
            Some(Json5Value::Array(items)) => items.clone(),
            other => panic!("{link:?}: {other:?}"),
        };
        assert_eq!(values.len(), 1, "{link:?}: {doc:?}");
        assert_eq!(word(member(&values[0], "path")), Some("$.temp"));
        // The whole message is not a piece.
        assert!(matches!(
            member(&recs[3], "segment"),
            Some(Json5Value::Null)
        ));
    }
}

#[test]
fn the_values_door_reads_a_fixed_id_and_says_why_an_unclosed_message_has_no_value() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        put(&mut wire, 7, None, &piece(1, 1, 0..6));
        put(&mut wire, 7, None, &piece(1, 1, 6..11));
        // A damaged piece of a second message: it joins nothing.
        let mut damaged = piece(1, 2, 0..6);
        *damaged.last_mut().expect("a chunk") ^= 0x01;
        put(&mut wire, 7, None, &damaged);
        let doc = values(
            &mut wire,
            &split_declarations("#%7=demo/large\ndemo/**=json"),
            "$.temp",
        );
        let recs = value_records(&doc);
        assert_eq!(recs.len(), 3, "{link:?}: {doc:?}");
        for rec in &recs {
            assert_eq!(word(member(rec, "keyexpr")), Some("demo/large"));
            assert_eq!(word(member(rec, "keyexpr_source")), Some("fixed_id"));
        }
        assert_eq!(word(member(&recs[1], "state")), Some("decoded"));
        assert_eq!(word(member(&recs[2], "state")), Some("segment_piece"));
        let why = member(&recs[2], "segment").expect("a segment");
        assert_eq!(word(member(why, "unjoined")), Some("crc_mismatch"));
    }
}

#[test]
fn an_unfixed_id_splits_are_joined_and_told_as_an_unknown_key() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        put(&mut wire, 7, None, &piece(1, 1, 0..6));
        put(&mut wire, 7, None, &piece(1, 1, 6..11));
        let doc = values(&mut wire, &split_declarations("demo/**=json"), "$.temp");
        let recs = value_records(&doc);
        let states: Vec<&str> = recs
            .iter()
            .map(|r| word(member(r, "state")).unwrap_or("-"))
            .collect();
        assert_eq!(
            states,
            ["segment_piece", "keyexpr_unresolved"],
            "{link:?}: {doc:?}"
        );
        let closing = member(&recs[1], "segment").expect("a segment");
        assert_eq!(word(member(closing, "place")), Some("closing"));
    }
}

/// The values documents the gates read to reach what revision 2 adds: a piece
/// of each kind of `segment_piece` record (the first of a message, one that
/// disagrees on the total, one whose CRC is wrong, one that ends an unfinished
/// message), a message completed under a fixed id, and a whole message under a
/// key the wire wrote, so `keyexpr_source`, `place` and `unjoined` each arrive
/// with two words or more and `ended_transfers` holds an entry.
pub(crate) fn values_documents_for_the_gates() -> Vec<String> {
    let mut wire = Wire::new(crate::e2e_row_tests::Link::Tcp, true);
    put(&mut wire, 7, None, &piece(1, 1, 0..4));
    put(&mut wire, 7, None, &demo_piece(1, 1, 40, 4, b"abcd"));
    let mut damaged = piece(1, 1, 4..8);
    *damaged.last_mut().expect("a chunk") ^= 0x01;
    put(&mut wire, 7, None, &damaged);
    put(&mut wire, 7, None, &piece(1, 2, 0..6));
    put(&mut wire, 7, None, &piece(1, 2, 6..11));
    put(&mut wire, 0, Some("demo/large"), MESSAGE);
    wire.d.finish();
    let any = crate::filter::Filter::any();
    let text = split_declarations("#%7=demo/large\ndemo/**=json");
    let doc = field_values_since(
        &wire.d,
        &Numbered,
        ValuesAsk {
            declarations: &text,
            selector: "",
            filter: &any,
            paths: "$.temp",
            after_seq: 0,
            through_seq: u64::MAX,
        },
        &mut ValuesMemory::new(),
        None,
    )
    .expect("a document");
    alloc::vec![doc]
}

#[test]
fn the_gate_documents_reach_every_word_revision_two_adds() {
    let docs = values_documents_for_the_gates();
    let doc = &docs[0];
    for needle in [
        "\"keyexpr_source\":\"fixed_id\"",
        "\"keyexpr_source\":\"wire\"",
        "\"place\":\"first\"",
        "\"place\":\"closing\"",
        "\"unjoined\":\"crc_mismatch\"",
        "\"unjoined\":\"total_disagrees\"",
        "\"state\":\"segment_piece\"",
        "\"received_bytes\":4",
    ] {
        assert!(doc.contains(needle), "{needle} in {doc}");
    }
}
