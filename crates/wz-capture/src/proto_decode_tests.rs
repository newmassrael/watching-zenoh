// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Tests of the typed reader ([`crate::proto_decode`]) and of the open door that
//! reads a protected frame's body with it
//! ([`crate::e2e_json::open_body_document`]).
//!
//! The oracle for a value is the value that was WRITTEN: a body is built by the
//! wrap door from field values in protobuf's JSON mapping, opened by the open
//! door, and the listing the door reports is turned back into field values,
//! which must be the values written (in the canonical spelling the corpus uses)
//! and must make the writer build the same bytes again. The writer is held to
//! `protoc --encode` by `wz-integration-tests`, and this reader to
//! `protoc --decode` beside it; here the two halves are held to each other
//! through the doors a consumer calls.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use wz_session_core::json::escape_into;
use wz_session_core::json5::{self, Json5Value};

use crate::doc_revision::{key_set, E2E_OPEN_R1_KEYS, E2E_OPEN_R2_KEYS};
use crate::e2e_json::{open_body_document, open_document, wrap_document};
use crate::proto_decode::{decode_message, DecodeError, DecodedField, Unknown, Value};
use crate::proto_encode::encode_message;
use crate::proto_schema::ProtoFile;

// ---------------------------------------------------------------- profiles

/// A CRC-32/AUTOSAR over the body alone: the length field is outside the CRC,
/// so a frame can disagree with its length and still verify.
const ONLY_BODY: &str = r#"{
  "name": "synth-body",
  "fields": [
    {"name": "crc", "bytes": 4},
    {"name": "length", "bytes": 2},
    {"name": "counter", "bytes": 2}
  ],
  "crc": {"field": "crc", "width": 32, "poly": "0xF4ACFB13", "init": "0xFFFFFFFF",
          "refin": true, "refout": true, "xorout": "0xFFFFFFFF",
          "cover": ["@payload"]},
  "length": {"field": "length", "counts": "frame"},
  "counter": {"field": "counter", "max_gap": 3, "timeout_ms": 100}
}"#;

/// A CRC that covers header fields on both sides of the body, in a header of
/// twelve bytes, so the body does not start where it starts under the other.
const AROUND: &str = r#"{
  "name": "synth-around",
  "fields": [
    {"name": "crc", "bytes": 4},
    {"name": "length", "bytes": 2},
    {"name": "counter", "bytes": 2},
    {"name": "ident", "bytes": 4, "xor": "0x0F0F0F0F",
     "split": [{"name": "domain", "lsb": 24, "width": 8},
               {"name": "msg", "lsb": 0, "width": 16}]}
  ],
  "crc": {"field": "crc", "width": 32, "poly": "0xF4ACFB13", "init": "0xFFFFFFFF",
          "refin": true, "refout": true, "xorout": "0xFFFFFFFF",
          "cover": ["length", "ident", "@payload", "counter"]},
  "length": {"field": "length", "counts": "frame"},
  "counter": {"field": "counter", "max_gap": 3, "timeout_ms": 100}
}"#;

const AROUND_HEADER: &str = r#""counter":9,"ident":{"domain":3,"msg":4660}"#;
const AROUND_HEADER_BYTES: usize = 12;

// ----------------------------------------------------------------- schemas

/// Every arm the reader has, in one proto3 message: a nested message, packed
/// and unpacked repeated fields, two maps (of messages and of enums), a oneof,
/// an enum alone and packed, and each scalar kind that reads differently.
const POSE: &str = "syntax = \"proto3\";
package demo;
enum Mode { MODE_UNSET = 0; MODE_ON = 1; MODE_NEG = -2; }
message Inner { double ratio = 1; bool ok = 2; repeated string tags = 3; }
message Pose {
  sint32 x = 1;
  string label = 2;
  repeated int32 hist = 3;
  Inner inner = 4;
  fixed32 stamp = 5;
  map<string, Inner> by_name = 6;
  map<int32, Mode> modes = 7;
  oneof pick { uint64 big = 8; string word = 9; Inner sub = 10; }
  Mode mode = 11;
  repeated Mode history = 12;
  repeated sint64 deltas = 13 [packed = false];
  bytes blob = 14;
  float f = 15;
  sfixed64 s64 = 16;
  int64 i64 = 17;
  repeated Inner list = 18;
  double d = 19;
}";

/// The fields of [`POSE`] that are repeated: a listing says a field occurred
/// once, and only the schema says that one occurrence is a list of one.
const POSE_REPEATED: &[&str] = &["hist", "tags", "history", "deltas", "list"];

/// Values for [`POSE`], written in the canonical spelling the reader writes:
/// the field names as the schema spells them, enum values by name, an integer
/// past 2^53 - 1 as a string.
const POSE_VALUES: &str = r#"{"x":-3,"label":"hi","hist":[1,2,300],
 "inner":{"ratio":0.5,"ok":true,"tags":["a","","b"]},"stamp":7,
 "by_name":{"k":{"ratio":-1.25},"":{}},"modes":{"-1":"MODE_NEG","5":"MODE_ON"},
 "big":"18446744073709551615","mode":"MODE_ON",
 "history":["MODE_ON","MODE_UNSET","MODE_NEG"],"deltas":["-9007199254740993",4],
 "blob":"AQL/","f":0.1,"s64":-2,"i64":"9007199254740993",
 "list":[{"ok":true},{}],"d":1e300}"#;

/// The other member of the oneof, a message this time, and an enum number the
/// enum has no name for (proto3 enums are open).
const POSE_OTHER: &str = r#"{"sub":{"tags":["x"]},"mode":7,"x":2147483647,"f":"-Infinity"}"#;

/// proto2: presence at the default, a closed enum nested in the message, the
/// unpacked default and `[packed = true]`.
const REC: &str = "syntax = \"proto2\";
message Rec {
  enum E { A = 1; B = 2; }
  required int32 id = 1;
  optional string name = 2;
  repeated fixed32 v = 3;
  repeated bool b = 4 [packed = true];
  optional E e = 5;
  optional sint64 neg = 6;
}";
const REC_REPEATED: &[&str] = &["v", "b"];
const REC_VALUES: &str = r#"{"id":0,"name":"","v":[1,4294967295],"b":[true,false],"e":"B","neg":"-9223372036854775808"}"#;

/// A message that holds itself, for the depth bound.
const RECURSIVE: &str = "syntax = \"proto3\"; message N { N n = 1; int32 v = 2; }";

// ----------------------------------------------------------------- helpers

fn quoted(text: &str) -> String {
    let mut out = String::new();
    escape_into(text, &mut out);
    out
}

/// The open door's body description for one file.
fn description(file: &str, message: &str) -> String {
    format!(
        "{{\"files\":[{{\"name\":\"m.proto\",\"text\":{}}}],\"message\":{}}}",
        quoted(file),
        quoted(message)
    )
}

/// The wrap door's `@body` member.
fn body_member(file: &str, message: &str, values: &str) -> String {
    format!(
        "\"@body\":{{\"files\":[{{\"name\":\"m.proto\",\"text\":{}}}],\"message\":{},\"values\":{values}}}",
        quoted(file),
        quoted(message)
    )
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

fn proto_files<'a>(schema: &'a [(&'a str, &'a str)]) -> Vec<ProtoFile<'a>> {
    schema
        .iter()
        .map(|(name, text)| ProtoFile {
            name,
            text: text.as_bytes(),
        })
        .collect()
}

/// The frame the wrap door builds around the body `values` describe.
fn wrapped(profile: &str, header: &str, file: &str, message: &str, values: &str) -> Vec<u8> {
    let text = format!("{{{header},{}}}", body_member(file, message, values));
    let doc = wrap_document(profile, &text, &[]);
    let tree = json5::parse(&doc).expect("the wrap document is JSON");
    assert_eq!(get(&tree, "ok"), &Json5Value::Bool(true), "{doc}");
    match get(&tree, "frame") {
        Json5Value::String(hex) => unhex(hex),
        other => panic!("no frame: {other:?}"),
    }
}

fn get<'t>(tree: &'t Json5Value, key: &str) -> &'t Json5Value {
    match tree {
        Json5Value::Object(entries) => entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("no `{key}` in {}", tree.to_json_text())),
        other => panic!("`{key}` asked of {}", other.to_json_text()),
    }
}

fn has(tree: &Json5Value, key: &str) -> bool {
    matches!(tree, Json5Value::Object(e) if e.iter().any(|(k, _)| k == key))
}

fn number(tree: &Json5Value, key: &str) -> usize {
    match get(tree, key) {
        Json5Value::Number(n) => n.parse().expect("a count"),
        other => panic!("`{key}` is {other:?}"),
    }
}

fn items(tree: &Json5Value) -> &[Json5Value] {
    match tree {
        Json5Value::Array(items) => items,
        other => panic!("not an array: {}", other.to_json_text()),
    }
}

/// The open door's document over `frame`, parsed.
fn opened(profile: &str, file: &str, message: &str, frame: &[u8]) -> Json5Value {
    let doc = open_body_document(profile, &description(file, message), frame);
    json5::parse(&doc).unwrap_or_else(|e| panic!("not JSON ({e:?}): {doc}"))
}

/// The listing a document's `body` reports, turned back into field values in
/// protobuf's JSON mapping: what a consumer that holds the schema would do with
/// it. A name that occurs more than once, or is in `repeated`, is a list; an
/// entry of a map field (its type is `map<...>`) is a member of an object keyed
/// by its `key`.
fn to_values(listing: &[Json5Value], repeated: &[&str]) -> Json5Value {
    let mut order: Vec<String> = Vec::new();
    let mut grouped: Vec<(String, Vec<&Json5Value>)> = Vec::new();
    for node in listing {
        let name = match get(node, "name") {
            Json5Value::String(n) => n.clone(),
            other => panic!("a field of the body with no name: {other:?}"),
        };
        match grouped.iter_mut().find(|(n, _)| *n == name) {
            Some((_, nodes)) => nodes.push(node),
            None => {
                order.push(name.clone());
                grouped.push((name, alloc::vec![node]));
            }
        }
    }
    let one = |node: &Json5Value| -> Json5Value {
        if has(node, "fields") {
            to_values(items(get(node, "fields")), repeated)
        } else {
            get(node, "value").clone()
        }
    };
    let mut members = Vec::new();
    for (name, nodes) in grouped {
        let is_map =
            matches!(get(nodes[0], "type"), Json5Value::String(t) if t.starts_with("map<"));
        let value = if is_map {
            let mut entries = Vec::new();
            for entry in &nodes {
                let fields = items(get(entry, "fields"));
                let pick = |which: &str| {
                    fields
                        .iter()
                        .find(|f| get(f, "name") == &Json5Value::String(which.to_string()))
                };
                let key = match pick("key").map(|k| get(k, "value")) {
                    Some(Json5Value::String(s)) => s.clone(),
                    Some(Json5Value::Number(n)) => n.clone(),
                    Some(Json5Value::Bool(b)) => b.to_string(),
                    other => panic!("a map key: {other:?}"),
                };
                let value = pick("value").map_or(Json5Value::Object(Vec::new()), one);
                entries.push((key, value));
            }
            Json5Value::Object(entries)
        } else if nodes.len() > 1 || repeated.contains(&name.as_str()) {
            Json5Value::Array(nodes.iter().map(|n| one(n)).collect())
        } else {
            one(nodes[0])
        };
        members.push((name, value));
    }
    Json5Value::Object(members)
}

/// `value` with every object's members sorted by key, so two spellings of one
/// object in different orders compare equal and nothing else does.
fn canonical(value: &Json5Value) -> Json5Value {
    match value {
        Json5Value::Object(entries) => {
            let mut sorted: Vec<(String, Json5Value)> = entries
                .iter()
                .map(|(k, v)| (k.clone(), canonical(v)))
                .collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            Json5Value::Object(sorted)
        }
        Json5Value::Array(items) => Json5Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

/// The round trip, through the doors: build the frame from `values`, open it,
/// and hold the reported body to the values and to the bytes.
fn round_trip(file: &str, message: &str, values: &str, repeated: &[&str]) {
    for (profile, header, header_bytes) in [
        (AROUND, AROUND_HEADER, AROUND_HEADER_BYTES),
        (ONLY_BODY, r#""counter":1"#, 8),
    ] {
        let frame = wrapped(profile, header, file, message, values);
        let doc = opened(profile, file, message, &frame);
        let text = doc.to_json_text();
        assert_eq!(get(&doc, "ok"), &Json5Value::Bool(true), "{text}");
        assert_eq!(get(&doc, "crc_ok"), &Json5Value::Bool(true), "{text}");
        assert_eq!(
            get(&doc, "body_message"),
            &Json5Value::String(message.to_string())
        );
        assert_eq!(number(&doc, "payload_offset"), header_bytes);
        let body = get(&doc, "body");
        assert_eq!(get(body, "decoded"), &Json5Value::Bool(true), "{text}");
        let listing = items(get(body, "fields"));

        // The values written are the values read.
        let read = to_values(listing, repeated);
        let written = json5::parse(values).expect("the corpus is JSON");
        assert_eq!(
            canonical(&read).to_json_text(),
            canonical(&written).to_json_text(),
            "{message} under {profile}"
        );

        // And the writer builds the same body bytes from what was read.
        let again = encode_message(
            message,
            &proto_files(&[("m.proto", file)]),
            0,
            &read.to_json_text(),
        )
        .expect("what was read is values the writer takes");
        assert_eq!(again.as_slice(), &frame[header_bytes..]);

        // Every field lies inside the body, the first at its start and the
        // last at its end: the spans are frame offsets.
        let first = number(&listing[0], "offset");
        let last = listing.last().expect("a field");
        assert_eq!(first, header_bytes);
        assert_eq!(
            number(last, "offset") + number(last, "bytes"),
            frame.len(),
            "{text}"
        );
    }
}

// ---------------------------------------------------------------- round trip

#[test]
fn a_wrapped_body_reads_back_as_the_values_it_was_built_from() {
    round_trip(POSE, "demo.Pose", POSE_VALUES, POSE_REPEATED);
}

#[test]
fn the_other_oneof_member_and_an_enum_number_without_a_name_read_back() {
    round_trip(POSE, "demo.Pose", POSE_OTHER, POSE_REPEATED);
}

#[test]
fn a_proto2_body_reads_back_with_its_defaults_and_its_closed_enum() {
    round_trip(REC, "Rec", REC_VALUES, REC_REPEATED);
}

#[test]
fn an_empty_body_is_a_message_with_no_fields() {
    let frame = wrapped(AROUND, AROUND_HEADER, POSE, "demo.Pose", "{}");
    assert_eq!(frame.len(), AROUND_HEADER_BYTES);
    let doc = open_body_document(AROUND, &description(POSE, "demo.Pose"), &frame);
    assert!(
        doc.ends_with(",\"body\":{\"decoded\":true,\"fields\":[]}}"),
        "{doc}"
    );
}

/// The listing of the protobuf guide's three examples, written out key by key:
/// the shape the header documents, with offsets in the frame.
#[test]
fn the_listing_is_the_shape_the_documents_promise() {
    let schema = "syntax = \"proto3\";\nmessage T1 { int32 a = 1; }\n\
                  message M { int32 a = 1; string b = 2; T1 c = 3; repeated int32 d = 4; }";
    let frame = wrapped(
        ONLY_BODY,
        r#""counter":1"#,
        schema,
        "M",
        r#"{"a":150,"b":"testing","c":{"a":150},"d":[3,270]}"#,
    );
    let doc = open_body_document(ONLY_BODY, &description(schema, "M"), &frame);
    let want = concat!(
        ",\"body_message\":\"M\",",
        "\"payload_offset\":8,\"payload_bytes\":22,",
    );
    assert!(doc.contains(want), "{doc}");
    let body = concat!(
        ",\"body\":{\"decoded\":true,\"fields\":[",
        "{\"number\":1,\"name\":\"a\",\"type\":\"int32\",\"offset\":8,\"bytes\":3,\"value\":150},",
        "{\"number\":2,\"name\":\"b\",\"type\":\"string\",\"offset\":11,\"bytes\":9,\"value\":\"testing\"},",
        "{\"number\":3,\"name\":\"c\",\"type\":\"T1\",\"offset\":20,\"bytes\":5,\"fields\":[",
        "{\"number\":1,\"name\":\"a\",\"type\":\"int32\",\"offset\":22,\"bytes\":3,\"value\":150}]},",
        "{\"number\":4,\"name\":\"d\",\"type\":\"int32\",\"offset\":27,\"bytes\":1,\"value\":3},",
        "{\"number\":4,\"name\":\"d\",\"type\":\"int32\",\"offset\":28,\"bytes\":2,\"value\":270}",
        "]}}"
    );
    assert!(doc.ends_with(body), "{doc}");
}

// ----------------------------------------------- the header does not gate it

#[test]
fn a_body_whose_crc_fails_is_still_read() {
    let mut frame = wrapped(AROUND, AROUND_HEADER, POSE, "demo.Pose", POSE_VALUES);
    let good = open_body_document(AROUND, &description(POSE, "demo.Pose"), &frame);
    frame[0] ^= 0x01;
    let bad = open_body_document(AROUND, &description(POSE, "demo.Pose"), &frame);
    assert!(bad.contains("\"crc_ok\":false"), "{bad}");
    let body = |doc: &str| String::from(doc.split_once(",\"body\":").expect("a body").1);
    assert_eq!(body(&bad), body(&good));
}

#[test]
fn a_body_whose_length_field_disagrees_is_read_over_the_frame() {
    // The length field is outside this profile's CRC: the frame verifies, says
    // its length wrongly, and the body is still everything after the header.
    let mut frame = wrapped(ONLY_BODY, r#""counter":1"#, POSE, "demo.Pose", POSE_VALUES);
    frame[5] = frame[5].wrapping_add(1);
    let doc = opened(ONLY_BODY, POSE, "demo.Pose", &frame);
    assert_eq!(get(&doc, "crc_ok"), &Json5Value::Bool(true));
    assert_eq!(get(&doc, "length_matches_frame"), &Json5Value::Bool(false));
    let body = get(&doc, "body");
    assert_eq!(get(body, "decoded"), &Json5Value::Bool(true));
    let read = to_values(items(get(body, "fields")), POSE_REPEATED);
    assert_eq!(
        canonical(&read).to_json_text(),
        canonical(&json5::parse(POSE_VALUES).expect("JSON")).to_json_text()
    );
}

// ------------------------------------------------- a body that is not one

/// The body block of `frame` opened under [`ONLY_BODY`], which puts the body
/// at offset 8.
fn body_block(schema: &str, message: &str, body: &[u8]) -> String {
    let mut frame = alloc::vec![0u8; 8];
    frame.extend_from_slice(body);
    let doc = open_body_document(ONLY_BODY, &description(schema, message), &frame);
    assert!(doc.contains("\"ok\":true"), "{doc}");
    String::from(doc.split_once(",\"body\":").expect("a body").1)
}

#[test]
fn a_body_that_is_not_a_message_of_the_schema_says_where_and_in_which_field() {
    let s = "syntax = \"proto3\";\nmessage M { string s = 1; fixed32 f = 2; repeated fixed32 r = 3; M m = 4; }";
    let cases: [(&[u8], &str); 9] = [
        // The bytes end inside a tag, a value, a length.
        (&[0x80], "{\"decoded\":false,\"offset\":8,\"reason\":\"the bytes end inside a tag\"}}"),
        (
            &[0x15, 0x01, 0x02],
            "{\"decoded\":false,\"offset\":9,\"reason\":\"the bytes end inside a 4-byte value (2 left)\"}}",
        ),
        (
            &[0x0a, 0x05, b'a'],
            "{\"decoded\":false,\"offset\":9,\"reason\":\"a length of 5 byte(s) runs past the end of the message (1 left)\"}}",
        ),
        // Field number zero; a group marker; a wire type that is none.
        (
            &[0x00, 0x01],
            "{\"decoded\":false,\"offset\":8,\"reason\":\"field number 0 is no field: a tag must name a field from 1\"}}",
        ),
        (
            &[0x0b],
            "{\"decoded\":false,\"offset\":9,\"reason\":\"wire type 3 is a group marker: groups are written with the deprecated group markers, which this reader does not walk\"}}",
        ),
        (&[0x0e], "{\"decoded\":false,\"offset\":9,\"reason\":\"wire type 6 is not a wire type\"}}"),
        // Inside a known field: the field is named.
        (
            &[0x0a, 0x02, 0xc3, 0x28],
            "{\"decoded\":false,\"offset\":10,\"field\":\"M.s\",\"reason\":\"a `string` field holds bytes that are not UTF-8\"}}",
        ),
        (
            &[0x1a, 0x03, 0x01, 0x02, 0x03],
            "{\"decoded\":false,\"offset\":10,\"field\":\"M.r\",\"reason\":\"the bytes end inside a 4-byte value (3 left)\"}}",
        ),
        (
            &[0x22, 0x02, 0x15, 0x01],
            "{\"decoded\":false,\"offset\":11,\"field\":\"M.m\",\"reason\":\"the bytes end inside a 4-byte value (1 left)\"}}",
        ),
    ];
    for (bytes, want) in cases {
        assert_eq!(body_block(s, "M", bytes), want, "{bytes:02x?}");
    }
}

#[test]
fn a_varint_past_64_bits_is_refused_at_its_first_byte() {
    let s = "syntax = \"proto3\";\nmessage M { uint64 u = 1; }";
    let mut ten = alloc::vec![0x08];
    ten.extend_from_slice(&[0xff; 9]);
    ten.push(0x01);
    // Ten bytes whose last carries the one bit left: u64::MAX.
    assert!(body_block(s, "M", &ten).contains("\"value\":\"18446744073709551615\""));
    *ten.last_mut().expect("ten bytes") = 0x02;
    assert_eq!(
        body_block(s, "M", &ten),
        "{\"decoded\":false,\"offset\":9,\"reason\":\"a varint does not fit 64 bits\"}}"
    );
    let mut eleven = alloc::vec![0x08];
    eleven.extend_from_slice(&[0x80; 10]);
    eleven.push(0x00);
    assert!(body_block(s, "M", &eleven).contains("\"decoded\":false"));
}

#[test]
fn messages_nest_to_the_bound_and_no_deeper() {
    // `n` inside `n`, `levels` messages in all, the innermost holding v = 1.
    let nested = |levels: usize| -> Vec<u8> {
        let mut bytes = alloc::vec![0x10, 0x01];
        for _ in 1..levels {
            let mut outer = alloc::vec![0x0a];
            let mut len = bytes.len();
            while len >= 0x80 {
                outer.push((len as u8) | 0x80);
                len >>= 7;
            }
            outer.push(len as u8);
            outer.extend_from_slice(&bytes);
            bytes = outer;
        }
        bytes
    };
    let bound = crate::proto_decode::MAX_DECODE_DEPTH;
    let at = nested(bound);
    let decoded = decode_message("N", &proto_files(&[("m.proto", RECURSIVE)]), 0, &at)
        .expect("the bound is reachable");
    let mut depth = 1;
    let mut level = &decoded;
    while let [DecodedField {
        value: Value::Message(inner),
        ..
    }] = level.as_slice()
    {
        depth += 1;
        level = inner;
    }
    assert_eq!(depth, bound);
    match decode_message(
        "N",
        &proto_files(&[("m.proto", RECURSIVE)]),
        0,
        &nested(bound + 1),
    ) {
        Err(DecodeError::Wire(e)) => {
            assert_eq!(
                e.reason,
                format!("messages nest deeper than {bound} levels")
            );
            assert_eq!(e.field.as_deref(), Some("N.n"));
        }
        other => panic!("{other:?}"),
    }
}

// ---------------------------------------------- what the schema does not know

#[test]
fn a_field_the_schema_does_not_know_is_listed_raw_with_its_wire_type() {
    let s = "syntax = \"proto3\";\nmessage M { int32 a = 1; string b = 2; }";
    // Field 9 is no field; field 1 arrives as a length-delimited value, a wire
    // type an int32 is never written with; field 2 as a varint; then two more
    // unknown fields of the fixed widths.
    let bytes = [
        0x48, 0x07, 0x0a, 0x01, 0xff, 0x10, 0x05, 0x55, 1, 0, 0, 0, 0x59, 2, 0, 0, 0, 0, 0, 0, 0,
    ];
    let block = body_block(s, "M", &bytes);
    let want = concat!(
        "{\"decoded\":true,\"fields\":[",
        "{\"number\":9,\"offset\":8,\"bytes\":2,\"wire_type\":\"varint\",\"value\":7},",
        "{\"number\":1,\"offset\":10,\"bytes\":3,\"wire_type\":\"len\",\"value\":\"/w==\"},",
        "{\"number\":2,\"offset\":13,\"bytes\":2,\"wire_type\":\"varint\",\"value\":5},",
        "{\"number\":10,\"offset\":15,\"bytes\":5,\"wire_type\":\"i32\",\"value\":1},",
        "{\"number\":11,\"offset\":20,\"bytes\":9,\"wire_type\":\"i64\",\"value\":2}",
        "]}}"
    );
    assert_eq!(block, want);
}

#[test]
fn a_repeated_field_reads_the_same_packed_or_not() {
    // The schema packs `p` and does not pack `u`; the bytes do the opposite.
    let s = "syntax = \"proto3\";\nmessage M { repeated sint32 p = 1; repeated int32 u = 2 [packed = false]; }";
    let bytes = [0x08, 0x03, 0x08, 0x04, 0x12, 0x02, 0x05, 0x06];
    let decoded = decode_message("M", &proto_files(&[("m.proto", s)]), 0, &bytes).expect("reads");
    let values: Vec<(u64, &Value)> = decoded.iter().map(|f| (f.number, &f.value)).collect();
    assert_eq!(
        values,
        [
            (1, &Value::Signed(-2)),
            (1, &Value::Signed(2)),
            (2, &Value::Signed(5)),
            (2, &Value::Signed(6)),
        ]
    );
    // Each element of the packed run has its own span inside the run.
    assert_eq!((decoded[2].start, decoded[2].end), (6, 7));
    assert_eq!((decoded[3].start, decoded[3].end), (7, 8));
}

#[test]
fn a_field_written_twice_is_listed_twice() {
    let s =
        "syntax = \"proto3\";\nmessage M { int32 a = 1; oneof o { int32 b = 2; int32 c = 3; } }";
    let bytes = [0x08, 0x01, 0x08, 0x02, 0x10, 0x05, 0x18, 0x06];
    let decoded = decode_message("M", &proto_files(&[("m.proto", s)]), 0, &bytes).expect("reads");
    let names: Vec<&str> = decoded.iter().filter_map(|f| f.name.as_deref()).collect();
    assert_eq!(names, ["a", "a", "b", "c"]);
}

#[test]
fn the_wire_type_words_are_the_four_and_no_more() {
    assert_eq!(Unknown::wire_type_names(), ["varint", "i64", "len", "i32"]);
}

/// The open door's documents a family gate measures `wire_type` over: a body
/// holding a field the schema does not know in each of the four wire types,
/// beside the fields it does know, and one with a single unknown field.
pub(crate) fn documents_for_the_carries_gate() -> Vec<String> {
    let s = "syntax = \"proto3\";\nmessage M { int32 a = 1; string b = 2; }";
    let bodies: [&[u8]; 2] = [
        &[
            0x08, 0x01, 0x48, 0x07, 0x52, 0x01, 0xff, 0x55, 1, 0, 0, 0, 0x59, 2, 0, 0, 0, 0, 0, 0,
            0, 0x12, 0x01, b'x',
        ],
        &[0x0a, 0x01, 0xff],
    ];
    bodies
        .iter()
        .map(|body| {
            let mut frame = alloc::vec![0u8; 8];
            frame.extend_from_slice(body);
            open_body_document(ONLY_BODY, &description(s, "M"), &frame)
        })
        .collect()
}

#[test]
fn the_carries_gate_documents_reach_every_wire_type() {
    let docs = documents_for_the_carries_gate();
    for word in Unknown::wire_type_names() {
        assert!(
            docs.iter()
                .any(|d| d.contains(&format!("\"wire_type\":\"{word}\""))),
            "{word}: {docs:?}"
        );
    }
}

// --------------------------------------------------------------- refusals

#[test]
fn the_body_description_and_the_schema_are_refused_at_their_place() {
    let frame = wrapped(AROUND, AROUND_HEADER, POSE, "demo.Pose", "{}");
    let cases = [
        (
            "{".to_string(),
            "\"ok\":false,\"stage\":\"body\",\"body_offset\":1,",
        ),
        (
            r#"{"files":[],"message":"M"}"#.to_string(),
            "\"ok\":false,\"stage\":\"body\",\"body_path\":\"/files\",\"reason\":\"a body needs at least one schema file\"",
        ),
        (
            r#"{"files":[{"name":"m.proto","text":""}],"message":"M","values":{}}"#.to_string(),
            "\"ok\":false,\"stage\":\"body\",\"body_path\":\"/values\",",
        ),
        (
            r#"{"files":[{"name":"m.proto","text":""}]}"#.to_string(),
            "\"ok\":false,\"stage\":\"body\",\"body_path\":\"\",",
        ),
        (
            description("syntax = \"proto3\";\nmessage M { int32 a = 1 }", "M"),
            "\"ok\":false,\"stage\":\"body\",\"file\":\"m.proto\",\"line\":2,\"column\":",
        ),
        (
            description(POSE, "demo.Nope"),
            "\"ok\":false,\"stage\":\"body\",\"file\":\"m.proto\",\"reason\":",
        ),
        (
            r#"{"files":[{"name":"m.proto","text":""}],"root_file":3,"message":"M"}"#.to_string(),
            "\"ok\":false,\"stage\":\"body\",\"reason\":\"the root file index 3 is outside the 1 file(s) given\"",
        ),
    ];
    for (text, want) in cases {
        let doc = open_body_document(AROUND, &text, &frame);
        assert!(doc.contains(want), "{text}\n{doc}");
        assert!(!doc.contains("\"body\":"), "{doc}");
    }
}

#[test]
fn the_first_problem_is_the_profile_then_the_body_then_the_schema_then_the_frame() {
    let short = [0u8; 3];
    let bad_body = "{";
    let bad_schema = description("message", "M");
    let good = description(POSE, "demo.Pose");
    let doc = open_body_document("{", bad_body, &short);
    assert!(doc.contains("\"profile_offset\""), "{doc}");
    let doc = open_body_document(AROUND, bad_body, &short);
    assert!(doc.contains("\"body_offset\""), "{doc}");
    let doc = open_body_document(AROUND, &bad_schema, &short);
    assert!(doc.contains("\"file\":\"m.proto\""), "{doc}");
    let doc = open_body_document(AROUND, &good, &short);
    assert!(
        doc.contains("\"ok\":false,\"reason\":") && !doc.contains("stage"),
        "{doc}"
    );
}

// ------------------------------------------------------------ the registry

#[test]
fn the_open_documents_use_exactly_the_keys_revision_two_pins() {
    let frame = wrapped(AROUND, AROUND_HEADER, POSE, "demo.Pose", POSE_VALUES);
    let mut unknown = alloc::vec![0u8; 8];
    unknown.extend_from_slice(&[0x48, 0x07]);
    let mut torn = alloc::vec![0u8; 8];
    torn.extend_from_slice(&[0x12, 0x02, 0xc3, 0x28]);
    let s = "syntax = \"proto3\";\nmessage M { string s = 2; }";
    let docs = [
        open_body_document(AROUND, &description(POSE, "demo.Pose"), &frame),
        open_body_document(ONLY_BODY, &description(s, "M"), &unknown),
        open_body_document(ONLY_BODY, &description(s, "M"), &torn),
        open_body_document("{", "{}", &frame),
        open_body_document("{}", "{}", &frame),
        open_body_document(AROUND, "{", &frame),
        open_body_document(AROUND, "{\"a\":1}", &frame),
        open_body_document(AROUND, &description("message M {", "M"), &frame),
        open_body_document(AROUND, &description(POSE, "demo.Nope"), &frame),
        open_body_document(AROUND, &description(POSE, "demo.Pose"), &[0u8; 2]),
    ];
    let mut keys: Vec<&str> = Vec::new();
    for doc in &docs {
        assert!(
            doc.starts_with(r#"{"document":{"name":"e2e_open","revision":2}"#),
            "{doc}"
        );
        // A key that does not apply is absent, on every branch and at every
        // depth of the listing.
        assert!(!doc.contains("null"), "{doc}");
        keys.extend(key_set(doc));
    }
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys, E2E_OPEN_R2_KEYS);
}

#[test]
fn the_first_open_door_reads_as_it_did_but_for_the_revision() {
    let frame = wrapped(AROUND, AROUND_HEADER, POSE, "demo.Pose", POSE_VALUES);
    let plain = open_document(AROUND, &frame);
    let read = open_body_document(AROUND, &description(POSE, "demo.Pose"), &frame);
    // The body door's document is the first door's, with `body_message` after
    // the profile and `body` at the end.
    let without = read
        .replacen(",\"body_message\":\"demo.Pose\"", "", 1)
        .split_once(",\"body\":")
        .map(|(head, _)| format!("{head}}}"))
        .expect("a body");
    assert_eq!(without, plain);
    let short = open_document(AROUND, &[0u8; 2]);
    let refused = open_document("{", &frame);
    let mut keys = key_set(&plain);
    keys.extend(key_set(&short));
    keys.extend(key_set(&refused));
    keys.sort_unstable();
    keys.dedup();
    assert!(
        keys.iter().all(|k| E2E_OPEN_R1_KEYS.contains(k)),
        "{keys:?}"
    );
}
