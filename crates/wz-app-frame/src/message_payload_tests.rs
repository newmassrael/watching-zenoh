// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Model tests of the message payload, on a SYNTHETIC schema.
//!
//! Every expected byte string is laid by hand from the protobuf encoding rules
//! (a tag is `number << 3 | wire type`, a varint seven bits a byte, low first),
//! not by a writer of this workspace, so the payload's writing is checked
//! against a second reading of the format. The names, numbers and values are
//! made up and unlike any deployment's.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::message_payload::{Given, Got, Payload, Refusal, Wanted};
use crate::proto_decode::SchemaSet;
use crate::proto_schema::ProtoFile;

const SHAPES: &str = r#"
syntax = "proto3";
package syn.payload;

enum Tone {
  TONE_NONE = 0;
  TONE_WARM = 1;
  TONE_COLD = 2;
}

message Point {
  sint32 x = 1;
  sint32 y = 2;
}

message Sample {
  uint32 serial = 1;
  int32 offset = 2;
  double weight = 3;
  float ratio = 4;
  bool lit = 5;
  string label = 6;
  bytes blob = 7;
  Tone tone = 8;
  Point origin = 9;
  repeated Point path = 10;
  repeated int32 counts = 11;
  repeated string tags = 12;
  optional uint64 stamp = 13;
  oneof pick {
    string word = 14;
    int64 number = 15;
  }
  map<string, int32> extra = 16;
  fixed32 mark = 17;
  sfixed64 shift = 18;
  repeated uint32 loose = 19 [packed = false];
  repeated string words = 20 [packed = true];
  uint64 big = 21;
}
"#;

const LEGACY: &str = r#"
syntax = "proto2";
package syn.legacy;

enum Level {
  LOW = 1;
  HIGH = 2;
}

message Record {
  required uint32 id = 1;
  optional Level level = 2;
  repeated int32 values = 3;
  repeated int32 dense = 4 [packed = true];
  optional string note = 5;
}
"#;

fn schema() -> SchemaSet {
    let files = [
        ProtoFile {
            name: "syn/shapes.proto",
            text: SHAPES.as_bytes(),
        },
        ProtoFile {
            name: "syn/legacy.proto",
            text: LEGACY.as_bytes(),
        },
    ];
    SchemaSet::read(&files).expect("the synthetic schema reads")
}

fn payload<'s>(schema: &'s SchemaSet, message: &str) -> Payload<&'s SchemaSet> {
    let found = schema
        .message(message)
        .expect("the message is in the schema");
    Payload::new(schema, found)
}

fn set(p: &mut Payload<&SchemaSet>, path: &str, value: Given<'_>) {
    p.set(path, value)
        .unwrap_or_else(|why| panic!("`{path}` is set: {why}"));
}

fn bytes(p: &Payload<&SchemaSet>) -> Vec<u8> {
    p.encode()
        .unwrap_or_else(|why| panic!("the payload encodes: {why}"))
}

#[test]
fn scalars_set_by_path_are_written_in_field_order_with_their_wire_types() {
    let schema = schema();
    let mut p = payload(&schema, "syn.payload.Sample");
    assert_eq!(p.message_name(), "syn.payload.Sample");
    set(&mut p, "label", Given::Text("hi"));
    set(&mut p, "lit", Given::Bool(true));
    set(&mut p, "offset", Given::Signed(-2));
    set(&mut p, "serial", Given::Unsigned(150));
    assert_eq!(
        bytes(&p),
        [
            0x08, 0x96, 0x01, // serial: varint 150
            0x10, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x01, // offset: -2, ten bytes
            0x28, 0x01, // lit
            0x32, 0x02, b'h', b'i', // label
        ]
    );
}

#[test]
fn a_field_without_presence_at_its_default_is_left_out_and_negative_zero_is_not() {
    let schema = schema();
    let mut p = payload(&schema, "syn.payload.Sample");
    set(&mut p, "serial", Given::Unsigned(0));
    set(&mut p, "lit", Given::Bool(false));
    set(&mut p, "label", Given::Text(""));
    set(&mut p, "ratio", Given::Real(-0.0));
    assert_eq!(bytes(&p), [0x25, 0x00, 0x00, 0x00, 0x80]);
}

#[test]
fn reals_and_fixed_widths_are_little_endian() {
    let schema = schema();
    let mut p = payload(&schema, "syn.payload.Sample");
    set(&mut p, "weight", Given::Real(1.5));
    set(&mut p, "mark", Given::Unsigned(7));
    set(&mut p, "shift", Given::Signed(-1));
    let mut want = vec![0x19, 0, 0, 0, 0, 0, 0, 0xF8, 0x3F];
    want.extend_from_slice(&[0x8D, 0x01, 7, 0, 0, 0]);
    want.extend_from_slice(&[0x91, 0x01]);
    want.extend_from_slice(&[0xFF; 8]);
    assert_eq!(bytes(&p), want);
}

#[test]
fn a_sint_is_zigzagged_and_a_message_field_with_presence_is_written_empty() {
    let schema = schema();
    let mut p = payload(&schema, "syn.payload.Sample");
    set(&mut p, "origin.x", Given::Signed(-3));
    assert_eq!(bytes(&p), [0x4A, 0x02, 0x08, 0x05]);

    let mut q = payload(&schema, "syn.payload.Sample");
    set(&mut q, "origin.y", Given::Signed(0));
    assert_eq!(bytes(&q), [0x4A, 0x00]);
}

#[test]
fn a_repeated_number_is_packed_in_proto3_unless_the_field_says_otherwise() {
    let schema = schema();
    let mut p = payload(&schema, "syn.payload.Sample");
    set(&mut p, "counts[0]", Given::Signed(3));
    set(&mut p, "counts[1]", Given::Signed(270));
    set(&mut p, "counts[2]", Given::Signed(86_942));
    set(&mut p, "tags[0]", Given::Text("a"));
    set(&mut p, "tags[1]", Given::Text("b"));
    set(&mut p, "loose[0]", Given::Unsigned(1));
    set(&mut p, "loose[1]", Given::Unsigned(2));
    assert_eq!(
        bytes(&p),
        [
            0x5A, 0x06, 0x03, 0x8E, 0x02, 0x9E, 0xA7, 0x05, // counts, one packed run
            0x62, 0x01, b'a', 0x62, 0x01, b'b', // tags, a tag each
            0x98, 0x01, 0x01, 0x98, 0x01, 0x02, // loose, `packed = false`
        ]
    );
}

#[test]
fn elements_of_a_repeated_message_are_made_at_the_end_of_the_list() {
    let schema = schema();
    let mut p = payload(&schema, "syn.payload.Sample");
    set(&mut p, "path[0].x", Given::Signed(1));
    set(&mut p, "path[1].y", Given::Signed(2));
    assert_eq!(p.count("path"), Ok(2));
    assert_eq!(bytes(&p), [0x52, 0x02, 0x08, 0x02, 0x52, 0x02, 0x10, 0x04]);
    // An index past the end is refused before anything is made.
    assert!(matches!(
        p.set("path[3].x", Given::Signed(1)),
        Err(Refusal::Range { .. })
    ));
    assert_eq!(p.count("path"), Ok(2));
    set(&mut p, "path[0].y", Given::Signed(9));
    assert_eq!(p.get("path[0].y", Wanted::Signed), Ok(Got::Signed(9)));
    assert_eq!(p.get("path[0].x", Wanted::Signed), Ok(Got::Signed(1)));
    assert_eq!(p.count("path"), Ok(2));
}

#[test]
fn an_enum_is_set_by_name_or_number_and_read_either_way() {
    let schema = schema();
    let mut p = payload(&schema, "syn.payload.Sample");
    assert_eq!(p.get("tone", Wanted::Text), Ok(Got::Text("TONE_NONE")));
    set(&mut p, "tone", Given::Text("TONE_COLD"));
    assert_eq!(bytes(&p), [0x40, 0x02]);
    assert_eq!(p.get("tone", Wanted::Signed), Ok(Got::Signed(2)));
    assert_eq!(p.get("tone", Wanted::Text), Ok(Got::Text("TONE_COLD")));
    // A proto3 enum is open: a number it has no name for is a value, and has
    // no name to read.
    set(&mut p, "tone", Given::Signed(7));
    assert!(matches!(
        p.get("tone", Wanted::Text),
        Err(Refusal::Range { .. })
    ));
    assert!(matches!(
        p.set("tone", Given::Text("TONE_HOT")),
        Err(Refusal::Range { .. })
    ));
    assert_eq!(p.get("tone", Wanted::Signed), Ok(Got::Signed(7)));
}

#[test]
fn a_oneof_keeps_its_last_member() {
    let schema = schema();
    let mut p = payload(&schema, "syn.payload.Sample");
    set(&mut p, "word", Given::Text("x"));
    set(&mut p, "number", Given::Signed(5));
    assert!(matches!(
        p.get("word", Wanted::Text),
        Err(Refusal::Absent { .. })
    ));
    assert_eq!(p.get("number", Wanted::Signed), Ok(Got::Signed(5)));
    assert_eq!(bytes(&p), [0x78, 0x05]);
}

#[test]
fn a_field_with_presence_reads_absent_until_set_and_is_written_at_zero() {
    let schema = schema();
    let mut p = payload(&schema, "syn.payload.Sample");
    assert_eq!(
        p.get("stamp", Wanted::Unsigned),
        Err(Refusal::Absent {
            path: String::from("stamp"),
            at: String::from("stamp"),
        })
    );
    assert_eq!(
        p.get("origin.x", Wanted::Signed),
        Err(Refusal::Absent {
            path: String::from("origin.x"),
            at: String::from("origin"),
        })
    );
    // Without presence, a field that is not set reads as its default.
    assert_eq!(p.get("serial", Wanted::Unsigned), Ok(Got::Unsigned(0)));
    assert_eq!(p.get("label", Wanted::Text), Ok(Got::Text("")));
    assert_eq!(p.get("lit", Wanted::Bool), Ok(Got::Bool(false)));
    assert_eq!(p.get("blob", Wanted::Bytes), Ok(Got::Bytes(&[])));
    assert_eq!(p.get("weight", Wanted::Real), Ok(Got::Real(0.0)));

    set(&mut p, "stamp", Given::Unsigned(0));
    assert_eq!(p.get("stamp", Wanted::Unsigned), Ok(Got::Unsigned(0)));
    assert_eq!(bytes(&p), [0x68, 0x00]);
}

#[test]
fn paths_that_name_no_field_are_refused_by_name() {
    let schema = schema();
    let mut p = payload(&schema, "syn.payload.Sample");
    let deep = "origin.".repeat(64) + "x";
    for path in [
        "nosuch",
        "serial[0]",
        "counts",
        "origin.x.y",
        "extra",
        "path.x",
        "",
        "serial.",
        "a..b",
        "counts[01]",
        "counts[x]",
        "counts[0",
        "9lives",
        deep.as_str(),
    ] {
        assert!(
            matches!(p.set(path, Given::Signed(1)), Err(Refusal::Path { .. })),
            "setting `{path}` is refused as a path"
        );
    }
    assert!(matches!(p.count("serial"), Err(Refusal::Path { .. })));
    assert!(matches!(p.count("counts[0]"), Err(Refusal::Path { .. })));
    assert!(matches!(
        p.get("counts", Wanted::Signed),
        Err(Refusal::Path { .. })
    ));
    assert_eq!(bytes(&p), Vec::<u8>::new());
}

#[test]
fn a_value_of_another_type_is_refused_and_read_as_another_type_too() {
    let schema = schema();
    let mut p = payload(&schema, "syn.payload.Sample");
    for (path, value) in [
        ("serial", Given::Real(1.0)),
        ("label", Given::Signed(1)),
        ("blob", Given::Text("x")),
        ("origin", Given::Signed(1)),
        ("lit", Given::Unsigned(1)),
        ("weight", Given::Signed(1)),
    ] {
        assert!(
            matches!(p.set(path, value), Err(Refusal::Type { .. })),
            "setting `{path}` with {value:?} is a type mismatch"
        );
    }
    set(&mut p, "lit", Given::Bool(true));
    set(&mut p, "tone", Given::Signed(1));
    assert!(matches!(
        p.get("lit", Wanted::Signed),
        Err(Refusal::Type { .. })
    ));
    assert!(matches!(
        p.get("tone", Wanted::Real),
        Err(Refusal::Type { .. })
    ));
    assert!(matches!(
        p.get("serial", Wanted::Text),
        Err(Refusal::Type { .. })
    ));
}

#[test]
fn a_value_that_does_not_fit_its_field_is_refused_and_changes_nothing() {
    let schema = schema();
    let mut p = payload(&schema, "syn.payload.Sample");
    for (path, value) in [
        ("offset", Given::Signed(i64::from(i32::MAX) + 1)),
        ("serial", Given::Signed(-1)),
        ("serial", Given::Unsigned(u64::from(u32::MAX) + 1)),
        ("ratio", Given::Real(1e40)),
        ("counts[1]", Given::Signed(1)),
    ] {
        assert!(
            matches!(p.set(path, value), Err(Refusal::Range { .. })),
            "setting `{path}` with {value:?} is out of range"
        );
    }
    assert_eq!(bytes(&p), Vec::<u8>::new());
    // An infinity is a float's value, and is written.
    set(&mut p, "ratio", Given::Real(f64::INFINITY));
    assert_eq!(bytes(&p), [0x25, 0x00, 0x00, 0x80, 0x7F]);

    set(&mut p, "offset", Given::Signed(-2));
    assert!(matches!(
        p.get("offset", Wanted::Unsigned),
        Err(Refusal::Range { .. })
    ));
    set(&mut p, "big", Given::Unsigned(u64::MAX));
    assert!(matches!(
        p.get("big", Wanted::Signed),
        Err(Refusal::Range { .. })
    ));
    assert_eq!(p.get("big", Wanted::Unsigned), Ok(Got::Unsigned(u64::MAX)));
    assert!(matches!(
        p.get("counts[0]", Wanted::Signed),
        Err(Refusal::Range { .. })
    ));
}

#[test]
fn count_and_clear_name_a_list_or_an_element() {
    let schema = schema();
    let mut p = payload(&schema, "syn.payload.Sample");
    for (i, v) in [3, 270, 86_942].into_iter().enumerate() {
        set(&mut p, &alloc::format!("counts[{i}]"), Given::Signed(v));
    }
    assert_eq!(p.count("counts"), Ok(3));
    p.clear("counts[1]").expect("an element is cleared");
    assert_eq!(p.count("counts"), Ok(2));
    assert_eq!(p.get("counts[1]", Wanted::Signed), Ok(Got::Signed(86_942)));
    assert!(matches!(p.clear("counts[5]"), Err(Refusal::Range { .. })));
    p.clear("counts").expect("a list is cleared");
    assert_eq!(p.count("counts"), Ok(0));

    // Nothing to clear inside a message that is not there.
    p.clear("origin.x").expect("nothing is cleared");
    assert_eq!(bytes(&p), Vec::<u8>::new());

    set(&mut p, "serial", Given::Unsigned(5));
    p.clear("serial").expect("a field is cleared");
    assert_eq!(p.get("serial", Wanted::Unsigned), Ok(Got::Unsigned(0)));

    set(&mut p, "label", Given::Text("gone"));
    p.reset();
    assert_eq!(bytes(&p), Vec::<u8>::new());
}

/// A payload with a value in every kind of field the path addresses.
fn full(schema: &SchemaSet) -> Payload<&SchemaSet> {
    let mut p = payload(schema, "syn.payload.Sample");
    set(&mut p, "serial", Given::Unsigned(150));
    set(&mut p, "offset", Given::Signed(-2));
    set(&mut p, "weight", Given::Real(1.5));
    set(&mut p, "ratio", Given::Real(0.5));
    set(&mut p, "lit", Given::Bool(true));
    set(&mut p, "label", Given::Text("hi"));
    set(&mut p, "blob", Given::Bytes(&[1, 2, 3]));
    set(&mut p, "tone", Given::Text("TONE_WARM"));
    set(&mut p, "origin.x", Given::Signed(-3));
    set(&mut p, "path[0].y", Given::Signed(4));
    set(&mut p, "counts[0]", Given::Signed(-1));
    set(&mut p, "tags[0]", Given::Text("t"));
    set(&mut p, "stamp", Given::Unsigned(7));
    set(&mut p, "word", Given::Text("w"));
    set(&mut p, "mark", Given::Unsigned(9));
    set(&mut p, "shift", Given::Signed(-5));
    set(&mut p, "loose[0]", Given::Unsigned(11));
    set(&mut p, "big", Given::Unsigned(u64::MAX));
    p
}

#[test]
fn a_decoded_payload_reads_back_what_was_set_and_encodes_the_same_bytes() {
    let schema = schema();
    let sent = bytes(&full(&schema));
    let mut p = payload(&schema, "syn.payload.Sample");
    p.decode(&sent).expect("the bytes decode");
    assert_eq!(p.get("serial", Wanted::Unsigned), Ok(Got::Unsigned(150)));
    assert_eq!(p.get("offset", Wanted::Signed), Ok(Got::Signed(-2)));
    assert_eq!(p.get("weight", Wanted::Real), Ok(Got::Real(1.5)));
    assert_eq!(p.get("ratio", Wanted::Real), Ok(Got::Real(0.5)));
    assert_eq!(p.get("lit", Wanted::Bool), Ok(Got::Bool(true)));
    assert_eq!(p.get("label", Wanted::Text), Ok(Got::Text("hi")));
    assert_eq!(p.get("blob", Wanted::Bytes), Ok(Got::Bytes(&[1, 2, 3])));
    assert_eq!(p.get("tone", Wanted::Text), Ok(Got::Text("TONE_WARM")));
    assert_eq!(p.get("origin.x", Wanted::Signed), Ok(Got::Signed(-3)));
    assert_eq!(p.get("path[0].y", Wanted::Signed), Ok(Got::Signed(4)));
    assert_eq!(p.get("counts[0]", Wanted::Signed), Ok(Got::Signed(-1)));
    assert_eq!(p.get("tags[0]", Wanted::Text), Ok(Got::Text("t")));
    assert_eq!(p.get("stamp", Wanted::Unsigned), Ok(Got::Unsigned(7)));
    assert_eq!(p.get("word", Wanted::Text), Ok(Got::Text("w")));
    assert_eq!(p.get("mark", Wanted::Unsigned), Ok(Got::Unsigned(9)));
    assert_eq!(p.get("shift", Wanted::Signed), Ok(Got::Signed(-5)));
    assert_eq!(p.get("loose[0]", Wanted::Unsigned), Ok(Got::Unsigned(11)));
    assert_eq!(p.get("big", Wanted::Unsigned), Ok(Got::Unsigned(u64::MAX)));
    assert_eq!(bytes(&p), sent);
}

#[test]
fn decoding_merges_a_message_written_twice_and_keeps_the_last_scalar() {
    let schema = schema();
    let mut p = payload(&schema, "syn.payload.Sample");
    let wire = [
        0x4A, 0x02, 0x08, 0x02, // origin { x: 1 }
        0x4A, 0x02, 0x10, 0x04, // origin { y: 2 }
        0x08, 0x01, // serial: 1
        0x08, 0x02, // serial: 2
    ];
    p.decode(&wire).expect("the bytes decode");
    assert_eq!(p.get("origin.x", Wanted::Signed), Ok(Got::Signed(1)));
    assert_eq!(p.get("origin.y", Wanted::Signed), Ok(Got::Signed(2)));
    assert_eq!(p.get("serial", Wanted::Unsigned), Ok(Got::Unsigned(2)));
}

#[test]
fn fields_the_payload_does_not_address_are_kept_as_written() {
    let schema = schema();
    let mut p = payload(&schema, "syn.payload.Sample");
    let serial = [0x08, 0x01];
    let entry = [0x82, 0x01, 0x05, 0x0A, 0x01, b'k', 0x10, 0x01]; // extra { "k": 1 }
    let unknown = [0x98, 0x06, 0x01]; // field 99, varint 1
    let mut wire = Vec::new();
    wire.extend_from_slice(&entry);
    wire.extend_from_slice(&serial);
    wire.extend_from_slice(&unknown);
    p.decode(&wire).expect("the bytes decode");
    assert_eq!(p.get("serial", Wanted::Unsigned), Ok(Got::Unsigned(1)));
    let mut again = Vec::new();
    again.extend_from_slice(&serial);
    again.extend_from_slice(&entry);
    again.extend_from_slice(&unknown);
    assert_eq!(bytes(&p), again);
}

#[test]
fn bytes_that_are_not_a_message_are_refused_and_leave_the_payload_as_it_was() {
    let schema = schema();
    let mut p = payload(&schema, "syn.payload.Sample");
    set(&mut p, "serial", Given::Unsigned(9));
    assert!(matches!(p.decode(&[0x08]), Err(Refusal::Wire(_))));
    assert_eq!(p.get("serial", Wanted::Unsigned), Ok(Got::Unsigned(9)));
}

#[test]
fn a_repeated_number_decodes_packed_or_not() {
    let schema = schema();
    let mut p = payload(&schema, "syn.payload.Sample");
    p.decode(&[0x58, 0x03, 0x58, 0x04])
        .expect("the bytes decode");
    assert_eq!(p.count("counts"), Ok(2));
    assert_eq!(p.get("counts[1]", Wanted::Signed), Ok(Got::Signed(4)));
    assert_eq!(bytes(&p), [0x5A, 0x02, 0x03, 0x04]);
}

#[test]
fn a_proto2_record_needs_its_required_field_and_keeps_its_enum_closed() {
    let schema = schema();
    let mut p = payload(&schema, "syn.legacy.Record");
    assert_eq!(
        p.encode(),
        Err(Refusal::Absent {
            path: String::from("id"),
            at: String::from("id"),
        })
    );
    assert!(matches!(
        p.get("note", Wanted::Text),
        Err(Refusal::Absent { .. })
    ));
    assert!(matches!(
        p.set("level", Given::Signed(3)),
        Err(Refusal::Range { .. })
    ));
    set(&mut p, "level", Given::Text("HIGH"));
    set(&mut p, "id", Given::Unsigned(1));
    set(&mut p, "values[0]", Given::Signed(5));
    set(&mut p, "values[1]", Given::Signed(6));
    set(&mut p, "dense[0]", Given::Signed(1));
    set(&mut p, "dense[1]", Given::Signed(2));
    set(&mut p, "note", Given::Text(""));
    assert_eq!(
        bytes(&p),
        [
            0x08, 0x01, // id
            0x10, 0x02, // level: HIGH
            0x18, 0x05, 0x18, 0x06, // values, a tag each in proto2
            0x22, 0x02, 0x01, 0x02, // dense, `packed = true`
            0x2A, 0x00, // note: present, so written empty
        ]
    );
}

#[test]
fn a_packed_option_the_writer_cannot_act_on_refuses_the_encoding() {
    let schema = schema();
    let mut p = payload(&schema, "syn.payload.Sample");
    set(&mut p, "words[0]", Given::Text("a"));
    assert!(matches!(p.encode(), Err(Refusal::Schema { .. })));
}

#[test]
fn a_refusal_says_what_is_absent() {
    let schema = schema();
    let p = payload(&schema, "syn.payload.Sample");
    let why = p
        .get("origin.x", Wanted::Signed)
        .expect_err("origin is absent");
    assert_eq!(
        alloc::format!("{why}"),
        "`origin.x` is not set: `origin` is absent"
    );
}
