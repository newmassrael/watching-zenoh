// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Model tests of the protobuf wire writer, on SYNTHETIC schemas.
//!
//! Every expected byte string is laid by hand from the protobuf encoding rules
//! (a tag is `number << 3 | wire type`, a varint seven bits a byte, low first),
//! not by a writer of this workspace. The names, numbers and values are made up
//! and unlike any deployment's.

use alloc::vec;
use alloc::vec::Vec;

use crate::proto_decode::SchemaSet;
use crate::proto_parse::ScalarKind;
use crate::proto_range::{RangeRefusal, RangeSource, ValueRange};
use crate::proto_schema::{FileOptions, Fld, Linker, Msg, ProtoFile};
use crate::proto_write::{
    has_presence, map_entry, packed, put_field, put_repeated, put_singular, Narrowing,
    PackedRefusal, Wire,
};

const THREE: &str = r#"
syntax = "proto3";
package syn.write;

message Inner {
  int32 v = 1;
}

message Three {
  int32 bare = 1;
  optional int32 marked = 2;
  Inner inner = 3;
  oneof pick {
    int32 member = 4;
  }
  repeated int32 numbers = 5;
  repeated int32 loose = 6 [packed = false];
  repeated string words = 7;
  repeated Inner inners = 8;
  repeated string bad_true = 9 [packed = true];
  repeated int32 bad_word = 10 [packed = 1];
  map<string, int32> table = 11;
}
"#;

const TWO: &str = r#"
syntax = "proto2";
package syn.write2;

message Two {
  optional int32 a = 1;
  required int32 b = 2;
  repeated int32 c = 3;
  repeated int32 d = 4 [packed = true];
}
"#;

const NARROW: &str = r#"
syntax = "proto3";
package syn.narrow;
option (nanopb_fileopt).int_size = IS_16;

message Gauge {
  uint32 by_file = 1;
  uint32 small = 2 [(nanopb).int_size = IS_8];
  int64 signed_small = 3 [(nanopb).int_size = IS_8];
  uint32 odd = 4 [(nanopb).int_size = IS_12];
  fixed32 fixed = 5 [(nanopb).int_size = IS_8];
  uint32 swapped = 6 [(nanopb).type_override = TYPE_UINT64];
  string text = 7;
  map<int32, uint32> table = 8;
}
"#;

fn files() -> [ProtoFile<'static>; 3] {
    [
        ProtoFile {
            name: "syn/three.proto",
            text: THREE.as_bytes(),
        },
        ProtoFile {
            name: "syn/two.proto",
            text: TWO.as_bytes(),
        },
        ProtoFile {
            name: "syn/narrow.proto",
            text: NARROW.as_bytes(),
        },
    ]
}

fn schema() -> SchemaSet {
    SchemaSet::read(&files()).expect("the synthetic schema reads")
}

fn message<'s>(schema: &'s SchemaSet, name: &str) -> &'s Msg {
    let found = schema.message(name).expect("the message is in the schema");
    schema.linked(found)
}

fn field<'m>(msg: &'m Msg, name: &str) -> &'m Fld {
    msg.fields
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no field {name}"))
}

fn put(wire: &Wire<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    wire.put(&mut out);
    out
}

fn ten_bytes_of_minus_one() -> Vec<u8> {
    let mut bytes = vec![0xFF; 9];
    bytes.push(0x01);
    bytes
}

fn by_type(low: i128, high: i128) -> Result<ValueRange, RangeRefusal> {
    Ok(ValueRange {
        low,
        high,
        source: RangeSource::Type,
    })
}

fn nanopb(low: i128, high: i128, bits: u8) -> Result<ValueRange, RangeRefusal> {
    Ok(ValueRange {
        low,
        high,
        source: RangeSource::NanopbIntSize { bits },
    })
}

#[test]
fn each_scalar_takes_its_wire_form() {
    assert_eq!(put(&Wire::integer(ScalarKind::Uint32, 300)), [0xAC, 0x02]);
    // Sign-extended to 64 bits: a negative int32 is ten bytes.
    assert_eq!(
        put(&Wire::integer(ScalarKind::Int32, -1)),
        ten_bytes_of_minus_one()
    );
    assert_eq!(
        put(&Wire::integer(ScalarKind::Uint64, i128::from(u64::MAX))),
        ten_bytes_of_minus_one()
    );
    // Zigzag: -1 is 1, 1 is 2, -2 is 3.
    assert_eq!(put(&Wire::integer(ScalarKind::Sint32, -1)), [0x01]);
    assert_eq!(put(&Wire::integer(ScalarKind::Sint32, 1)), [0x02]);
    assert_eq!(put(&Wire::integer(ScalarKind::Sint64, -2)), [0x03]);
    assert_eq!(
        put(&Wire::integer(ScalarKind::Sfixed32, -2)),
        [0xFE, 0xFF, 0xFF, 0xFF]
    );
    assert_eq!(
        put(&Wire::integer(ScalarKind::Fixed64, 1)),
        [0x01, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(put(&Wire::enum_number(-1)), ten_bytes_of_minus_one());
    assert_eq!(put(&Wire::delimited(&b"hi"[..])), [0x02, b'h', b'i']);
    assert_eq!(Wire::Varint(0).wire_type(), 0);
    assert_eq!(Wire::Fixed64(0).wire_type(), 1);
    assert_eq!(Wire::delimited(Vec::<u8>::new()).wire_type(), 2);
    assert_eq!(Wire::Fixed32(0).wire_type(), 5);
}

#[test]
fn a_field_without_presence_is_left_out_at_its_default_and_negative_zero_is_not() {
    let mut out = Vec::new();
    put_singular(&mut out, 1, false, &Wire::Varint(0));
    put_singular(&mut out, 2, false, &Wire::delimited(Vec::<u8>::new()));
    put_singular(&mut out, 4, false, &Wire::Fixed64(0));
    assert!(out.is_empty(), "{out:02X?}");
    put_singular(&mut out, 1, true, &Wire::Varint(0));
    put_singular(&mut out, 3, false, &Wire::Fixed32((-0.0f32).to_bits()));
    assert_eq!(out, [0x08, 0x00, 0x1D, 0x00, 0x00, 0x00, 0x80]);
}

#[test]
fn a_repeated_field_is_one_run_when_packed_and_a_tag_each_when_not() {
    let numbers = [Wire::Varint(1), Wire::Varint(300)];
    let mut out = Vec::new();
    put_repeated(&mut out, 4, true, &numbers);
    assert_eq!(out, [0x22, 0x03, 0x01, 0xAC, 0x02]);
    let mut out = Vec::new();
    put_repeated(&mut out, 4, false, &numbers);
    assert_eq!(out, [0x20, 0x01, 0x20, 0xAC, 0x02]);
    let words = [Wire::delimited(&b"a"[..]), Wire::delimited(&b""[..])];
    let mut out = Vec::new();
    put_repeated(&mut out, 7, false, &words);
    assert_eq!(out, [0x3A, 0x01, b'a', 0x3A, 0x00]);
    // No element writes nothing, packed or not.
    let mut out = Vec::new();
    put_repeated(&mut out, 4, true, &[]);
    put_repeated(&mut out, 4, false, &[]);
    assert!(out.is_empty(), "{out:02X?}");
}

#[test]
fn a_map_entry_writes_its_key_and_value_even_at_their_defaults() {
    let entry = map_entry(&Wire::delimited(&b""[..]), &Wire::Varint(0));
    assert_eq!(entry, [0x0A, 0x00, 0x10, 0x00]);
    let mut out = Vec::new();
    put_field(&mut out, 11, &Wire::delimited(entry));
    assert_eq!(out, [0x5A, 0x04, 0x0A, 0x00, 0x10, 0x00]);
    // A field number whose tag takes two bytes.
    let mut out = Vec::new();
    put_field(&mut out, 16, &Wire::Varint(1));
    assert_eq!(out, [0x80, 0x01, 0x01]);
}

#[test]
fn presence_follows_the_label_the_oneof_and_the_kind() {
    let schema = schema();
    let three = message(&schema, "syn.write.Three");
    assert!(!has_presence(three, field(three, "bare")));
    for name in ["marked", "inner", "member"] {
        assert!(has_presence(three, field(three, name)), "{name}");
    }
    let two = message(&schema, "syn.write2.Two");
    for name in ["a", "b"] {
        assert!(has_presence(two, field(two, name)), "{name}");
    }
}

#[test]
fn packing_follows_the_syntax_unless_the_field_says_otherwise() {
    let schema = schema();
    let three = message(&schema, "syn.write.Three");
    let packed_of = |msg: &Msg, name: &str| packed(msg, field(msg, name)).ok();
    assert_eq!(packed_of(three, "numbers"), Some(true));
    assert_eq!(packed_of(three, "loose"), Some(false));
    assert_eq!(packed_of(three, "words"), Some(false));
    assert_eq!(packed_of(three, "inners"), Some(false));
    let two = message(&schema, "syn.write2.Two");
    assert_eq!(packed_of(two, "c"), Some(false));
    assert_eq!(packed_of(two, "d"), Some(true));
}

#[test]
fn a_packed_option_the_writer_cannot_act_on_is_refused_with_the_option() {
    let schema = schema();
    let three = message(&schema, "syn.write.Three");
    assert!(matches!(
        packed(three, field(three, "bad_true")),
        Err(PackedRefusal::NotPackable(option)) if option.name == "packed"
    ));
    assert!(matches!(
        packed(three, field(three, "bad_word")),
        Err(PackedRefusal::NotABool(option)) if option.name == "packed"
    ));
}

#[test]
fn the_linker_and_the_schema_set_answer_the_same_file_options() {
    let files = files();
    let linker = Linker::read(&files, 2).expect("the narrowing file reads");
    let schema = schema();
    let names = |options: &[crate::proto_parse::FieldOption]| {
        options.iter().map(|o| o.name.clone()).collect::<Vec<_>>()
    };
    assert_eq!(
        names(linker.options_of_file(2)),
        ["(nanopb_fileopt).int_size"]
    );
    assert_eq!(
        names(schema.options_of_file(2)),
        names(linker.options_of_file(2))
    );
    assert!(schema.options_of_file(0).is_empty());
    // An index the schema has no file at states nothing.
    assert!(schema.options_of_file(3).is_empty());
    assert!(linker.options_of_file(3).is_empty());
}

#[test]
fn a_writer_that_does_not_narrow_holds_an_integer_to_its_type() {
    let schema = schema();
    let gauge = message(&schema, "syn.narrow.Gauge");
    let range = |name: &str| Narrowing::Type.field_range(&schema, gauge, field(gauge, name));
    for name in ["by_file", "small", "odd", "swapped"] {
        assert_eq!(range(name), by_type(0, i128::from(u32::MAX)), "{name}");
    }
    assert_eq!(
        range("signed_small"),
        by_type(i128::from(i64::MIN), i128::from(i64::MAX))
    );
    assert_eq!(range("text"), Err(RangeRefusal::NotAnInteger));
    assert_eq!(range("table"), Err(RangeRefusal::Map));
    assert_eq!(Narrowing::default(), Narrowing::Type);
    assert_eq!(
        Narrowing::Type.map_entry_range(&schema, gauge.file, ScalarKind::Int32),
        by_type(i128::from(i32::MIN), i128::from(i32::MAX))
    );
}

#[test]
fn a_writer_that_narrows_by_nanopb_holds_an_integer_to_its_c_type() {
    let schema = schema();
    let gauge = message(&schema, "syn.narrow.Gauge");
    let range =
        |name: &str| Narrowing::NanopbIntSize.field_range(&schema, gauge, field(gauge, name));
    // The file's option narrows a field that states none.
    assert_eq!(range("by_file"), nanopb(0, 65_535, 16));
    assert_eq!(range("small"), nanopb(0, 255, 8));
    assert_eq!(range("signed_small"), nanopb(-128, 127, 8));
    // A fixed width is not in nanopb's table, so the option does not change it.
    assert_eq!(range("fixed"), by_type(0, i128::from(u32::MAX)));
    // A width the reader cannot read, or another type nanopb encodes the field
    // as, leaves the range unknown.
    assert_eq!(range("odd"), Err(RangeRefusal::UnmodelledOption));
    assert_eq!(range("swapped"), Err(RangeRefusal::UnmodelledOption));
    assert_eq!(range("text"), Err(RangeRefusal::NotAnInteger));
    // A map entry takes the file's options.
    assert_eq!(
        Narrowing::NanopbIntSize.map_entry_range(&schema, gauge.file, ScalarKind::Int32),
        nanopb(-32_768, 32_767, 16)
    );
    assert_eq!(
        Narrowing::NanopbIntSize.map_entry_range(&schema, gauge.file, ScalarKind::String),
        Err(RangeRefusal::NotAnInteger)
    );
}
