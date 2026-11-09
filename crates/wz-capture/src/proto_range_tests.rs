// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The tests of [`crate::proto_range`]: the integers a field may hold, by its type
//! and the nanopb `int_size` in force.
//!
//! The expected ranges are the C types nanopb's generator gives the varint kinds
//! under each `int_size` (`intN_t` for `int32`, `int64`, `sint32`, `sint64`;
//! `uintN_t` for `uint32`, `uint64`), written out by hand from the widths, never
//! produced by the code under test.

use alloc::vec::Vec;

use crate::proto_nanopb::IntSize;
use crate::proto_parse::ScalarKind;
use crate::proto_range::{
    field_range, map_entry_range, refusal_words, source_words, value_range, RangeRefusal,
    RangeSource, ValueRange,
};
use crate::proto_schema::{FieldKind, Linker, ProtoFile};

fn nanopb(low: i128, high: i128, bits: u8) -> Result<ValueRange, RangeRefusal> {
    Ok(ValueRange {
        low,
        high,
        source: RangeSource::NanopbIntSize { bits },
    })
}

fn by_type(low: i128, high: i128) -> Result<ValueRange, RangeRefusal> {
    Ok(ValueRange {
        low,
        high,
        source: RangeSource::Type,
    })
}

#[test]
fn an_int_size_narrows_a_varint_integer_to_its_c_type() {
    assert_eq!(
        value_range(ScalarKind::Uint32, IntSize::Bits(8)),
        nanopb(0, 255, 8)
    );
    assert_eq!(
        value_range(ScalarKind::Int32, IntSize::Bits(8)),
        nanopb(-128, 127, 8)
    );
    assert_eq!(
        value_range(ScalarKind::Sint64, IntSize::Bits(16)),
        nanopb(-32768, 32767, 16)
    );
    assert_eq!(
        value_range(ScalarKind::Uint64, IntSize::Bits(32)),
        nanopb(0, 4_294_967_295, 32)
    );
    assert_eq!(
        value_range(ScalarKind::Int64, IntSize::Bits(32)),
        nanopb(-2_147_483_648, 2_147_483_647, 32)
    );
}

#[test]
fn an_int_size_that_narrows_nothing_leaves_the_type_as_the_source() {
    // A 64-bit C integer for a 64-bit type is the type.
    assert_eq!(
        value_range(ScalarKind::Uint64, IntSize::Bits(64)),
        by_type(0, i128::from(u64::MAX))
    );
    // And it never widens one: an `int32` stored in an `int64_t` still arrived
    // as an `int32`.
    assert_eq!(
        value_range(ScalarKind::Int32, IntSize::Bits(64)),
        by_type(i128::from(i32::MIN), i128::from(i32::MAX))
    );
    assert_eq!(
        value_range(ScalarKind::Uint32, IntSize::Bits(32)),
        by_type(0, i128::from(u32::MAX))
    );
    assert_eq!(
        value_range(ScalarKind::Sint32, IntSize::Default),
        by_type(i128::from(i32::MIN), i128::from(i32::MAX))
    );
}

#[test]
fn the_fixed_widths_ignore_int_size() {
    assert_eq!(
        value_range(ScalarKind::Fixed32, IntSize::Bits(8)),
        by_type(0, i128::from(u32::MAX))
    );
    assert_eq!(
        value_range(ScalarKind::Sfixed64, IntSize::Bits(16)),
        by_type(i128::from(i64::MIN), i128::from(i64::MAX))
    );
    // Not even an unreadable one: the option has no bearing on them.
    assert_eq!(
        value_range(ScalarKind::Fixed64, IntSize::Unreadable),
        by_type(0, i128::from(u64::MAX))
    );
}

#[test]
fn an_unreadable_int_size_claims_no_range_for_a_varint_integer() {
    for kind in [
        ScalarKind::Int32,
        ScalarKind::Int64,
        ScalarKind::Uint32,
        ScalarKind::Uint64,
        ScalarKind::Sint32,
        ScalarKind::Sint64,
    ] {
        assert_eq!(
            value_range(kind, IntSize::Unreadable),
            Err(RangeRefusal::UnmodelledOption),
            "{}",
            kind.keyword()
        );
    }
    // A width the option does not have is no C type either.
    assert_eq!(
        value_range(ScalarKind::Uint32, IntSize::Bits(12)),
        Err(RangeRefusal::UnmodelledOption)
    );
}

#[test]
fn a_kind_that_holds_no_integer_has_no_range() {
    for kind in [
        ScalarKind::Double,
        ScalarKind::Float,
        ScalarKind::Bool,
        ScalarKind::String,
        ScalarKind::Bytes,
    ] {
        assert_eq!(
            value_range(kind, IntSize::Bits(8)),
            Err(RangeRefusal::NotAnInteger),
            "{}",
            kind.keyword()
        );
    }
}

#[test]
fn the_word_lists_are_the_variants_words() {
    assert_eq!(source_words(), ["type", "nanopb_int_size"]);
    assert_eq!(RangeSource::Type.word(), "type");
    assert_eq!(
        RangeSource::NanopbIntSize { bits: 16 }.word(),
        "nanopb_int_size"
    );
    let words: Vec<&str> = RangeRefusal::ALL.iter().map(|r| r.word()).collect();
    assert_eq!(words, refusal_words());
    assert_eq!(
        refusal_words(),
        ["not_an_integer", "enum", "map", "unmodelled_option"]
    );
}

/// The range of field `name` of message `message` in the one-file schema `text`.
fn range_of(text: &str, message: &str, name: &str) -> Result<ValueRange, RangeRefusal> {
    let files = [ProtoFile {
        name: "a.proto",
        text: text.as_bytes(),
    }];
    let linker = Linker::read(&files, 0).unwrap_or_else(|d| panic!("{d}\n{text}"));
    let msg = linker
        .msgs
        .iter()
        .find(|m| m.full_name == message)
        .unwrap_or_else(|| panic!("no message {message}"));
    let field = msg
        .fields
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no field {name}"));
    field_range(&linker, msg, field)
}

/// The ranges of the key and the value of map field `name` of `message`.
fn entry_ranges_of(
    text: &str,
    message: &str,
    name: &str,
) -> (
    Result<ValueRange, RangeRefusal>,
    Result<ValueRange, RangeRefusal>,
) {
    let files = [ProtoFile {
        name: "a.proto",
        text: text.as_bytes(),
    }];
    let linker = Linker::read(&files, 0).unwrap_or_else(|d| panic!("{d}\n{text}"));
    let msg = linker
        .msgs
        .iter()
        .find(|m| m.full_name == message)
        .unwrap_or_else(|| panic!("no message {message}"));
    let field = msg
        .fields
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no field {name}"));
    let FieldKind::Map { key, value } = field.kind else {
        panic!("{name} is no map");
    };
    let crate::proto_schema::MapValueKind::Scalar(value) = value else {
        panic!("the value of {name} is no scalar");
    };
    (
        map_entry_range(&linker, msg.file, key),
        map_entry_range(&linker, msg.file, value),
    )
}

#[test]
fn the_field_message_and_file_options_merge_innermost_last() {
    let text = "syntax = \"proto3\";\n\
                option (nanopb_fileopt).int_size = IS_16;\n\
                message M {\n\
                  uint32 plain = 1;\n\
                  uint32 small = 2 [(nanopb).int_size = IS_8];\n\
                  uint32 back = 3 [(nanopb).int_size = IS_DEFAULT];\n\
                }\n\
                message N {\n\
                  option (nanopb_msgopt).int_size = IS_8;\n\
                  int32 by_message = 1;\n\
                  message Inner { int32 by_file = 1; }\n\
                }\n";
    assert_eq!(range_of(text, "M", "plain"), nanopb(0, 65_535, 16));
    assert_eq!(range_of(text, "M", "small"), nanopb(0, 255, 8));
    // `IS_DEFAULT` set on the field replaces the file's width.
    assert_eq!(
        range_of(text, "M", "back"),
        by_type(0, i128::from(u32::MAX))
    );
    assert_eq!(range_of(text, "N", "by_message"), nanopb(-128, 127, 8));
    // A nested message takes the file's options, not the message around it.
    assert_eq!(
        range_of(text, "N.Inner", "by_file"),
        nanopb(-32_768, 32_767, 16)
    );
}

#[test]
fn the_aggregate_form_is_read_and_an_unreadable_value_is_refused() {
    let text = "syntax = \"proto3\";\n\
                message M {\n\
                  uint32 agg = 1 [(nanopb) = { int_size: IS_8 }];\n\
                  uint32 odd = 2 [(nanopb).int_size = IS_7];\n\
                  uint32 nested = 3 [(nanopb) = { x { y: 1 } }];\n\
                  fixed32 fixed = 4 [(nanopb).int_size = IS_7];\n\
                }\n";
    assert_eq!(range_of(text, "M", "agg"), nanopb(0, 255, 8));
    assert_eq!(
        range_of(text, "M", "odd"),
        Err(RangeRefusal::UnmodelledOption)
    );
    // An aggregate this reader cannot follow might set `int_size`.
    assert_eq!(
        range_of(text, "M", "nested"),
        Err(RangeRefusal::UnmodelledOption)
    );
    // A fixed width is not changed by the option, readable or not.
    assert_eq!(
        range_of(text, "M", "fixed"),
        by_type(0, i128::from(u32::MAX))
    );
}

#[test]
fn a_field_that_is_no_integer_says_which_kind_it_is() {
    let text = "syntax = \"proto3\";\n\
                enum E { A = 0; }\n\
                message P { int32 x = 1; }\n\
                message M {\n\
                  E e = 1 [(nanopb).int_size = IS_8];\n\
                  map<string, uint32> m = 2;\n\
                  P p = 3;\n\
                  string s = 4;\n\
                  repeated uint32 r = 5 [(nanopb).int_size = IS_16];\n\
                }\n";
    assert_eq!(range_of(text, "M", "e"), Err(RangeRefusal::Enum));
    assert_eq!(range_of(text, "M", "m"), Err(RangeRefusal::Map));
    assert_eq!(range_of(text, "M", "p"), Err(RangeRefusal::NotAnInteger));
    assert_eq!(range_of(text, "M", "s"), Err(RangeRefusal::NotAnInteger));
    // A repeated integer has the range of each element.
    assert_eq!(range_of(text, "M", "r"), nanopb(0, 65_535, 16));
}

/// `type_override` makes nanopb encode a field as a type the `.proto` does not
/// declare, so the declared type's range would be a claim about the wrong
/// type. It is refused for every kind, a fixed width and an enum included,
/// which the `int_size` rule alone would have answered by the declared type.
#[test]
fn a_type_override_claims_no_range_whatever_the_declared_type() {
    let text = "syntax = \"proto3\";\n\
                enum E { A = 0; }\n\
                message M {\n\
                  uint32 u = 1 [(nanopb).type_override = TYPE_INT32];\n\
                  fixed32 f = 2 [(nanopb).type_override = TYPE_UINT32];\n\
                  E e = 3 [(nanopb).type_override = TYPE_UINT32];\n\
                  uint32 plain = 4;\n\
                }\n";
    for name in ["u", "f", "e"] {
        assert_eq!(
            range_of(text, "M", name),
            Err(RangeRefusal::UnmodelledOption),
            "{name}"
        );
    }
    // The control: the field beside them keeps its type's range.
    assert_eq!(
        range_of(text, "M", "plain"),
        by_type(0, i128::from(u32::MAX))
    );
}

#[test]
fn a_map_entry_takes_the_file_options_and_not_the_map_fields() {
    let text = "syntax = \"proto3\";\n\
                option (nanopb_fileopt).int_size = IS_8;\n\
                message M {\n\
                  option (nanopb_msgopt).int_size = IS_16;\n\
                  map<int32, uint32> m = 1 [(nanopb).int_size = IS_32];\n\
                }\n";
    let (key, value) = entry_ranges_of(text, "M", "m");
    assert_eq!(key, nanopb(-128, 127, 8));
    assert_eq!(value, nanopb(0, 255, 8));
    // Without a file option the entry is the types' own.
    let plain = "syntax = \"proto3\";\n\
                 message M {\n\
                   option (nanopb_msgopt).int_size = IS_8;\n\
                   map<uint64, sint32> m = 1;\n\
                 }\n";
    let (key, value) = entry_ranges_of(plain, "M", "m");
    assert_eq!(key, by_type(0, i128::from(u64::MAX)));
    assert_eq!(value, by_type(i128::from(i32::MIN), i128::from(i32::MAX)));
}
