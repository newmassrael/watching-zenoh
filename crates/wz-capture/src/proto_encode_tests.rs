// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The corpus-free tests of [`crate::proto_encode`]: every one runs on every
//! machine and needs no `protoc`. The comparison against `protoc` itself is in
//! `wz-integration-tests`.
//!
//! The expected bytes are written out by hand from the protobuf encoding guide
//! (the `150` varint, the `testing` string, the nested message, the packed
//! example, the zigzag table), never produced by the code under test.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::payload::formats::{FormatMap, PayloadFormat, Protobuf};
use crate::proto_encode::{
    encode_message, EncodeError, ValueError, MAX_ENCODED_BYTES, MAX_VALUES_DEPTH,
};
use crate::proto_schema::{declarations_from_proto, ProtoFile};

const P3: &str = "syntax = \"proto3\";\n";
const P2: &str = "syntax = \"proto2\";\n";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn files<'a>(schema: &'a [(&'a str, &'a str)]) -> Vec<ProtoFile<'a>> {
    schema
        .iter()
        .map(|(name, text)| ProtoFile {
            name,
            text: text.as_bytes(),
        })
        .collect()
}

/// The result of encoding `values` as `root`, written in the one file `schema`.
fn run(root: &str, schema: &str, values: &str) -> Result<Vec<u8>, EncodeError> {
    encode_message(root, &files(&[("a.proto", schema)]), 0, values)
}

/// The bytes as lowercase hex, or a panic that prints why not.
fn enc(root: &str, schema: &str, values: &str) -> String {
    match run(root, schema, values) {
        Ok(bytes) => hex(&bytes),
        Err(e) => panic!("{e}\nschema: {schema}\nvalues: {values}"),
    }
}

fn value_error(root: &str, schema: &str, values: &str) -> ValueError {
    match run(root, schema, values) {
        Err(EncodeError::Value(v)) => v,
        Err(other) => panic!("expected a value error, got: {other}"),
        Ok(bytes) => panic!("expected a refusal, got {}", hex(&bytes)),
    }
}

/// A one-message schema in `syntax` with the field lines `body`.
fn m(syntax: &str, body: &str) -> String {
    format!("{syntax}message M {{\n{body}\n}}")
}

// ---- the public wire examples ---------------------------------------------

#[test]
fn the_guides_varint_example_is_150() {
    // Test1 { int32 a = 1; } with a = 150 is 08 96 01.
    assert_eq!(enc("M", &m(P3, "int32 a = 1;"), r#"{"a":150}"#), "089601");
}

#[test]
fn the_guides_string_example_is_testing() {
    // Test2 { string b = 2; } with b = "testing" is 12 07 74 65 73 74 69 6e 67.
    assert_eq!(
        enc("M", &m(P3, "string b = 2;"), r#"{"b":"testing"}"#),
        "120774657374696e67"
    );
}

#[test]
fn the_guides_nested_example_wraps_test1_in_field_3() {
    // Test3 { Test1 c = 3; } with c.a = 150 is 1a 03 08 96 01.
    let schema = format!("{P3}message Test1 {{ int32 a = 1; }} message M {{ Test1 c = 3; }}");
    assert_eq!(enc("M", &schema, r#"{"c":{"a":150}}"#), "1a03089601");
}

#[test]
fn the_guides_packed_example_is_one_run_of_varints() {
    // repeated int32 d = 4 [packed=true] with 3, 270, 86942 is
    // 22 06 03 8e 02 9e a7 05.
    assert_eq!(
        enc(
            "M",
            &m(P2, "repeated int32 d = 4 [packed=true];"),
            r#"{"d":[3,270,86942]}"#
        ),
        "2206038e029ea705"
    );
}

#[test]
fn sint_values_are_zigzag_and_int_values_are_not() {
    // The guide's table: 0 -> 0, -1 -> 1, 1 -> 2, -2 -> 3, 2147483647 ->
    // 4294967294, -2147483648 -> 4294967295.
    let sint = m(P3, "sint32 a = 1;");
    assert_eq!(enc("M", &sint, r#"{"a":-1}"#), "0801");
    assert_eq!(enc("M", &sint, r#"{"a":1}"#), "0802");
    assert_eq!(enc("M", &sint, r#"{"a":-2}"#), "0803");
    assert_eq!(enc("M", &sint, r#"{"a":2147483647}"#), "08feffffff0f");
    assert_eq!(enc("M", &sint, r#"{"a":-2147483648}"#), "08ffffffff0f");
    let sint64 = m(P3, "sint64 a = 1;");
    assert_eq!(enc("M", &sint64, r#"{"a":-1}"#), "0801");
    assert_eq!(
        enc("M", &sint64, r#"{"a":"-9223372036854775808"}"#),
        "08ffffffffffffffffff01"
    );
    // The same -1 as a plain int32 is not zigzagged.
    assert_eq!(
        enc("M", &m(P3, "int32 a = 1;"), r#"{"a":-1}"#),
        "08ffffffffffffffffff01"
    );
}

#[test]
fn fixed_width_kinds_are_little_endian_at_their_own_width() {
    let one = |ty: &str, v: &str| {
        enc(
            "M",
            &m(P3, &format!("{ty} a = 1;")),
            &format!(r#"{{"a":{v}}}"#),
        )
    };
    assert_eq!(one("fixed32", "1"), "0d01000000");
    assert_eq!(one("sfixed32", "-1"), "0dffffffff");
    assert_eq!(one("fixed64", "1"), "090100000000000000");
    assert_eq!(one("sfixed64", "-2"), "09feffffffffffffff");
    assert_eq!(one("float", "1.0"), "0d0000803f");
    assert_eq!(one("double", "1.0"), "09000000000000f03f");
    assert_eq!(one("float", "-2.5"), "0d000020c0");
}

#[test]
fn a_bool_is_a_one_byte_varint() {
    let schema = m(P3, "bool a = 1;");
    assert_eq!(enc("M", &schema, r#"{"a":true}"#), "0801");
    assert_eq!(enc("M", &schema, r#"{"a":false}"#), "");
}

// ---- which fields are written, and in what order ---------------------------

#[test]
fn fields_are_written_in_field_number_order_whatever_the_order_given() {
    let schema = m(P3, "int32 high = 9;\nint32 low = 1;\nint32 mid = 5;");
    // low = 1 is field 1, mid = 2 is field 5, high = 3 is field 9.
    assert_eq!(
        enc("M", &schema, r#"{"mid":2,"high":3,"low":1}"#),
        "080128024803"
    );
}

#[test]
fn a_proto3_scalar_at_its_default_is_not_written() {
    let schema = m(
        P3,
        "int32 a = 1; string b = 2; bytes c = 3; bool d = 4; double e = 5; float f = 6;",
    );
    assert_eq!(
        enc(
            "M",
            &schema,
            r#"{"a":0,"b":"","c":"","d":false,"e":0.0,"f":0}"#
        ),
        ""
    );
}

#[test]
fn a_negative_zero_float_is_not_the_default_and_is_written() {
    // The default test is on the bits, so -0.0 differs from 0.0.
    assert_eq!(
        enc("M", &m(P3, "float a = 1;"), r#"{"a":-0.0}"#),
        "0d00000080"
    );
    assert_eq!(
        enc("M", &m(P3, "double a = 1;"), r#"{"a":-0.0}"#),
        "090000000000000080"
    );
    assert_eq!(enc("M", &m(P3, "double a = 1;"), r#"{"a":0.0}"#), "");
}

#[test]
fn a_field_with_presence_is_written_at_its_default() {
    // A proto3 optional, a oneof member, a message field, and the singular
    // fields of proto2.
    assert_eq!(
        enc("M", &m(P3, "optional int32 a = 1;"), r#"{"a":0}"#),
        "0800"
    );
    assert_eq!(
        enc(
            "M",
            &m(P3, "oneof pick { int32 a = 1; string b = 2; }"),
            r#"{"a":0}"#
        ),
        "0800"
    );
    assert_eq!(
        enc(
            "M",
            &m(P3, "oneof pick { int32 a = 1; string b = 2; }"),
            r#"{"b":""}"#
        ),
        "1200"
    );
    let nested = format!("{P3}message N {{ int32 x = 1; }} message M {{ N n = 1; }}");
    assert_eq!(enc("M", &nested, r#"{"n":{}}"#), "0a00");
    assert_eq!(
        enc(
            "M",
            &m(P2, "optional int32 a = 1;\nrequired int32 r = 2;"),
            r#"{"a":0,"r":0}"#
        ),
        "08001000"
    );
}

#[test]
fn null_leaves_a_field_out() {
    let schema = m(P3, "optional int32 a = 1; int32 b = 2;");
    assert_eq!(enc("M", &schema, r#"{"a":null,"b":7}"#), "1007");
}

#[test]
fn two_members_of_one_oneof_are_refused() {
    let schema = m(P3, "oneof pick { int32 a = 1; string b = 2; }");
    let e = value_error("M", &schema, r#"{"a":1,"b":"x"}"#);
    assert_eq!(e.path, "/b");
    assert!(e.reason.contains("oneof `pick`"), "{}", e.reason);
    assert!(e.reason.contains("already has `a`"), "{}", e.reason);
}

#[test]
fn a_missing_required_field_is_refused_and_a_null_one_counts_as_missing() {
    let schema = m(P2, "required int32 r = 1;\noptional int32 o = 2;");
    for values in [r#"{"o":1}"#, r#"{"r":null,"o":1}"#, "{}"] {
        let e = value_error("M", &schema, values);
        assert_eq!(e.path, "");
        assert_eq!(e.field.as_deref(), Some("M.r"));
        assert!(e.reason.contains("required field `r`"), "{}", e.reason);
    }
    assert_eq!(enc("M", &schema, r#"{"r":4}"#), "0804");
}

// ---- repeated fields -------------------------------------------------------

#[test]
fn proto3_packs_numeric_repeated_fields_unless_told_not_to() {
    let packed = m(P3, "repeated int32 a = 1;");
    assert_eq!(enc("M", &packed, r#"{"a":[1,2,3]}"#), "0a03010203");
    let unpacked = m(P3, "repeated int32 a = 1 [packed=false];");
    assert_eq!(enc("M", &unpacked, r#"{"a":[1,2,3]}"#), "080108020803");
}

#[test]
fn proto2_leaves_numeric_repeated_fields_unpacked_unless_told_to_pack() {
    let unpacked = m(P2, "repeated int32 a = 1;");
    assert_eq!(enc("M", &unpacked, r#"{"a":[1,2,3]}"#), "080108020803");
    let packed = m(P2, "repeated int32 a = 1 [packed=true];");
    assert_eq!(enc("M", &packed, r#"{"a":[1,2,3]}"#), "0a03010203");
}

#[test]
fn packed_fixed_width_and_enum_fields_are_one_run_too() {
    let schema = format!(
        "{P3}enum E {{ Z = 0; ONE = 1; }}
         message M {{ repeated fixed32 f = 1; repeated E e = 2; repeated bool b = 3; }}"
    );
    assert_eq!(
        enc(
            "M",
            &schema,
            r#"{"f":[1,2],"e":["ONE","Z"],"b":[true,false]}"#
        ),
        concat!("0a0801000000020000001202", "01001a020100")
    );
}

#[test]
fn strings_bytes_and_messages_are_one_tag_per_element_even_in_proto3() {
    let schema = format!(
        "{P3}message N {{ int32 x = 1; }}
         message M {{ repeated string s = 1; repeated bytes b = 2; repeated N n = 3; }}"
    );
    assert_eq!(
        enc(
            "M",
            &schema,
            r#"{"s":["a","b"],"b":["AQ=="],"n":[{"x":1},{}]}"#
        ),
        "0a01610a01621201011a0208011a00"
    );
}

#[test]
fn an_empty_array_writes_nothing() {
    assert_eq!(enc("M", &m(P3, "repeated int32 a = 1;"), r#"{"a":[]}"#), "");
    assert_eq!(
        enc("M", &m(P2, "repeated string a = 1;"), r#"{"a":[]}"#),
        ""
    );
}

#[test]
fn packed_on_a_type_that_cannot_be_packed_is_a_schema_error_at_the_option() {
    let schema = m(P2, "repeated string a = 1 [packed=true];");
    match run("M", &schema, r#"{"a":["x"]}"#) {
        Err(EncodeError::Schema(d)) => {
            assert_eq!((d.file.as_deref(), d.line), (Some("a.proto"), Some(3)));
            assert!(d.reason.contains("packed"), "{d}");
        }
        other => panic!("expected a schema error, got {other:?}"),
    }
    // Only a field the values name is judged.
    assert_eq!(enc("M", &schema, "{}"), "");
}

// ---- maps ------------------------------------------------------------------

#[test]
fn a_map_is_repeated_entries_with_key_1_and_value_2_in_key_order() {
    let schema = m(P3, "map<int32, string> m = 1;");
    // Entry one: key 08 01, value 12 01 61; entry two: key 08 02, value 12 01 62.
    assert_eq!(
        enc("M", &schema, r#"{"m":{"2":"b","1":"a"}}"#),
        concat!("0a050801120161", "0a050802120162")
    );
}

#[test]
fn integer_map_keys_are_ordered_as_numbers_not_as_text() {
    let schema = m(P3, "map<int32, int32> m = 1;");
    // "10" sorts before "2" as text and after it as a number; -3 is the ten-byte
    // sign-extended varint.
    assert_eq!(
        enc("M", &schema, r#"{"m":{"10":1,"2":1,"-3":1}}"#),
        concat!(
            "0a0d08fdffffffffffffffff011001",
            "0a0408021001",
            "0a04080a1001"
        )
    );
}

#[test]
fn a_map_entry_writes_its_key_and_value_even_when_both_are_defaults() {
    let schema = m(P3, "map<string, int32> m = 1;");
    // key 0a 00 (the empty string), value 10 00.
    assert_eq!(enc("M", &schema, r#"{"m":{"":0}}"#), "0a040a001000");
}

#[test]
fn bool_keys_are_false_then_true_and_message_values_are_nested() {
    let schema = format!("{P3}message N {{ int32 x = 1; }} message M {{ map<bool, N> m = 1; }}");
    assert_eq!(
        enc("M", &schema, r#"{"m":{"true":{"x":1},"false":{}}}"#),
        concat!("0a0408001200", "0a06080112020801")
    );
    let e = value_error("M", &schema, r#"{"m":{"yes":{}}}"#);
    assert_eq!(e.path, "/m/yes");
}

#[test]
fn a_map_key_given_twice_in_any_spelling_is_refused() {
    let schema = m(P3, "map<int32, int32> m = 1;");
    // Three spellings of one key: the digits, a zero before them, a sign.
    for twin in ["01", "+1", "0001"] {
        let values = format!(r#"{{"m":{{"1":1,"{twin}":2}}}}"#);
        let e = value_error("M", &schema, &values);
        assert_eq!(e.path, format!("/m/{twin}"));
        assert!(e.reason.contains("given twice"), "{}", e.reason);
    }
}

#[test]
fn an_integer_map_key_is_digits_with_a_sign_and_not_a_fraction_or_an_exponent() {
    let schema = m(P3, "map<int32, int32> m = 1;\nmap<uint32, int32> u = 2;");
    assert_eq!(
        enc("M", &schema, r#"{"m":{"-3":1}}"#),
        "0a0d08fdffffffffffffffff011001"
    );
    for key in ["1.0", "1e3", " 1", "0x1", "-", "+", ""] {
        let values = format!(r#"{{"m":{{"{key}":1}}}}"#);
        let e = value_error("M", &schema, &values);
        assert_eq!(e.path, format!("/m/{key}"), "{key:?}");
    }
    // An unsigned key takes no minus sign.
    let e = value_error("M", &schema, r#"{"u":{"-0":1}}"#);
    assert!(e.reason.contains("no minus sign"), "{}", e.reason);
}

#[test]
fn a_map_key_that_is_no_integer_is_refused_at_the_key() {
    let schema = m(P3, "map<int32, int32> m = 1;");
    let e = value_error("M", &schema, r#"{"m":{"x":1}}"#);
    assert_eq!(e.path, "/m/x");
    assert!(
        e.expected.as_deref().unwrap_or("").contains("int32"),
        "{e:?}"
    );
    let e = value_error("M", &schema, r#"{"m":{"1":null}}"#);
    assert!(e.reason.contains("null"), "{}", e.reason);
}

// ---- enums -----------------------------------------------------------------

const ENUMS: &str = "enum E { ZERO = 0; ONE = 1; NEG = -1; }\n";

#[test]
fn an_enum_is_written_from_its_name_or_its_number() {
    let schema = format!("{P3}{ENUMS}message M {{ E e = 1; }}");
    assert_eq!(enc("M", &schema, r#"{"e":"ONE"}"#), "0801");
    assert_eq!(enc("M", &schema, r#"{"e":1}"#), "0801");
    assert_eq!(enc("M", &schema, r#"{"e":"ZERO"}"#), "");
    // A negative value is sign-extended, ten bytes.
    assert_eq!(
        enc("M", &schema, r#"{"e":"NEG"}"#),
        "08ffffffffffffffffff01"
    );
    assert_eq!(enc("M", &schema, r#"{"e":-1}"#), "08ffffffffffffffffff01");
}

#[test]
fn an_unknown_enum_name_is_refused_and_a_proto3_unknown_number_is_not() {
    let schema = format!("{P3}{ENUMS}message M {{ E e = 1; }}");
    let e = value_error("M", &schema, r#"{"e":"TWO"}"#);
    assert_eq!(e.path, "/e");
    assert!(e.reason.contains("`TWO`"), "{}", e.reason);
    assert!(e
        .expected
        .as_deref()
        .unwrap_or("")
        .contains("ZERO, ONE, NEG"));
    assert_eq!(enc("M", &schema, r#"{"e":7}"#), "0807");
}

#[test]
fn a_string_of_digits_is_a_number_to_an_enum_because_a_name_cannot_be_one() {
    let schema = format!("{P3}{ENUMS}message M {{ E e = 1; }}");
    assert_eq!(enc("M", &schema, r#"{"e":"1"}"#), "0801");
    assert_eq!(enc("M", &schema, r#"{"e":"-1"}"#), "08ffffffffffffffffff01");
    assert_eq!(enc("M", &schema, r#"{"e":"7"}"#), "0807");
    // Anything else that is not a name is refused as one.
    for text in ["1.0", "x1", "", " 1", "1e0"] {
        let values = format!(r#"{{"e":"{text}"}}"#);
        let e = value_error("M", &schema, &values);
        assert!(
            e.reason.contains("not a value of the enum"),
            "{text:?}: {}",
            e.reason
        );
    }
    // A digit string past int32 is a number out of range, not a misspelt name.
    let e = value_error("M", &schema, r#"{"e":"2147483648"}"#);
    assert!(e.reason.contains("out of range for int32"), "{}", e.reason);
}

#[test]
fn a_proto2_enum_is_closed() {
    let schema = format!("{P2}{ENUMS}message M {{ optional E e = 1; }}");
    assert_eq!(enc("M", &schema, r#"{"e":1}"#), "0801");
    for values in [r#"{"e":7}"#, r#"{"e":"7"}"#] {
        let e = value_error("M", &schema, values);
        assert!(e.reason.contains("closed"), "{values}: {}", e.reason);
    }
    // A name is always one of the values.
    assert_eq!(
        enc("M", &schema, r#"{"e":"NEG"}"#),
        "08ffffffffffffffffff01"
    );
}

// ---- integers, floats, strings, bytes --------------------------------------

#[test]
fn a_64_bit_value_keeps_every_bit_as_a_number_or_a_string() {
    let u = m(P3, "uint64 a = 1;");
    assert_eq!(
        enc("M", &u, r#"{"a":"18446744073709551615"}"#),
        "08ffffffffffffffffff01"
    );
    // 2^53 + 1 is the first integer a double cannot hold: through a double it
    // would be 2^53, whose varint starts 80 where this starts 81.
    let want = "088180808080808010";
    assert_eq!(enc("M", &u, r#"{"a":"9007199254740993"}"#), want);
    assert_eq!(enc("M", &u, r#"{"a":9007199254740993}"#), want);
    let i = m(P3, "int64 a = 1;");
    assert_eq!(
        enc("M", &i, r#"{"a":"-9223372036854775808"}"#),
        "0880808080808080808001"
    );
    assert_eq!(
        enc("M", &i, r#"{"a":9223372036854775807}"#),
        "08ffffffffffffffff7f"
    );
}

#[test]
fn an_integer_may_be_written_with_an_exponent_or_a_zero_fraction_but_not_rounded() {
    let schema = m(P3, "int32 a = 1;");
    assert_eq!(enc("M", &schema, r#"{"a":1e3}"#), "08e807");
    assert_eq!(enc("M", &schema, r#"{"a":2.0}"#), "0802");
    assert_eq!(enc("M", &schema, r#"{"a":1.50e1}"#), "080f");
    assert_eq!(enc("M", &schema, r#"{"a":-0}"#), "");
    let e = value_error("M", &schema, r#"{"a":1.5}"#);
    assert_eq!(e.path, "/a");
    assert!(e.reason.contains("not an integer"), "{}", e.reason);
    let e = value_error("M", &schema, r#"{"a":0.5}"#);
    assert!(e.reason.contains("not an integer"), "{}", e.reason);
}

#[test]
fn an_integer_out_of_its_type_is_refused_with_the_type() {
    let schema = m(
        P3,
        "int32 a = 1; uint32 b = 2; sint32 c = 3; fixed32 d = 4; int64 e = 5; uint64 f = 6;",
    );
    for (values, field, shown) in [
        (r#"{"a":2147483648}"#, "a", "int32"),
        (r#"{"a":-2147483649}"#, "a", "int32"),
        (r#"{"b":-1}"#, "b", "uint32"),
        (r#"{"b":4294967296}"#, "b", "uint32"),
        (r#"{"c":"2147483648"}"#, "c", "sint32"),
        (r#"{"d":4294967296}"#, "d", "fixed32"),
        (r#"{"e":"9223372036854775808"}"#, "e", "int64"),
        (r#"{"f":"18446744073709551616"}"#, "f", "uint64"),
        (r#"{"f":1e30}"#, "f", "uint64"),
        (r#"{"f":1e400}"#, "f", "uint64"),
    ] {
        let e = value_error("M", &schema, values);
        assert_eq!(e.path, format!("/{field}"), "{values}");
        assert_eq!(e.field.as_deref(), Some(format!("M.{field}").as_str()));
        assert!(e.reason.contains("out of range"), "{values}: {}", e.reason);
        assert!(
            e.expected.as_deref().unwrap_or("").starts_with(shown),
            "{e:?}"
        );
    }
}

#[test]
fn a_value_that_is_not_a_plain_number_is_refused_not_guessed() {
    let schema = m(P3, "int32 a = 1;");
    for values in [
        r#"{"a":true}"#,
        r#"{"a":[1]}"#,
        r#"{"a":{}}"#,
        r#"{"a":"abc"}"#,
        r#"{"a":""}"#,
        r#"{"a":"0x10"}"#,
        r#"{"a":0x10}"#,
        r#"{"a":+1}"#,
        r#"{"a":01}"#,
        r#"{"a":" 1"}"#,
        r#"{"a":"1.0"}"#,
        r#"{"a":"1e3"}"#,
        r#"{"a":"1.50e1"}"#,
        r#"{"a":"-"}"#,
        r#"{"a":"1 "}"#,
        r#"{"a":"1_0"}"#,
    ] {
        let e = value_error("M", &schema, values);
        assert_eq!(e.path, "/a", "{values}");
        assert!(
            e.expected.as_deref().unwrap_or("").starts_with("int32"),
            "{values}"
        );
    }
}

#[test]
fn a_string_of_digits_may_carry_a_sign_and_leading_zeros_where_a_number_may_not() {
    let schema = m(P3, "int32 a = 1; uint64 b = 2;");
    assert_eq!(enc("M", &schema, r#"{"a":"+7"}"#), "0807");
    assert_eq!(enc("M", &schema, r#"{"a":"007"}"#), "0807");
    assert_eq!(
        enc("M", &schema, r#"{"a":"-007"}"#),
        "08f9ffffffffffffffff01"
    );
    assert_eq!(
        enc("M", &schema, r#"{"b":"+18446744073709551615"}"#),
        "10ffffffffffffffffff01"
    );
    assert_eq!(
        enc(
            "M",
            &schema,
            r#"{"b":"0000000000000000000000000000000000000000007"}"#
        ),
        "1007"
    );
    // The leading zeros are not significant digits, so they cannot push a small
    // number out of range; a long run of significant digits is out of range.
    let e = value_error(
        "M",
        &schema,
        r#"{"b":"1000000000000000000000000000000000"}"#,
    );
    assert!(e.reason.contains("out of range"), "{}", e.reason);
}

#[test]
fn a_string_for_an_unsigned_type_takes_no_minus_sign_not_even_on_a_zero() {
    let schema = m(P3, "uint32 a = 1; fixed64 b = 2; int32 c = 3;");
    for values in [
        r#"{"a":"-0"}"#,
        r#"{"b":"-0"}"#,
        r#"{"a":-1}"#,
        r#"{"a":"-1"}"#,
    ] {
        let e = value_error("M", &schema, values);
        assert!(e.reason.contains("out of range"), "{values}: {}", e.reason);
    }
    // A JSON number -0 is the number zero, and a signed type takes "-0".
    assert_eq!(enc("M", &schema, r#"{"a":-0}"#), "");
    assert_eq!(enc("M", &schema, r#"{"c":"-0"}"#), "");
}

#[test]
fn floats_take_numbers_strings_and_the_three_special_words() {
    let f = m(P3, "float a = 1;");
    assert_eq!(enc("M", &f, r#"{"a":"1.5"}"#), "0d0000c03f");
    assert_eq!(enc("M", &f, r#"{"a":"NaN"}"#), "0d0000c07f");
    assert_eq!(enc("M", &f, r#"{"a":"Infinity"}"#), "0d0000807f");
    assert_eq!(enc("M", &f, r#"{"a":"-Infinity"}"#), "0d000080ff");
    assert_eq!(enc("M", &f, r#"{"a":3.4028235e38}"#), "0dffff7f7f");
    let d = m(P3, "double a = 1;");
    assert_eq!(enc("M", &d, r#"{"a":"NaN"}"#), "09000000000000f87f");
    assert_eq!(enc("M", &d, r#"{"a":0.5}"#), "09000000000000e03f");
}

#[test]
fn a_finite_value_that_does_not_fit_a_float_is_refused_not_made_infinite() {
    let f = m(P3, "float a = 1;");
    let e = value_error("M", &f, r#"{"a":1e39}"#);
    assert!(e.reason.contains("out of range for float"), "{}", e.reason);
    let e = value_error("M", &f, r#"{"a":"inf"}"#);
    assert!(e.reason.contains("not a decimal number"), "{}", e.reason);
    let d = m(P3, "double a = 1;");
    let e = value_error("M", &d, r#"{"a":1e999}"#);
    assert!(e.reason.contains("out of range for double"), "{}", e.reason);
}

#[test]
fn bytes_are_base64_in_either_alphabet_with_or_without_padding() {
    let schema = m(P3, "bytes a = 1;");
    assert_eq!(enc("M", &schema, r#"{"a":"AAEC"}"#), "0a03000102");
    assert_eq!(enc("M", &schema, r#"{"a":"AAE="}"#), "0a020001");
    assert_eq!(enc("M", &schema, r#"{"a":"AAE"}"#), "0a020001");
    // ff fe fd is "//79" in the standard alphabet and "__79" in the URL-safe one.
    assert_eq!(enc("M", &schema, r#"{"a":"//79"}"#), "0a03fffefd");
    assert_eq!(enc("M", &schema, r#"{"a":"__79"}"#), "0a03fffefd");
}

#[test]
fn bytes_that_are_not_canonical_base64_are_refused() {
    let schema = m(P3, "bytes a = 1;");
    for (text, why) in [
        ("A", "left over"),
        ("AAE==", "padding"),
        ("AA=", "padding"),
        ("AA E", "not a base64 character"),
        ("AQ\\n==", "not a base64 character"),
        ("AQI!", "not a base64 character"),
        ("+_", "mixed"),
        ("AAF=", "beyond the data"),
        ("=AAA", "not a base64 character"),
    ] {
        let e = value_error("M", &schema, &format!(r#"{{"a":"{text}"}}"#));
        assert_eq!(e.path, "/a", "{text}");
        assert!(e.reason.contains(why), "{text}: {}", e.reason);
    }
}

#[test]
fn a_string_is_written_as_utf8() {
    let schema = m(P3, "string a = 1;");
    assert_eq!(
        enc("M", &schema, r#"{"a":"hé 😀"}"#),
        "0a0868c3a920f09f9880"
    );
}

// ---- names -----------------------------------------------------------------

#[test]
fn a_field_answers_to_its_own_name_and_to_its_json_name() {
    let schema = m(P3, "int32 sensor_id = 1;");
    assert_eq!(enc("M", &schema, r#"{"sensor_id":5}"#), "0805");
    assert_eq!(enc("M", &schema, r#"{"sensorId":5}"#), "0805");
    let e = value_error("M", &schema, r#"{"sensor_id":5,"sensorId":6}"#);
    assert_eq!(e.path, "/sensorId");
    assert!(e.reason.contains("given twice"), "{}", e.reason);
}

#[test]
fn a_json_name_option_replaces_the_derived_name() {
    let schema = m(P3, r#"int32 sensor_id = 1 [json_name = "sid"];"#);
    assert_eq!(enc("M", &schema, r#"{"sid":5}"#), "0805");
    assert_eq!(enc("M", &schema, r#"{"sensor_id":5}"#), "0805");
    let e = value_error("M", &schema, r#"{"sensorId":5}"#);
    assert_eq!(e.path, "/sensorId");
}

#[test]
fn a_name_that_two_fields_answer_to_is_refused_as_ambiguous() {
    let schema = m(P3, "int32 foo_bar = 1;\nint32 fooBar = 2;");
    assert_eq!(enc("M", &schema, r#"{"foo_bar":1}"#), "0801");
    let e = value_error("M", &schema, r#"{"fooBar":1}"#);
    assert!(e.reason.contains("several fields"), "{}", e.reason);
}

#[test]
fn a_key_that_is_no_field_is_refused_with_the_fields_there_are() {
    let schema = m(P3, "int32 alpha = 1;\nint32 beta = 2;");
    let e = value_error("M", &schema, r#"{"alpha":1,"gamma":2}"#);
    assert_eq!(e.path, "/gamma");
    assert_eq!(e.field, None);
    assert!(e.reason.contains("no field `gamma`"), "{}", e.reason);
    assert!(e.expected.as_deref().unwrap_or("").contains("alpha, beta"));
    // Even with nothing to write, a key that is no field is refused.
    let e = value_error("M", &schema, r#"{"gamma":null}"#);
    assert_eq!(e.path, "/gamma");
}

#[test]
fn a_malformed_json_name_is_a_schema_error_at_the_option() {
    let schema = m(P3, "int32 a = 1 [json_name = 5];");
    match run("M", &schema, r#"{"a":1}"#) {
        Err(EncodeError::Schema(d)) => {
            assert_eq!(d.line, Some(3));
            assert!(d.reason.contains("json_name"), "{d}");
        }
        other => panic!("expected a schema error, got {other:?}"),
    }
}

// ---- shape errors and where they are blamed --------------------------------

#[test]
fn a_value_error_names_the_json_pointer_the_field_and_the_type() {
    let schema = format!(
        "{P3}message Inner {{ int32 v = 1; }}
         message M {{ repeated Inner xs = 1; }}"
    );
    let e = value_error("M", &schema, r#"{"xs":[{"v":1},{"v":"x"}]}"#);
    assert_eq!(e.path, "/xs/1/v");
    assert_eq!(e.field.as_deref(), Some("Inner.v"));
    assert!(e.expected.as_deref().unwrap_or("").starts_with("int32"));
    assert_eq!(
        EncodeError::Value(e).to_string(),
        "values /xs/1/v: `x` is not a decimal integer: a string of digits with an optional sign \
         is needed"
    );
}

#[test]
fn a_member_name_with_a_slash_is_escaped_in_the_pointer() {
    let schema = m(P3, "map<string, int32> m = 1;");
    let e = value_error("M", &schema, r#"{"m":{"a/b~c":"x"}}"#);
    assert_eq!(e.path, "/m/a~1b~0c");
}

#[test]
fn shapes_that_do_not_match_the_field_are_refused_at_their_place() {
    let schema = format!("{P3}message N {{ int32 x = 1; }} message M {{ N n = 1; repeated int32 r = 2; map<string,int32> m = 3; int32 s = 4; }}");
    for (values, path, word) in [
        (r#"{"n":5}"#, "/n", "expected an object for the message `N`"),
        (r#"{"r":5}"#, "/r", "expected an array"),
        (r#"{"r":[1,null]}"#, "/r/1", "null is not an element"),
        (r#"{"m":[1]}"#, "/m", "expected an object"),
        (r#"{"s":[1]}"#, "/s", "found an array"),
    ] {
        let e = value_error("M", &schema, values);
        assert_eq!(e.path, path, "{values}");
        assert!(e.reason.contains(word), "{values}: {}", e.reason);
    }
    // The whole text must be an object.
    let e = value_error("M", &schema, "[1]");
    assert_eq!(e.path, "");
    assert!(e.reason.contains("expected an object for the message `M`"));
}

#[test]
fn a_well_known_type_in_its_special_json_form_is_refused_with_the_reason() {
    let schema = "syntax = \"proto3\";\npackage google.protobuf;\n\
                  message Timestamp { int64 seconds = 1; int32 nanos = 2; }";
    let e = value_error(
        "google.protobuf.Timestamp",
        schema,
        r#""2020-01-01T00:00:00Z""#,
    );
    assert!(e.reason.contains("special JSON form"), "{}", e.reason);
    assert_eq!(
        enc("google.protobuf.Timestamp", schema, r#"{"seconds":"60"}"#),
        "083c"
    );
}

#[test]
fn groups_and_extensions_are_refused_where_the_values_name_them() {
    let schema = format!(
        "{P2}message M {{ optional group G = 1 {{ optional int32 x = 1; }} optional int32 y = 2; }}
         extend M {{ optional int32 ext = 100; }}"
    );
    // Held by the schema and left out of the values, a group is no obstacle.
    assert_eq!(enc("M", &schema, r#"{"y":3}"#), "1003");
    let e = value_error("M", &schema, r#"{"g":{}}"#);
    assert_eq!(e.path, "/g");
    assert!(e.reason.contains("group"), "{}", e.reason);
    let e = value_error("M", &schema, r#"{"[ext]":1}"#);
    assert_eq!(e.path, "/[ext]");
    assert!(e.reason.contains("extension"), "{}", e.reason);
}

#[test]
fn a_recursive_message_encodes_as_deep_as_the_values_go() {
    let schema = m(P3, "int32 v = 1;\nM next = 2;");
    assert_eq!(
        enc("M", &schema, r#"{"v":1,"next":{"v":2,"next":{}}}"#),
        "0801120408021200"
    );
}

// ---- the text of the values -------------------------------------------------

#[test]
fn text_that_is_not_json_is_blamed_at_its_byte() {
    let schema = m(P3, "int32 a = 1;");
    match run("M", &schema, r#"{"a":1,}x"#) {
        Err(EncodeError::Syntax { offset, .. }) => assert!(offset >= 7, "{offset}"),
        other => panic!("expected a syntax error, got {other:?}"),
    }
    match run("M", &schema, r#"{"a":"#) {
        Err(e @ EncodeError::Syntax { .. }) => {
            assert!(e.to_string().starts_with("values at byte "), "{e}");
        }
        other => panic!("expected a syntax error, got {other:?}"),
    }
}

#[test]
fn json5_comments_and_trailing_commas_are_read_but_numbers_stay_strict() {
    let schema = m(P3, "int32 a = 1;");
    assert_eq!(enc("M", &schema, "{ // five\n a: 5, /* more */ }"), "0805");
}

#[test]
fn nesting_past_the_bound_is_refused_before_it_can_exhaust_the_stack() {
    let schema = m(P3, "repeated int32 a = 1;");
    let depth = MAX_VALUES_DEPTH + 10;
    let deep = format!(r#"{{"a":{}{}}}"#, "[".repeat(depth), "]".repeat(depth));
    match run("M", &schema, &deep) {
        Err(EncodeError::Syntax { expected, .. }) => {
            assert_eq!(expected, "a shallower value");
        }
        other => panic!("expected a syntax error, got {other:?}"),
    }
}

#[test]
fn the_output_is_bounded() {
    let schema = m(P3, "bytes a = 1;");
    // 4 MiB + 3 bytes of zeros, as base64.
    let groups = (MAX_ENCODED_BYTES + 3) / 3;
    let values = format!(r#"{{"a":"{}"}}"#, "AAAA".repeat(groups));
    let e = value_error("M", &schema, &values);
    assert!(e.reason.contains("more than"), "{}", e.reason);
    // Exactly at the bound (less the tag and length) is fine.
    let ok = format!(r#"{{"a":"{}"}}"#, "AAAA".repeat(1000));
    assert_eq!(run("M", &schema, &ok).expect("encodes").len(), 3000 + 1 + 2);
}

// ---- the schema's own refusals come first ----------------------------------

#[test]
fn the_schema_is_judged_before_the_values_are_read() {
    // Both are wrong; the schema is blamed.
    match run("M", "message M { int32 a = 1 }", "{{{") {
        Err(EncodeError::Schema(d)) => {
            assert_eq!((d.file.as_deref(), d.line), (Some("a.proto"), Some(1)));
        }
        other => panic!("expected a schema error, got {other:?}"),
    }
    match run("Nope", &m(P3, "int32 a = 1;"), "{{{") {
        Err(EncodeError::Schema(d)) => assert!(d.reason.contains("`Nope` is not defined"), "{d}"),
        other => panic!("expected a schema error, got {other:?}"),
    }
}

#[test]
fn arguments_are_checked_like_the_declaration_door_checks_them() {
    let schema = m(P3, "int32 a = 1;");
    let one = [("a.proto", schema.as_str())];
    let f = files(&one);
    match encode_message("M", &f, 3, "{}") {
        Err(EncodeError::Schema(d)) => assert!(d.reason.contains("root file index 3"), "{d}"),
        other => panic!("{other:?}"),
    }
    let both = [("a.proto", schema.as_str()), ("a.proto", schema.as_str())];
    let twice = files(&both);
    match encode_message("M", &twice, 0, "{}") {
        Err(EncodeError::Schema(d)) => assert!(d.reason.contains("two files are named"), "{d}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_import_is_resolved_by_name_across_files() {
    let a = format!("{P3}import \"b.proto\";\nmessage M {{ B b = 1; }}");
    let b = format!("{P3}message B {{ int32 v = 2; }}");
    let spec = [("a.proto", a.as_str()), ("b.proto", b.as_str())];
    let f = files(&spec);
    assert_eq!(
        hex(&encode_message("M", &f, 0, r#"{"b":{"v":9}}"#).expect("encodes")),
        "0a021009"
    );
}

// ---- the round trip through the repository's own reader ---------------------

/// What the schemaless reader and the declared names make of `bytes`: the rows
/// as `(path, name, value)`.
fn read_back(schema: &str, root: &str, bytes: &[u8]) -> Vec<(String, String, String)> {
    let declared = declarations_from_proto("demo/t", root, &files(&[("a.proto", schema)]), 0)
        .expect("declares");
    let mut map = FormatMap::new();
    map.declare_all(&declared.text).expect("installs");
    Protobuf
        .decode(bytes)
        .expect("a protobuf message")
        .iter()
        .map(|f| {
            (
                f.path.clone(),
                map.field_name("demo/t", &f.path)
                    .map_or_else(|| String::from("?"), |(_, n)| n.to_string()),
                f.value.clone(),
            )
        })
        .collect()
}

#[test]
fn what_is_written_is_read_back_under_the_names_the_schema_declares() {
    let schema = format!(
        "{P3}message Meta {{ string tag = 2; sint32 delta = 3; }}
         message M {{
           int32 value = 1;
           Meta meta = 3;
           fixed32 stamp = 4;
           double ratio = 5;
           repeated int32 xs = 6;
         }}"
    );
    let bytes = run(
        "M",
        &schema,
        r#"{"value":150,"meta":{"tag":"hi","delta":-1},"stamp":7,"ratio":1.0,"xs":[1,2]}"#,
    )
    .expect("encodes");
    let rows = read_back(&schema, "M", &bytes);
    let want = [
        ("1", "value", "varint 150"),
        ("3", "meta", "len 2 field(s)"),
        ("3.2", "tag", "len \"hi\""),
        ("3.3", "delta", "varint 1"),
        ("4", "stamp", "i32 0x00000007"),
        ("5", "ratio", "i64 0x3ff0000000000000"),
        ("6", "xs", "len 2 byte(s)"),
    ];
    let got: Vec<(&str, &str, &str)> = rows
        .iter()
        .map(|(p, n, v)| (p.as_str(), n.as_str(), v.as_str()))
        .collect();
    assert_eq!(got, want);
}
