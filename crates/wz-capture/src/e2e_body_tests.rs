// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Tests of the wrap door's described body ([`crate::e2e_body`]): a schema and
//! field values in the values text, the protobuf writer building the bytes, and
//! the header put around them.
//!
//! The profiles are synthetic and the CRCs are graded against the public check
//! values of CRC-32/AUTOSAR (`0x1697D06A`) and CRC-64/XZ (`0x995DC9BBDF1939FA`),
//! which are the CRC of the nine bytes `123456789`. A protobuf message whose
//! wire bytes ARE those nine bytes makes the check value an oracle for the whole
//! path: field 6 as a `fixed64` starts with the tag byte `0x31`, which is `1`,
//! and the eight bytes after it are `23456789`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use wz_session_core::json::escape_into;

use crate::doc_revision::{key_set, E2E_WRAP_R2_KEYS};
use crate::e2e_body::{scan, Scan};
use crate::e2e_json::{open_document, wrap_document};
use crate::payload::formats::{FormatMap, PayloadFormat, Protobuf};
use crate::proto_encode::{encode_message, EncodeError};
use crate::proto_schema::{declarations_from_proto, ProtoFile};

// ---------------------------------------------------------------- profiles

/// A 32-bit CRC-32/AUTOSAR over the body alone: the oracle profile.
const ONLY_BODY_32: &str = r#"{
  "name": "synth-32",
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

/// A 64-bit CRC-64/XZ over the body alone, in a wider header.
const ONLY_BODY_64: &str = r#"{
  "name": "synth-64",
  "fields": [
    {"name": "crc", "bytes": 8},
    {"name": "length", "bytes": 4},
    {"name": "counter", "bytes": 4},
    {"name": "ident", "bytes": 4, "xor": "0x0F0F0F0F",
     "split": [{"name": "domain", "lsb": 24, "width": 8},
               {"name": "msg", "lsb": 0, "width": 16}]}
  ],
  "crc": {"field": "crc", "width": 64, "poly": "0x42F0E1EBA9EA3693",
          "init": "0xFFFFFFFFFFFFFFFF", "refin": true, "refout": true,
          "xorout": "0xFFFFFFFFFFFFFFFF", "cover": ["@payload"]},
  "length": {"field": "length", "counts": "frame"},
  "counter": {"field": "counter", "max_gap": 3, "timeout_ms": 100}
}"#;

/// A CRC that covers header fields on both sides of the body, so a CRC taken
/// before the body is known, or over the body in another place, comes out
/// different.
const AROUND_BODY: &str = r#"{
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

/// The header values every `AROUND_BODY` frame here is built with.
const AROUND_HEADER: &str = r#""counter":9,"ident":{"domain":3,"msg":4660}"#;

// ----------------------------------------------------------------- schemas

const POSE: &str = "syntax = \"proto3\";
package demo;
message Inner { double ratio = 1; bool ok = 2; }
message Pose {
  sint32 x = 1;
  string label = 2;
  repeated int32 hist = 3;
  Inner inner = 4;
  fixed32 stamp = 5;
}";

const POSE_VALUES: &str =
    r#"{"x":-3,"label":"hi","hist":[1,2,300],"inner":{"ratio":0.5,"ok":true},"stamp":7}"#;

/// `fixed64 f = 6`: with the value below, the wire bytes are `123456789`.
const CHECK: &str = "syntax = \"proto3\"; message Check { fixed64 f = 6; }";

// ----------------------------------------------------------------- helpers

fn quoted(text: &str) -> String {
    let mut out = String::new();
    escape_into(text, &mut out);
    out
}

/// The `"@body":{...}` member for one file.
fn body(file: &str, message: &str, values: &str) -> String {
    body_of(&[("m.proto", file)], None, message, values)
}

fn body_of(files: &[(&str, &str)], root: Option<usize>, message: &str, values: &str) -> String {
    let listed: Vec<String> = files
        .iter()
        .map(|(name, text)| format!("{{\"name\":{},\"text\":{}}}", quoted(name), quoted(text)))
        .collect();
    let root = root.map_or_else(String::new, |r| format!("\"root_file\":{r},"));
    format!(
        "\"@body\":{{\"files\":[{}],{root}\"message\":{},\"values\":{values}}}",
        listed.join(","),
        quoted(message)
    )
}

fn values_text(header: &str, body: &str) -> String {
    format!("{{{header},{body}}}")
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// The text between `"key":"` and the next quote.
fn string_after<'d>(doc: &'d str, key: &str) -> &'d str {
    let rest = doc
        .split_once(&format!("\"{key}\":\""))
        .unwrap_or_else(|| panic!("{key} in {doc}"))
        .1;
    rest.split_once('"').expect("a closing quote").0
}

fn number_after(doc: &str, key: &str) -> usize {
    let rest = doc
        .split_once(&format!("\"{key}\":"))
        .unwrap_or_else(|| panic!("{key} in {doc}"))
        .1;
    rest.chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .expect("a number")
}

fn frame_of(doc: &str) -> Vec<u8> {
    unhex(string_after(doc, "frame"))
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

/// The refusal facts every refusal here shares: it is one, it built no frame,
/// and it wrote no null.
fn assert_refused(doc: &str) {
    assert!(doc.contains("\"ok\":false"), "{doc}");
    assert!(!doc.contains("\"frame\""), "{doc}");
    assert!(!doc.contains("null"), "{doc}");
}

fn check_body() -> String {
    // The eight bytes "23456789" as the little-endian value of a fixed64.
    let value = u64::from_le_bytes(*b"23456789");
    body(CHECK, "Check", &format!("{{\"f\":\"{value}\"}}"))
}

// ------------------------------------------------- the public CRC check values

#[test]
fn a_frame_around_a_described_body_carries_the_public_crc32_check_value() {
    // The body the writer builds is `123456789`, so the CRC over it is the
    // catalogue's check value for CRC-32/AUTOSAR, which no code here computed.
    let text = values_text(r#""counter":1"#, &check_body());
    let doc = wrap_document(ONLY_BODY_32, &text, &[]);
    assert!(doc.contains("\"ok\":true"), "{doc}");
    assert!(
        doc.contains(&format!("\"crc_computed\":{}", 0x1697_D06A_u64)),
        "{doc}"
    );
    assert!(doc.contains("\"payload_bytes\":9"), "{doc}");
    assert!(doc.contains("\"body_message\":\"Check\""), "{doc}");
    let frame = frame_of(&doc);
    assert_eq!(&frame[frame.len() - 9..], b"123456789");
    assert_eq!(&frame[..4], &0x1697_D06A_u32.to_be_bytes());
}

#[test]
fn a_frame_around_a_described_body_carries_the_public_crc64_check_value() {
    let text = values_text(
        r#""counter":1,"ident":{"domain":3,"msg":4660}"#,
        &check_body(),
    );
    let doc = wrap_document(ONLY_BODY_64, &text, &[]);
    assert!(doc.contains("\"ok\":true"), "{doc}");
    // Past 2^53, so a decimal string by the integer rule of these documents.
    assert!(
        doc.contains(&format!(
            "\"crc_computed\":\"{}\"",
            0x995D_C9BB_DF19_39FA_u64
        )),
        "{doc}"
    );
    let frame = frame_of(&doc);
    assert_eq!(&frame[..8], &0x995D_C9BB_DF19_39FA_u64.to_be_bytes());
    assert_eq!(&frame[frame.len() - 9..], b"123456789");
}

// ---------------------------------------------------------------- round trip

/// What the schemaless reader and the declared names make of `bytes`.
fn read_back(schema: &str, root: &str, bytes: &[u8]) -> Vec<(String, String, String)> {
    let declared = declarations_from_proto("demo/t", root, &proto_files(&[("m.proto", schema)]), 0)
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
fn a_wrapped_body_opens_with_sound_verdicts_and_reads_back_as_the_values() {
    let text = values_text(AROUND_HEADER, &body(POSE, "demo.Pose", POSE_VALUES));
    let wrapped = wrap_document(AROUND_BODY, &text, &[]);
    assert!(wrapped.contains("\"ok\":true"), "{wrapped}");
    assert!(
        wrapped.contains("\"body_message\":\"demo.Pose\""),
        "{wrapped}"
    );
    let frame = frame_of(&wrapped);

    let opened = open_document(AROUND_BODY, &frame);
    assert!(opened.contains("\"crc_ok\":true"), "{opened}");
    assert!(opened.contains("\"length_matches_frame\":true"), "{opened}");
    let offset = number_after(&opened, "payload_offset");
    assert_eq!(offset, number_after(&wrapped, "payload_offset"));
    let body_bytes = &frame[offset..];
    assert_eq!(body_bytes.len(), number_after(&opened, "payload_bytes"));

    // The same bytes the writer gives on its own door, and they read back under
    // the names the schema declares, with the values that were written.
    let alone = encode_message(
        "demo.Pose",
        &proto_files(&[("m.proto", POSE)]),
        0,
        POSE_VALUES,
    )
    .expect("encodes");
    assert_eq!(body_bytes, alone.as_slice());
    let rows = read_back(POSE, "demo.Pose", body_bytes);
    let want = [
        ("1", "x", "varint 5"), // sint32 -3, zigzagged
        ("2", "label", "len \"hi\""),
        ("3", "hist", "len 4 byte(s)"), // 1, 2, 300 packed
        ("4", "inner", "len 2 field(s)"),
        ("4.1", "ratio", "i64 0x3fe0000000000000"), // 0.5
        ("4.2", "ok", "varint 1"),
        ("5", "stamp", "i32 0x00000007"),
    ];
    let got: Vec<(&str, &str, &str)> = rows
        .iter()
        .map(|(p, n, v)| (p.as_str(), n.as_str(), v.as_str()))
        .collect();
    assert_eq!(got, want);
}

#[test]
fn the_message_a_body_is_built_from_is_the_name_a_profile_rule_carries() {
    // `demo/pose=prof@demo.Pose` carries `demo.Pose` as `body_schema`; the wrap
    // door takes the same string as `message`, and the rule's own check accepts
    // it, so a caller passes one name to both.
    assert!(crate::e2e_rule::check_schema("demo.Pose").is_ok());
}

// ------------------------------------------- equality with the two-step path

#[test]
fn a_described_body_is_the_frame_the_two_step_path_builds() {
    let nested = "syntax = \"proto3\"; message Test1 { int32 a = 1; } message M { Test1 c = 3; }";
    let packed = "syntax = \"proto2\"; message M { repeated int32 d = 4 [packed=true]; }";
    let cases: [(&str, &str, &str); 7] = [
        (
            "syntax = \"proto3\"; message M { int32 a = 1; }",
            "M",
            r#"{"a":150}"#,
        ),
        (
            "syntax = \"proto3\"; message M { string b = 2; }",
            "M",
            r#"{"b":"testing"}"#,
        ),
        (nested, "M", r#"{"c":{"a":150}}"#),
        (packed, "M", r#"{"d":[3,270,86942]}"#),
        (
            "syntax = \"proto3\"; message M { int32 a = 1; }",
            "M",
            r#"{"a":-1}"#,
        ),
        // An empty message is an empty body, which is a frame of the header alone.
        ("syntax = \"proto3\"; message M { int32 a = 1; }", "M", "{}"),
        (POSE, "demo.Pose", POSE_VALUES),
    ];
    for (schema, message, values) in cases {
        let bytes = encode_message(message, &proto_files(&[("m.proto", schema)]), 0, values)
            .expect("encodes");
        let two_step = wrap_document(AROUND_BODY, &values_text(AROUND_HEADER, ""), &bytes);
        // `values_text` with an empty tail leaves a trailing comma, which the
        // reader admits; the header values are the same either way.
        assert!(two_step.contains("\"ok\":true"), "{two_step}");
        let described = wrap_document(
            AROUND_BODY,
            &values_text(AROUND_HEADER, &body(schema, message, values)),
            &[],
        );
        let mark = format!(",\"body_message\":{}", quoted(message));
        assert!(described.contains(&mark), "{described}");
        assert_eq!(described.replace(&mark, ""), two_step, "{message} {values}");
    }
}

#[test]
fn a_second_file_and_a_root_file_index_are_read_as_the_writer_reads_them() {
    let a = "syntax = \"proto3\"; import \"b.proto\"; message M { B b = 1; }";
    let b = "syntax = \"proto3\"; message B { int32 v = 2; }";
    let files = [("a.proto", a), ("b.proto", b)];
    let text = values_text(
        AROUND_HEADER,
        &body_of(&files, Some(0), "M", r#"{"b":{"v":9}}"#),
    );
    let doc = wrap_document(AROUND_BODY, &text, &[]);
    let frame = frame_of(&doc);
    assert_eq!(&frame[frame.len() - 4..], [0x0a, 0x02, 0x10, 0x09]);
    // The index is optional and defaults to the first file.
    let default = wrap_document(
        AROUND_BODY,
        &values_text(
            AROUND_HEADER,
            &body_of(&files, None, "M", r#"{"b":{"v":9}}"#),
        ),
        &[],
    );
    assert_eq!(default, doc);
    // A message that file does not define is the writer's refusal, not ours.
    let other = wrap_document(
        AROUND_BODY,
        &values_text(AROUND_HEADER, &body_of(&files, Some(1), "M", "{}")),
        &[],
    );
    assert_refused(&other);
    assert!(
        other.contains("\"stage\":\"body\",\"file\":\"b.proto\""),
        "{other}"
    );
}

// ----------------------------------------------------- the writer's refusals

#[test]
fn the_writers_value_refusal_is_reported_with_its_diagnostic_and_no_frame() {
    let values = r#"{"x":-3,"hist":[1,"two"]}"#;
    let want = match encode_message("demo.Pose", &proto_files(&[("m.proto", POSE)]), 0, values) {
        Err(EncodeError::Value(v)) => v,
        other => panic!("{other:?}"),
    };
    let text = values_text(AROUND_HEADER, &body(POSE, "demo.Pose", values));
    let doc = wrap_document(AROUND_BODY, &text, &[]);
    assert_refused(&doc);
    // The pointer is a place in the text the caller passed.
    assert_eq!(want.path, "/hist/1");
    assert!(
        doc.contains("\"ok\":false,\"stage\":\"body\",\"values_path\":\"/@body/values/hist/1\""),
        "{doc}"
    );
    assert!(
        doc.contains(&format!(
            "\"field\":{}",
            quoted(&want.field.clone().expect("a field"))
        )),
        "{doc}"
    );
    assert!(
        doc.contains(&format!(
            "\"expected\":{}",
            quoted(&want.expected.clone().expect("a type"))
        )),
        "{doc}"
    );
    assert!(
        doc.contains(&format!("\"reason\":{}", quoted(&want.reason))),
        "{doc}"
    );
    assert!(
        doc.contains(&format!(
            "\"message\":{}",
            quoted(&format!("values /@body/values/hist/1: {}", want.reason))
        )),
        "{doc}"
    );
    for absent in ["\"file\"", "\"line\"", "profile_"] {
        assert!(!doc.contains(absent), "{absent} in {doc}");
    }
}

#[test]
fn the_writers_schema_refusal_names_the_file_line_and_column_it_found() {
    let broken = "syntax = \"proto3\";\nmessage M { int32 a = 1 }";
    let want = match encode_message("M", &proto_files(&[("m.proto", broken)]), 0, "{}") {
        Err(EncodeError::Schema(d)) => d,
        other => panic!("{other:?}"),
    };
    let text = values_text(AROUND_HEADER, &body(broken, "M", "{}"));
    let doc = wrap_document(AROUND_BODY, &text, &[]);
    assert_refused(&doc);
    assert!(
        doc.contains(&format!(
            "\"ok\":false,\"stage\":\"body\",\"file\":\"m.proto\",\"line\":{},\"column\":{},",
            want.line.expect("a line"),
            want.column.expect("a column")
        )),
        "{doc}"
    );
    assert!(!doc.contains("values_"), "{doc}");
    assert!(
        doc.contains(&format!("\"message\":{}", quoted(&want.to_string()))),
        "{doc}"
    );
}

#[test]
fn a_message_the_schema_does_not_define_and_a_root_index_out_of_range_are_refused() {
    let text = values_text(AROUND_HEADER, &body(POSE, "demo.Nope", "{}"));
    let doc = wrap_document(AROUND_BODY, &text, &[]);
    assert_refused(&doc);
    assert!(
        doc.contains("\"stage\":\"body\",\"file\":\"m.proto\","),
        "{doc}"
    );
    assert!(!doc.contains("\"line\""), "{doc}");

    let text = values_text(
        AROUND_HEADER,
        &body_of(&[("m.proto", POSE)], Some(4), "demo.Pose", "{}"),
    );
    let doc = wrap_document(AROUND_BODY, &text, &[]);
    assert_refused(&doc);
    assert!(
        doc.contains("\"ok\":false,\"stage\":\"body\",\"reason\":\"the root file index 4"),
        "{doc}"
    );
    for absent in ["\"file\"", "\"line\"", "values_"] {
        assert!(!doc.contains(absent), "{absent} in {doc}");
    }
}

#[test]
fn values_that_are_not_an_object_are_the_writers_refusal_at_the_values_pointer() {
    let text = values_text(AROUND_HEADER, &body(POSE, "demo.Pose", "[1]"));
    let doc = wrap_document(AROUND_BODY, &text, &[]);
    assert_refused(&doc);
    assert!(
        doc.contains("\"stage\":\"body\",\"values_path\":\"/@body/values\""),
        "{doc}"
    );
}

// ----------------------------------------------- the description's own shape

#[test]
fn a_description_that_is_not_what_it_should_be_is_refused_at_its_place() {
    let file = r#"{"name":"m.proto","text":"x"}"#;
    let cases: [(String, &str, &str); 11] = [
        (
            r#""@body":{"files":[],"message":"M","values":{}}"#.to_string(),
            "/@body/files",
            "at least one schema file",
        ),
        (
            format!(r#""@body":{{"files":[{file}],"values":{{}}}}"#),
            "/@body",
            "the key `message` is required",
        ),
        (
            format!(r#""@body":{{"files":[{file}],"message":"M"}}"#),
            "/@body",
            "the key `values` is required",
        ),
        (
            r#""@body":{"message":"M","values":{}}"#.to_string(),
            "/@body",
            "the key `files` is required",
        ),
        (
            format!(r#""@body":{{"files":[{file}],"message":"M","values":{{}},"extra":1}}"#),
            "/@body/extra",
            "unknown key `extra`",
        ),
        (
            r#""@body":{"files":[{"text":"x"}],"message":"M","values":{}}"#.to_string(),
            "/@body/files/0",
            "the key `name` is required",
        ),
        (
            r#""@body":{"files":[{"name":"","text":"x"}],"message":"M","values":{}}"#.to_string(),
            "/@body/files/0/name",
            "a file needs a name",
        ),
        (
            r#""@body":{"files":[{"name":"a","text":5}],"message":"M","values":{}}"#.to_string(),
            "/@body/files/0/text",
            "expected a string, found a number",
        ),
        (
            format!(r#""@body":{{"files":[{file}],"root_file":"x","message":"M","values":{{}}}}"#),
            "/@body/root_file",
            "not an unsigned integer",
        ),
        (
            format!(r#""@body":{{"files":[{file}],"message":7,"values":{{}}}}"#),
            "/@body/message",
            "expected a string, found a number",
        ),
        (
            r#""@body":[1]"#.to_string(),
            "/@body",
            "expected an object, found an array",
        ),
    ];
    for (member, path, reason) in cases {
        let doc = wrap_document(AROUND_BODY, &values_text(AROUND_HEADER, &member), &[]);
        assert_refused(&doc);
        assert!(
            doc.contains(&format!(
                "\"ok\":false,\"stage\":\"body\",\"values_path\":\"{path}\","
            )),
            "{path}: {doc}"
        );
        assert!(doc.contains(reason), "{reason}: {doc}");
        assert!(
            doc.contains(&format!("\"message\":\"values {path}: ")),
            "{doc}"
        );
    }
}

#[test]
fn a_body_given_as_bytes_and_as_a_member_is_refused_not_resolved() {
    let text = values_text(AROUND_HEADER, &body(POSE, "demo.Pose", POSE_VALUES));
    let doc = wrap_document(AROUND_BODY, &text, b"\x01");
    assert_refused(&doc);
    assert!(
        doc.contains("\"ok\":false,\"stage\":\"body\",\"values_path\":\"/@body\",\"reason\":\"the body is given twice"),
        "{doc}"
    );
}

#[test]
fn a_member_written_twice_is_refused_like_any_repeated_key() {
    let one = body(POSE, "demo.Pose", POSE_VALUES);
    let text = values_text(AROUND_HEADER, &format!("{one},{one}"));
    let doc = wrap_document(AROUND_BODY, &text, &[]);
    assert_refused(&doc);
    assert!(
        doc.contains(
            "\"ok\":false,\"values_path\":\"/@body\",\"reason\":\"the key `@body` appears twice\""
        ),
        "{doc}"
    );
    assert!(!doc.contains("stage"), "{doc}");
}

#[test]
fn a_body_that_is_not_json_is_blamed_at_its_byte() {
    let text = format!("{{{AROUND_HEADER},\"@body\":{{\"files\":[}}}}");
    let doc = wrap_document(AROUND_BODY, &text, &[]);
    assert_refused(&doc);
    assert!(
        doc.contains("\"ok\":false,\"stage\":\"body\",\"values_offset\":"),
        "{doc}"
    );
    assert!(
        doc.contains("\"reason\":\"the text is not JSON: expected "),
        "{doc}"
    );
}

// ---------------------------------------- the header, beside a described body

#[test]
fn a_header_value_that_names_no_field_is_refused_without_a_body_stage() {
    let text = values_text(
        r#""counter":9,"nofield":1"#,
        &body(POSE, "demo.Pose", POSE_VALUES),
    );
    let doc = wrap_document(AROUND_BODY, &text, &[]);
    assert_refused(&doc);
    assert!(
        doc.contains(
            "\"ok\":false,\"values_path\":\"/nofield\",\"reason\":\"no field is called `nofield`\""
        ),
        "{doc}"
    );
    assert!(!doc.contains("stage"), "{doc}");
}

#[test]
fn a_bad_body_is_reported_before_a_bad_header_value() {
    // The order is documented: the header cannot be finished until the body's
    // bytes are known, so the body's problem is the first one found.
    let text = values_text(
        r#""counter":9,"nofield":1"#,
        &body(POSE, "demo.Pose", r#"{"x":"no"}"#),
    );
    let doc = wrap_document(AROUND_BODY, &text, &[]);
    assert!(doc.contains("\"stage\":\"body\""), "{doc}");
    assert!(!doc.contains("nofield"), "{doc}");
}

#[test]
fn a_header_shape_error_is_found_before_the_body_is_read() {
    let text = values_text(r#""counter":"x""#, &body(POSE, "demo.Pose", POSE_VALUES));
    let doc = wrap_document(AROUND_BODY, &text, &[]);
    assert_refused(&doc);
    assert!(doc.contains("\"values_path\":\"/counter\""), "{doc}");
    assert!(!doc.contains("stage"), "{doc}");
}

#[test]
fn a_body_too_long_for_the_length_field_is_the_frames_refusal() {
    let text = values_text(
        AROUND_HEADER,
        &body(
            "syntax = \"proto3\"; message M { bytes b = 1; }",
            "M",
            // 65600 zero bytes in base64 is 87467 characters, past the 2-byte length.
            &format!("{{\"b\":\"{}\"}}", "AAAA".repeat(21_900)),
        ),
    );
    let doc = wrap_document(AROUND_BODY, &text, &[]);
    assert_refused(&doc);
    assert!(
        doc.contains("\"ok\":false,\"reason\":\"a body of 65704 bytes makes the length"),
        "{doc}"
    );
    assert!(!doc.contains("stage"), "{doc}");
}

// ------------------------------------------------------------------ nesting

/// `depth` nested objects of `message N { N n = 1; }`, the innermost empty.
fn nested(depth: usize) -> String {
    format!(
        "{}{}",
        "{\"n\":".repeat(depth - 1),
        "{}".to_string() + &"}".repeat(depth - 1)
    )
}

const RECURSIVE: &str = "syntax = \"proto3\"; message N { N n = 1; int32 v = 2; }";

#[test]
fn a_body_may_nest_as_deep_as_the_writer_was_written_for_and_no_deeper() {
    let at_bound = values_text(
        AROUND_HEADER,
        &body(
            RECURSIVE,
            "N",
            &nested(crate::proto_encode::MAX_VALUES_DEPTH),
        ),
    );
    let doc = wrap_document(AROUND_BODY, &at_bound, &[]);
    assert!(doc.contains("\"ok\":true"), "{doc}");

    let over = nested(crate::proto_encode::MAX_VALUES_DEPTH + 1);
    let member = body(RECURSIVE, "N", &over);
    let text = values_text(AROUND_HEADER, &member);
    let doc = wrap_document(AROUND_BODY, &text, &[]);
    assert_refused(&doc);
    // The byte that opens the first level past the bound, in the caller's text.
    let start = text.find(&over).expect("the values are in the text");
    let offset = start
        + over
            .match_indices('{')
            .nth(crate::proto_encode::MAX_VALUES_DEPTH)
            .expect("a level past the bound")
            .0;
    assert!(
        doc.contains(&format!(
            "\"ok\":false,\"stage\":\"body\",\"values_offset\":{offset},\"reason\":\"the text is not JSON: expected a shallower value\""
        )),
        "{offset}: {doc}"
    );
}

#[test]
fn a_text_without_a_body_keeps_the_original_depth_bound_and_refusal() {
    // Far deeper than any stack could take if the reader were let in, with no
    // `@body` member: refused at the byte the original bound gives.
    for open in ["{\"a\":", "["] {
        let text = open.repeat(200_000);
        let doc = wrap_document(AROUND_BODY, &text, &[]);
        let want = crate::e2e_profile::MAX_JSON_DEPTH * open.len();
        assert!(
            doc.contains(&format!("\"ok\":false,\"values_offset\":{want},")),
            "{doc}"
        );
        assert!(!doc.contains("stage"), "{doc}");
    }
    // A header member too deep beside a good `@body` member is the same refusal
    // as without the body: the body's wider bound is the body's alone.
    let deep = format!("{}1{}", "[".repeat(9), "]".repeat(9));
    let text = values_text(
        &format!("\"counter\":{deep}"),
        &body(POSE, "demo.Pose", POSE_VALUES),
    );
    let doc = wrap_document(AROUND_BODY, &text, &[]);
    assert_refused(&doc);
    assert!(!doc.contains("stage"), "{doc}");
    assert!(doc.contains("\"values_offset\":"), "{doc}");
}

// ------------------------------------------------------------- the key scan

#[test]
fn the_scan_finds_a_top_level_body_member_however_its_name_is_spelled() {
    let member = body(CHECK, "Check", "{}");
    for text in [
        format!("{{{member}}}"),
        format!("{{ \"counter\": 1, {member} }}"),
        format!("// a note\n{{{member}}}"),
        format!("{{{}}}", member.replace("\"@body\"", "'@body'")),
        format!("{{{}}}", member.replace("\"@body\"", "\"\\u0040body\"")),
    ] {
        assert!(matches!(scan(&text), Scan::Body(_)), "{text}");
    }
    for text in [
        "{}".to_string(),
        "[1]".to_string(),
        "".to_string(),
        r#"{"counter":1}"#.to_string(),
        // Not top level.
        r#"{"x":{"@body":1}}"#.to_string(),
        // A member name that only starts like it.
        r#"{"@bodyx":1}"#.to_string(),
        // Not a document: the original reader says why.
        format!("{{{member}"),
        format!("{{{member}}} trailing"),
        format!("{{{member} \"counter\" 1}}"),
    ] {
        assert!(matches!(scan(&text), Scan::Plain), "{text}");
    }
}

// ------------------------------------------------------------ the registry

#[test]
fn the_documents_use_exactly_the_keys_revision_two_pins() {
    let good = body(POSE, "demo.Pose", POSE_VALUES);
    let broken = body("syntax = \"proto3\";\nmessage M { int32 a = 1 }", "M", "{}");
    let docs = [
        // Built from bytes and from a body.
        wrap_document(AROUND_BODY, &values_text(AROUND_HEADER, ""), b"\x01\x02"),
        wrap_document(AROUND_BODY, &values_text(AROUND_HEADER, &good), &[]),
        // The profile or the header values refused.
        wrap_document("{", "{}", &[]),
        wrap_document("{}", "{}", &[]),
        wrap_document(AROUND_BODY, "{", &[]),
        wrap_document(AROUND_BODY, "{\"a\": 1}", &[]),
        // The frame refused.
        wrap_document(AROUND_BODY, &values_text(AROUND_HEADER, ""), &[0u8; 65536]),
        // The description refused, by place and by byte; given twice.
        wrap_document(
            AROUND_BODY,
            &values_text(AROUND_HEADER, "\"@body\":[]"),
            &[],
        ),
        wrap_document(
            AROUND_BODY,
            &format!("{{{AROUND_HEADER},\"@body\":{{\"files\":[}}}}"),
            &[],
        ),
        wrap_document(AROUND_BODY, &values_text(AROUND_HEADER, &good), b"\x01"),
        // The writer's refusals: a value (with a field), a message that is no
        // field's (without), the schema at a place, a file as a whole, an
        // argument.
        wrap_document(
            AROUND_BODY,
            &values_text(AROUND_HEADER, &body(POSE, "demo.Pose", r#"{"x":"no"}"#)),
            &[],
        ),
        wrap_document(
            AROUND_BODY,
            &values_text(AROUND_HEADER, &body(POSE, "demo.Pose", r#"{"zz":1}"#)),
            &[],
        ),
        wrap_document(AROUND_BODY, &values_text(AROUND_HEADER, &broken), &[]),
        wrap_document(
            AROUND_BODY,
            &values_text(AROUND_HEADER, &body(POSE, "demo.Nope", "{}")),
            &[],
        ),
        wrap_document(
            AROUND_BODY,
            &values_text(
                AROUND_HEADER,
                &body_of(&[("m.proto", POSE)], Some(4), "demo.Pose", "{}"),
            ),
            &[],
        ),
    ];
    let mut keys: Vec<&str> = Vec::new();
    for doc in &docs {
        assert!(!doc.contains("null"), "{doc}");
        assert!(
            doc.starts_with(r#"{"document":{"name":"e2e_wrap","revision":2}"#),
            "{doc}"
        );
        keys.extend(key_set(doc));
    }
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys, E2E_WRAP_R2_KEYS);
}
