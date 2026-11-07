// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A payload read by its schema from a declaration text: the schema file line,
//! the `protobuf@` rule, what a field becomes, what the row says, and what is
//! refused.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::payload::formats::{
    declaration_text, parse_declaration, DeclarationKind, DeclarationText, FormatMap,
    FormatMapError, PayloadField, PayloadFormatError, TypedValue,
};
use crate::proto_schema::ProtoFile;

const SCHEMA: &str = r#"syntax = "proto3";
package pkg;
enum Gear { GEAR_UNSPECIFIED = 0; GEAR_PARK = 1; GEAR_DRIVE = 2; }
message Inner { double ratio = 1; }
message Pose {
  sint32 x = 1;
  double heading = 2;
  Gear gear = 3;
  Inner inner = 4;
  repeated int32 samples = 5;
  string label = 6;
  map<string, int32> counts = 7;
}
"#;

const VALUES: &str = r#"{"x": -3, "heading": 0.5, "gear": "GEAR_DRIVE",
  "inner": {"ratio": 1.25}, "samples": [1, 2, 300], "label": "hi",
  "counts": {"a": 7}}"#;

/// `#@<name>=<text as one JSON string>`.
fn file_line(name: &str, text: &str) -> String {
    let mut line = alloc::format!("#@{name}=");
    wz_session_core::json::escape_into(text, &mut line);
    line
}

fn map_of(text: &str) -> FormatMap<'static> {
    let mut map = FormatMap::new();
    map.declare_all(text).expect("the declarations install");
    map
}

fn refusal(text: &str) -> FormatMapError {
    FormatMap::new()
        .declare_all(text)
        .expect_err("refused")
        .error
}

fn pose_bytes() -> Vec<u8> {
    crate::proto_encode::encode_message(
        "pkg.Pose",
        &[ProtoFile {
            name: "pose.proto",
            text: SCHEMA.as_bytes(),
        }],
        0,
        VALUES,
    )
    .expect("the writer builds the message")
}

fn typed_text() -> String {
    alloc::format!(
        "{}\ndemo/pose=protobuf@pkg.Pose\n",
        file_line("pose.proto", SCHEMA)
    )
}

/// Path, name, `value`, type, typed value and enum number, per field.
fn summary(fields: &[PayloadField]) -> Vec<(String, Option<String>, String, TypedValue)> {
    fields
        .iter()
        .map(|f| {
            (
                f.path.clone(),
                f.name.clone(),
                f.value.clone(),
                f.typed
                    .clone()
                    .expect("every field of a typed read is typed"),
            )
        })
        .collect()
}

fn tv(ty: &str, json: Option<&str>, enum_number: Option<i32>) -> TypedValue {
    TypedValue {
        ty: Some(ty.to_string()),
        json: json.map(str::to_string),
        enum_number,
    }
}

#[test]
fn a_schema_file_line_reads_as_its_own_kind_and_reads_back_as_written() {
    let line = file_line("dir/pose.proto", SCHEMA);
    let read = parse_declaration(&line).expect("a declaration");
    assert!(matches!(
        read,
        DeclarationText::SchemaFile {
            name: "dir/pose.proto",
            ..
        }
    ));
    assert_eq!(read.kind(), DeclarationKind::SchemaFile);
    assert_eq!(read.kind().word(), "schema_file");
    assert_eq!(declaration_text(&read), line);
    // And the map hands it back as it was written, under its own kind.
    let map = map_of(&typed_text());
    let files: Vec<_> = map
        .declarations()
        .into_iter()
        .filter(|d| d.kind == DeclarationKind::SchemaFile)
        .collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].text, file_line("pose.proto", SCHEMA));
}

/// A format definition whose name opens with `@` is still a definition: only a
/// value that opens a JSON string makes the line a schema file.
#[test]
fn a_definition_named_with_an_at_sign_is_still_a_definition() {
    let read = parse_declaration("#@rec=a:u8").expect("a declaration");
    assert_eq!(read.kind(), DeclarationKind::FormatDefinition);
}

#[test]
fn a_protobuf_rule_with_a_schema_reads_every_field_by_its_type() {
    let map = map_of(&typed_text());
    let format = map.matching_rule("demo/pose").expect("a rule").format;
    assert_eq!(format.name(), "protobuf");
    let schema = format.body_schema().expect("the rule names a schema");
    assert_eq!((schema.message, schema.read), ("pkg.Pose", true));
    assert!(format.reads_types());
    let fields = format.decode(&pose_bytes()).expect("a Pose");
    let s = |path: &str, name: &str, value: &str, typed: TypedValue| {
        (
            path.to_string(),
            Some(name.to_string()),
            value.to_string(),
            typed,
        )
    };
    assert_eq!(
        summary(&fields),
        [
            s("1", "x", "-3", tv("sint32", Some("-3"), None)),
            s("2", "heading", "0.5", tv("double", Some("0.5"), None)),
            s(
                "3",
                "gear",
                "GEAR_DRIVE (2)",
                tv("pkg.Gear", Some("\"GEAR_DRIVE\""), Some(2))
            ),
            s("4", "inner", "1 field(s)", tv("pkg.Inner", None, None)),
            s("4.1", "ratio", "1.25", tv("double", Some("1.25"), None)),
            s("5", "samples", "1", tv("int32", Some("1"), None)),
            s("5", "samples", "2", tv("int32", Some("2"), None)),
            s("5", "samples", "300", tv("int32", Some("300"), None)),
            s("6", "label", "\"hi\"", tv("string", Some("\"hi\""), None)),
            s(
                "7",
                "counts",
                "2 field(s)",
                tv("map<string, int32>", None, None)
            ),
            s("7.1", "key", "\"a\"", tv("string", Some("\"a\""), None)),
            s("7.2", "value", "7", tv("int32", Some("7"), None)),
        ]
    );
    // The first field is its tag and a zigzagged -3: two bytes from 0.
    assert_eq!((fields[0].start, fields[0].end), (0, 2));
}

/// The wire walk the same bytes get without a schema: the values this module
/// exists to replace, held here so the difference is the measured one.
#[test]
fn the_same_bytes_walked_by_the_wire_alone_carry_no_type() {
    let map = map_of("demo/pose=protobuf");
    let format = map.matching_rule("demo/pose").expect("a rule").format;
    assert!(!format.reads_types());
    assert_eq!(format.body_schema(), None);
    let fields = format.decode(&pose_bytes()).expect("walks");
    assert_eq!(fields[0].value, "varint 5");
    assert!(fields.iter().all(|f| f.typed.is_none()));
}

#[test]
fn an_empty_payload_is_a_message_with_every_field_absent() {
    let map = map_of(&typed_text());
    let format = map.matching_rule("demo/pose").expect("a rule").format;
    assert_eq!(format.decode(&[]), Ok(Vec::new()));
}

#[test]
fn bytes_that_are_not_the_message_are_refused_with_the_field_and_the_byte() {
    let map = map_of(&typed_text());
    let format = map.matching_rule("demo/pose").expect("a rule").format;
    // Field 6 (`label`, a string) holding bytes that are not UTF-8.
    let refused = format.decode(&[0x32, 0x01, 0xff]).expect_err("not a Pose");
    match refused {
        PayloadFormatError::Malformed { at, why } => {
            assert_eq!(at, 2);
            assert!(why.starts_with("pkg.Pose.label: "), "{why}");
        }
        other => panic!("{other:?}"),
    }
}

/// A text that carries no schema file carries the name alone, as a profile
/// rule's always has: the payload is walked by the wire and the row says so.
#[test]
fn a_schema_named_without_any_file_is_carried_and_not_read() {
    let map = map_of("demo/pose=protobuf@pkg.Pose");
    let format = map.matching_rule("demo/pose").expect("a rule").format;
    let schema = format.body_schema().expect("named");
    assert_eq!((schema.message, schema.read), ("pkg.Pose", false));
    assert!(!format.reads_types());
    assert_eq!(
        format.decode(&pose_bytes()).expect("walks")[0].value,
        "varint 5"
    );
    // And it reads back as written.
    assert!(map
        .declarations()
        .iter()
        .any(|d| d.text == "demo/pose=protobuf@pkg.Pose"));
}

#[test]
fn a_schema_the_declared_files_do_not_define_is_refused() {
    let text = alloc::format!(
        "{}\ndemo/pose=protobuf@pkg.Missing\n",
        file_line("pose.proto", SCHEMA)
    );
    match refusal(&text) {
        FormatMapError::BadBodySchema(token, why) => {
            assert_eq!(token, "protobuf@pkg.Missing");
            assert!(why.0.contains("no declared schema file defines"), "{why}");
        }
        other => panic!("{other:?}"),
    }
    let text = alloc::format!(
        "{}\ndemo/pose=protobuf@pkg.Gear\n",
        file_line("pose.proto", SCHEMA)
    );
    assert!(matches!(
        refusal(&text),
        FormatMapError::BadBodySchema(_, why) if why.0.contains("is an enum")
    ));
}

#[test]
fn a_schema_file_the_reader_refuses_refuses_the_rule_with_its_place() {
    let text = alloc::format!(
        "{}\ndemo/pose=protobuf@pkg.Pose\n",
        file_line("pose.proto", "syntax = \"proto3\";\nmessage {")
    );
    match refusal(&text) {
        FormatMapError::SchemaRefused(token, why) => {
            assert_eq!(token, "protobuf@pkg.Pose");
            assert_eq!(why.file.as_deref(), Some("pose.proto"));
            assert_eq!(why.line, Some(2));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_schema_after_a_format_that_reads_none_is_refused() {
    assert!(matches!(
        refusal("demo/pose=json@pkg.Pose"),
        FormatMapError::BadBodySchema(token, _) if token == "json@pkg.Pose"
    ));
}

#[test]
fn a_file_declared_twice_installs_once_and_a_different_one_is_refused() {
    let line = file_line("pose.proto", SCHEMA);
    let map = map_of(&alloc::format!(
        "{line}\n{line}\ndemo/pose=protobuf@pkg.Pose"
    ));
    assert_eq!(
        map.declarations()
            .iter()
            .filter(|d| d.kind == DeclarationKind::SchemaFile)
            .count(),
        1
    );
    let other = file_line("pose.proto", "syntax = \"proto3\";");
    assert!(matches!(
        refusal(&alloc::format!("{line}\n{other}")),
        FormatMapError::BadSchemaFile(name, _) if name == "pose.proto"
    ));
    assert!(matches!(
        refusal("#@pose.proto=\"unterminated"),
        FormatMapError::BadSchemaFile(..)
    ));
    assert!(matches!(
        refusal("#@pose.proto=\"a\" \"b\""),
        FormatMapError::BadSchemaFile(..)
    ));
}

/// A file a rule's message imports is read too, wherever the text puts it.
#[test]
fn an_import_is_read_from_a_file_declared_after_the_one_that_imports_it() {
    let inner = "syntax = \"proto3\"; package lib; message Inner { sint64 v = 1; }";
    let outer = "syntax = \"proto3\"; package app; import \"lib.proto\"; \
                 message Outer { lib.Inner inner = 1; }";
    let text = alloc::format!(
        "demo/o=protobuf@app.Outer\n{}\n{}\n",
        file_line("app.proto", outer),
        file_line("lib.proto", inner)
    );
    let map = map_of(&text);
    let format = map.matching_rule("demo/o").expect("a rule").format;
    // inner { v: -1 } -> 0a 02 08 01
    let fields = format.decode(&[0x0a, 0x02, 0x08, 0x01]).expect("an Outer");
    assert_eq!(fields[1].path, "1.1");
    assert_eq!(
        fields[1].typed.as_ref().and_then(|t| t.json.as_deref()),
        Some("-1")
    );
}

/// What a run records and what a row writes: the field layer, which the
/// `dissect` feature builds.
#[cfg(feature = "dissect")]
mod rendered {
    use super::*;
    use crate::payload_decode::{push_decoding, Declarations, PayloadDecoding};

    /// The ledger of what a run applied: a rule that READ by the files applied
    /// every one of them, so none is reported as having bound nothing.
    #[test]
    fn a_rule_that_read_by_the_files_marks_every_file_used() {
        let map = map_of(&typed_text());
        let run = Declarations::new(&map);
        assert!(run
            .unused()
            .iter()
            .any(|d| d.kind == DeclarationKind::SchemaFile));
        run.rule_for_keyexpr("demo/pose").expect("the rule wins");
        assert!(run.unused().is_empty(), "{:?}", run.unused());
    }

    #[test]
    fn the_row_says_it_was_typed_and_every_field_carries_three_keys() {
        let map = map_of(&typed_text());
        let format = map.matching_rule("demo/pose").expect("a rule").format;
        let fields = format.decode(&pose_bytes()).expect("a Pose");
        let decoded = PayloadDecoding::Decoded {
            keyexpr: "demo/pose".to_string(),
            rule: map.matching_rule("demo/pose").expect("a rule").rule,
            format: format.name().to_string(),
            fields,
            despite_encoding: None,
            typed: format.reads_types(),
            schema: format.body_schema().map(|s| s.message.to_string()),
        };
        let mut out = String::new();
        push_decoding(&decoded, &mut out);
        assert!(
            out.contains("\"typed\":true,\"schema\":\"pkg.Pose\""),
            "{out}"
        );
        assert!(
            out.contains(
                "{\"path\":\"1\",\"name\":\"x\",\"value\":\"-3\",\"start\":0,\"end\":2,\
             \"depth\":0,\"parent\":null,\"type\":\"sint32\",\"typed_value\":-3,\
             \"enum_number\":null}"
            ),
            "{out}"
        );
        assert!(
            out.contains("\"type\":\"pkg.Gear\",\"typed_value\":\"GEAR_DRIVE\",\"enum_number\":2}"),
            "{out}"
        );
        assert!(
            out.contains("\"type\":\"pkg.Inner\",\"typed_value\":null,\"enum_number\":null}"),
            "{out}"
        );
        let parsed = wz_session_core::json5::parse(&out).expect("the block is JSON");
        assert!(parsed.get("fields").is_some());
    }

    #[test]
    fn a_row_walked_by_the_wire_writes_the_same_keys_as_null() {
        let map = map_of("demo/pose=protobuf");
        let format = map.matching_rule("demo/pose").expect("a rule").format;
        let decoded = PayloadDecoding::Decoded {
            keyexpr: "demo/pose".to_string(),
            rule: map.matching_rule("demo/pose").expect("a rule").rule,
            format: format.name().to_string(),
            fields: format.decode(&pose_bytes()).expect("walks"),
            despite_encoding: None,
            typed: format.reads_types(),
            schema: None,
        };
        let mut out = String::new();
        push_decoding(&decoded, &mut out);
        assert!(out.contains("\"typed\":false,\"schema\":null"), "{out}");
        assert!(
            out.contains(
                "\"value\":\"varint 5\",\"start\":0,\"end\":2,\"depth\":0,\
                      \"parent\":null,\"type\":null,\"typed_value\":null,\
                      \"enum_number\":null}"
            ),
            "{out}"
        );
    }
}

/// A described record knows its types too, and says them the same way.
#[test]
fn a_described_record_carries_its_types() {
    let map = map_of("#rec=speed:u16le,temp:i8,ratio:f32le,tail:rest\ndemo/r=rec");
    let format = map.matching_rule("demo/r").expect("a rule").format;
    assert!(format.reads_types());
    let fields = format
        .decode(&[0x01, 0x02, 0xff, 0x00, 0x00, 0xc0, 0x3f, 0xab])
        .expect("a record");
    let typed: Vec<_> = fields
        .iter()
        .map(|f| f.typed.clone().expect("typed"))
        .collect();
    assert_eq!(typed[0], tv("u16le", Some("513"), None));
    assert_eq!(typed[1], tv("i8", Some("-1"), None));
    assert_eq!(typed[2], tv("f32le", Some("1.5"), None));
    assert_eq!(typed[3], tv("rest", Some("\"qw==\""), None));
    // The text a person reads is what it was.
    assert_eq!(fields[0].value, "513");
    assert_eq!(fields[3].value, "ab");
}

/// The `.proto` door's text carries the files and the typed rule, so a
/// consumer that installs what the door wrote reads by the schema.
#[test]
fn the_proto_doors_text_reads_the_payload_by_its_types() {
    let out = crate::proto_schema::declarations_from_proto(
        "demo/pose",
        "pkg.Pose",
        &[ProtoFile {
            name: "pose.proto",
            text: SCHEMA.as_bytes(),
        }],
        0,
    )
    .expect("declares");
    let map = map_of(&out.text);
    let format = map.matching_rule("demo/pose").expect("a rule").format;
    assert!(format.reads_types());
    let fields = format.decode(&pose_bytes()).expect("a Pose");
    assert_eq!(
        fields[0].typed.as_ref().and_then(|t| t.json.as_deref()),
        Some("-3")
    );
}

/// An end-to-end profile rule reads its BODY by the same files, with the spans
/// in payload coordinates.
#[test]
fn a_profile_rule_reads_its_body_by_the_declared_files() {
    // A ten-byte header: crc, length, counter, ident. The walk does not judge
    // it; `e2e_slots` does.
    let profile = r#"{"name": "p", "fields": [{"name": "crc", "bytes": 4}, {"name": "length", "bytes": 2}, {"name": "counter", "bytes": 2}, {"name": "ident", "bytes": 2}], "crc": {"field": "crc", "width": 32, "poly": "0xF4ACFB13", "init": "0xFFFFFFFF", "refin": true, "refout": true, "xorout": "0xFFFFFFFF", "cover": ["length", "ident", "@payload", "counter"]}, "length": {"field": "length", "counts": "frame"}, "counter": {"field": "counter", "max_gap": 3, "timeout_ms": 100}}"#;
    let text = alloc::format!(
        "#p={profile}\n{}\ndemo/pose=p@pkg.Pose\n",
        file_line("pose.proto", SCHEMA)
    );
    let map = map_of(&text);
    let format = map.matching_rule("demo/pose").expect("a rule").format;
    assert!(format.reads_types());
    let mut payload = alloc::vec![0u8; 10];
    payload.extend(pose_bytes());
    let fields = format.decode(&payload).expect("a frame");
    assert_eq!((fields[0].start, fields[0].end), (10, 12));
    assert_eq!(
        fields[0].typed.as_ref().and_then(|t| t.ty.as_deref()),
        Some("sint32")
    );
}
