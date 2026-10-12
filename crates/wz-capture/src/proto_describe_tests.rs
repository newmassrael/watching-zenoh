// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The tests of [`crate::proto_describe`] and its document. Corpus-free: every one
//! runs on every machine and needs no `protoc`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::proto_describe::{
    describe_proto, type_words, FieldDescription, ProtoDescription, Target, LABEL_WORDS,
    SYNTAX_WORDS,
};
use crate::proto_describe_json::proto_message_json;
use crate::proto_schema::{ProtoDiagnostic, ProtoFile};

fn files<'a>(files: &'a [(&'a str, &'a str)]) -> Vec<ProtoFile<'a>> {
    files
        .iter()
        .map(|(name, text)| ProtoFile {
            name,
            text: text.as_bytes(),
        })
        .collect()
}

fn describe(root: &str, given: &[(&str, &str)]) -> Result<ProtoDescription, ProtoDiagnostic> {
    describe_proto(root, &files(given), 0)
}

fn described(root: &str, text: &str) -> ProtoDescription {
    describe(root, &[("a.proto", text)]).unwrap_or_else(|d| panic!("{d}\n{text}"))
}

fn field<'a>(d: &'a ProtoDescription, message: &str, name: &str) -> &'a FieldDescription {
    d.messages
        .iter()
        .find(|m| m.full_name == message)
        .unwrap_or_else(|| panic!("no message {message}"))
        .fields
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no field {name} in {message}"))
}

/// A schema with every scalar type as a regular field, an enum, a message, the
/// three label spellings, a oneof, a `json_name`, a packed option each way and
/// maps of several key and value types, plus a proto2 message it reaches.
const RICH: &str = r#"syntax = "proto3";
package demo;
import "legacy.proto";
enum Mode { MODE_OFF = 0; MODE_ON = 1; MODE_NEG = -1; }
message Point { double x = 1; double y = 2; }
message Rich {
  double f_double = 1; float f_float = 2; int32 f_int32 = 3; int64 f_int64 = 4;
  uint32 f_uint32 = 5; uint64 f_uint64 = 6; sint32 f_sint32 = 7; sint64 f_sint64 = 8;
  fixed32 f_fixed32 = 9; fixed64 f_fixed64 = 10; sfixed32 f_sfixed32 = 11;
  sfixed64 f_sfixed64 = 12; bool f_bool = 13; string f_string = 14; bytes f_bytes = 15;
  Mode mode = 16;
  Point origin = 17;
  optional int32 maybe = 18;
  repeated sint32 samples = 19;
  repeated int32 unpacked = 20 [packed = false];
  repeated string tags = 21;
  repeated Point path = 22;
  map<string, int32> counts = 23;
  map<int32, Point> points = 24;
  map<fixed32, Mode> modes = 25;
  oneof choice { string name = 26; uint32 code = 27; }
  string snake_case_name = 28 [json_name = "customName"];
  map<bool, bytes> flags = 29;
  Legacy legacy = 30;
}
"#;

const LEGACY: &str = r#"syntax = "proto2";
package demo;
message Legacy {
  required int32 id = 1;
  optional string note = 2;
  repeated int32 xs = 3;
  repeated int32 ys = 4 [packed = true];
}
"#;

fn rich() -> ProtoDescription {
    describe("demo.Rich", &[("a.proto", RICH), ("legacy.proto", LEGACY)])
        .unwrap_or_else(|d| panic!("{d}"))
}

/// THE ROOT FIRST, EVERY REACHED MESSAGE ONCE, in the order the declaration door
/// would meet them: a field's message before the next field's.
#[test]
fn the_root_comes_first_and_each_reached_message_once() {
    let d = rich();
    assert_eq!(d.root, "demo.Rich");
    let names: Vec<&str> = d.messages.iter().map(|m| m.full_name.as_str()).collect();
    assert_eq!(
        names,
        ["demo.Rich", "demo.Point", "demo.Legacy"],
        "{names:?}"
    );
    // `Point` is held by three fields and described once.
    assert_eq!(names.iter().filter(|n| **n == "demo.Point").count(), 1);
    // The syntax is the syntax of the FILE the message is written in.
    assert_eq!(d.messages[0].syntax, "proto3");
    assert_eq!(d.messages[2].syntax, "proto2");
    assert_eq!(d.messages[2].file, "legacy.proto");
}

/// EVERY SCALAR KEYWORD IS ITS OWN TYPE, in declaration order: the writer's
/// `sint32` is not its `int32`, and a consumer drawing an input needs the
/// difference.
#[test]
fn every_scalar_keyword_is_reported_as_itself() {
    let d = rich();
    let want = [
        ("f_double", "double"),
        ("f_float", "float"),
        ("f_int32", "int32"),
        ("f_int64", "int64"),
        ("f_uint32", "uint32"),
        ("f_uint64", "uint64"),
        ("f_sint32", "sint32"),
        ("f_sint64", "sint64"),
        ("f_fixed32", "fixed32"),
        ("f_fixed64", "fixed64"),
        ("f_sfixed32", "sfixed32"),
        ("f_sfixed64", "sfixed64"),
        ("f_bool", "bool"),
        ("f_string", "string"),
        ("f_bytes", "bytes"),
    ];
    for (name, ty) in want {
        let f = field(&d, "demo.Rich", name);
        assert_eq!(f.ty, ty, "{name}");
        assert_eq!(f.label, "singular", "{name}");
        assert_eq!(f.target, Target::None, "{name}");
    }
    // The fifteen are the first fifteen fields, in the order written.
    let order: Vec<&str> = d.messages[0].fields[..15]
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(order, want.map(|(n, _)| n));
}

#[test]
fn an_enum_a_message_and_a_map_say_what_they_point_at() {
    let d = rich();
    let mode = field(&d, "demo.Rich", "mode");
    assert_eq!(mode.ty, "enum");
    let Target::Enum(e) = &mode.target else {
        panic!("{mode:?}")
    };
    assert_eq!(e.name, "demo.Mode");
    // The number is the number written, negative included, in the order written.
    assert_eq!(
        e.values,
        [
            (String::from("MODE_OFF"), 0),
            (String::from("MODE_ON"), 1),
            (String::from("MODE_NEG"), -1)
        ]
    );

    let origin = field(&d, "demo.Rich", "origin");
    assert_eq!(origin.ty, "message");
    assert_eq!(origin.target, Target::Message(String::from("demo.Point")));

    // A map is a repeated entry, whatever the text said; its key is a scalar
    // keyword and its value says what it points at.
    let counts = field(&d, "demo.Rich", "counts");
    assert_eq!((counts.ty, counts.label), ("map", "repeated"));
    let map = counts.map.as_ref().expect("a map field has a map");
    assert_eq!((map.key, map.value_type), ("string", "int32"));
    assert_eq!(map.value, Target::None);

    let points = field(&d, "demo.Rich", "points").map.as_ref().expect("map");
    assert_eq!((points.key, points.value_type), ("int32", "message"));
    assert_eq!(points.value, Target::Message(String::from("demo.Point")));

    let modes = field(&d, "demo.Rich", "modes").map.as_ref().expect("map");
    assert_eq!((modes.key, modes.value_type), ("fixed32", "enum"));
    assert!(matches!(&modes.value, Target::Enum(e) if e.name == "demo.Mode"));

    // A field that is not a map has none.
    assert!(field(&d, "demo.Rich", "origin").map.is_none());
}

/// THE LABEL, in both syntaxes: a proto3 field with no label is `singular`,
/// `optional` is its own word, and a proto2 file has `required`.
#[test]
fn the_label_is_the_one_the_field_was_written_with() {
    let d = rich();
    assert_eq!(field(&d, "demo.Rich", "f_int32").label, "singular");
    assert_eq!(field(&d, "demo.Rich", "maybe").label, "optional");
    assert_eq!(field(&d, "demo.Rich", "tags").label, "repeated");
    assert_eq!(field(&d, "demo.Legacy", "id").label, "required");
    assert_eq!(field(&d, "demo.Legacy", "note").label, "optional");
    assert_eq!(field(&d, "demo.Legacy", "xs").label, "repeated");
    // A member of a oneof has no label of its own.
    assert_eq!(field(&d, "demo.Rich", "name").label, "singular");
}

/// `packed` IS ANSWERED ONLY WHERE THE QUESTION EXISTS, and by the syntax's
/// default unless the option says: proto3 packs a repeated scalar, proto2 does
/// not, and a string cannot be packed at all.
#[test]
fn packed_is_the_effective_form_of_a_repeated_packable_field() {
    let d = rich();
    assert_eq!(field(&d, "demo.Rich", "samples").packed, Some(true));
    assert_eq!(field(&d, "demo.Rich", "unpacked").packed, Some(false));
    assert_eq!(field(&d, "demo.Legacy", "xs").packed, Some(false));
    assert_eq!(field(&d, "demo.Legacy", "ys").packed, Some(true));
    // Not packable, not repeated, a map: no answer.
    for (message, name) in [
        ("demo.Rich", "tags"),
        ("demo.Rich", "path"),
        ("demo.Rich", "f_int32"),
        ("demo.Rich", "counts"),
    ] {
        assert_eq!(field(&d, message, name).packed, None, "{name}");
    }
}

#[test]
fn a_oneof_member_names_its_oneof_and_the_message_lists_them() {
    let d = rich();
    assert_eq!(d.messages[0].oneofs, ["choice"]);
    assert_eq!(
        field(&d, "demo.Rich", "name").oneof.as_deref(),
        Some("choice")
    );
    assert_eq!(
        field(&d, "demo.Rich", "code").oneof.as_deref(),
        Some("choice")
    );
    assert_eq!(field(&d, "demo.Rich", "f_int32").oneof, None);
}

/// THE JSON NAME is the `json_name` option when it is a string and protoc's
/// lower-camel-case spelling otherwise.
#[test]
fn the_json_name_is_the_option_or_protocs_default() {
    let d = rich();
    assert_eq!(
        field(&d, "demo.Rich", "snake_case_name").json_name,
        "customName"
    );
    assert_eq!(field(&d, "demo.Rich", "f_sfixed64").json_name, "fSfixed64");
    assert_eq!(field(&d, "demo.Rich", "mode").json_name, "mode");
}

/// A MESSAGE THAT CONTAINS ITSELF IS DESCRIBED, where the declaration door
/// refuses it: nothing is expanded into paths, so the cycle has an end.
#[test]
fn a_recursive_message_is_described_once() {
    let text =
        "syntax = \"proto3\"; message Tree { int32 v = 1; Tree left = 2; repeated Tree kids = 3; }";
    let d = described("Tree", text);
    assert_eq!(d.messages.len(), 1);
    let left = field(&d, "Tree", "left");
    assert_eq!(left.target, Target::Message(String::from("Tree")));
    // The declaration door says no to the same text, for the cycle.
    let declared = crate::proto_schema::declarations_from_proto(
        "demo/t",
        "Tree",
        &files(&[("a.proto", text)]),
        0,
    );
    assert!(declared.is_err(), "{declared:?}");
}

/// THE REFUSALS ARE THE OTHER DOORS', since the reader is shared: a type that is
/// not defined, a root that is not defined, a `group` the root reaches.
#[test]
fn the_refusals_are_the_shared_readers() {
    let bad = describe(
        "M",
        &[("a.proto", "syntax = \"proto3\"; message M { Nope n = 1; }")],
    )
    .expect_err("an undefined type");
    assert_eq!(bad.file.as_deref(), Some("a.proto"));
    assert!(bad.line.is_some(), "{bad:?}");

    let bad = describe(
        "Missing",
        &[("a.proto", "syntax = \"proto3\"; message M { int32 a = 1; }")],
    )
    .expect_err("a root that is not there");
    assert_eq!((bad.file.as_deref(), bad.line), (Some("a.proto"), None));

    let group = "message M { optional group G = 1 { optional int32 a = 2; } }";
    let bad = describe("M", &[("a.proto", group)]).expect_err("a group");
    assert!(bad.reason.contains("group"), "{bad:?}");
}

/// THE DOCUMENT: every key of a field row is present, and the family words are
/// the closed vocabularies this module lists.
#[test]
fn the_document_has_one_shape_for_every_row_and_closed_words() {
    let doc = proto_message_json(
        "demo.Rich",
        &files(&[("a.proto", RICH), ("legacy.proto", LEGACY)]),
        0,
    );
    assert!(
        doc.starts_with("{\"document\":{\"name\":\"proto_message\",\"revision\":1},\"ok\":true,"),
        "{doc}"
    );
    // A field row with nothing to point at writes every key, `null` where it
    // does not apply: that is what makes `type`, `label` and the rest passengers.
    assert!(
        doc.contains(
            "{\"name\":\"f_int32\",\"json_name\":\"fInt32\",\"number\":3,\"type\":\"int32\",\
             \"label\":\"singular\",\"oneof\":null,\"packed\":null,\"enum\":null,\
             \"message_type\":null,\"map\":null}"
        ),
        "{doc}"
    );
    // An enum, negative number included, and a map.
    assert!(
        doc.contains("\"enum\":{\"name\":\"demo.Mode\",\"values\":[{\"name\":\"MODE_OFF\",\"number\":0},{\"name\":\"MODE_ON\",\"number\":1},{\"name\":\"MODE_NEG\",\"number\":-1}]}"),
        "{doc}"
    );
    assert!(
        doc.contains("\"map\":{\"key\":\"fixed32\",\"value\":{\"type\":\"enum\",\"enum\":{"),
        "{doc}"
    );
    assert!(
        doc.contains("\"map\":{\"key\":\"int32\",\"value\":{\"type\":\"message\",\"enum\":null,\"message_type\":\"demo.Point\"}}"),
        "{doc}"
    );
}

/// A REFUSAL KEEPS ITS PLACE KEYS TOGETHER, as the declaration document does,
/// and omits the ones that do not apply.
#[test]
fn a_refusal_carries_the_place_keys_that_apply_and_no_null() {
    let at_a_place = proto_message_json(
        "M",
        &files(&[("a.proto", "syntax = \"proto3\"; message M { Nope n = 1; }")]),
        0,
    );
    for key in [
        "\"file\":\"a.proto\"",
        "\"line\":1",
        "\"column\":",
        "\"reason\":",
    ] {
        assert!(at_a_place.contains(key), "{key}: {at_a_place}");
    }
    assert!(at_a_place.contains("\"ok\":false"), "{at_a_place}");
    let whole_file = proto_message_json(
        "Missing",
        &files(&[("a.proto", "syntax = \"proto3\"; message M { int32 a = 1; }")]),
        0,
    );
    assert!(whole_file.contains("\"file\":\"a.proto\""), "{whole_file}");
    assert!(!whole_file.contains("\"line\""), "{whole_file}");
    assert!(!whole_file.contains("null"), "{whole_file}");
}

/// THE VOCABULARIES THE DOCUMENT DECLARES ARE THE WALKS THEY ARE HELD TO.
#[test]
fn the_declared_vocabularies_are_the_walks() {
    use crate::doc_revision as rev;
    let family = |key: &str| -> Vec<&'static str> {
        rev::newest(rev::PROTO_MESSAGE)
            .expect("a revision")
            .families
            .iter()
            .find(|f| f.key == key)
            .unwrap_or_else(|| panic!("no family {key}"))
            .values
            .to_vec()
    };
    let mut types = type_words();
    types.sort_unstable();
    assert_eq!(family("type"), types);
    let mut labels = LABEL_WORDS.to_vec();
    labels.sort_unstable();
    assert_eq!(family("label"), labels);
    assert_eq!(family("syntax"), SYNTAX_WORDS.to_vec());
    // A map key is any scalar a map may be keyed by: the fifteen less the three
    // (`double`, `float`, `bytes`) the language guide refuses.
    let keys = family("key");
    assert_eq!(keys.len(), 12, "{keys:?}");
    for refused in ["double", "float", "bytes"] {
        assert!(!keys.contains(&refused), "{refused}");
    }
    for word in &keys {
        assert!(types.contains(word), "{word}");
    }
}

/// The documents a family gate measures `type`, `key`, `label` and `syntax` over:
/// the rich schema (every type word, every label, both syntaxes), a small one,
/// and each shape of refusal.
pub(crate) fn documents_for_the_carries_gate() -> Vec<String> {
    let both = files(&[("a.proto", RICH), ("legacy.proto", LEGACY)]);
    alloc::vec![
        proto_message_json("demo.Rich", &both, 0),
        proto_message_json(
            "Reading",
            &files(&[(
                "a.proto",
                "syntax = \"proto3\"; message Reading { uint32 sensor_id = 1; }"
            )]),
            0,
        ),
        proto_message_json(
            "M",
            &files(&[("a.proto", "syntax = \"proto3\"; message M { Nope n = 1; }")]),
            0,
        ),
        proto_message_json(
            "Missing",
            &files(&[("a.proto", "syntax = \"proto3\"; message M { int32 a = 1; }")]),
            0,
        ),
        proto_message_json(
            "M",
            &files(&[("a.proto", "syntax = \"proto3\"; message M { int32 a = 1; }")]),
            7
        ),
    ]
}

#[test]
fn the_carries_gate_documents_reach_every_word_of_every_family() {
    let docs = documents_for_the_carries_gate();
    let all = docs.join("\n");
    for word in type_words() {
        assert!(all.contains(&format!("\"type\":\"{word}\"")), "type {word}");
    }
    for word in LABEL_WORDS {
        assert!(
            all.contains(&format!("\"label\":\"{word}\"")),
            "label {word}"
        );
    }
    for word in SYNTAX_WORDS {
        assert!(
            all.contains(&format!("\"syntax\":\"{word}\"")),
            "syntax {word}"
        );
    }
}
