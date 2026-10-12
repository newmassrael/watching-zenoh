// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The tests of [`crate::proto_describe`] and its document. Corpus-free: every one
//! runs on every machine and needs no `protoc`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::proto_describe::{
    describe_proto, type_words, FieldDescription, OptionDescription, OptionValueDescription,
    ProtoDescription, Target, LABEL_WORDS, OPTION_KIND_WORDS, SYNTAX_WORDS,
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
        doc.starts_with("{\"document\":{\"name\":\"proto_message\",\"revision\":2},\"ok\":true,"),
        "{doc}"
    );
    // A field row with nothing to point at writes every key, `null` where it
    // does not apply: that is what makes `type`, `label` and the rest passengers.
    assert!(
        doc.contains(
            "{\"name\":\"f_int32\",\"json_name\":\"fInt32\",\"number\":3,\"type\":\"int32\",\
             \"label\":\"singular\",\"oneof\":null,\"packed\":null,\"enum\":null,\
             \"message_type\":null,\"map\":null,\"comment\":null,\"trailing_comment\":null,\
             \"options\":[]}"
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
    let mut kinds = OPTION_KIND_WORDS.to_vec();
    kinds.sort_unstable();
    assert_eq!(family("kind"), kinds);
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

/// A schema whose comments sit in every position `protoc`'s rule tells apart.
/// Every expectation below was read off `protoc` 3.21.12 (`--include_source_info`,
/// `leading_comments` / `trailing_comments` of each location), not off this
/// reader's idea of the rule: the oracle test in `wz-integration-tests` makes the
/// same comparison on every machine that has `protoc`.
const COMMENTED: &str = "// File header, detached by the blank line.\n\
\n\
syntax = \"proto3\";\n\
\n\
// The point of a plot.\n\
message Point { // opens Point\n\
  // The x.\n\
  double x = 1; // trailing x\n\
  double y = 2;\n\
  /* block lead of z */\n\
  double z = 3;\n\
  // Run of\n\
  // two lines.\n\
  double w = 4;\n\
\n\
  // Detached from v by a blank line below.\n\
\n\
  double v = 5; /* same-line block */ double u = 6;\n\
  double t = 7;\n\
  // Trails t: followed by a blank line.\n\
\n\
  double s = 8;\n\
  /** Doc block\n\
   *  second line\n\
   */\n\
  double r = 9;\n\
  // Before the close.\n\
}\n\
// After the message.\n\
message Other {}\n";

fn comments_of(
    d: &ProtoDescription,
    message: &str,
    name: &str,
) -> (Option<String>, Option<String>) {
    let f = field(d, message, name);
    (f.comment.clone(), f.trailing_comment.clone())
}

/// A COMMENT BELONGS TO THE DECLARATION `protoc` GIVES IT TO. Leading is the
/// comment right before a declaration; trailing is the one on its own line after
/// it, or the run on the next lines when a blank line follows; a blank line
/// detaches; a block comment with a token after it on the line belongs to
/// nobody; a comment before a closing brace trails the declaration above.
#[test]
fn a_comment_goes_where_protoc_puts_it() {
    let d = described("Point", COMMENTED);
    let some = |s: &str| Some(String::from(s));
    // A message's trailing comment is the one after its `{`.
    let point = &d.messages[0];
    assert_eq!(point.comment, some(" The point of a plot.\n"));
    assert_eq!(point.trailing_comment, some(" opens Point\n"));
    assert_eq!(
        comments_of(&d, "Point", "x"),
        (some(" The x.\n"), some(" trailing x\n"))
    );
    // Nothing around `y`: the comment above `z` is `z`'s.
    assert_eq!(comments_of(&d, "Point", "y"), (None, None));
    // A block comment keeps no trailing newline of its own.
    assert_eq!(
        comments_of(&d, "Point", "z"),
        (some(" block lead of z "), None)
    );
    // A run of line comments is ONE comment.
    assert_eq!(
        comments_of(&d, "Point", "w"),
        (some(" Run of\n two lines.\n"), None)
    );
    // A blank line detaches the comment from `v`; a block comment that has a
    // token after it on its line belongs to nobody, so `u` has none either.
    assert_eq!(comments_of(&d, "Point", "v"), (None, None));
    assert_eq!(comments_of(&d, "Point", "u"), (None, None));
    // A comment on the line after, with a blank line below it, trails.
    assert_eq!(
        comments_of(&d, "Point", "t"),
        (None, some(" Trails t: followed by a blank line.\n"))
    );
    assert_eq!(comments_of(&d, "Point", "s"), (None, None));
    // A doc block: the leading `*`, then each line without its indent and `*`.
    // The comment before the closing brace trails the declaration above it.
    assert_eq!(
        comments_of(&d, "Point", "r"),
        (
            some("* Doc block\n  second line\n"),
            some(" Before the close.\n")
        )
    );
    // The comment after a message's closing brace leads the next one.
    let other = described("Other", COMMENTED);
    assert_eq!(other.messages[0].comment, some(" After the message.\n"));
}

/// THE FIRST DECLARATION'S COMMENT, and a oneof's members: the comment before
/// the first statement of a file leads it (here `syntax`, so the message after
/// it has none), and a field inside a oneof is a declaration like any other.
#[test]
fn the_first_comment_of_a_file_and_a_oneof_member() {
    let text = "// Lead of syntax.\nsyntax = \"proto3\";\nmessage M {\n  oneof pick {\n    \
                // The name.\n    string name = 1;\n    uint32 code = 2; // The code.\n  }\n}\n";
    let d = described("M", text);
    assert_eq!(d.messages[0].comment, None);
    assert_eq!(
        comments_of(&d, "M", "name"),
        (Some(String::from(" The name.\n")), None)
    );
    assert_eq!(
        comments_of(&d, "M", "code"),
        (None, Some(String::from(" The code.\n")))
    );
}

/// A comment is not a token: the reader's refusals do not move for one, and a
/// comment is never mistaken for a declaration's end.
#[test]
fn comments_do_not_change_what_is_refused() {
    let bad = "syntax = \"proto3\";\n// c\nmessage M { /* c */ Nope n = 1; // c\n}\n";
    let d = describe("M", &[("a.proto", bad)]).expect_err("an undefined type");
    assert_eq!(d.line, Some(3));
    let torn = "syntax = \"proto3\";\nmessage M {\n  // c\n  int32 a = 1 // no semicolon\n}\n";
    assert!(describe("M", &[("a.proto", torn)]).is_err());
}

/// A schema with an option of every kind, on a message and on fields: a dotted
/// extension path, an integer, an enum word, a string, a negative number, a
/// float, an aggregate and plain options. Nothing is dropped and nothing is
/// judged.
const OPTIONED: &str = "syntax = \"proto2\";\n\
message Opt {\n\
  option (ext.msg).id = 7;\n\
  option deprecated = true;\n\
  optional int32 a = 1 [(ext).size = 16, (ext).kind = KIND_X, deprecated = true, default = -5];\n\
  optional string b = 2 [(ext) = { max: 3, tag: \"x\" }, json_name = \"bee\"];\n\
  optional double c = 3 [default = -1.5e3, (ext.f) = 2.5, (.ext).neg = -7];\n\
  optional double d = 4 [default = -inf];\n\
  optional int32 e = 5;\n\
  oneof o { option (x) = 1; int32 f = 6; }\n\
}\n";

fn options_of(options: &[OptionDescription]) -> Vec<(&str, OptionValueDescription)> {
    options
        .iter()
        .map(|o| (o.name.as_str(), o.value.clone()))
        .collect()
}

/// EVERY OPTION OF A FIELD AND OF A MESSAGE IS KEPT, in the order written, with
/// the name the file spelled and the value as it was written.
#[test]
fn every_option_is_kept_as_written() {
    use OptionValueDescription as V;
    let d = described("Opt", OPTIONED);
    let s = |t: &str| String::from(t);
    assert_eq!(
        options_of(&d.messages[0].options),
        [
            ("(ext.msg).id", V::Integer(7)),
            ("deprecated", V::Identifier(s("true")))
        ]
    );
    assert_eq!(
        options_of(&field(&d, "Opt", "a").options),
        [
            ("(ext).size", V::Integer(16)),
            ("(ext).kind", V::Identifier(s("KIND_X"))),
            ("deprecated", V::Identifier(s("true"))),
            ("default", V::Integer(-5)),
        ]
    );
    assert_eq!(
        options_of(&field(&d, "Opt", "b").options),
        [
            ("(ext)", V::Aggregate(s("max: 3, tag: \"x\""))),
            ("json_name", V::String(s("bee"))),
        ]
    );
    assert_eq!(
        options_of(&field(&d, "Opt", "c").options),
        [
            ("default", V::Float(s("-1.5e3"))),
            ("(ext.f)", V::Float(s("2.5"))),
            ("(.ext).neg", V::Integer(-7)),
        ]
    );
    assert_eq!(
        options_of(&field(&d, "Opt", "d").options),
        [("default", V::Identifier(s("-inf")))]
    );
    // A field with none has an empty list, and the options the value door reads
    // are still read: `json_name` above is `bee`.
    assert!(field(&d, "Opt", "e").options.is_empty());
    assert_eq!(field(&d, "Opt", "b").json_name, "bee");
    // The words are the reader's own list.
    for v in [
        V::Identifier(s("")),
        V::Integer(0),
        V::Float(s("")),
        V::String(s("")),
        V::Aggregate(s("")),
    ] {
        assert!(OPTION_KIND_WORDS.contains(&v.kind()), "{}", v.kind());
    }
}

/// An option's JSON row: a number for an integer by the integer rule, the text
/// for the rest, the kind beside it.
#[test]
fn the_options_document_row_says_the_kind_beside_the_value() {
    let doc = proto_message_json("Opt", &files(&[("a.proto", OPTIONED)]), 0);
    for row in [
        "{\"name\":\"(ext.msg).id\",\"kind\":\"integer\",\"value\":7}",
        "{\"name\":\"deprecated\",\"kind\":\"identifier\",\"value\":\"true\"}",
        "{\"name\":\"default\",\"kind\":\"integer\",\"value\":-5}",
        "{\"name\":\"(ext)\",\"kind\":\"aggregate\",\"value\":\"max: 3, tag: \\\"x\\\"\"}",
        "{\"name\":\"json_name\",\"kind\":\"string\",\"value\":\"bee\"}",
        "{\"name\":\"default\",\"kind\":\"float\",\"value\":\"-1.5e3\"}",
        "{\"name\":\"default\",\"kind\":\"identifier\",\"value\":\"-inf\"}",
    ] {
        assert!(doc.contains(row), "{row}\n{doc}");
    }
}

/// The documents a family gate measures `type`, `key`, `label`, `syntax` and
/// `kind` over: the rich schema (every type word, every label, both syntaxes), the
/// schema with an option of every kind, a small one, and each shape of refusal.
pub(crate) fn documents_for_the_carries_gate() -> Vec<String> {
    let both = files(&[("a.proto", RICH), ("legacy.proto", LEGACY)]);
    alloc::vec![
        proto_message_json("demo.Rich", &both, 0),
        proto_message_json("Opt", &files(&[("a.proto", OPTIONED)]), 0),
        proto_message_json("Point", &files(&[("a.proto", COMMENTED)]), 0),
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
    for word in OPTION_KIND_WORDS {
        assert!(all.contains(&format!("\"kind\":\"{word}\"")), "kind {word}");
    }
}
