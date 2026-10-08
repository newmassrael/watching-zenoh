// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The corpus-free tests of [`crate::proto_schema`]: every one runs on every
//! machine and needs no `protoc`. The comparison against `protoc` itself is in
//! `wz-integration-tests`, which is where a program the build does not provide
//! is allowed to be required.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::payload::formats::{FormatMap, PayloadFormat, Protobuf};
use crate::proto_schema::{
    declarations_from_proto, ProtoDiagnostic, ProtoFile, MAX_DECLARATIONS, MAX_PATH_DEPTH,
};

/// The key pattern most tests declare under.
const KEY: &str = "demo/sensor";

/// Declarations for `root` over `files`, the first of which is the root file.
fn declare(root: &str, files: &[(&str, &str)]) -> Result<String, ProtoDiagnostic> {
    let files: Vec<ProtoFile<'_>> = files
        .iter()
        .map(|(name, text)| ProtoFile {
            name,
            text: text.as_bytes(),
        })
        .collect();
    declarations_from_proto(KEY, root, &files, 0).map(|d| d.text)
}

fn one(root: &str, text: &str) -> Result<String, ProtoDiagnostic> {
    declare(root, &[("a.proto", text)])
}

/// The declarations, or a panic that prints the diagnostic.
fn ok(root: &str, text: &str) -> String {
    one(root, text).unwrap_or_else(|d| panic!("{d}\n{text}"))
}

/// The diagnostic, or a panic that prints what was produced instead.
fn refused(root: &str, text: &str) -> ProtoDiagnostic {
    one(root, text).expect_err("the schema must be refused")
}

fn lines(text: &str) -> Vec<&str> {
    text.lines().collect()
}

#[test]
fn a_flat_message_declares_its_fields_in_declaration_order() {
    let text = ok(
        "Reading",
        r#"syntax = "proto3";
           message Reading {
             int32 value = 7;
             string unit = 2;
             bool valid = 100;
           }"#,
    );
    assert_eq!(
        lines(&text),
        [
            "demo/sensor=protobuf",
            "demo/sensor:7=value",
            "demo/sensor:2=unit",
            "demo/sensor:100=valid",
        ]
    );
}

#[test]
fn a_nested_message_field_is_addressed_by_dotted_field_numbers() {
    let text = ok(
        "pkg.Outer",
        r#"syntax = "proto3";
           package pkg;
           message Outer {
             int32 id = 1;
             Meta meta = 3;
             message Meta {
               string tag = 2;
               Deep deep = 5;
             }
             message Deep { bool ok = 9; }
           }"#,
    );
    assert_eq!(
        lines(&text),
        [
            "demo/sensor=protobuf",
            "demo/sensor:1=id",
            "demo/sensor:3=meta",
            "demo/sensor:3.2=tag",
            "demo/sensor:3.5=deep",
            "demo/sensor:3.5.9=ok",
        ]
    );
}

#[test]
fn the_root_message_is_found_by_its_full_name_and_only_by_it() {
    let schema = r#"syntax = "proto3";
        package a.b;
        message M { int32 x = 1; message N { int32 y = 1; } }"#;
    ok("a.b.M", schema);
    ok("a.b.M.N", schema);
    let short = refused("M", schema);
    assert_eq!(short.file.as_deref(), Some("a.proto"));
    assert_eq!(short.line, None);
    assert!(short.reason.contains("`M` is not defined"), "{short}");
    let partial = refused("b.M", schema);
    assert!(partial.reason.contains("not defined"), "{partial}");
    let package = refused("a.b", schema);
    assert!(
        package.reason.contains("a package, not a message"),
        "{package}"
    );
    let field = refused("a.b.M.x", schema);
    assert!(field.reason.contains("not a message"), "{field}");
}

#[test]
fn a_root_that_is_an_enum_is_named_as_one() {
    let d = refused("E", "syntax = \"proto3\"; enum E { Z = 0; } message M {}");
    assert!(d.reason.contains("an enum, not a message"), "{d}");
}

#[test]
fn oneof_members_are_ordinary_fields_and_the_oneof_itself_is_not_a_path() {
    let text = ok(
        "M",
        r#"syntax = "proto3";
           message M {
             int32 before = 1;
             oneof pick { string s = 2; int64 i = 3; }
             int32 after = 4;
           }"#,
    );
    assert_eq!(
        lines(&text),
        [
            "demo/sensor=protobuf",
            "demo/sensor:1=before",
            "demo/sensor:2=s",
            "demo/sensor:3=i",
            "demo/sensor:4=after",
        ]
    );
}

#[test]
fn proto2_labels_and_a_repeated_message_field_share_one_path() {
    let text = ok(
        "M",
        r#"syntax = "proto2";
           message M {
             required int32 a = 1;
             optional N n = 2 [deprecated = true];
             repeated N many = 3;
             message N { optional int32 x = 1; }
           }"#,
    );
    assert_eq!(
        lines(&text),
        [
            "demo/sensor=protobuf",
            "demo/sensor:1=a",
            "demo/sensor:2=n",
            "demo/sensor:2.1=x",
            "demo/sensor:3=many",
            "demo/sensor:3.1=x",
        ]
    );
}

#[test]
fn a_file_with_no_syntax_statement_is_read_as_proto2() {
    let text = ok("M", "message M { optional int32 a = 1; }");
    assert!(text.contains(":1=a"));
    let d = refused("M", "message M { int32 a = 1; }");
    assert_eq!(d.line, Some(1));
    assert!(
        d.reason.contains("`required`, `optional` or `repeated`"),
        "{d}"
    );
}

/// THE MAP DECISION, stated where it is tested: a map field is declared as the
/// repeated entry message it is on the wire.
#[test]
fn a_map_field_declares_its_entry_message_key_and_value() {
    let text = ok(
        "M",
        r#"syntax = "proto3";
           message M {
             int32 id = 1;
             map<string, int32> counts = 5;
           }"#,
    );
    assert_eq!(
        lines(&text),
        [
            "demo/sensor=protobuf",
            "demo/sensor:1=id",
            "demo/sensor:5=counts",
            "demo/sensor:5.1=key",
            "demo/sensor:5.2=value",
        ]
    );
}

#[test]
fn a_map_whose_value_is_a_message_declares_that_messages_fields_under_the_value() {
    let text = ok(
        "M",
        r#"syntax = "proto3";
           message M {
             map<int32, Entry> by_id = 4;
             map<string, Color> by_name = 6;
             message Entry { string label = 3; Entry2 more = 4; }
             message Entry2 { bool flag = 1; }
             enum Color { RED = 0; }
           }"#,
    );
    assert_eq!(
        lines(&text),
        [
            "demo/sensor=protobuf",
            "demo/sensor:4=by_id",
            "demo/sensor:4.1=key",
            "demo/sensor:4.2=value",
            "demo/sensor:4.2.3=label",
            "demo/sensor:4.2.4=more",
            "demo/sensor:4.2.4.1=flag",
            "demo/sensor:6=by_name",
            "demo/sensor:6.1=key",
            "demo/sensor:6.2=value",
        ]
    );
}

#[test]
fn a_map_key_must_be_integral_or_string() {
    for key in ["float", "double", "bytes", "Msg", "Color"] {
        let d = refused(
            "M",
            &format!(
                "syntax = \"proto3\";\nenum Color {{ Z = 0; }}\nmessage Msg {{}}\n\
                 message M {{\n  map<{key}, int32> a = 1;\n}}\n"
            ),
        );
        assert_eq!(d.line, Some(5), "{key}: {d}");
        assert!(d.reason.contains("cannot be a map key"), "{key}: {d}");
    }
    for key in [
        "int32", "int64", "uint32", "uint64", "sint32", "sint64", "fixed32", "fixed64", "sfixed32",
        "sfixed64", "bool", "string",
    ] {
        ok(
            "M",
            &format!("syntax = \"proto3\"; message M {{ map<{key}, int32> a = 1; }}"),
        );
    }
}

#[test]
fn an_enum_typed_field_names_its_own_path_and_nothing_under_it() {
    let text = ok(
        "M",
        r#"syntax = "proto3";
           enum Unit { UNIT_UNSPECIFIED = 0; CELSIUS = 1; }
           message M { Unit unit = 2; }"#,
    );
    assert_eq!(lines(&text), ["demo/sensor=protobuf", "demo/sensor:2=unit"]);
}

#[test]
fn the_innermost_scope_that_has_the_first_name_wins() {
    // `Inner` is defined at the top and again inside `Outer`. A field in
    // `Outer` that says `Inner` means the nested one, and only the nested one
    // has a field called `deep`.
    let text = ok(
        "Outer",
        r#"syntax = "proto3";
           message Inner { int32 shallow = 1; }
           message Outer {
             message Inner { int32 deep = 1; }
             Inner i = 1;
             .Inner top = 2;
           }"#,
    );
    assert_eq!(
        lines(&text),
        [
            "demo/sensor=protobuf",
            "demo/sensor:1=i",
            "demo/sensor:1.1=deep",
            "demo/sensor:2=top",
            "demo/sensor:2.1=shallow",
        ]
    );
}

#[test]
fn a_dotted_name_descends_from_the_first_part_it_finds_and_does_not_turn_back() {
    let schema = r#"syntax = "proto3";
        package p;
        message A { message B { int32 in_a_b = 1; } }
        message C {
          message A { }
          A.B x = 1;
        }"#;
    // `A` is found first as `p.C.A`, which has no `B`: protoc does not go on to
    // `p.A.B`. The reference is not defined, and the reader says so.
    let d = refused("p.C", schema);
    assert_eq!(d.line, Some(6));
    assert!(d.reason.contains("\"A.B\" is not defined"), "{d}");
    // Written from the package root it is fine.
    let text = ok("p.C", &schema.replace("A.B x = 1;", "p.A.B x = 1;"));
    assert!(text.contains(":1.1=in_a_b"), "{text}");
}

#[test]
fn a_type_name_that_is_a_field_is_not_a_type() {
    let d = refused(
        "N",
        r#"syntax = "proto3";
           message M { int32 a = 1; }
           message N { M.a b = 1; }"#,
    );
    assert_eq!(d.line, Some(3));
    assert!(d.reason.contains("\"M.a\" is not a type"), "{d}");
}

#[test]
fn an_undefined_type_is_blamed_at_the_type() {
    let d = refused("M", "syntax = \"proto3\";\nmessage M {\n  Foo a = 1;\n}\n");
    assert_eq!((d.line, d.column), (Some(3), Some(3)));
    assert!(d.reason.contains("\"Foo\" is not defined"), "{d}");
    let d = refused(
        "M",
        "syntax = \"proto3\";\nmessage M {\n  .pkg.Foo a = 1;\n}\n",
    );
    assert!(d.reason.contains("\".pkg.Foo\" is not defined"), "{d}");
}

#[test]
fn field_numbers_are_judged_at_the_edges() {
    for (number, accepted) in [
        (0u64, false),
        (1, true),
        (18_999, true),
        (19_000, false),
        (19_999, false),
        (20_000, true),
        (536_870_911, true),
        (536_870_912, false),
    ] {
        let text = format!("syntax = \"proto3\";\nmessage M {{\n  int32 a = {number};\n}}\n");
        match one("M", &text) {
            Ok(_) => assert!(accepted, "{number} must be refused"),
            Err(d) => {
                assert!(!accepted, "{number} must be accepted: {d}");
                assert_eq!((d.line, d.column), (Some(3), Some(13)), "{number}");
            }
        }
    }
    let d = refused("M", "syntax = \"proto3\"; message M { int32 a = 0; }");
    assert!(d.reason.contains("positive"), "{d}");
    let d = refused(
        "M",
        "syntax = \"proto3\"; message M { int32 a = 536870912; }",
    );
    assert!(d.reason.contains("536870911"), "{d}");
    let d = refused("M", "syntax = \"proto3\"; message M { int32 a = 19500; }");
    assert!(d.reason.contains("19000 through 19999"), "{d}");
}

#[test]
fn a_repeated_field_number_is_blamed_at_the_second_use() {
    let d = refused(
        "M",
        "syntax = \"proto3\";\nmessage M {\n  int32 a = 1;\n  oneof o {\n    int32 b = 1;\n  }\n}\n",
    );
    assert_eq!(d.line, Some(5));
    assert!(d.reason.contains("number 1 is already used"), "{d}");
    assert!(d.reason.contains("`a`"), "{d}");
    // The same number in two messages is fine.
    ok(
        "M",
        "syntax = \"proto3\"; message M { int32 a = 1; message N { int32 a = 1; } }",
    );
}

#[test]
fn reserved_numbers_and_names_cannot_be_used() {
    let d = refused(
        "M",
        "syntax = \"proto3\";\nmessage M {\n  reserved 2, 5 to 7;\n  int32 a = 6;\n}\n",
    );
    assert_eq!(d.line, Some(4));
    assert!(d.reason.contains("reserved number 6"), "{d}");
    // Both ends of a range are inside it, and the numbers beside it are not.
    for (number, reserved) in [
        (1, false),
        (2, true),
        (3, false),
        (4, false),
        (5, true),
        (7, true),
        (8, false),
    ] {
        let text = format!(
            "syntax = \"proto3\";\nmessage M {{\n  reserved 2, 5 to 7;\n  int32 a = {number};\n}}\n"
        );
        assert_eq!(one("M", &text).is_err(), reserved, "number {number}");
    }
    let d = refused(
        "M",
        "syntax = \"proto3\";\nmessage M {\n  reserved \"x\";\n  int32 x = 1;\n}\n",
    );
    assert_eq!((d.line, d.column), (Some(4), Some(9)));
    assert!(d.reason.contains("`x` is reserved"), "{d}");
    // `max` reaches the top of the number space.
    let d = refused(
        "M",
        "syntax = \"proto3\";\nmessage M {\n  reserved 100 to max;\n  int32 a = 100000;\n}\n",
    );
    assert_eq!(d.line, Some(4));
    // Reserved in a message does not reach its neighbours.
    ok(
        "M",
        "syntax = \"proto3\"; message M { reserved 1; message N { int32 a = 1; } }",
    );
}

#[test]
fn names_clash_across_fields_nested_types_and_enum_values() {
    let d = refused(
        "M",
        "syntax = \"proto3\";\nmessage M {\n  int32 a = 1;\n  int32 a = 2;\n}\n",
    );
    assert_eq!((d.line, d.column), (Some(4), Some(9)));
    assert!(
        d.reason.contains("\"a\" is already defined in \"M\""),
        "{d}"
    );

    // A field registered before a nested message of the same name: the nested
    // message is the second definition, as in `protoc`.
    let d = refused(
        "M",
        "syntax = \"proto3\";\nmessage M {\n  int32 a = 1;\n  message a {}\n}\n",
    );
    assert_eq!(d.line, Some(4));

    let d = refused("M", "syntax = \"proto3\";\nmessage M {}\nmessage M {}\n");
    assert_eq!(d.line, Some(3));
    assert!(d.reason.contains("\"M\" is already defined"), "{d}");

    // Enum values are siblings of their enum.
    let d = refused(
        "M",
        "syntax = \"proto3\";\nmessage M {\n  enum E { A = 0; }\n  enum F { A = 0; }\n}\n",
    );
    assert_eq!((d.line, d.column), (Some(4), Some(12)));
    assert!(d.reason.contains("siblings of their enum"), "{d}");
}

// ---- recursion and size ----------------------------------------------------

#[test]
fn a_message_that_contains_itself_is_refused_and_the_cycle_is_named() {
    let d = refused(
        "Node",
        "syntax = \"proto3\";\nmessage Node {\n  int32 value = 1;\n  repeated Node children = 2;\n}\n",
    );
    assert_eq!(d.line, Some(4));
    assert!(d.reason.contains("contains itself"), "{d}");
    assert!(d.reason.contains("Node -> Node"), "{d}");
}

#[test]
fn a_cycle_through_other_messages_and_through_a_map_is_named_whole() {
    let d = refused(
        "p.A",
        r#"syntax = "proto3";
           package p;
           message A { B b = 1; }
           message B { map<string, C> c = 1; }
           message C { A back = 1; }"#,
    );
    assert_eq!(d.line, Some(5));
    assert!(d.reason.contains("p.A -> p.B -> p.C -> p.A"), "{d}");
}

#[test]
fn a_cycle_not_reachable_from_the_root_does_not_matter() {
    let text = ok(
        "Root",
        r#"syntax = "proto3";
           message Root { int32 a = 1; }
           message Loop { Loop again = 1; }"#,
    );
    assert_eq!(lines(&text), ["demo/sensor=protobuf", "demo/sensor:1=a"]);
}

#[test]
fn a_message_used_twice_without_a_cycle_is_expanded_twice() {
    let text = ok(
        "M",
        r#"syntax = "proto3";
           message M { P first = 1; P second = 2; }
           message P { int32 x = 1; }"#,
    );
    assert_eq!(
        lines(&text),
        [
            "demo/sensor=protobuf",
            "demo/sensor:1=first",
            "demo/sensor:1.1=x",
            "demo/sensor:2=second",
            "demo/sensor:2.1=x",
        ]
    );
}

#[test]
fn an_expansion_with_no_cycle_is_still_bounded_in_size() {
    // Twenty messages, each holding two of the next: 2^20 paths from a few
    // lines. Without a bound this would build a million-line string.
    let mut schema = String::from("syntax = \"proto3\";\n");
    for i in 0..20 {
        schema.push_str(&format!(
            "message M{i} {{ M{n} a = 1; M{n} b = 2; }}\n",
            n = i + 1
        ));
    }
    schema.push_str("message M20 { int32 leaf = 1; }\n");
    let d = refused("M0", &schema);
    assert!(
        d.reason
            .contains(&format!("more than {MAX_DECLARATIONS} declarations")),
        "{d}"
    );
}

#[test]
fn the_line_budget_is_exact_the_rule_line_included() {
    // A flat message of N fields is N + 1 lines. The budget admits exactly
    // MAX_DECLARATIONS of them and refuses the next, so a result is never one
    // line longer than the bound the header states.
    let flat = |fields: usize| {
        let mut schema = String::from("syntax = \"proto3\";\nmessage M {\n");
        for i in 1..=fields {
            schema.push_str(&format!("  int32 f{i} = {i};\n"));
        }
        schema.push_str("}\n");
        schema
    };
    let at_the_bound = ok("M", &flat(MAX_DECLARATIONS - 1));
    assert_eq!(at_the_bound.lines().count(), MAX_DECLARATIONS);
    let d = refused("M", &flat(MAX_DECLARATIONS));
    assert!(d.reason.contains("more than"), "{d}");
}

#[test]
fn a_chain_of_distinct_messages_past_the_path_bound_is_refused_not_overflowed() {
    // A chain of `links` messages, each holding the next, and a leaf at the end:
    // `links + 1` messages on the expansion stack at its deepest.
    let chain = |links: usize| {
        let mut schema = String::from("syntax = \"proto3\";\n");
        for i in 0..links {
            schema.push_str(&format!("message M{i} {{ M{n} next = 1; }}\n", n = i + 1));
        }
        schema.push_str(&format!("message M{links} {{ int32 leaf = 1; }}\n"));
        schema
    };
    // The bound is exact: MAX_PATH_DEPTH messages on the stack are accepted and
    // one more is not.
    ok("M0", &chain(MAX_PATH_DEPTH - 1));
    let d = refused("M0", &chain(MAX_PATH_DEPTH));
    assert!(
        d.reason
            .contains(&format!("nested more than {MAX_PATH_DEPTH} levels")),
        "{d}"
    );
    // And a chain far past it is refused the same way rather than overflowing
    // the stack of whatever thread called.
    let d = refused("M0", &chain(MAX_PATH_DEPTH + 5000));
    assert!(d.reason.contains("levels deep"), "{d}");
}

// ---- imports ---------------------------------------------------------------

#[test]
fn an_import_is_resolved_by_exact_name_against_the_list() {
    let text = declare(
        "m.Root",
        &[
            (
                "m/root.proto",
                "syntax = \"proto3\";\npackage m;\nimport \"common/types.proto\";\n\
                 message Root { common.Stamp at = 1; }\n",
            ),
            (
                "common/types.proto",
                "syntax = \"proto3\";\npackage common;\nmessage Stamp { int64 secs = 1; int32 nanos = 2; }\n",
            ),
        ],
    )
    .expect("declares");
    assert_eq!(
        lines(&text),
        [
            "demo/sensor=protobuf",
            "demo/sensor:1=at",
            "demo/sensor:1.1=secs",
            "demo/sensor:1.2=nanos",
        ]
    );
}

#[test]
fn an_import_that_is_not_in_the_list_is_blamed_at_the_import() {
    let d = declare(
        "M",
        &[(
            "a.proto",
            "syntax = \"proto3\";\nimport \"b.proto\";\nmessage M {}\n",
        )],
    )
    .expect_err("refused");
    assert_eq!(d.file.as_deref(), Some("a.proto"));
    assert_eq!((d.line, d.column), (Some(2), Some(1)));
    assert!(d.reason.contains("not among the files given"), "{d}");
    // A path that only differs by a leading `./` is a different name.
    let d = declare(
        "M",
        &[
            (
                "a.proto",
                "syntax = \"proto3\";\nimport \"./b.proto\";\nmessage M {}\n",
            ),
            ("b.proto", "syntax = \"proto3\";\n"),
        ],
    )
    .expect_err("refused");
    assert_eq!(d.line, Some(2));
}

#[test]
fn a_type_from_a_file_that_is_not_imported_directly_is_refused() {
    let files = |mid: &'static str| {
        [
            ("a.proto", mid),
            (
                "mid.proto",
                "syntax = \"proto3\";\nimport \"leaf.proto\";\n",
            ),
            (
                "leaf.proto",
                "syntax = \"proto3\";\nmessage Leaf { int32 x = 1; }\n",
            ),
        ]
    };
    // `mid` imports `leaf` plainly, so `a` cannot name `Leaf` through it.
    let d = declare(
        "U",
        &files("syntax = \"proto3\";\nimport \"mid.proto\";\nmessage U { Leaf l = 1; }\n"),
    )
    .expect_err("refused");
    assert_eq!(d.file.as_deref(), Some("a.proto"));
    assert_eq!(d.line, Some(3));
    assert!(d.reason.contains("not imported by \"a.proto\""), "{d}");
    // Importing it directly is the fix.
    declare(
        "U",
        &files("syntax = \"proto3\";\nimport \"mid.proto\";\nimport \"leaf.proto\";\nmessage U { Leaf l = 1; }\n"),
    )
    .expect("declares");
}

#[test]
fn import_public_re_exports_and_only_import_public_does() {
    let a = "syntax = \"proto3\";\nimport \"mid.proto\";\nmessage U { Leaf l = 1; }\n";
    let leaf = "syntax = \"proto3\";\nmessage Leaf { int32 x = 1; }\n";
    let text = declare(
        "U",
        &[
            ("a.proto", a),
            (
                "mid.proto",
                "syntax = \"proto3\";\nimport public \"leaf.proto\";\n",
            ),
            ("leaf.proto", leaf),
        ],
    )
    .expect("a public import is visible through its importer");
    assert!(text.contains(":1.1=x"), "{text}");
}

#[test]
fn a_root_message_may_live_in_an_imported_file() {
    let text = declare(
        "leaf.Leaf",
        &[
            ("a.proto", "syntax = \"proto3\";\nimport \"leaf.proto\";\n"),
            (
                "leaf.proto",
                "syntax = \"proto3\";\npackage leaf;\nmessage Leaf { int32 x = 1; }\n",
            ),
        ],
    )
    .expect("declares");
    assert!(text.contains(":1=x"));
}

#[test]
fn a_file_nothing_imports_is_not_read_even_if_it_is_broken() {
    declare(
        "M",
        &[
            (
                "a.proto",
                "syntax = \"proto3\";\nmessage M { int32 x = 1; }\n",
            ),
            ("unrelated.proto", "this is not a proto file"),
        ],
    )
    .expect("an unreferenced file is ignored");
}

#[test]
fn an_import_cycle_is_blamed_where_it_starts_with_the_chain() {
    let d = declare(
        "A",
        &[
            (
                "c1.proto",
                "syntax = \"proto3\";\nimport \"c2.proto\";\nmessage A {}\n",
            ),
            (
                "c2.proto",
                "syntax = \"proto3\";\nimport \"c1.proto\";\nmessage B {}\n",
            ),
        ],
    )
    .expect_err("refused");
    assert_eq!(d.file.as_deref(), Some("c1.proto"));
    assert_eq!(d.line, Some(2));
    assert!(d.reason.contains("c1.proto -> c2.proto -> c1.proto"), "{d}");
    let d = declare(
        "A",
        &[(
            "self.proto",
            "syntax = \"proto3\";\nimport \"self.proto\";\nmessage A {}\n",
        )],
    )
    .expect_err("refused");
    assert_eq!((d.file.as_deref(), d.line), (Some("self.proto"), Some(2)));
}

#[test]
fn importing_the_same_file_twice_is_refused_at_the_second_import() {
    let d = declare(
        "A",
        &[
            (
                "a.proto",
                "syntax = \"proto3\";\nimport \"b.proto\";\nimport \"b.proto\";\nmessage A {}\n",
            ),
            ("b.proto", "syntax = \"proto3\";\n"),
        ],
    )
    .expect_err("refused");
    assert_eq!(d.line, Some(3));
    assert!(d.reason.contains("listed twice"), "{d}");
}

#[test]
fn an_imported_files_own_problem_is_blamed_in_that_file_and_before_the_importers() {
    // `a` has a semantic problem at line 3 and `b` a syntax error at line 2.
    // protoc builds the import first, so it is `b` that is reported.
    let d = declare(
        "A",
        &[
            (
                "a.proto",
                "syntax = \"proto3\";\nimport \"b.proto\";\nmessage A { Missing m = 1; }\n",
            ),
            (
                "b.proto",
                "syntax = \"proto3\";\nmessage B { int32 = 1; }\n",
            ),
        ],
    )
    .expect_err("refused");
    assert_eq!(d.file.as_deref(), Some("b.proto"));
    assert_eq!(d.line, Some(2));
}

#[test]
fn a_syntax_error_beats_a_semantic_one_earlier_in_the_same_file() {
    let d = refused(
        "M",
        "syntax = \"proto3\";\nmessage M {\n  int32 a = 0;\n  int32 b = 2\n  int32 c = 3;\n}\n",
    );
    assert_eq!(
        d.line,
        Some(5),
        "the missing `;` is reported, not the zero at line 3: {d}"
    );
}

#[test]
fn a_problem_in_a_message_the_root_never_reaches_is_still_a_problem() {
    // protoc refuses the whole file, and so does this reader: a schema that
    // does not compile is not one whose names can be trusted.
    let d = refused(
        "Root",
        "syntax = \"proto3\";\nmessage Root { int32 a = 1; }\nmessage Other { Missing m = 1; }\n",
    );
    assert_eq!(d.line, Some(3));
}

#[test]
fn the_files_given_must_have_distinct_names() {
    let files = [
        ProtoFile {
            name: "a.proto",
            text: b"",
        },
        ProtoFile {
            name: "a.proto",
            text: b"",
        },
    ];
    let d = declarations_from_proto(KEY, "M", &files, 0).expect_err("refused");
    assert!(d.reason.contains("two files are named `a.proto`"), "{d}");
    assert_eq!(d.file, None);
}

#[test]
fn the_root_file_must_be_one_of_the_files_given() {
    let files = [ProtoFile {
        name: "a.proto",
        text: b"message M {}",
    }];
    // The first index past the end is the one a `>` for a `>=` would let in.
    let d = declarations_from_proto(KEY, "M", &files, 1).expect_err("refused");
    assert!(d.reason.contains("root file index 1"), "{d}");
    assert_eq!(d.file, None);
    let d = declarations_from_proto(KEY, "M", &[], 0).expect_err("refused");
    assert!(d.reason.contains("0 file(s)"), "{d}");
    declarations_from_proto(KEY, "M", &files, 0).expect("the control: index 0 is fine");
}

// ---- refusals that name a reason --------------------------------------------

#[test]
fn group_extend_weak_import_and_editions_are_refused_with_their_line() {
    let d = refused(
        "M",
        "syntax = \"proto2\";\nmessage M {\n  optional group G = 1 {\n    optional int32 x = 2;\n  }\n}\n",
    );
    assert_eq!(
        (d.file.as_deref(), d.line, d.column),
        (Some("a.proto"), Some(3), Some(12))
    );
    assert!(d.reason.contains("group"), "{d}");
    let d = refused(
        "M",
        "syntax = \"proto2\";\nmessage M {\n  optional int32 a = 1;\n  extensions 100 to 199;\n}\nextend M {\n  optional int32 x = 100;\n}\n",
    );
    assert_eq!(d.line, Some(6));
    assert!(d.reason.contains("`extend`"), "{d}");
    let d = declare(
        "M",
        &[
            (
                "a.proto",
                "syntax = \"proto3\";\nimport weak \"b.proto\";\nmessage M {}\n",
            ),
            ("b.proto", "syntax = \"proto3\";\n"),
        ],
    )
    .expect_err("refused");
    assert_eq!(d.line, Some(2));
    assert!(d.reason.contains("import weak"), "{d}");
    let d = refused("M", "edition = \"2023\";\nmessage M {}\n");
    assert_eq!(d.line, Some(1));
    assert!(d.reason.contains("editions"), "{d}");
}

#[test]
fn extension_ranges_alone_are_accepted_in_proto2() {
    let text = ok(
        "M",
        "syntax = \"proto2\"; message M { optional int32 a = 1; extensions 100 to max; }",
    );
    assert_eq!(lines(&text), ["demo/sensor=protobuf", "demo/sensor:1=a"]);
}

#[test]
fn comments_strings_options_services_and_whitespace_do_not_disturb_the_names() {
    let text = ok(
        "M",
        r#"// leading comment
           syntax = "proto3"; /* block */
           option java_package = "com.example";
           option (custom).nested = { a: 1 b: "}" };
           ;
           message M {}"#,
    );
    assert_eq!(lines(&text), ["demo/sensor=protobuf"]);

    let text = ok(
        "M",
        "syntax = \"proto3\";\n\
         service S { rpc Do(M) returns (M) { option deprecated = true; } }\n\
         message M {\n\
           option deprecated = true;\n\
           // int32 hidden = 9;\n\
           int32 shown = 1 [deprecated = true, (my.opt) = \"x;y\"]; /* int32 also_hidden = 8; */\n\
           string tricky = 2 [default = \"}\"];\n\
         }\n",
    );
    assert_eq!(
        lines(&text),
        [
            "demo/sensor=protobuf",
            "demo/sensor:1=shown",
            "demo/sensor:2=tricky",
        ]
    );
}

#[test]
fn field_names_are_emitted_as_written() {
    let text = ok(
        "M",
        "syntax = \"proto3\"; message M { int32 snake_case_Name2 = 1; string _lead = 2; }",
    );
    assert!(text.contains(":1=snake_case_Name2\n"));
    assert!(text.contains(":2=_lead\n"));
}

#[test]
fn lines_and_columns_count_from_one_and_columns_count_bytes() {
    let d = refused(
        "M",
        "syntax = \"proto3\";\nmessage M {\n\tint32 a = 0;\n}\n",
    );
    // A tab is one column here (protoc would say 19).
    assert_eq!((d.line, d.column), (Some(3), Some(12)));
    let d = refused(
        "M",
        "syntax = \"proto3\";\nmessage M {\n  string s = 1; // \u{e9}\n  Foo a = 2;\n}\n",
    );
    assert_eq!((d.line, d.column), (Some(4), Some(3)));
}

#[test]
fn a_byte_order_mark_and_crlf_line_ends_are_read() {
    let text = ok(
        "M",
        "\u{feff}syntax = \"proto3\";\r\nmessage M {\r\n  int32 a = 1;\r\n}\r\n",
    );
    assert!(text.contains(":1=a"));
    let d = refused(
        "M",
        "\u{feff}syntax = \"proto3\";\r\nmessage M {\r\n  Foo a = 1;\r\n}\r\n",
    );
    assert_eq!((d.line, d.column), (Some(3), Some(3)));
}

// ---- the key pattern ---------------------------------------------------------

fn with_key(
    key: &str,
    text: &str,
) -> Result<crate::proto_schema::ProtoDeclarations, ProtoDiagnostic> {
    declarations_from_proto(
        key,
        "M",
        &[ProtoFile {
            name: "a.proto",
            text: text.as_bytes(),
        }],
        0,
    )
}

const SMALL: &str =
    "syntax = \"proto3\"; message M { int32 a = 1; Inner b = 2; message Inner { bool c = 3; } }";

#[cfg(feature = "filter-wildcards")]
#[test]
fn a_wildcard_pattern_is_declared_as_written() {
    let out = with_key("demo/**", SMALL).expect("declares");
    assert_eq!(
        lines(&out.text),
        [
            "demo/**=protobuf",
            "demo/**:1=a",
            "demo/**:2=b",
            "demo/**:2.3=c",
        ]
    );
    assert_eq!(out.installed, 4);
}

/// A build whose keyexpr matcher has no wildcards cannot honour `demo/**`, and
/// the installer refuses it by name rather than matching it literally. This
/// door passes that refusal on in the installer's words instead of handing back
/// text that would fail the first time it was used.
#[cfg(not(feature = "filter-wildcards"))]
#[test]
fn a_wildcard_this_build_cannot_match_is_refused_in_the_installers_words() {
    let d = with_key("demo/**", SMALL).expect_err("refused");
    assert_eq!(d.file, None);
    assert!(
        d.reason.contains("the key pattern cannot be declared"),
        "{d}"
    );
    assert!(d.reason.contains("filter-wildcards"), "{d}");
}

#[test]
fn the_characters_the_dialect_reserves_are_quoted_for_the_caller() {
    // The pattern is a key expression, not declaration text: the `:` in it
    // would otherwise read back as the separator of a field-name line.
    let out = with_key("demo/temp:c", SMALL).expect("declares");
    assert_eq!(out.text.lines().next(), Some("demo/temp\\:c=protobuf"));
    let mut map = FormatMap::new();
    assert_eq!(map.declare_all(&out.text).expect("installs"), out.installed);
    assert_eq!(
        map.field_name("demo/temp:c", "2.3").map(|(_, name)| name),
        Some("c")
    );
    let out = with_key("a=b/c\\d", SMALL).expect("declares");
    let mut map = FormatMap::new();
    map.declare_all(&out.text).expect("installs");
    assert_eq!(map.field_name("a=b/c\\d", "1").map(|(_, n)| n), Some("a"));
}

#[test]
fn a_key_pattern_the_installer_refuses_is_refused_in_its_words() {
    let d = with_key("/leading", SMALL).expect_err("refused");
    assert_eq!(d.file, None);
    assert!(
        d.reason.contains("the key pattern cannot be declared"),
        "{d}"
    );
    assert!(d.reason.contains("/leading"), "{d}");
    let d = with_key("", SMALL).expect_err("refused");
    assert!(d.reason.contains("empty"), "{d}");
    let d = with_key("demo/a\nother=cbor", SMALL).expect_err("refused");
    assert!(d.reason.contains("line break"), "{d}");
    let d = with_key("demo/a\r", SMALL).expect_err("refused");
    assert!(d.reason.contains("line break"), "{d}");
}

#[test]
fn what_comes_out_installs_unchanged_and_the_names_reach_the_decoder_paths() {
    // A message with a nested message, built on the wire by hand, decoded by
    // the schemaless decoder, and named by the declarations: the paths the
    // decoder reports are exactly the paths the declarations address.
    let schema = r#"syntax = "proto3";
        message M {
          int32 value = 1;
          Meta meta = 3;
          message Meta { string tag = 2; }
        }"#;
    let out = with_key("demo/sensor", schema).expect("declares");
    let mut map = FormatMap::new();
    assert_eq!(map.declare_all(&out.text).expect("installs"), out.installed);

    // field 1 = 150, field 3 = { field 2 = "hi" }
    let wire = [0x08, 0x96, 0x01, 0x1a, 0x04, 0x12, 0x02, b'h', b'i'];
    let fields = Protobuf.decode(&wire).expect("a protobuf message");
    let named: Vec<(String, Option<String>)> = fields
        .iter()
        .map(|f| {
            (
                f.path.clone(),
                map.field_name("demo/sensor", &f.path)
                    .map(|(_, n)| n.to_string()),
            )
        })
        .collect();
    assert_eq!(
        named,
        [
            ("1".to_string(), Some("value".to_string())),
            ("3".to_string(), Some("meta".to_string())),
            ("3.2".to_string(), Some("tag".to_string())),
        ]
    );
    let (_, rule) = map.for_keyexpr("demo/sensor").expect("the rule matches");
    assert_eq!(rule.name(), "protobuf");
}

// ---- text and display ------------------------------------------------------

#[test]
fn bytes_that_are_not_utf8_are_blamed_where_they_stop_and_only_when_read() {
    let broken: &[u8] = b"syntax = \"proto3\";\n// line two \xff\nmessage M {}\n";
    let files = [ProtoFile {
        name: "a.proto",
        text: broken,
    }];
    let d = declarations_from_proto(KEY, "M", &files, 0).expect_err("refused");
    assert_eq!(
        (d.file.as_deref(), d.line, d.column),
        (Some("a.proto"), Some(2), Some(13))
    );
    assert!(d.reason.contains("UTF-8"), "{d}");

    // The same bytes in a file nothing imports are never looked at.
    let files = [
        ProtoFile {
            name: "a.proto",
            text: b"syntax = \"proto3\";\nmessage M {}\n",
        },
        ProtoFile {
            name: "unread.proto",
            text: broken,
        },
    ];
    declarations_from_proto(KEY, "M", &files, 0).expect("an unread file is not judged");

    // And an imported one is read, and blamed under its own name.
    let files = [
        ProtoFile {
            name: "a.proto",
            text: b"syntax = \"proto3\";\nimport \"b.proto\";\nmessage M {}\n",
        },
        ProtoFile {
            name: "b.proto",
            text: broken,
        },
    ];
    let d = declarations_from_proto(KEY, "M", &files, 0).expect_err("refused");
    assert_eq!((d.file.as_deref(), d.line), (Some("b.proto"), Some(2)));
}

#[test]
fn a_nul_byte_in_the_text_is_a_lexical_refusal_with_a_position() {
    let d = refused(
        "M",
        "syntax = \"proto3\";\nmessage M { int32 a = 1; \u{0} }\n",
    );
    assert_eq!((d.line, d.column), (Some(2), Some(26)));
    assert!(d.reason.contains("0x00"), "{d}");
}

#[test]
fn a_diagnostic_reads_as_one_line_in_each_of_its_three_shapes() {
    let at = ProtoDiagnostic {
        file: Some("a.proto".to_string()),
        line: Some(3),
        column: Some(9),
        reason: "boom".to_string(),
    };
    assert_eq!(at.to_string(), "a.proto: line 3: boom");
    let whole = ProtoDiagnostic {
        file: Some("a.proto".to_string()),
        line: None,
        column: None,
        reason: "boom".to_string(),
    };
    assert_eq!(whole.to_string(), "a.proto: boom");
    let none = ProtoDiagnostic {
        file: None,
        line: None,
        column: None,
        reason: "boom".to_string(),
    };
    assert_eq!(none.to_string(), "boom");
}

#[test]
fn the_first_declaration_line_is_the_rule_and_every_line_ends_in_a_newline() {
    let out = with_key("k", SMALL).expect("declares");
    assert!(out.text.starts_with("k=protobuf\n"));
    assert!(out.text.ends_with('\n'));
    assert_eq!(out.text.lines().count(), out.installed);
    // Two results concatenate into one valid text: no line is left open.
    let both = format!(
        "{}{}",
        out.text,
        with_key("other", SMALL).expect("declares").text
    );
    let mut map = FormatMap::new();
    assert_eq!(map.declare_all(&both).expect("installs"), out.installed * 2);
}

#[test]
fn the_text_of_a_big_flat_message_declares_every_field_once() {
    let mut schema = String::from("syntax = \"proto3\";\nmessage M {\n");
    for i in 1..=2000u32 {
        schema.push_str(&format!("  int32 f{i} = {i};\n"));
    }
    schema.push_str("}\n");
    let out = with_key("k", &schema).expect("declares");
    assert_eq!(out.installed, 2001);
}
