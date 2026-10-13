// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The tests of [`crate::proto_message_list`] and its document. Corpus-free: every
//! one runs on every machine and needs no `protoc`.

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::proto_message_list::{list_proto_messages, ListedMessage};
use crate::proto_message_list_json::proto_message_list_json;
use crate::proto_schema::ProtoFile;

fn files<'a>(files: &'a [(&'a str, &'a str)]) -> Vec<ProtoFile<'a>> {
    files
        .iter()
        .map(|(name, text)| ProtoFile {
            name,
            text: text.as_bytes(),
        })
        .collect()
}

fn listed(given: &[(&str, &str)]) -> Vec<ListedMessage> {
    list_proto_messages(&files(given)).unwrap_or_else(|d| panic!("{d}"))
}

fn row(m: &ListedMessage) -> (&str, usize, &str, Option<&str>) {
    (
        m.full_name.as_str(),
        m.file_index,
        m.file.as_str(),
        m.parent.as_deref(),
    )
}

const MAIN: &str = "syntax = \"proto3\";\npackage app;\nimport \"dep.proto\";\n\
    message Outer {\n  message Inner { message Deep { int32 d = 1; } int32 i = 1; }\n  Inner inner = 1;\n  dep.Leaf leaf = 2;\n}\n\
    message Second { map<string, Outer> by_name = 1; }\n";
const DEP: &str = "syntax = \"proto3\";\npackage dep;\nmessage Leaf { int32 v = 1; }\n\
    message Unused { Leaf leaf = 1; }\n";

/// EVERY MESSAGE IS LISTED, nested ones included, in the order of the files as
/// listed and, inside a file, in declaration order: a message, then the messages
/// written inside it, then the next one of the enclosing scope. The order of the
/// files is the order handed over, and not the order the reader loaded them in
/// (an import is loaded before its importer).
#[test]
fn every_message_is_listed_in_file_order_then_declaration_order() {
    let all = listed(&[("main.proto", MAIN), ("dep.proto", DEP)]);
    let rows: Vec<_> = all.iter().map(row).collect();
    assert_eq!(
        rows,
        [
            ("app.Outer", 0, "main.proto", None),
            ("app.Outer.Inner", 0, "main.proto", Some("app.Outer")),
            (
                "app.Outer.Inner.Deep",
                0,
                "main.proto",
                Some("app.Outer.Inner")
            ),
            ("app.Second", 0, "main.proto", None),
            ("dep.Leaf", 1, "dep.proto", None),
            ("dep.Unused", 1, "dep.proto", None),
        ]
    );
    assert!(all[1].nested() && all[2].nested());
    assert!(!all[0].nested() && !all[3].nested() && !all[4].nested());

    // The same files listed the other way round list the other way round: the
    // import loads first either way.
    let swapped = listed(&[("dep.proto", DEP), ("main.proto", MAIN)]);
    let names: Vec<&str> = swapped.iter().map(|m| m.full_name.as_str()).collect();
    assert_eq!(
        names,
        [
            "dep.Leaf",
            "dep.Unused",
            "app.Outer",
            "app.Outer.Inner",
            "app.Outer.Inner.Deep",
            "app.Second"
        ]
    );
    assert_eq!(swapped[2].file_index, 1);
}

/// A map's entry type and a group's body are not messages the author declared, and
/// a message nothing reaches is listed all the same: there is no root.
#[test]
fn only_declared_messages_are_listed_reachable_or_not() {
    let all = listed(&[("main.proto", MAIN), ("dep.proto", DEP)]);
    assert!(
        !all.iter().any(|m| m.full_name.contains("ByName")),
        "a map entry is not a declared message"
    );
    assert!(all.iter().any(|m| m.full_name == "dep.Unused"));
}

/// A `group` and an `extend` are refusals only when a root reaches them; with no
/// root they are not, and an extension's own message is listed.
#[test]
fn a_group_or_an_extend_is_not_a_refusal_without_a_root() {
    let all = listed(&[(
        "g.proto",
        "syntax = \"proto2\";\nmessage Base { optional group G = 1 { optional int32 q = 1; } extensions 100 to 199; }\n\
         extend Base { optional int32 more = 100; }\n",
    )]);
    let names: Vec<&str> = all.iter().map(|m| m.full_name.as_str()).collect();
    assert!(names.contains(&"Base"), "{names:?}");
}

/// The refusals are the shared reader's: a syntax error, an import that is not
/// among the files, a type that is not defined, and two files with one name.
#[test]
fn the_refusals_are_the_shared_readers() {
    let refused = |given: &[(&str, &str)]| {
        list_proto_messages(&files(given))
            .expect_err("refused")
            .to_string()
    };
    assert!(refused(&[("a.proto", "syntax = \"proto3\"; message {")]).contains("a.proto"));
    assert!(
        refused(&[("a.proto", "syntax = \"proto3\"; import \"nope.proto\";")])
            .contains("is not among the files given")
    );
    assert!(
        refused(&[("a.proto", "syntax = \"proto3\"; message M { Nope n = 1; }")])
            .contains("\"Nope\" is not defined")
    );
    assert!(
        refused(&[("a.proto", "syntax = \"proto3\";"), ("a.proto", "")])
            .contains("two files are named")
    );
    // A file nothing imports is read too, so its error is found.
    assert!(refused(&[
        ("ok.proto", "syntax = \"proto3\"; message A {}"),
        (
            "lonely.proto",
            "syntax = \"proto3\"; message B { Nope n = 1; }"
        ),
    ])
    .contains("lonely.proto"));
}

/// No files give an empty list, and the document says so.
#[test]
fn no_files_give_an_empty_list() {
    assert!(list_proto_messages(&[]).expect("empty").is_empty());
    assert_eq!(
        proto_message_list_json(&[]),
        format!(
            "{{{},\"ok\":true,\"messages\":[]}}",
            crate::doc_revision::envelope(crate::doc_revision::PROTO_MESSAGE_LIST)
        )
    );
}

/// THE DOCUMENT: five members on every row, `parent` null at the top level, and
/// `nested` its boolean.
#[test]
fn the_document_has_one_shape_for_every_row() {
    let doc = proto_message_list_json(&files(&[("main.proto", MAIN), ("dep.proto", DEP)]));
    let head = crate::doc_revision::envelope(crate::doc_revision::PROTO_MESSAGE_LIST);
    assert!(
        doc.starts_with(&format!("{{{head},\"ok\":true,\"messages\":[")),
        "{doc}"
    );
    for want in [
        "{\"full_name\":\"app.Outer\",\"file\":\"main.proto\",\"file_index\":0,\"parent\":null,\"nested\":false}",
        "{\"full_name\":\"app.Outer.Inner\",\"file\":\"main.proto\",\"file_index\":0,\"parent\":\"app.Outer\",\"nested\":true}",
        "{\"full_name\":\"dep.Unused\",\"file\":\"dep.proto\",\"file_index\":1,\"parent\":null,\"nested\":false}",
    ] {
        assert!(doc.contains(want), "{want}\n{doc}");
    }
    assert_eq!(doc.matches("\"full_name\"").count(), 6);
}

/// A refusal is a document with the place keys that apply and no `null`, the keys
/// the `proto_message` document gives.
#[test]
fn a_refusal_carries_the_place_keys_that_apply_and_no_null() {
    let doc = proto_message_list_json(&files(&[("a.proto", "syntax = \"proto3\"; message {")]));
    assert!(doc.contains("\"ok\":false"), "{doc}");
    for key in [
        "\"file\":\"a.proto\"",
        "\"line\":",
        "\"column\":",
        "\"reason\":",
        "\"message\":",
    ] {
        assert!(doc.contains(key), "{key}\n{doc}");
    }
    assert!(!doc.contains("null"), "{doc}");
    // A problem with an argument names no file and no place.
    let arg = proto_message_list_json(&files(&[("a.proto", ""), ("a.proto", "")]));
    assert!(
        arg.contains("\"ok\":false") && !arg.contains("\"file\""),
        "{arg}"
    );
}
