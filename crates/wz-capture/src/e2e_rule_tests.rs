// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The declaration that ties a key expression pattern to a profile: how it is
//! written, how it is read back, which rule wins for a key, and what is
//! refused.
//!
//! Every profile here is synthetic, as in `e2e_tests`.

use alloc::format;
use alloc::string::String;
#[cfg(feature = "filter-wildcards")]
use alloc::vec::Vec;

use crate::e2e_frame::{build, Values};
use crate::e2e_profile::{DocError, Profile};
use crate::payload::formats::{
    declaration_text, parse_declaration, DeclarationKind, DeclarationText, FormatMap,
    FormatMapError, PayloadFormat, PayloadFormatError,
};

/// A profile on ONE line, as a declaration carries it.
fn profile_line(name: &str, counter_bytes: u32) -> String {
    format!(
        r#"{{"name": "{name}", "fields": [{{"name": "crc", "bytes": 4}}, {{"name": "length", "bytes": 2}}, {{"name": "counter", "bytes": {counter_bytes}}}, {{"name": "ident", "bytes": 2}}], "crc": {{"field": "crc", "width": 32, "poly": "0xF4ACFB13", "init": "0xFFFFFFFF", "refin": true, "refout": true, "xorout": "0xFFFFFFFF", "cover": ["length", "ident", "@payload", "counter"]}}, "length": {{"field": "length", "counts": "frame"}}, "counter": {{"field": "counter", "max_gap": 3, "timeout_ms": 100}}}}"#
    )
}

fn define(name: &str) -> String {
    format!("#{name}={}", profile_line(name, 2))
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

#[test]
fn a_profile_definition_reads_as_a_definition_and_reads_back_as_written() {
    let line = define("slot-a");
    let read = parse_declaration(&line).expect("a declaration");
    assert_eq!(
        read,
        DeclarationText::Definition {
            name: "slot-a",
            layout: &profile_line("slot-a", 2),
        }
    );
    assert_eq!(declaration_text(&read), line);
    assert_eq!(read.kind(), DeclarationKind::FormatDefinition);
}

#[test]
fn a_profile_description_may_hold_an_equals_sign_without_moving_the_cut() {
    // JSON5 admits a comment, and a comment is the one place a description can
    // hold an `=`. The record-layout rule cuts at the LAST `=`, which here is
    // inside the comment; a profile definition cuts at the first.
    let text = profile_line("slot-a", 2).replacen('{', "{ /* a=b */", 1);
    let line = format!("#slot-a={text}");
    assert_eq!(
        parse_declaration(&line).expect("a declaration"),
        DeclarationText::Definition {
            name: "slot-a",
            layout: &text,
        }
    );
    let mut map = FormatMap::new();
    map.declare(&line)
        .expect("installs despite the equals sign");
}

#[test]
fn a_record_layout_definition_is_cut_where_it_always_was() {
    // The profile branch must not change a line that is not a profile: the
    // layout grammar has no `{`.
    for (line, name, layout) in [
        (
            "#profile=tag:u8,value:u16le",
            "profile",
            "tag:u8,value:u16le",
        ),
        ("#a=b=c:u8", "a=b", "c:u8"),
    ] {
        assert_eq!(
            parse_declaration(line).expect("a declaration"),
            DeclarationText::Definition { name, layout },
            "{line}"
        );
    }
}

// Gated on the wildcard matcher: a pattern with `*` is refused without it, and
// what is asked here is how the matcher's answer picks a rule.
#[cfg(feature = "filter-wildcards")]
#[test]
fn the_first_rule_that_covers_a_key_decides_whether_it_is_a_profile_key() {
    let text = format!(
        "{}\n{}\ndemo/a/**=slot-a@pkg.Pose\ndemo/b/*=slot-b\ndemo/**=json\n",
        define("slot-a"),
        define("slot-b")
    );
    let map = map_of(&text);

    let a = map.e2e_for_keyexpr("demo/a/x/y").expect("a profile key");
    assert_eq!(a.format.profile().name(), "slot-a");
    assert_eq!(a.format.schema(), Some("pkg.Pose"));
    assert_eq!((a.rule.index, a.rule.pattern.as_str()), (0, "demo/a/**"));

    let b = map.e2e_for_keyexpr("demo/b/x").expect("a profile key");
    assert_eq!(b.format.profile().name(), "slot-b");
    assert_eq!(b.format.schema(), None);
    assert_eq!(b.rule.index, 1);

    // `*` is one chunk: `demo/b/x/y` is not covered by the second rule, so the
    // third wins, and the third is `json`, not a profile.
    assert!(map.e2e_for_keyexpr("demo/b/x/y").is_none());
    assert!(map.e2e_for_keyexpr("demo/c").is_none());
    assert!(map.e2e_for_keyexpr("other").is_none());
    // The wildcard rules are matched as key expressions: `**` covers no chunks
    // too, so the pattern `demo/a/**` covers `demo/a`.
    assert!(map.e2e_for_keyexpr("demo/a").is_some());

    // A rule AHEAD of the profile rule decides, even though the profile rule
    // also covers the key.
    let shadowed = map_of(&format!(
        "{}\ndemo/**=json\ndemo/a=slot-a\n",
        define("slot-a")
    ));
    assert!(shadowed.e2e_for_keyexpr("demo/a").is_none());
    assert_eq!(
        shadowed.matching_rule("demo/a").expect("a rule").rule.index,
        0
    );
}

#[cfg(feature = "filter-wildcards")]
#[test]
fn the_declarations_a_map_reports_read_back_into_the_same_map() {
    let text = format!(
        "{}\n{}\ndemo/a/**=slot-a@pkg.Pose\ndemo/b/*=slot-b\n",
        define("slot-a"),
        define("slot-b")
    );
    let map = map_of(&text);
    let reported: Vec<String> = map.declarations().into_iter().map(|d| d.text).collect();
    assert!(reported.contains(&String::from("demo/a/**=slot-a@pkg.Pose")));
    assert!(reported.contains(&String::from("demo/b/*=slot-b")));
    assert!(reported.contains(&define("slot-a")));
    assert!(reported.contains(&define("slot-b")));

    let again = map_of(&reported.join("\n"));
    let second: Vec<String> = again.declarations().into_iter().map(|d| d.text).collect();
    assert_eq!(second, reported);
}

#[test]
fn a_profile_rule_that_fired_marks_the_definition_it_resolved_through() {
    let map = map_of(&format!(
        "{}\n{}\ndemo/a=slot-a\n",
        define("slot-a"),
        define("slot-b")
    ));
    let rule = map.e2e_for_keyexpr("demo/a").expect("a profile key").id;
    let definition = map.definition_of(rule).expect("resolved through one");
    let declared = map.declarations();
    let named = declared
        .iter()
        .find(|d| d.id == definition)
        .expect("the definition has a declaration");
    assert_eq!(named.kind, DeclarationKind::FormatDefinition);
    assert_eq!(named.text, define("slot-a"));
    // And not the OTHER profile's.
    let other = declared
        .iter()
        .find(|d| d.text == define("slot-b"))
        .expect("slot-b is declared");
    assert_ne!(other.id, definition);
}

#[test]
fn a_pattern_that_is_refused_leaves_no_bound_format_behind() {
    let mut map = map_of(&define("slot-a"));
    map.declare("demo//x=slot-a@pkg.Lost")
        .expect_err("not a key expression");
    // A walker that skips all its work when no rule names a profile asks this;
    // a format left behind by a refused rule would make it say yes, and make
    // every capture pay for the judge's walk with nothing to judge.
    assert!(
        !map.has_e2e_rules(),
        "the refused rule left its format behind"
    );
    map.declare("demo/ok=slot-a@pkg.Kept").expect("installs");
    let ok = map.e2e_for_keyexpr("demo/ok").expect("a profile key");
    assert_eq!(ok.format.schema(), Some("pkg.Kept"));
    assert!(map.has_e2e_rules());
}

#[test]
fn what_is_refused_names_the_reason() {
    let mismatch = refusal(&format!("#other={}", profile_line("slot-a", 2)));
    assert_eq!(
        mismatch,
        FormatMapError::E2eProfileNamedElsewhere {
            declared: "other".into(),
            described: "slot-a".into(),
        }
    );

    match refusal(r#"#slot-a={"name": "slot-a"}"#) {
        FormatMapError::BadE2eProfile(name, DocError::Invalid { reason, .. }) => {
            assert_eq!(name, "slot-a");
            assert!(reason.contains("required"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        refusal("#slot-a={oops"),
        FormatMapError::BadE2eProfile(_, DocError::Syntax { .. })
    ));

    // One namespace for format names: a built-in, a described format and an
    // earlier profile all take a name.
    assert_eq!(
        refusal(&format!("#json={}", profile_line("json", 2))),
        FormatMapError::FormatNameTaken("json".into())
    );
    assert_eq!(
        refusal(&format!("{}\n{}", define("slot-a"), define("slot-a"))),
        FormatMapError::FormatNameTaken("slot-a".into())
    );
    assert_eq!(
        refusal(&format!("#slot-a=tag:u8\n{}", define("slot-a"))),
        FormatMapError::FormatNameTaken("slot-a".into())
    );

    // A description in a declaration is one line.
    let mut map = FormatMap::new();
    let two_lines = profile_line("slot-a", 2).replacen(", ", ",\n", 1);
    match map.define("slot-a", &two_lines).expect_err("refused") {
        FormatMapError::BadE2eProfile(_, DocError::Invalid { reason, .. }) => {
            assert!(reason.contains("one line"), "{reason}");
        }
        other => panic!("{other:?}"),
    }

    // A rule names a registered profile or nothing.
    match refusal(&format!("{}\ndemo=nope", define("slot-a"))) {
        FormatMapError::NoSuchFormat(name, available) => {
            assert_eq!(name, "nope");
            assert!(available.contains(&String::from("slot-a")), "{available:?}");
            assert!(available.contains(&String::from("json")), "{available:?}");
        }
        other => panic!("{other:?}"),
    }
    for schema in ["", "1x", "a..b", "a.b-c", ".a", "a."] {
        let token = format!("slot-a@{schema}");
        match refusal(&format!("{}\ndemo={token}", define("slot-a"))) {
            FormatMapError::BadBodySchema(shown, _) => assert_eq!(shown, token),
            other => panic!("{token}: {other:?}"),
        }
    }
}

#[test]
fn the_body_walk_reads_what_follows_the_header_in_payload_coordinates() {
    let map = map_of(&format!("{}\ndemo/a=slot-a\n", define("slot-a")));
    let rule = map.e2e_for_keyexpr("demo/a").expect("a profile key");
    let profile = Profile::parse(&profile_line("slot-a", 2)).expect("reads");
    let header = profile.header_bytes();

    // Field 1 as a varint, 150: the protobuf documentation's own example.
    let frame = build(
        &profile,
        &Values::new().whole("counter", 1).whole("ident", 9),
        &[0x08, 0x96, 0x01],
    )
    .expect("builds")
    .bytes;
    let fields = rule.format.decode(&frame).expect("a body");
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].path, "1");
    assert_eq!(fields[0].value, "varint 150");
    assert_eq!((fields[0].start, fields[0].end), (header, header + 3));

    // The CRC verdict is not a precondition of reading the body: a header byte
    // damaged, the body is still what it is.
    let mut damaged = frame.clone();
    damaged[0] ^= 0xFF;
    assert_eq!(rule.format.decode(&damaged).expect("a body"), fields);

    // No header, no body.
    assert_eq!(
        rule.format.decode(&frame[..header - 1]),
        Err(PayloadFormatError::Truncated(header - 1))
    );
    // A body that stops inside a field reports WHERE in the payload.
    let mut cut = frame[..header].to_vec();
    cut.extend_from_slice(&[0x08, 0x96]);
    match rule.format.decode(&cut).expect_err("truncated") {
        PayloadFormatError::Truncated(at) | PayloadFormatError::Malformed { at, .. } => {
            assert!(at >= header, "offset {at} is in body coordinates");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(rule.format.name(), "slot-a");
}

#[cfg(feature = "filter-wildcards")]
#[test]
fn the_declaration_verdict_calls_a_profile_a_format_definition() {
    let doc = crate::diagnose_json::declarations_diagnose_json(&format!(
        "{}\ndemo/**=slot-a@pkg.Pose",
        define("slot-a")
    ));
    assert!(doc.contains("\"ok\":true,\"installed\":2"), "{doc}");
    assert!(
        doc.contains("{\"line\":0,\"kind\":\"format_definition\"}"),
        "{doc}"
    );
    assert!(
        doc.contains(
            "{\"line\":1,\"kind\":\"format_rule\",\"pattern\":\"demo/**\",\"rule_index\":0}"
        ),
        "{doc}"
    );
    let refused = crate::diagnose_json::declarations_diagnose_json("#slot-a={oops");
    assert!(refused.contains("\"ok\":false,\"line\":0"), "{refused}");
    assert!(refused.contains("end-to-end profile"), "{refused}");
}
