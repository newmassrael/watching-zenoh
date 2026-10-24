// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The format language's own rules, one assertion each. The comparison with upstream's crate is
//! `conformance/differential`; these hold the crate to the documented behaviour where none is linked.

use alloc::string::ToString;

use super::*;

fn ke(s: &str) -> &keyexpr {
    keyexpr::new(s).unwrap()
}

#[test]
fn a_spec_is_named_patterned_and_may_have_a_default() {
    let format = KeFormat::new("a/${a:*}/b/$#{b:**}#/c").unwrap();
    let segments = format.storage.segments();
    assert_eq!(segments[0].prefix(), Some(ke("a")));
    assert_eq!(segments[0].id(), "a");
    assert_eq!(segments[0].pattern().as_str(), "*");
    assert_eq!(segments[1].prefix(), Some(ke("b")));
    assert_eq!(segments[1].id(), "b");
    assert_eq!(segments[1].pattern().as_str(), "**");
    assert_eq!(format.suffix, "/c");
    let with_default = KeFormat::new("${t:a/*#dflt}").unwrap();
    let segment = with_default.storage.segments()[0];
    assert_eq!(segment.pattern().as_str(), "a/*");
    assert_eq!(segment.default().map(keyexpr::as_str), Some("dflt"));
    assert_eq!(segment.id(), "t");
}

#[test]
fn a_format_that_breaks_a_rule_is_refused() {
    for bad in [
        "${a:*}${b:*}",
        "x${a:*}",
        "${a:*}x",
        "${a:*}/${a:**}",
        "${a}",
        "${a:}",
        "${a:*",
        "${a:*#}x",
        "$x",
        "a/*/${a:*}",
        "${a:#bad}",
    ] {
        assert!(KeFormat::new(bad).is_err(), "`{bad}`");
    }
}

#[test]
fn a_formatter_builds_what_the_patterns_allow() {
    let format = KeFormat::new("a/${a:*}/b/$#{b:**}#/c").unwrap();
    let built = format
        .formatter()
        .set("a", 1)
        .unwrap()
        .set("b", "hi/there")
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(built.as_str(), "a/1/b/hi/there/c");
    let empty_double_wild = format
        .formatter()
        .set("a", 1)
        .unwrap()
        .set("b", "")
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(empty_double_wild.as_str(), "a/1/b/c");
    let mut formatter = format.formatter();
    assert_eq!(
        formatter.set("nope", 1).unwrap_err(),
        FormatSetError::InvalidId
    );
    assert_eq!(
        formatter.set("a", "x/y").unwrap_err(),
        FormatSetError::PatternNotMatched
    );
    assert_eq!(
        formatter.set("a", "").unwrap_err(),
        FormatSetError::PatternNotMatched
    );
    assert!(formatter.build().is_err());
    formatter.set("a", 5).unwrap().set("b", "q").unwrap();
    assert_eq!(formatter.get("a"), Some("5"));
    formatter.set("a", 6).unwrap();
    assert_eq!(formatter.get("a"), Some("6"));
    assert_eq!(formatter.get("b"), Some("q"));
    formatter.clear();
    assert_eq!(formatter.get("a"), None);
}

#[test]
fn a_default_fills_what_was_not_set() {
    let format = KeFormat::new("a/${t:*#d}/z").unwrap();
    assert_eq!(format.formatter().build().unwrap().as_str(), "a/d/z");
    let mut formatter = format.formatter();
    formatter.set("t", "q").unwrap();
    assert_eq!(formatter.build().unwrap().as_str(), "a/q/z");
}

#[test]
fn parsing_is_greedy_from_the_left() {
    let format = KeFormat::new("${a:**}/-/${b:**}").unwrap();
    let parsed = format.parse(ke("hey/-/-/there")).unwrap();
    assert_eq!(parsed.get("a").unwrap(), "hey/-");
    assert_eq!(parsed.get("b").unwrap(), "there");
    let format = KeFormat::new("${a:**}/${b:**}").unwrap();
    assert_eq!(
        format.parse(ke("a/b/c")).unwrap().get("a").unwrap(),
        "a/b/c"
    );
    assert_eq!(format.parse(ke("**")).unwrap().get("b").unwrap(), "**");
    let format = KeFormat::new("hi/${a:there}/@/${b:**}").unwrap();
    let parsed = format.parse(ke("hi/**/@")).unwrap();
    assert_eq!(parsed.get("a").unwrap(), "**");
    assert_eq!(parsed.get("b").unwrap(), "");
    assert!(KeFormat::new("a/${x:*}").unwrap().parse(ke("b/c")).is_err());
    assert!(parsed.get("nope").is_err());
}

#[test]
fn a_formatter_and_the_parser_are_inverse() {
    for spec in ["${a:*}", "a/${a:*}"] {
        for b_spec in ["b/${b:**}", "${b:**}"] {
            let text = [spec, b_spec, "c"].join("/");
            let format: KeFormat<[Segment; 2]> = KeFormat::noalloc_new(&text).unwrap();
            let mut formatter = format.formatter();
            formatter.set("a", "hi").unwrap();
            for b in ["hello", "hello/there", ""] {
                formatter.set("b", b).unwrap();
                let built = OwnedKeyExpr::try_from(&formatter).unwrap();
                let parsed = format.parse(&built).unwrap();
                assert_eq!(parsed.get("a").unwrap(), "hi");
                assert_eq!(parsed.get("b").unwrap(), b);
            }
        }
    }
}

#[test]
fn an_owned_format_and_the_iterator_work_as_the_borrowed_ones() {
    let owned: OwnedKeFormat = "x/${a:*}/${b:**}".to_string().try_into().unwrap();
    let parsed = owned.parse(ke("x/1/2/3")).unwrap();
    let pairs: alloc::vec::Vec<_> = parsed
        .iter()
        .map(|(id, v)| (id, v.map(keyexpr::as_str)))
        .collect();
    assert_eq!(pairs, [("a", Some("1")), ("b", Some("2/3"))]);
    assert_eq!(parsed.iter().len(), 2);
    assert_eq!(parsed.iter().next_back().unwrap().0, "b");
    assert_eq!(owned.to_string(), "x/${a:*}/${b:**}");
    assert_eq!(*owned, KeFormat::new("x/${a:*}/${b:**}").unwrap());
}
