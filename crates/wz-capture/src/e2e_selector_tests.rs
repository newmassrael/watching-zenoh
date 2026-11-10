// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The selector's `e2e` fields over captures built packet by packet: that the
//! payload plane judges the frames it walks, that its words select the rows
//! whose `e2e` block says the same thing, and that a door handed no
//! declarations leaves a sample undecided rather than answering `no`.
//!
//! Every test runs over both link kinds, for the reason `e2e_row_tests` gives.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use wz_session_core::json5::{self, Json5Value};

use crate::e2e_row_tests::{damaged, frame, profile_text, Wire, LINKS};
use crate::e2e_words::{COUNTER_WORDS, CRC_WORDS, TIMEOUT_WORDS, VERDICT_WORDS};
use crate::fields_json::fields_json_where;
use crate::filter::Filter;
use crate::payload::formats::FormatMap;
use crate::payload_decode::Declarations;

const MS: u64 = 1_000_000;

fn declarations() -> String {
    format!("#prof={}\ndemo/e2e/**=prof\n", profile_text("prof", 3))
}

/// The capture every test reads: a named conversation whose low end sends one
/// stream of frames, each judged for a different reason, and one sample under a
/// key no profile rule covers.
///
/// | # | frame | crc | counter | timeout | e2e |
/// |---|---|---|---|---|---|
/// | 1 | counter 1 | ok | unjudged (first) | ok | unjudged |
/// | 2 | counter 2 | ok | none | ok | ok |
/// | 3 | counter 2 | ok | repeat | ok | error |
/// | 4 | counter 3, damaged | error | unjudged | ok | error |
/// | 5 | counter 3 | ok | none | ok | ok |
/// | 6 | counter 9 | ok | out_of_range | ok | error |
/// | 7 | counter 9 again, 500 ms later | ok | repeat | error | error |
/// | – | `demo/plain/b` | – | – | – | none |
///
/// The timeout of row 7 is an error because a repetition moves nothing, so it
/// is judged against the last valid frame's instant, row 6's; a valid frame
/// clears its own timeout however late it is ([`crate::e2e_judge`]).
fn capture(link: crate::e2e_row_tests::Link) -> Wire {
    let mut wire = Wire::new(link, true);
    wire.put(true, Some(MS), "demo/e2e/a", &frame(1, b"one"));
    wire.put(true, Some(2 * MS), "demo/e2e/a", &frame(2, b"two"));
    wire.put(true, Some(3 * MS), "demo/e2e/a", &frame(2, b"again"));
    wire.put(
        true,
        Some(4 * MS),
        "demo/e2e/a",
        &damaged(frame(3, b"hurt")),
    );
    wire.put(true, Some(5 * MS), "demo/e2e/a", &frame(3, b"three"));
    wire.put(true, Some(6 * MS), "demo/e2e/a", &frame(9, b"jump"));
    wire.put(true, Some(506 * MS), "demo/e2e/a", &frame(9, b"late"));
    wire.put(true, Some(507 * MS), "demo/plain/b", b"not a frame");
    wire
}

/// The words the table above gives each Push row, in order: `e2e`, `e2e.crc`,
/// `e2e.counter`, `e2e.timeout`, `None` for a part the record does not carry.
type Expected = (
    &'static str,
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
);

const TABLE: [Expected; 8] = [
    ("unjudged", Some("ok"), Some("unjudged"), Some("ok")),
    ("ok", Some("ok"), Some("none"), Some("ok")),
    ("error", Some("ok"), Some("repeat"), Some("ok")),
    ("error", Some("error"), Some("unjudged"), Some("ok")),
    ("ok", Some("ok"), Some("none"), Some("ok")),
    ("error", Some("ok"), Some("out_of_range"), Some("ok")),
    ("error", Some("ok"), Some("repeat"), Some("error")),
    ("none", None, None, None),
];

/// The `selected` word of every message row of `doc` whose message is a
/// `Frame` carrying a `Push`, in document order, and of every other row apart.
fn selected(doc: &str) -> (Vec<String>, Vec<String>) {
    fn walk(v: &Json5Value, pushes: &mut Vec<String>, others: &mut Vec<String>) {
        match v {
            Json5Value::Object(entries) => {
                if let (Some(_), Some(_)) = (v.get("direction"), v.get("offset_space")) {
                    let word = match v.get("selected") {
                        Some(Json5Value::String(word)) => word.clone(),
                        other => format!("{other:?}"),
                    };
                    if format!("{v:?}").contains("\"Push\"") {
                        pushes.push(word);
                    } else {
                        others.push(word);
                    }
                    return;
                }
                for (_, child) in entries {
                    walk(child, pushes, others);
                }
            }
            Json5Value::Array(items) => {
                for child in items {
                    walk(child, pushes, others);
                }
            }
            _ => {}
        }
    }
    let value = json5::parse(doc).expect("the document parses");
    let mut pushes = Vec::new();
    let mut others = Vec::new();
    walk(&value, &mut pushes, &mut others);
    (pushes, others)
}

fn document(wire: &mut Wire, declarations: Option<&str>, selector: &str) -> String {
    wire.d.finish();
    let filter = Filter::parse(selector).unwrap_or_else(|e| panic!("{selector:?}: {e}"));
    let mut map = FormatMap::new();
    if let Some(text) = declarations {
        map.declare_all(text).expect("declarations install");
    }
    let run = Declarations::new(&map);
    fields_json_where(
        &wire.d,
        &wire.file(),
        None,
        declarations.map(|_| &run),
        &filter,
    )
}

/// Every word of every field selects exactly the rows the table gives that
/// word, and a part the record does not carry is a decided `no` (`!=` is
/// `yes`), so each word's rows and its negation's rows are the Push rows split
/// in two with nothing undecided.
/// A field, its closed words, and the part of a table row it reads.
type FieldReading = (
    &'static str,
    &'static [&'static str],
    fn(&Expected) -> Option<&'static str>,
);

#[test]
fn every_word_selects_the_rows_the_judge_gave_it() {
    let fields: [FieldReading; 4] = [
        ("e2e", VERDICT_WORDS, |e| Some(e.0)),
        ("e2e.crc", CRC_WORDS, |e| e.1),
        ("e2e.counter", COUNTER_WORDS, |e| e.2),
        ("e2e.timeout", TIMEOUT_WORDS, |e| e.3),
    ];
    for link in LINKS {
        let mut wire = capture(link);
        let text = declarations();
        for (field, words, of) in fields {
            for word in words {
                let want: Vec<&str> = TABLE
                    .iter()
                    .map(|row| if of(row) == Some(*word) { "yes" } else { "no" })
                    .collect();
                let doc = document(&mut wire, Some(&text), &format!("{field} == {word}"));
                let (pushes, others) = selected(&doc);
                assert_eq!(pushes, want, "{link:?}: {field} == {word}: {doc}");
                // The two Init rows carry no record: decided, never undecided.
                assert!(
                    others.iter().all(|w| w == "no"),
                    "{link:?}: {field} == {word}: {others:?}"
                );
                let negated: Vec<&str> = want
                    .iter()
                    .map(|w| if *w == "yes" { "no" } else { "yes" })
                    .collect();
                let doc = document(&mut wire, Some(&text), &format!("{field} != {word}"));
                assert_eq!(selected(&doc).0, negated, "{link:?}: {field} != {word}");
            }
        }
    }
}

/// The words restate the block the same document writes for the same row: a
/// row the CRC field selects has `crc_error: true`, and the counter field's
/// word is the block's `counter_reason` wherever the block judged one.
#[test]
fn the_words_restate_the_block_of_the_same_row() {
    for link in LINKS {
        let mut wire = capture(link);
        let text = declarations();
        let doc = document(&mut wire, Some(&text), "e2e.crc == error");
        let (pushes, _) = selected(&doc);
        let damaged_rows: Vec<usize> = pushes
            .iter()
            .enumerate()
            .filter(|(_, w)| *w == "yes")
            .map(|(i, _)| i)
            .collect();
        assert_eq!(damaged_rows, [3], "{link:?}: {doc}");
        assert_eq!(
            doc.matches("\"crc_error\":true").count(),
            1,
            "{link:?}: one damaged frame in the blocks: {doc}"
        );
        for reason in ["repeat", "out_of_range"] {
            let doc = document(&mut wire, Some(&text), &format!("e2e.counter == {reason}"));
            let yes = selected(&doc).0.iter().filter(|w| *w == "yes").count();
            let blocks = doc
                .matches(&format!("\"counter_reason\":\"{reason}\""))
                .count();
            assert_eq!(yes, blocks, "{link:?}: {reason}: {doc}");
        }
    }
}

/// A door handed no declarations cannot say whether a sample is a frame: every
/// Push row is undecided, under a word and under its negation, while a row
/// that carries no record is still decided.
#[test]
fn a_door_handed_no_declarations_leaves_every_sample_undecided() {
    for link in LINKS {
        let mut wire = capture(link);
        for selector in ["e2e == ok", "e2e != ok", "e2e == none", "e2e.crc == error"] {
            let doc = document(&mut wire, None, selector);
            let (pushes, others) = selected(&doc);
            assert!(
                pushes.iter().all(|w| w == "undecided"),
                "{link:?}: {selector}: {pushes:?}"
            );
            assert!(
                others.iter().all(|w| w != "undecided"),
                "{link:?}: {selector}: {others:?}"
            );
        }
    }
}

/// Declarations whose rules name no profile judge nothing, and that is decided:
/// every sample reads `none`.
#[test]
fn declarations_that_name_no_profile_make_every_sample_none() {
    for link in LINKS {
        let mut wire = capture(link);
        let doc = document(&mut wire, Some("demo/**=json\n"), "e2e == none");
        assert!(
            selected(&doc).0.iter().all(|w| w == "yes"),
            "{link:?}: {doc}"
        );
    }
}

/// A word the field does not have is refused at the value, with the field
/// named; every word the field list prints is accepted.
#[test]
fn a_word_outside_a_fields_closed_set_is_refused() {
    for (field, words) in [
        ("e2e", VERDICT_WORDS),
        ("e2e.crc", CRC_WORDS),
        ("e2e.counter", COUNTER_WORDS),
        ("e2e.timeout", TIMEOUT_WORDS),
    ] {
        for word in words {
            let selector = format!("{field} == {word}");
            assert!(Filter::parse(&selector).is_ok(), "{selector}");
        }
        let selector = format!("{field} == passed");
        let err = Filter::parse(&selector).expect_err("not a word of the field");
        assert_eq!(err.at, field.len() + 4, "{selector}: {err}");
        let in_set = format!("{field} in {{{}}}", words.join(", "));
        assert!(Filter::parse(&in_set).is_ok(), "{in_set}");
    }
    // Only the equality operators: an ordering over a word is refused.
    assert!(Filter::parse("e2e < ok").is_err());
}
