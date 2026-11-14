// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The selection documents handed declarations: that their `e2e` words are the
//! judge's (the words the field document's rows get), that a document handed
//! none leaves every sample `undecided`, and that a selection memory is for one
//! selector under one declaration text.
//!
//! Every test runs over both link kinds, for the reason `e2e_row_tests` gives.

use alloc::format;
use alloc::string::String;

use crate::e2e_row_tests::LINKS;
use crate::e2e_selector_tests::{capture, declarations, TABLE};
use crate::fields_json::RowCoordinates;
use crate::filter::Filter;
use crate::payload::formats::FormatMap;
use crate::selection_json::{
    selection_json_where_coordinated, selection_since_json_coordinated, Declared,
    SelectionMemories, SelectionMemory, SelectionWindow,
};

/// The cursor the since documents here are asked at once every row is written:
/// above every number [`Numbered`] gives a row of these captures.
const THROUGH: u64 = 1 << 40;

/// Every list numbered by its place and every row by its list and place, so two
/// lists never share a number.
struct Numbered;

impl RowCoordinates for Numbered {
    fn list_id(&self, list: usize) -> Option<u64> {
        Some(list as u64)
    }

    fn scouting_list_id(&self, _flow: &crate::link::FlowKey) -> Option<u64> {
        None
    }

    fn row_seq(&self, list: usize, produced: u64) -> Option<u64> {
        Some(((list as u64) << 20) + produced + 1)
    }
}

/// The declarations of the capture's profile, installed.
fn installed(text: &str) -> FormatMap<'static> {
    let mut map = FormatMap::new();
    map.declare_all(text).expect("declarations install");
    map
}

/// How many rows of `doc` carry `"selected":"<word>"`.
fn count(doc: &str, word: &str) -> usize {
    doc.matches(&format!("\"selected\":\"{word}\"")).count()
}

fn since(
    wire: &crate::e2e_row_tests::Wire,
    selector: &str,
    declared: Option<Declared<'_, '_>>,
    after_seq: u64,
    memory: &mut SelectionMemory,
) -> String {
    let filter = Filter::parse(selector).unwrap_or_else(|e| panic!("{selector:?}: {e}"));
    selection_since_json_coordinated(
        &wire.d,
        &filter,
        declared,
        &Numbered,
        SelectionWindow {
            after_seq,
            through_seq: THROUGH,
        },
        memory,
    )
}

/// Under the profile's declarations the selection document decides every `e2e`
/// term over every sample: the rows that read `yes` are as many as the judge's
/// table gives that word, and no row is `undecided`.
#[test]
fn the_selection_document_decides_e2e_terms_under_declarations() {
    let text = declarations();
    let map = installed(&text);
    for link in LINKS {
        let mut wire = capture(link);
        wire.d.finish();
        for (word, want) in [
            ("ok", TABLE.iter().filter(|r| r.0 == "ok").count()),
            ("error", TABLE.iter().filter(|r| r.0 == "error").count()),
            (
                "unjudged",
                TABLE.iter().filter(|r| r.0 == "unjudged").count(),
            ),
            ("none", TABLE.iter().filter(|r| r.0 == "none").count()),
        ] {
            let selector = format!("e2e == {word}");
            let filter = Filter::parse(&selector).expect("parses");
            let doc = selection_json_where_coordinated(&wire.d, &filter, Some(&map), &Numbered);
            assert_eq!(count(&doc, "yes"), want, "{link:?}: {selector}: {doc}");
            assert_eq!(count(&doc, "undecided"), 0, "{link:?}: {selector}: {doc}");
        }
    }
}

/// Handed no declarations, the same document cannot say whether a sample is a
/// frame: every Push row is `undecided`, and no row is `yes`.
#[test]
fn the_selection_document_handed_no_declarations_leaves_every_sample_undecided() {
    for link in LINKS {
        let mut wire = capture(link);
        wire.d.finish();
        let filter = Filter::parse("e2e == error").expect("parses");
        let doc = selection_json_where_coordinated(&wire.d, &filter, None, &Numbered);
        assert_eq!(count(&doc, "undecided"), TABLE.len(), "{link:?}: {doc}");
        assert_eq!(count(&doc, "yes"), 0, "{link:?}: {doc}");
    }
}

/// An empty declaration text is not no declarations: it says no rule covers any
/// key, so every sample is decided `none`.
#[test]
fn an_empty_declaration_text_decides_every_sample_none() {
    let map = FormatMap::new();
    for link in LINKS {
        let mut wire = capture(link);
        wire.d.finish();
        let filter = Filter::parse("e2e == none").expect("parses");
        let doc = selection_json_where_coordinated(&wire.d, &filter, Some(&map), &Numbered);
        assert_eq!(count(&doc, "yes"), TABLE.len(), "{link:?}: {doc}");
        assert_eq!(count(&doc, "undecided"), 0, "{link:?}: {doc}");
    }
}

/// The since document over one memory: asked first with no declarations and
/// then under the profile, the planes begin again and every Push row the cursor
/// passed is written under `revised`, with `undecided` as what it read before.
/// Asked again under the same text, the planes go on and nothing moves.
#[test]
fn another_declaration_text_begins_the_planes_again_and_revises_the_samples() {
    let text = declarations();
    let map = installed(&text);
    let declared = Declared {
        map: &map,
        text: &text,
    };
    let errors = TABLE.iter().filter(|r| r.0 == "error").count();
    for link in LINKS {
        let mut wire = capture(link);
        wire.d.finish();
        let mut memory = SelectionMemory::default();

        let first = since(&wire, "e2e == error", None, 0, &mut memory);
        assert_eq!(count(&first, "undecided"), TABLE.len(), "{link:?}: {first}");
        let restarts = memory.work().fold.restarts;

        let judged = since(&wire, "e2e == error", Some(declared), THROUGH, &mut memory);
        assert!(judged.contains("\"rows\":[]"), "{link:?}: {judged}");
        assert_eq!(
            judged.matches("\"was\":\"undecided\"").count(),
            TABLE.len(),
            "{link:?}: every sample moved from undecided: {judged}"
        );
        assert_eq!(count(&judged, "yes"), errors, "{link:?}: {judged}");
        assert_eq!(
            memory.work().fold.restarts,
            restarts + 1,
            "{link:?}: another text began the planes again"
        );

        let again = since(&wire, "e2e == error", Some(declared), THROUGH, &mut memory);
        assert!(
            again.contains("\"rows\":[]") && again.contains("\"revised\":[]"),
            "{link:?}: {again}"
        );
        assert_eq!(
            memory.work().fold.restarts,
            restarts + 1,
            "{link:?}: the same text goes on"
        );
    }
}

/// The handle's memories are kept by selector AND declaration text: one
/// selector asked under two texts has two memories, an empty text is a third
/// apart from none, and with one memory a change of text empties it.
#[test]
fn a_memory_is_for_one_selector_under_one_declaration_text() {
    let text = declarations();
    let continued = |doc: &str| {
        if doc.contains("\"continued\":true") {
            true
        } else if doc.contains("\"continued\":false") {
            false
        } else {
            panic!("no continued in the window of {doc}")
        }
    };
    let selector = "e2e == error";
    for link in LINKS {
        let mut wire = capture(link);
        wire.d.finish();

        let mut two = SelectionMemories::default();
        assert_eq!(two.set_capacity(2), 2);
        assert!(!continued(&since(
            &wire,
            selector,
            None,
            0,
            two.for_selector(selector, Some(&text)),
        )));
        assert!(
            !continued(&since(
                &wire,
                selector,
                None,
                0,
                two.for_selector(selector, None),
            )),
            "{link:?}: the same selector with no text is another memory"
        );
        assert!(
            continued(&since(
                &wire,
                selector,
                None,
                0,
                two.for_selector(selector, Some(&text)),
            )),
            "{link:?}: the first text kept its memory beside the second"
        );
        assert!(
            !continued(&since(
                &wire,
                selector,
                None,
                0,
                two.for_selector(selector, Some("")),
            )),
            "{link:?}: an empty text is a memory of its own"
        );
        assert_eq!(two.len(), 2);
        assert_eq!(
            two.evictions(),
            1,
            "{link:?}: the least recent was given up"
        );

        let mut one = SelectionMemories::default();
        assert!(!continued(&since(
            &wire,
            selector,
            None,
            0,
            one.for_selector(selector, Some(&text)),
        )));
        assert!(!continued(&since(
            &wire,
            selector,
            None,
            0,
            one.for_selector(selector, Some("other")),
        )));
        assert!(
            !continued(&since(
                &wire,
                selector,
                None,
                0,
                one.for_selector(selector, Some(&text)),
            )),
            "{link:?}: with one memory, a change of text empties it"
        );
    }
}
