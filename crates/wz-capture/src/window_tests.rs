// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A WINDOW OF THE SINCE DOCUMENT: the rows after a cursor, up to a last number.
//!
//! What is held is the whole claim a consumer builds on. The windows of a capture,
//! taken in order from the cursor each one hands back, are the rows of the one
//! document of the whole capture: none missing, none twice, and each row the
//! text the whole document gives it. A window is therefore only a way to hold the
//! document in pieces, and never a different document.
//!
//! Every test runs over BOTH link kinds, since a stream flow and a datagram flow
//! are two row producers with their own loops.

use alloc::vec::Vec;

use wz_session_core::json5::{self, Json5Value};

use crate::datagram_tests::{frame_carrying, sender_space};
use crate::e2e_row_tests::{Link, Wire, LINKS};
use crate::exchange::tests::request_query;
use crate::fields_json::{
    fields_json_since_coordinated, fields_json_since_remembering, FieldsMemory, RowCoordinates,
    Since,
};
use crate::link::FlowKey;

/// A numbering that numbers every list and every row by its produced-index plus
/// one, as a handle's would.
struct Numbered;

impl RowCoordinates for Numbered {
    fn list_id(&self, list: usize) -> Option<u64> {
        Some(list as u64)
    }

    fn scouting_list_id(&self, _flow: &FlowKey) -> Option<u64> {
        Some(u64::MAX)
    }

    fn row_seq(&self, _list: usize, produced: u64) -> Option<u64> {
        Some(produced + 1)
    }

    fn scouting_row_seq(&self, _flow: &FlowKey, produced: u64) -> Option<u64> {
        Some(produced + 1)
    }
}

fn get<'a>(value: &'a Json5Value, key: &str) -> Option<&'a Json5Value> {
    match value {
        Json5Value::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn number(value: Option<&Json5Value>) -> Option<u64> {
    match value? {
        Json5Value::Number(n) => n.parse().ok(),
        _ => None,
    }
}

/// `(seq, the row)` of every message row of the document, in document order.
fn rows(doc: &str) -> Vec<(u64, Json5Value)> {
    let value = json5::parse(doc).expect("the document is JSON");
    let mut out = Vec::new();
    for flows in ["stream_flows", "datagram_flows"] {
        if let Some(Json5Value::Array(flows)) = get(&value, flows) {
            for flow in flows {
                if let Some(Json5Value::Array(messages)) = get(flow, "messages") {
                    for row in messages {
                        out.push((
                            number(get(row, "seq")).expect("a numbered row"),
                            row.clone(),
                        ));
                    }
                }
            }
        }
    }
    out
}

/// The window the document says it covers.
fn window_of(doc: &str) -> (u64, u64) {
    let value = json5::parse(doc).expect("the document is JSON");
    let window = get(&value, "window").expect("a since document names its window");
    (
        number(get(window, "after_seq")).expect("after_seq"),
        number(get(window, "through_seq")).expect("through_seq"),
    )
}

/// Two handshakes and `queries` requests, each in a Frame of its own.
fn capture(link: Link, queries: u64) -> Wire {
    let mut wire = Wire::new(link, true);
    for rid in 0..queries {
        wire.send(
            true,
            None,
            &frame_carrying(&request_query(rid, sender_space(0, Some("demo/q")))),
        );
    }
    wire
}

const QUERIES: u64 = 10;
/// Rows: two handshakes and the queries.
const ROWS: u64 = 2 + QUERIES;

fn whole(wire: &Wire) -> alloc::string::String {
    fields_json_since_coordinated(
        &wire.d,
        &wire.file(),
        None,
        &Numbered,
        Since {
            after_seq: 0,
            through_seq: ROWS,
        },
    )
}

/// THE WINDOWS OF A CAPTURE ARE ITS DOCUMENT IN PIECES: taken in order from the
/// cursor each hands back, they hold every row once, each as the whole document
/// writes it, and no window holds more rows than it was asked for.
#[test]
fn the_windows_of_a_capture_are_its_rows_each_once_and_as_the_whole_writes_them() {
    for link in LINKS {
        let wire = capture(link, QUERIES);
        let all = rows(&whole(&wire));
        assert_eq!(all.len() as u64, ROWS, "{link:?}");

        for size in [1u64, 3, 5, ROWS, ROWS + 4] {
            let mut cursor = 0u64;
            let mut seen: Vec<(u64, Json5Value)> = Vec::new();
            let mut calls = 0;
            while cursor < ROWS {
                let through = ROWS.min(cursor + size);
                let doc = fields_json_since_coordinated(
                    &wire.d,
                    &wire.file(),
                    None,
                    &Numbered,
                    Since {
                        after_seq: cursor,
                        through_seq: through,
                    },
                );
                let window = rows(&doc);
                assert!(
                    window.len() as u64 <= size,
                    "{link:?} size {size}: a window of {size} held {} rows",
                    window.len()
                );
                assert_eq!(
                    window_of(&doc),
                    (cursor, through),
                    "{link:?} size {size}: the window says what it covers"
                );
                seen.extend(window);
                cursor = through;
                calls += 1;
                assert!(
                    calls <= ROWS,
                    "{link:?} size {size}: the cursor did not advance"
                );
            }
            // Per flow the rows come in capture order, and a document groups by
            // flow, so compare as sets keyed by `seq`.
            seen.sort_by_key(|(seq, _)| *seq);
            let mut want = all.clone();
            want.sort_by_key(|(seq, _)| *seq);
            assert_eq!(
                seen, want,
                "{link:?} size {size}: the windows' rows are not the whole document's"
            );
        }
    }
}

/// A window that ends inside the list writes nothing past its end: the rows it
/// holds are numbered at most `through_seq`, and exactly the rows after the cursor.
#[test]
fn a_window_holds_only_the_numbers_it_covers() {
    for link in LINKS {
        let wire = capture(link, QUERIES);
        let doc = fields_json_since_coordinated(
            &wire.d,
            &wire.file(),
            None,
            &Numbered,
            Since {
                after_seq: 4,
                through_seq: 7,
            },
        );
        let seqs: Vec<u64> = rows(&doc).iter().map(|(seq, _)| *seq).collect();
        assert_eq!(seqs, alloc::vec![5, 6, 7], "{link:?}: {doc}");
    }
}

/// The same claim through the door that REMEMBERS between calls, which is the one
/// a live handle uses: windows in order, with the memory carried from one to the
/// next, hold every row once and say nothing was revised. A window that cut a list
/// must not be continued from, or the rows past it would be skipped.
#[test]
fn windows_through_the_remembering_door_lose_no_row_and_revise_none() {
    for link in LINKS {
        let wire = capture(link, QUERIES);
        let all = rows(&whole(&wire));
        let mut memory = FieldsMemory::new();
        let mut cursor = 0u64;
        let mut seen: Vec<u64> = Vec::new();
        while cursor < ROWS {
            let through = ROWS.min(cursor + 3);
            let doc = fields_json_since_remembering(
                &wire.d,
                &wire.file(),
                None,
                "",
                &Numbered,
                Since {
                    after_seq: cursor,
                    through_seq: through,
                },
                &mut memory,
            );
            assert!(
                doc.contains("\"revised\":[]"),
                "{link:?}: a capture that did not grow revised a row: {doc}"
            );
            seen.extend(rows(&doc).iter().map(|(seq, _)| *seq));
            cursor = through;
        }
        seen.sort_unstable();
        let want: Vec<u64> = all.iter().map(|(seq, _)| *seq).collect::<Vec<_>>();
        let mut want = want;
        want.sort_unstable();
        assert_eq!(seen, want, "{link:?}: the windows lost or repeated a row");
    }
}
