// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `closes` key of a `ResponseFinal`'s `carried` entry: which request the
//! final closed.
//!
//! What is held here is the three answers the key gives (an object for a paired
//! final, `null` for one whose request the capture does not hold, absent on every
//! other entry), that a row batching several records is told apart by the record's
//! place in it, that the pairing is the same under any selector, and that a walk
//! that continues from where the last one stopped still names a request it does
//! not visit again.
//!
//! Every test runs over BOTH link kinds: a stream flow and a datagram flow are two
//! row producers with their own loops, and a test over one would leave the other's
//! wiring unwatched.

use alloc::vec::Vec;

use wz_session_core::json5::{self, Json5Value};

use crate::datagram_tests::{frame_carrying, sender_space};
use crate::e2e_row_tests::{Link, Wire, LINKS};
use crate::exchange::tests::{request_put, request_query, response_final, response_reply};
use crate::fields_json::{
    fields_json, fields_json_since_coordinated, fields_json_since_remembering,
    fields_json_where_coordinated, FieldsMemory, RowCoordinates, Since,
};
use crate::filter::Filter;
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

/// Every message row of every flow of the document, in document order.
fn rows(doc: &str) -> Vec<Json5Value> {
    let value = json5::parse(doc).expect("the document is JSON");
    let mut out = Vec::new();
    for flows in ["stream_flows", "datagram_flows"] {
        if let Some(Json5Value::Array(flows)) = get(&value, flows) {
            for flow in flows {
                if let Some(Json5Value::Array(messages)) = get(flow, "messages") {
                    out.extend(messages.iter().cloned());
                }
            }
        }
    }
    out
}

/// The `carried` entries of a row whose `message` is `ResponseFinal`.
fn finals(row: &Json5Value) -> Vec<&Json5Value> {
    match get(row, "carried") {
        Some(Json5Value::Array(entries)) => entries
            .iter()
            .filter(|e| word(get(e, "message")) == Some("ResponseFinal"))
            .collect(),
        _ => Vec::new(),
    }
}

/// Whether EVERY `carried` entry of the row has a `closes` key and every one that
/// is not a `ResponseFinal` reads `null`: the key is structural, as `body` is.
fn only_finals_say_anything(row: &Json5Value) -> bool {
    match get(row, "carried") {
        Some(Json5Value::Array(entries)) => entries.iter().all(|e| {
            matches!(
                (word(get(e, "message")), get(e, "closes")),
                (Some("ResponseFinal"), Some(_)) | (Some(_), Some(Json5Value::Null))
            )
        }),
        _ => false,
    }
}

fn number(value: Option<&Json5Value>) -> Option<u64> {
    match value? {
        Json5Value::Number(n) => n.parse().ok(),
        _ => None,
    }
}

fn word(value: Option<&Json5Value>) -> Option<&str> {
    match value? {
        Json5Value::String(s) => Some(s.as_str()),
        _ => None,
    }
}

const KEY: &str = "demo/q";

/// Two handshakes, then a request, a reply and the final that closes it, each in
/// a Frame of its own.
fn exchange(link: Link, rid: u64) -> Wire {
    let mut wire = Wire::new(link, true);
    wire.send(
        true,
        None,
        &frame_carrying(&request_query(rid, sender_space(0, Some(KEY)))),
    );
    wire.send(
        false,
        None,
        &frame_carrying(&response_reply(rid, sender_space(0, Some(KEY)), b"x")),
    );
    wire.send(false, None, &frame_carrying(&response_final(rid)));
    wire
}

/// The documents the field document's pins read to reach `closes` and the keys
/// inside it, and to measure `request_kind` over MORE THAN ONE word: a put request
/// and a query request, each closed, and a final whose request the capture does not
/// hold. One through the numbering door (so `request_seq` is a number) and one
/// through the capture door (so it is `null`), over a STREAM link.
///
/// Stream only, for the reason `e2e_row_tests::pin_documents` gives: the key-set pin
/// these feed has never held the keys a datagram flow's document carries of its own
/// (`disagreements`). [`datagram_pin_documents`] is the same population over a
/// datagram link, for the gates that read shapes and not the key set.
pub(crate) fn pin_documents() -> Vec<alloc::string::String> {
    documents_over(Link::Tcp)
}

/// [`pin_documents`] over a datagram link, which writes its rows from the other row
/// producer.
pub(crate) fn datagram_pin_documents() -> Vec<alloc::string::String> {
    documents_over(Link::Udp)
}

fn documents_over(link: Link) -> Vec<alloc::string::String> {
    let mut out = Vec::new();
    {
        let mut wire = Wire::new(link, true);
        wire.send(
            true,
            None,
            &frame_carrying(&request_put(1, sender_space(0, Some(KEY)), b"v")),
        );
        wire.send(false, None, &frame_carrying(&response_final(1)));
        wire.send(
            true,
            None,
            &frame_carrying(&request_query(2, sender_space(0, Some(KEY)))),
        );
        wire.send(
            false,
            None,
            &frame_carrying(&response_reply(2, sender_space(0, Some(KEY)), b"x")),
        );
        wire.send(false, None, &frame_carrying(&response_final(2)));
        wire.send(false, None, &frame_carrying(&response_final(9)));
        out.push(fields_json(&wire.d, &wire.file(), None, None));
        // Through the selector door with a numbering, whose rows are the shape the
        // declared `carries` axis already measures (a number and a verdict); the
        // since door's unselected, numbered rows are a shape no population has
        // held, and this is not the round to widen the axis for it.
        let every = Filter::parse("bytes >= 0").expect("a selector that asks");
        out.push(fields_json_where_coordinated(
            &wire.d,
            &wire.file(),
            None,
            None,
            &every,
            &Numbered,
        ));
    }
    out
}

fn since_all(wire: &Wire, through_seq: u64) -> alloc::string::String {
    fields_json_since_coordinated(
        &wire.d,
        &wire.file(),
        None,
        &Numbered,
        Since {
            after_seq: 0,
            through_seq,
        },
    )
}

/// A paired final names its request's kind, the `seq` of the request's row and its
/// place in that row; every other entry carries no `closes` key at all.
#[test]
fn a_paired_final_names_the_request_it_closed_and_no_other_entry_says_anything() {
    for link in LINKS {
        let wire = exchange(link, 7);
        let doc = since_all(&wire, 5);
        let rows = rows(&doc);
        assert_eq!(rows.len(), 5, "{link:?}: {doc}");
        // Rows: init, init, request, reply, final.
        let request_seq = number(get(&rows[2], "seq")).expect("a numbered request row");
        let finals_of_row = finals(&rows[4]);
        assert_eq!(finals_of_row.len(), 1, "{link:?}: {doc}");
        let closes = get(finals_of_row[0], "closes").unwrap_or_else(|| panic!("{link:?}: {doc}"));
        assert_eq!(word(get(closes, "request_kind")), Some("query"), "{link:?}");
        assert_eq!(
            number(get(closes, "request_seq")),
            Some(request_seq),
            "{link:?}: the request's own row number"
        );
        assert_eq!(number(get(closes, "request_record")), Some(0), "{link:?}");
        for (i, row) in rows.iter().enumerate() {
            assert!(
                only_finals_say_anything(row),
                "{link:?}: row {i}: every entry has `closes`, and `null` unless it is a final: {doc}"
            );
        }
    }
}

/// A final whose request the capture does not hold says so with an object of
/// nulls, which is not the `null` of an entry that is no final: the key is there on
/// both, and only a final has an object to be empty.
#[test]
fn a_final_with_no_request_in_the_capture_says_nothing_to_name() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        wire.send(false, None, &frame_carrying(&response_final(9)));
        let doc = since_all(&wire, 3);
        let rows = rows(&doc);
        assert_eq!(rows.len(), 3, "{link:?}: {doc}");
        let finals_of_row = finals(&rows[2]);
        assert_eq!(finals_of_row.len(), 1, "{link:?}: {doc}");
        let closes = get(finals_of_row[0], "closes").unwrap_or_else(|| panic!("{link:?}: {doc}"));
        for key in ["request_kind", "request_seq", "request_record"] {
            assert_eq!(
                get(closes, key),
                Some(&Json5Value::Null),
                "{link:?}: {key} of an orphan: {doc}"
            );
        }
        assert!(only_finals_say_anything(&rows[2]), "{link:?}: {doc}");
    }
}

/// A capture door numbers no rows, so the request's row number is `null` beside
/// a kind that is still known.
#[test]
fn a_document_that_numbers_no_rows_still_names_the_kind() {
    for link in LINKS {
        let wire = exchange(link, 7);
        let doc = fields_json(&wire.d, &wire.file(), None, None);
        let rows = rows(&doc);
        let finals_of_row = finals(&rows[4]);
        assert_eq!(finals_of_row.len(), 1, "{link:?}: {doc}");
        let closes = get(finals_of_row[0], "closes").unwrap_or_else(|| panic!("{link:?}: {doc}"));
        assert_eq!(word(get(closes, "request_kind")), Some("query"), "{link:?}");
        assert_eq!(
            get(closes, "request_seq"),
            Some(&Json5Value::Null),
            "{link:?}: no row has a number to name"
        );
    }
}

/// A row batches records, and the final is told from its neighbours by the record's
/// place in the row: two requests in one Frame and two finals in another, answered
/// in the opposite order, name each other's records crosswise.
#[test]
fn two_finals_in_one_row_each_name_their_own_request() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        let mut requests = request_query(10, sender_space(0, Some(KEY)));
        requests.extend_from_slice(&request_put(11, sender_space(0, Some(KEY)), b"v"));
        wire.send(true, None, &frame_carrying(&requests));
        let mut closing = response_final(11);
        closing.extend_from_slice(&response_final(10));
        wire.send(false, None, &frame_carrying(&closing));
        let doc = since_all(&wire, 4);
        let rows = rows(&doc);
        assert_eq!(rows.len(), 4, "{link:?}: {doc}");
        let request_seq = number(get(&rows[2], "seq")).expect("a numbered request row");
        let finals_of_row = finals(&rows[3]);
        assert_eq!(finals_of_row.len(), 2, "{link:?}: {doc}");
        // The first final closes rid 11, the SECOND record of the request row, a
        // put; the second final closes rid 10, the first record, a query.
        let first = get(finals_of_row[0], "closes").unwrap_or_else(|| panic!("{link:?}: {doc}"));
        let second = get(finals_of_row[1], "closes").unwrap_or_else(|| panic!("{link:?}: {doc}"));
        assert_eq!(word(get(first, "request_kind")), Some("put"), "{link:?}");
        assert_eq!(number(get(first, "request_record")), Some(1), "{link:?}");
        assert_eq!(word(get(second, "request_kind")), Some("query"), "{link:?}");
        assert_eq!(number(get(second, "request_record")), Some(0), "{link:?}");
        for closes in [first, second] {
            assert_eq!(
                number(get(closes, "request_seq")),
                Some(request_seq),
                "{link:?}: both requests were in the same row"
            );
        }
    }
}

/// The pairing is a fact about the pair and not an answer to a selector: a
/// selector that rejects the exchange (`kind == put` against a query) leaves
/// `closes` exactly as it is without one, while the row's verdict says `no`.
#[test]
fn the_pairing_is_the_same_under_a_selector_that_rejects_the_exchange() {
    for link in LINKS {
        let wire = exchange(link, 7);
        let plain = rows(&since_all(&wire, 5));
        let filter = Filter::parse("kind == put").expect("the selector parses");
        let selected = rows(&fields_json_where_coordinated(
            &wire.d,
            &wire.file(),
            None,
            None,
            &filter,
            &Numbered,
        ));
        assert_eq!(selected.len(), plain.len(), "{link:?}");
        assert_eq!(
            get(finals(&selected[4])[0], "closes"),
            get(finals(&plain[4])[0], "closes"),
            "{link:?}: the selector moved the pairing"
        );
        assert_eq!(
            word(get(&selected[4], "selected")),
            Some("no"),
            "{link:?}: and the final follows its exchange's verdict"
        );
    }
}

/// A walk that continues from where the last one stopped does not visit the
/// request again, and still names it: the request's place is kept between calls.
#[test]
fn a_continuing_walk_names_a_request_it_does_not_visit_again() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        wire.send(
            true,
            None,
            &frame_carrying(&request_query(7, sender_space(0, Some(KEY)))),
        );
        let mut memory = FieldsMemory::new();
        let first = fields_json_since_remembering(
            &wire.d,
            &wire.file(),
            None,
            "",
            &Numbered,
            Since {
                after_seq: 0,
                through_seq: 3,
            },
            &mut memory,
        );
        let first_rows = rows(&first);
        assert_eq!(first_rows.len(), 3, "{link:?}: {first}");
        let request_seq = number(get(&first_rows[2], "seq")).expect("a numbered request row");

        wire.send(
            false,
            None,
            &frame_carrying(&response_reply(7, sender_space(0, Some(KEY)), b"x")),
        );
        wire.send(false, None, &frame_carrying(&response_final(7)));
        let second = fields_json_since_remembering(
            &wire.d,
            &wire.file(),
            None,
            "",
            &Numbered,
            Since {
                after_seq: 3,
                through_seq: 5,
            },
            &mut memory,
        );
        let second_rows = rows(&second);
        assert_eq!(second_rows.len(), 2, "{link:?}: {second}");
        let finals_of_row = finals(&second_rows[1]);
        assert_eq!(finals_of_row.len(), 1, "{link:?}: {second}");
        let closes =
            get(finals_of_row[0], "closes").unwrap_or_else(|| panic!("{link:?}: {second}"));
        assert_eq!(word(get(closes, "request_kind")), Some("query"), "{link:?}");
        assert_eq!(
            number(get(closes, "request_seq")),
            Some(request_seq),
            "{link:?}: {second}"
        );
        assert!(
            memory.stats().resumed >= 1,
            "{link:?}: the second call began again, so it proved nothing about continuing: {:?}",
            memory.stats()
        );
    }
}
