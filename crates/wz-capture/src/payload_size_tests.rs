// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `payload_size` key of a `carried` entry (field document revision 55):
//! the census's size of the payload of the message the entry names.
//!
//! What is held here is the contract a consumer drawing bytes per keyexpr and
//! per step relies on: over one capture, the `measured` bytes of the entries
//! attributed to a keyexpr add up to that keyexpr row's `payload_bytes` in the
//! census, the entries that are `elsewhere` or `unresolved` number its
//! `unsized_payloads`, and the `unresolved` bounds add up to its
//! `unresolved_at_most_bytes`. Each of the three verdicts is reached, records
//! batched in one `Frame` are sized one by one, and a record that arrived in
//! fragments is sized on the entry of the chain it completed.
//!
//! Every test runs over BOTH link kinds: a stream flow and a datagram flow are two
//! row producers with their own loops, and a test over one would leave the other's
//! wiring unwatched.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use wz_session_core::json5::{self, Json5Value};

use crate::agg::tests::{
    record_with_body_ext, request_query_truncated, request_query_valued, BodyExt, Carrier,
};
use crate::datagram_tests::{frame_carrying, push, sender_space};
use crate::e2e_row_tests::{fragment, Wire, LINKS};
use crate::fields_json::fields_json;

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

fn word(value: Option<&Json5Value>) -> Option<&str> {
    match value? {
        Json5Value::String(s) => Some(s.as_str()),
        _ => None,
    }
}

/// Every `carried` entry of every message row of the document, a row's own and
/// a completed chain's (`above_transport.carried`), in document order.
fn entries(doc: &str) -> Vec<Json5Value> {
    let value = json5::parse(doc).expect("the document is JSON");
    let mut out = Vec::new();
    for flows in ["stream_flows", "datagram_flows"] {
        let Some(Json5Value::Array(flows)) = get(&value, flows) else {
            continue;
        };
        for flow in flows {
            let Some(Json5Value::Array(messages)) = get(flow, "messages") else {
                continue;
            };
            for row in messages {
                if let Some(Json5Value::Array(list)) = get(row, "carried") {
                    out.extend(list.iter().cloned());
                }
                let chain = get(row, "above_transport").and_then(|a| get(a, "carried"));
                if let Some(Json5Value::Array(list)) = chain {
                    out.extend(list.iter().cloned());
                }
            }
        }
    }
    out
}

/// What the entries say about one keyexpr, summed the way the census sums it.
///
/// Its own names and not the census's: `payload_measurement_lint` holds every
/// write to a census counter name to the census's one door, and this is a
/// tally the test compares against the census, not a census counter.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Summed {
    measured_entries: u64,
    /// Against the census's `payload_bytes`.
    measured_bytes: u64,
    /// Against `unsized_payloads`.
    unmeasured: u64,
    /// Against `payloads_elsewhere`.
    elsewhere: u64,
    /// Against `payloads_unresolved`.
    unresolved: u64,
    /// Against `unresolved_at_most_bytes`.
    unresolved_bound: u64,
}

/// The entries' `payload_size` summed per keyexpr. Every entry must carry the
/// key, and every non-null one must have the one shape.
fn sum_by_key(doc: &str) -> BTreeMap<String, Summed> {
    let mut out: BTreeMap<String, Summed> = BTreeMap::new();
    for entry in entries(doc) {
        let size = get(&entry, "payload_size").expect("every entry carries `payload_size`");
        if matches!(size, Json5Value::Null) {
            continue;
        }
        let bytes = get(size, "bytes").expect("`bytes` is on every size");
        let at_most = get(size, "at_most_bytes").expect("`at_most_bytes` is on every size");
        let key = word(get(&entry, "keyexpr"))
            .expect("a sized entry in these captures names its key")
            .into();
        let summed = out.entry(key).or_default();
        match word(get(size, "size_verdict")) {
            Some("measured") => {
                assert!(matches!(at_most, Json5Value::Null), "{entry:?}");
                summed.measured_entries += 1;
                summed.measured_bytes += number(Some(bytes)).expect("a measured size");
            }
            Some("elsewhere") => {
                assert!(matches!(bytes, Json5Value::Null), "{entry:?}");
                assert!(matches!(at_most, Json5Value::Null), "{entry:?}");
                summed.unmeasured += 1;
                summed.elsewhere += 1;
            }
            Some("unresolved") => {
                assert!(matches!(bytes, Json5Value::Null), "{entry:?}");
                summed.unmeasured += 1;
                summed.unresolved += 1;
                summed.unresolved_bound += number(Some(at_most)).expect("a bound");
            }
            other => panic!("`size_verdict` {other:?} is not a declared word: {entry:?}"),
        }
    }
    out
}

/// The census's keyexpr row for `key`, in the same terms.
fn census(table: &crate::agg::ThroughputTable, key: &str) -> Summed {
    let totals = table.row(key).expect("the census has a row").totals();
    Summed {
        measured_entries: 0,
        measured_bytes: totals.payload_bytes,
        unmeasured: totals.unsized_payloads as u64,
        elsewhere: totals.payloads_elsewhere as u64,
        unresolved: totals.payloads_unresolved as u64,
        unresolved_bound: totals.unresolved_at_most_bytes,
    }
}

/// One capture holding every verdict: two puts batched in one `Frame`, a put
/// whose bytes went through shared memory, a query with a value, one whose
/// value's length prefix claims more than follows it, one with no value, and a
/// put that arrived in two fragments.
fn every_verdict(link: crate::e2e_row_tests::Link) -> Wire {
    let mut wire = Wire::new(link, true);
    let batch = [
        push(sender_space(0, Some("demo/a")), b"five!"),
        push(sender_space(0, Some("demo/a")), b"seven!!"),
    ]
    .concat();
    wire.send(true, None, &frame_carrying(&batch));
    wire.send(
        true,
        None,
        &frame_carrying(&record_with_body_ext(
            Carrier::Push,
            "demo/shm",
            b"descriptor",
            BodyExt::ShmMarker,
        )),
    );
    wire.send(
        true,
        None,
        &frame_carrying(&request_query_valued(
            1,
            sender_space(0, Some("demo/q")),
            Some(b"payload"),
        )),
    );
    wire.send(
        true,
        None,
        &frame_carrying(&request_query_truncated(2, sender_space(0, Some("demo/q")))),
    );
    wire.send(
        true,
        None,
        &frame_carrying(&request_query_valued(
            3,
            sender_space(0, Some("demo/q")),
            None,
        )),
    );
    // A chain's joined payload is a batch, as a Frame's is: here, of one record.
    let large = push(sender_space(0, Some("demo/frag")), &[0xAB; 150]);
    let (head, tail) = large.split_at(large.len() / 2);
    wire.send(true, None, &fragment(0, true, head));
    wire.send(true, None, &fragment(1, false, tail));
    wire
}

/// The documents the field document's pins read to reach `payload_size` and
/// every word of `size_verdict`, over a STREAM link.
///
/// Stream only, for the reason `closes_tests::pin_documents` gives: the key-set
/// pin these feed has never held the keys a datagram flow's document carries of
/// its own. [`datagram_pin_documents`] is the same capture over a datagram
/// link, for the gates that read shapes and not the key set.
pub(crate) fn pin_documents() -> Vec<String> {
    let wire = every_verdict(crate::e2e_row_tests::Link::Tcp);
    alloc::vec![fields_json(&wire.d, &wire.file(), None, None)]
}

/// [`pin_documents`] over a datagram link, which writes its rows from the other
/// row producer.
pub(crate) fn datagram_pin_documents() -> Vec<String> {
    let wire = every_verdict(crate::e2e_row_tests::Link::Udp);
    alloc::vec![fields_json(&wire.d, &wire.file(), None, None)]
}

/// THE CONTRACT. Per keyexpr, the entries add up to the census's row: the
/// measured bytes to `payload_bytes`, the unmeasured entries to
/// `unsized_payloads`, split the same way, and the bounds to
/// `unresolved_at_most_bytes`.
///
/// The expected numbers are written out as well, so the test cannot pass on a
/// document and a census that both lost the same records.
#[test]
fn the_entries_of_each_key_add_up_to_the_census_row() {
    for link in LINKS {
        let wire = every_verdict(link);
        let doc = fields_json(&wire.d, &wire.file(), None, None);
        let summed = sum_by_key(&doc);
        let table = crate::agg::aggregate(&wire.d);
        for key in ["demo/a", "demo/shm", "demo/q", "demo/frag"] {
            // The census counts no entries, so that one field is not compared.
            let mut from_rows = summed.get(key).cloned().unwrap_or_default();
            from_rows.measured_entries = 0;
            assert_eq!(
                from_rows,
                census(&table, key),
                "{link:?}/{key}: the entries add up to the census: {doc}"
            );
        }
        let a = &summed["demo/a"];
        assert_eq!(
            (a.measured_entries, a.measured_bytes),
            (2, 12),
            "{link:?}: two records batched in one Frame are sized one by one"
        );
        assert_eq!(summed["demo/shm"].elsewhere, 1, "{link:?}");
        let q = &summed["demo/q"];
        assert_eq!(
            (q.measured_entries, q.measured_bytes, q.unresolved),
            (1, 7, 1),
            "{link:?}: a valued query is measured, a lying prefix is unresolved, \
             and a bare query is not sized at all"
        );
        assert!(q.unresolved_bound > 0, "{link:?}");
        assert_eq!(
            (
                summed["demo/frag"].measured_entries,
                summed["demo/frag"].measured_bytes
            ),
            (1, 150),
            "{link:?}: a record that arrived in fragments is sized on the chain's entry"
        );
    }
}

/// The entries that name no sized payload say `null`: a row's own entry (a
/// transport message), and a query with no value.
#[test]
fn an_entry_with_no_sized_payload_says_null() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        wire.send(
            true,
            None,
            &frame_carrying(&request_query_valued(
                3,
                sender_space(0, Some("demo/q")),
                None,
            )),
        );
        let doc = fields_json(&wire.d, &wire.file(), None, None);
        let all = entries(&doc);
        assert!(!all.is_empty(), "{link:?}: {doc}");
        for entry in &all {
            assert!(
                matches!(get(entry, "payload_size"), Some(Json5Value::Null)),
                "{link:?}: {entry:?}"
            );
        }
        assert!(
            all.iter()
                .any(|e| word(get(e, "message")) == Some("Request")),
            "{link:?}: the query has an entry of its own: {doc}"
        );
    }
}

/// WHY `payload_size` IS NOT A MEMBER OF `payload`: the walk's slot of a query
/// value includes the value's length prefix, which the census does not count.
/// A consumer that sized a payload as `end - start` would disagree with the
/// census on this very record.
#[test]
fn a_query_values_slot_is_not_its_size() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        wire.send(
            true,
            None,
            &frame_carrying(&request_query_valued(
                1,
                sender_space(0, Some("demo/q")),
                Some(b"payload"),
            )),
        );
        let doc = fields_json(&wire.d, &wire.file(), None, None);
        let query = entries(&doc)
            .into_iter()
            .find(|e| word(get(e, "message")) == Some("Request"))
            .expect("the query has an entry");
        let slot = get(&query, "payload").expect("the key");
        let (start, end) = (
            number(get(slot, "start")).expect("the walk found the slot"),
            number(get(slot, "end")).expect("the walk found the slot"),
        );
        let size = get(&query, "payload_size").expect("the key");
        assert_eq!(word(get(size, "size_verdict")), Some("measured"), "{doc}");
        assert_eq!(number(get(size, "bytes")), Some(7), "{doc}");
        assert!(
            end - start > 7,
            "{link:?}: the slot holds the length prefix as well: {doc}"
        );
    }
}
