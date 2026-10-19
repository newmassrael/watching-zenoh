// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The selector's terms over a record's dissection tree: paths, presence,
//! lists, patterns and widths, judged over trees the dissection walker itself
//! built from wire bytes, and once end to end through the payload plane.

use alloc::string::ToString;

use crate::filter::{Content, Filter, FilterErrorKind, RecordKind, RecordView, Selection, Truth};
use wz_session_core::dissect::{dissect_network_message, Field};
use wz_session_core::passive::Direction;

/// A `Push` with no extension carrying an empty `Put`.
const PLAIN_PUSH: &[u8] = &[0x1D, 0x00, 0x01, 0x00];
/// A `Push` whose chain carries one `qos` (Z64, value 5: priority `Data`,
/// congestion `Drop`, not express), carrying an empty `Put`.
const QOS_PUSH: &[u8] = &[0x9D, 0x00, 0x21, 0x05, 0x01, 0x00];
/// A `Push` carrying a `Put` whose encoding is id 4 and whose payload is `hi`.
const ENCODED_PUSH: &[u8] = &[0x1D, 0x00, 0x41, 0x08, 0x02, b'h', b'i'];

fn tree(bytes: &[u8]) -> Field {
    dissect_network_message(bytes, 0)
        .expect("the fixture walks")
        .expect("the fixture is a network message")
}

/// A put on `demo/a` with the tree given, every other axis at its default.
fn record(tree: Option<&Field>) -> RecordView<'_> {
    RecordView {
        direction: Direction::A,
        keyexpr: Some("demo/a"),
        kind: crate::filter::Record::Is(RecordKind::Put),
        payload_bytes: Some(2),
        value: Content::Whole(b"hi"),
        observed_at_ms: None,
        elapsed_ms: None,
        unit_offset: Some(0),
        source_delay_ms: None,
        outcome: None,
        zid: None,
        tree,
        row: None,
    }
}

fn judge(selector: &str, bytes: &[u8]) -> Truth {
    let filter = Filter::parse(selector).unwrap_or_else(|e| panic!("{selector}: {e}"));
    let t = tree(bytes);
    filter.matches(&record(Some(&t)))
}

fn refusal(selector: &str) -> FilterErrorKind {
    Filter::parse(selector)
        .map(|_| ())
        .expect_err(selector)
        .kind
}

/// The fixtures are what their names say: the walker reads them, and reads
/// them whole.
#[test]
fn the_fixtures_walk_to_the_trees_the_tests_assume() {
    assert_eq!(tree(PLAIN_PUSH).name, "Push");
    let qos_tree = tree(QOS_PUSH);
    let qos = wz_session_core::dissect_schema::matching(&qos_tree, &["qos", "priority"]);
    assert_eq!(qos.len(), 1, "{qos_tree:#?}");
    let encoded = tree(ENCODED_PUSH);
    let payload = wz_session_core::dissect_schema::matching(&encoded, &["put", "payload"]);
    assert_eq!(payload.len(), 1, "{encoded:#?}");
}

/// A path alone asks whether the record carries the field.
#[test]
fn a_path_alone_is_a_presence_test() {
    assert_eq!(judge("qos", QOS_PUSH), Truth::Yes);
    assert_eq!(judge("qos", PLAIN_PUSH), Truth::No);
    assert_eq!(judge("not qos", PLAIN_PUSH), Truth::Yes);
    assert_eq!(judge("put.encoding and qos", ENCODED_PUSH), Truth::No);
    assert_eq!(judge("(put.encoding)", ENCODED_PUSH), Truth::Yes);
}

/// A label compares by its word, and a word outside its closed set is refused
/// rather than answered `no` for every record.
#[test]
fn a_label_compares_its_word_and_refuses_one_it_cannot_carry() {
    assert_eq!(judge("qos.priority == Data", QOS_PUSH), Truth::Yes);
    assert_eq!(judge("qos.priority == RealTime", QOS_PUSH), Truth::No);
    assert_eq!(judge("qos.congestion == Drop", QOS_PUSH), Truth::Yes);
    assert_eq!(judge("qos.express == no", QOS_PUSH), Truth::Yes);
    assert!(matches!(
        refusal("qos.priority == Fast"),
        FilterErrorKind::PathValue { .. }
    ));
    assert!(matches!(
        refusal("qos.priority > Data"),
        FilterErrorKind::PathOperator { .. }
    ));
}

/// THE ABSENCE RULE: a tree that was walked and lacks the field answers `no`
/// to `==` and `yes` to `!=`, which is `not ==`; a record with no tree answers
/// neither.
#[test]
fn an_absent_field_is_decided_and_a_missing_tree_is_not() {
    assert_eq!(judge("qos.priority == Data", PLAIN_PUSH), Truth::No);
    assert_eq!(judge("qos.priority != Data", PLAIN_PUSH), Truth::Yes);
    assert_eq!(
        judge("qos.priority and qos.priority != Data", PLAIN_PUSH),
        Truth::No,
        "present and different is written with the presence test"
    );
    let filter = Filter::parse("qos.priority == Data").expect("compiles");
    assert_eq!(filter.matches(&record(None)), Truth::Unknown);
    let filter = Filter::parse("qos.priority != Data").expect("compiles");
    assert_eq!(
        filter.matches(&record(None)),
        Truth::Unknown,
        "a tree this plane did not walk cannot show the field is absent"
    );
}

/// Integers compare with all six operators, in decimal or hex.
#[test]
fn an_integer_path_takes_every_comparison() {
    assert_eq!(judge("encoding.id == 4", ENCODED_PUSH), Truth::Yes);
    assert_eq!(judge("encoding.id == 0x4", ENCODED_PUSH), Truth::Yes);
    assert_eq!(judge("encoding.id > 3", ENCODED_PUSH), Truth::Yes);
    assert_eq!(judge("encoding.id < 4", ENCODED_PUSH), Truth::No);
    assert_eq!(judge("put.payload_len >= 2", ENCODED_PUSH), Truth::Yes);
    assert!(matches!(
        refusal("encoding.id == four"),
        FilterErrorKind::NotAnInteger(_)
    ));
}

/// `in` is a disjunction of `==`, and `not in` its negation.
#[test]
fn a_list_is_one_of_its_values() {
    assert_eq!(
        judge("qos.priority in {DataHigh, Data}", QOS_PUSH),
        Truth::Yes
    );
    assert_eq!(
        judge("qos.priority in {DataHigh,DataLow}", QOS_PUSH),
        Truth::No
    );
    assert_eq!(
        judge("qos.priority not in {DataHigh DataLow}", QOS_PUSH),
        Truth::Yes
    );
    assert_eq!(judge("kind in {del, put}", PLAIN_PUSH), Truth::Yes);
    assert_eq!(judge("encoding.id in {1, 4}", ENCODED_PUSH), Truth::Yes);
    assert!(matches!(refusal("kind in {}"), FilterErrorKind::EmptyList));
    assert!(matches!(
        refusal("kind in put"),
        FilterErrorKind::ExpectedList
    ));
    assert!(matches!(
        refusal("kind in {put"),
        FilterErrorKind::UnclosedList
    ));
    assert!(matches!(
        refusal("kind in {frob}"),
        FilterErrorKind::UnknownValue { .. }
    ));
    assert!(matches!(
        refusal("node in {a}"),
        FilterErrorKind::OperatorNotAdmitted { .. }
    ));
}

/// Bytes compare whole, hold a run, and are searched by a pattern.
#[test]
fn a_byte_path_compares_contains_and_matches() {
    assert_eq!(judge("put.payload == \"hi\"", ENCODED_PUSH), Truth::Yes);
    assert_eq!(judge("put.payload == 0x6869", ENCODED_PUSH), Truth::Yes);
    assert_eq!(
        judge("put.payload contains \"i\"", ENCODED_PUSH),
        Truth::Yes
    );
    assert_eq!(judge("put.payload contains \"x\"", ENCODED_PUSH), Truth::No);
    #[cfg(feature = "filter-regex")]
    {
        assert_eq!(
            judge("put.payload matches \"^h.$\"", ENCODED_PUSH),
            Truth::Yes
        );
        assert_eq!(judge("put.payload matches \"^i\"", ENCODED_PUSH), Truth::No);
        assert_eq!(judge("key matches \"^demo/\"", PLAIN_PUSH), Truth::Yes);
        assert_eq!(judge("value matches \"h\"", PLAIN_PUSH), Truth::Yes);
        assert!(matches!(
            refusal("key matches \"(\""),
            FilterErrorKind::BadPattern(_)
        ));
    }
    #[cfg(not(feature = "filter-regex"))]
    assert!(matches!(
        refusal("key matches \"demo\""),
        FilterErrorKind::PatternUnsupported
    ));
    assert_eq!(judge("key contains \"mo/\"", PLAIN_PUSH), Truth::Yes);
    assert!(matches!(
        refusal("put.encoding == 3"),
        FilterErrorKind::PathOperator { .. }
    ));
}

/// `len()` reads a field's wire width, and refuses a field that owns none.
#[test]
fn a_width_is_read_off_the_wire() {
    assert_eq!(judge("len(put.payload) == 2", ENCODED_PUSH), Truth::Yes);
    assert_eq!(judge("len(put.payload) != 2", ENCODED_PUSH), Truth::No);
    assert_eq!(judge("len(put.payload) > 5", ENCODED_PUSH), Truth::No);
    assert!(matches!(
        refusal("len(qos.priority) == 1"),
        FilterErrorKind::PathOperator { op: "len", .. }
    ));
    // A slice's own `len` field is still a field.
    assert!(Filter::parse("slice_entry.len == 3").is_ok());
}

/// A path written from its root names only that message's field.
#[test]
fn a_rooted_path_names_one_message() {
    assert_eq!(
        judge("Push.put.payload == \"hi\"", ENCODED_PUSH),
        Truth::Yes
    );
    assert_eq!(
        judge("Request.put.payload == \"hi\"", ENCODED_PUSH),
        Truth::No
    );
}

/// A tail that ends fields of two kinds is refused with the longer tails that
/// tell them apart, and a name nobody declared with the names nearest it.
#[test]
fn an_unsettled_path_is_refused_with_its_candidates() {
    let FilterErrorKind::AmbiguousPath { tails, .. } = refusal("encoding == 1") else {
        panic!("a bare `encoding` ends a group and a two-bit field");
    };
    assert!(
        tails
            .iter()
            .any(|(t, k)| t == "put.encoding" && *k == "nested"),
        "{tails:?}"
    );
    assert!(
        tails
            .iter()
            .any(|(t, k)| t == "ext.encoding" && *k == "bits"),
        "{tails:?}"
    );
    let shown = Filter::parse("qos.prioirty == Data")
        .expect_err("a typo is refused")
        .to_string();
    assert!(shown.contains("qos.priority"), "{shown}");
    let shown = Filter::parse("zzzzzzzzzz == 1")
        .expect_err("refused")
        .to_string();
    assert!(shown.contains("no field is near it"), "{shown}");
    // A fixed field still wins its own one-word name.
    assert!(!Filter::parse("value == \"x\"")
        .expect("compiles")
        .reads_tree());
    assert!(Filter::parse("put.payload == \"x\"")
        .expect("compiles")
        .reads_tree());
}

/// END TO END: the payload plane hands each record the tree of its own bytes,
/// so a path selects exactly the record that carries it.
#[cfg(feature = "network-codecs")]
#[test]
fn the_payload_plane_judges_a_path_over_each_records_own_bytes() {
    use crate::exchange::tests as fx;
    use crate::payload::tests_support::push_declaring;
    let d = fx::dissect(&[
        (true, Some(1), push_declaring("a/json", 5, b"{}")),
        (true, Some(1), push_declaring("a/text", 6, b"hello")),
    ]);
    let filter = Filter::parse("put.encoding.id == 5").expect("compiles");
    let selection: Selection = crate::payload::payloads_where(&d, &filter).selection();
    assert_eq!(
        (selection.matched, selection.rejected, selection.undecided),
        (1, 1, 0),
        "{selection:?}"
    );
    let filter = Filter::parse("len(put.payload) == 5").expect("compiles");
    let selection = crate::payload::payloads_where(&d, &filter).selection();
    assert_eq!(
        (selection.matched, selection.rejected, selection.undecided),
        (1, 1, 0)
    );
}
