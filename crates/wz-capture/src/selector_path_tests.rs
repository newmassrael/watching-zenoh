// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The selector's terms over a record's dissection tree: paths, presence,
//! lists, patterns and widths, judged over trees the dissection walker itself
//! built from wire bytes, and once end to end through the payload plane.

use alloc::string::ToString;

use crate::field_path::RecordTree;
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
fn record(tree: Option<&RecordTree>) -> RecordView<'_> {
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
    let t = RecordTree::message(tree(bytes));
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

/// A FORMER NAME READS AS THE FIELD IT NAMES NOW, spelled as a selector written
/// today spells it: the shortest tail of the current name that names exactly
/// the renamed fields, the record under a `Frame` included. A former name that
/// names no field is still unknown.
#[test]
fn a_former_name_reads_as_the_field_it_names_now() {
    use wz_session_core::dissect_schema::Renamed;
    let renames = [Renamed {
        from: "Push.put.old_payload",
        to: "Push.put.payload",
        since_fields_revision: 60,
    }];
    crate::field_path::with_shape(|shape| a_former_name_reads_under(shape.paths(), &renames));
}

fn a_former_name_reads_under(
    declared: &[crate::field_path::Declared],
    renames: &[wz_session_core::dissect_schema::Renamed],
) {
    use crate::field_path::{formerly_under, PathRefusal};
    let (spelled, images) =
        formerly_under(&["old_payload"], declared, renames).expect("a former name");
    let mut named: alloc::vec::Vec<alloc::string::String> =
        images.iter().map(|d| d.segments.join(".")).collect();
    named.sort();
    assert_eq!(
        named,
        ["Frame.payload.Push.put.payload", "Push.put.payload"],
        "the record alone and under a Frame"
    );
    assert_eq!(spelled, ["Push", "put", "payload"]);
    // Any tail of the former name reads the same.
    assert!(formerly_under(&["put", "old_payload"], declared, renames).is_ok());
    assert_eq!(
        formerly_under(&["never_named"], declared, renames).map(|(s, _)| s),
        Err(PathRefusal::Unknown)
    );
}

/// The first rename moves the field list's revision to one that pins the keys
/// of a `renamed` entry, which its header promises.
#[test]
fn a_rename_is_published_by_a_field_list_revision_that_pins_its_keys() {
    let renamed = !wz_session_core::dissect_schema::RENAMED.is_empty();
    let keys = crate::doc_revision::newest(crate::doc_revision::SELECTOR_FIELDS)
        .expect("a shape")
        .keys;
    assert!(keys.contains(&"renamed"), "{keys:?}");
    for key in ["from", "to", "since"] {
        assert_eq!(
            keys.contains(&key),
            renamed,
            "`{key}` is pinned exactly when a rename has been published: {keys:?}"
        );
    }
    let doc = crate::filter::selector_fields_json();
    assert!(doc.contains("\"renamed\":["), "{doc}");
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

/// A capture of `frames`, each `(sn, records)` one `Frame` of that `sn` carrying
/// the records back to back, one UDP datagram per frame.
#[cfg(feature = "network-codecs")]
fn frames_of(frames: &[(u8, alloc::vec::Vec<alloc::vec::Vec<u8>>)]) -> crate::Dissection {
    let mut d = crate::Dissection::new();
    for (i, (sn, records)) in frames.iter().enumerate() {
        let mut wire = alloc::vec![wz_session_core::wire_const::T_MID_FRAME, *sn];
        for record in records {
            wire.extend_from_slice(record);
        }
        let packet =
            crate::datagram_tests::udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &wire);
        d.push_packet_at(crate::link::LINKTYPE_ETHERNET, i, Some(i as u64), &packet);
    }
    d
}

/// ZA-side report: `Frame.sn == <v>` kept no row, because a record's tree was
/// its network message alone. A RECORD READS THE FRAME THAT CARRIED IT: the
/// `Frame`'s `sn` selects that frame's record, a path through `Frame.payload`
/// names the record's own fields, and a frame's other records stay apart.
#[cfg(feature = "network-codecs")]
#[test]
fn a_record_reads_the_frame_that_carried_it() {
    use crate::payload::tests_support::push_declaring;
    let d = frames_of(&[
        (3, alloc::vec![push_declaring("a/json", 5, b"{}")]),
        (
            9,
            alloc::vec![
                push_declaring("a/text", 6, b"hello"),
                push_declaring("a/bin", 7, b"xy"),
            ],
        ),
    ]);
    for (selector, expected) in [
        ("Frame.sn == 9", (2, 1, 0)),
        ("Frame.sn == 3", (1, 2, 0)),
        ("Frame.sn == 4", (0, 3, 0)),
        ("Frame.sn == 9 and put.encoding.id == 7", (1, 2, 0)),
        ("Frame.payload.Push.put.encoding.id == 6", (1, 2, 0)),
        // A record of the same frame is not part of this one's tree.
        ("Frame.sn == 9 and not put.encoding.id == 6", (1, 2, 0)),
        ("Frame.r", (3, 0, 0)),
        ("Frame.qos", (0, 3, 0)),
    ] {
        let filter = Filter::parse(selector).unwrap_or_else(|e| panic!("{selector}: {e}"));
        let s = crate::payload::payloads_where(&d, &filter).selection();
        assert_eq!(
            (s.matched, s.rejected, s.undecided),
            expected,
            "{selector}: {s:?}"
        );
    }
}

/// A record whose `Frame` was not read keeps every answer its own message
/// gives, and a path that could stand in the `Frame` is UNDECIDED, never `no`;
/// a record no `Frame` stands around answers such a path `no`.
#[cfg(feature = "network-codecs")]
#[test]
fn an_unread_frame_leaves_only_its_own_fields_undecided() {
    use crate::field_path::{record_tree, Envelope, FrameEnvelope};
    use crate::payload::tests_support::push_declaring;
    use wz_session_core::passive::Carried;
    let d = frames_of(&[(3, alloc::vec![push_declaring("a/json", 5, b"{}")])]);
    let order = d.message_frames_in_capture_order();
    let (_, list, _, row) = order.iter().next().expect("one message");
    let Carried::Batch(batch) = &row.carried else {
        panic!("a frame carrying a batch: {:?}", row.carried);
    };
    let (_, span) = batch.records().next().expect("one record");
    let held = order
        .held_message_bytes(&d, list, &row)
        .expect("a datagram list reads its own units");

    let read = record_tree(&row, &FrameEnvelope::of(&row, Some(&held)), span).expect("walks");
    let unread = record_tree(&row, &FrameEnvelope::of(&row, None), span).expect("walks");
    assert_eq!(read.envelope(), Envelope::Read);
    assert_eq!(unread.envelope(), Envelope::Unread);
    let alone = RecordTree::message(unread.root().clone());

    for (selector, over_read, over_unread, over_alone) in [
        ("Frame.sn == 3", Truth::Yes, Truth::Unknown, Truth::No),
        ("Frame.sn != 3", Truth::No, Truth::Unknown, Truth::Yes),
        ("put.encoding.id == 5", Truth::Yes, Truth::Yes, Truth::Yes),
        ("put.encoding.id == 6", Truth::No, Truth::No, Truth::No),
        (
            "Push.put.encoding.id == 5",
            Truth::Yes,
            Truth::Yes,
            Truth::Yes,
        ),
        (
            "Frame.payload.Push.put.encoding.id == 5",
            Truth::Yes,
            Truth::Unknown,
            Truth::No,
        ),
        // `qos.priority` ends the Push's and the Frame's: neither carries one,
        // and only the read Frame says so.
        ("qos.priority", Truth::No, Truth::Unknown, Truth::No),
    ] {
        let filter = Filter::parse(selector).unwrap_or_else(|e| panic!("{selector}: {e}"));
        for (tree, expected, which) in [
            (&read, over_read, "read"),
            (&unread, over_unread, "unread"),
            (&alone, over_alone, "alone"),
        ] {
            assert_eq!(
                filter.matches(&record(Some(tree))),
                expected,
                "{selector} over the {which} tree"
            );
        }
    }
}

/// THE PATH A ROW SHOWS ON A NODE NAMES THAT NODE IN ITS RECORD'S TREE: for
/// every node of a row's `fields` tree outside the row's other records, the
/// record's tree holds a node at that path with the same span and value. What
/// lets a consumer offer "filter on this field" off any row without building
/// the normalised view itself.
#[cfg(feature = "network-codecs")]
#[test]
fn a_rows_node_path_names_the_same_node_in_its_records_tree() {
    use crate::field_path::{record_tree, FrameEnvelope};
    use crate::payload::tests_support::push_declaring;
    use wz_session_core::dissect::FieldValue;
    use wz_session_core::passive::Carried;
    let records = alloc::vec![
        push_declaring("a/text", 6, b"hello"),
        push_declaring("a/bin", 7, b"xy"),
    ];
    let d = frames_of(&[(9, records)]);
    let order = d.message_frames_in_capture_order();
    let (_, list, _, row) = order.iter().next().expect("one message");
    let held = order.held_message_bytes(&d, list, &row).expect("held");
    let shown = wz_session_core::dissect::dissect_transport_message(&held, 0).expect("walks");
    let paths = wz_session_core::dissect_schema::node_paths(&shown);
    let Carried::Batch(batch) = &row.carried else {
        panic!("a batch");
    };
    let envelope = FrameEnvelope::of(&row, Some(&held));
    let FieldValue::Nested(top) = &shown.value else {
        panic!("a group");
    };
    let shown_records = match &top
        .iter()
        .find(|c| c.name == "payload")
        .expect("payload")
        .value
    {
        FieldValue::Nested(records) => records,
        other => panic!("{other:?}"),
    };
    let mut checked = 0usize;
    for (k, (_, span)) in batch.records().enumerate() {
        let tree = record_tree(&row, &envelope, span).expect("walks");
        // Every node of the row's tree but the other records'.
        let mut stack: alloc::vec::Vec<&Field> = alloc::vec![&shown];
        while let Some(node) = stack.pop() {
            if shown_records
                .iter()
                .enumerate()
                .any(|(j, r)| j != k && core::ptr::eq(r, node))
            {
                continue;
            }
            if let FieldValue::Nested(children) = &node.value {
                stack.extend(children.iter());
            }
            let Some(path) = paths.of(node) else {
                continue;
            };
            let segments: alloc::vec::Vec<&str> = path.split('.').collect();
            let hits = wz_session_core::dissect_schema::matching(tree.root(), &segments);
            assert!(
                hits.iter().any(|h| h.span == node.span
                    && (matches!(h.value, FieldValue::Nested(_)) || h.value == node.value)),
                "record {k}: {path} at {:?} is not in the record's tree",
                node.span
            );
            checked += 1;
        }
    }
    assert!(checked > 40, "{checked}");
}
