// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The row-facts document: the field document's rows with their two trees left
//! out, and nothing else changed.
//!
//! The oracle is the field document itself, written over the same capture by the
//! same writer with its trees: cut out every row's `fields` object and every
//! completed chain's `above_transport.fields` array, name the envelope
//! `row_facts`, and the text must be the row-facts document byte for byte. A
//! writer that dropped or changed any other key, or left a tree in, fails here.

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "reassembly")]
use crate::datagram_tests::{
    contiguous_record_dissection_with_file, reassembled_record_dissection_with_file,
};
use crate::datagram_tests::{framed_keepalive, tcp_packet};
use crate::doc_revision::{envelope, key_set, newest, FIELDS, ROW_FACTS};
use crate::fields_json::{
    fields_json_since_remembering_progress, FieldsMemory, RowCoordinates, Since, Trees,
};
use crate::link::{FlowKey, LINKTYPE_ETHERNET};
use crate::payload::formats::FormatMap;
use crate::Dissection;

/// Every list and row numbered by its produced-index, as a handle's.
struct Numbered;

impl RowCoordinates for Numbered {
    fn list_id(&self, list: usize) -> Option<u64> {
        Some(list as u64 + 1)
    }

    fn scouting_list_id(&self, _flow: &FlowKey) -> Option<u64> {
        None
    }

    fn row_seq(&self, list: usize, produced: u64) -> Option<u64> {
        Some(list as u64 * 1_000_000 + produced + 1)
    }
}

/// The since-document from cursor 0 over everything, from a fresh memory of
/// `trees`' shape.
fn document(d: &Dissection, file: &[u8], declared: Option<&str>, trees: Trees) -> String {
    let mut map = FormatMap::new();
    if let Some(text) = declared {
        map.declare_all(text).expect("the declarations install");
    }
    fields_json_since_remembering_progress(
        d,
        file,
        declared.map(|_| &map),
        declared.unwrap_or(""),
        &Numbered,
        Since {
            after_seq: 0,
            through_seq: u64::MAX,
        },
        &mut FieldsMemory::with_trees(trees),
        None,
    )
    .expect("nothing stops the call")
}

/// Where the object or array that opens at `start` closes, one past its last
/// byte, read through strings and their escapes.
fn balanced_end(text: &str, start: usize) -> usize {
    let bytes = text.as_bytes();
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if in_string {
            match (escaped, b) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    panic!("nothing closes what opens at {start}")
}

/// What the row-facts door writes for the state a field document `full` was written
/// at: `full` without its trees, under the row-facts envelope. The tests below hold
/// it to the door's own rendering, so the gates that need a row-facts population
/// over captures they only have field documents of take it from here.
pub(crate) fn as_row_facts(full: &str) -> String {
    without_trees(full).replacen(&envelope(FIELDS), &envelope(ROW_FACTS), 1)
}

/// The field document with its two trees cut out: a row's `"fields":{..}`, and the
/// `"fields":[..]` that follows a chain's `carried_state` word. A decoded payload's
/// `fields` array follows neither and stays.
fn without_trees(doc: &str) -> String {
    const KEY: &str = ",\"fields\":";
    const STATE: &str = "\"carried_state\":\"";
    let mut out = String::new();
    let mut rest = doc;
    while let Some(at) = rest.find(KEY) {
        let value = at + KEY.len();
        let before = &rest[..at];
        let tree = match rest.as_bytes()[value] {
            b'{' => true,
            b'[' => before.strip_suffix('"').is_some_and(|open| {
                open.rfind(STATE)
                    .is_some_and(|s| !open[s + STATE.len()..].contains('"'))
            }),
            _ => false,
        };
        if tree {
            out.push_str(before);
            rest = &rest[balanced_end(rest, value)..];
        } else {
            out.push_str(&rest[..value]);
            rest = &rest[value..];
        }
    }
    out.push_str(rest);
    out
}

/// The row-facts document over `file` is the field document over it without its
/// trees, under the row-facts envelope; and it carries no key the row-facts
/// revision does not list, and its CBOR form is one well-formed map.
fn holds(d: &Dissection, file: &[u8], declared: Option<&str>, trees_seen: &[&str]) {
    let full = document(d, file, declared, Trees::Written);
    let facts = document(d, file, declared, Trees::Left);
    for tree in trees_seen {
        assert!(
            full.contains(tree),
            "the case must write the tree it is about ({tree}): {full}"
        );
    }
    let expected = as_row_facts(&full);
    assert_eq!(facts, expected, "the row-facts document of {full}");

    let listed = newest(ROW_FACTS).expect("row_facts has a revision").keys;
    let unlisted: Vec<&str> = key_set(&facts)
        .into_iter()
        .filter(|k| !listed.contains(k))
        .collect();
    assert!(
        unlisted.is_empty(),
        "keys row_facts does not list: {unlisted:?}"
    );

    let cbor = crate::cbor_of_json::cbor_of_json(&facts).expect("the document is JSON");
    // Lossless: the bytes read back as the text they were made from.
    assert_eq!(
        crate::cbor_of_json::json_of_cbor(&cbor).as_ref(),
        Ok(&facts)
    );
    let summary = crate::payload_cbor::scan_cbor(&cbor).expect("the CBOR is well-formed");
    assert_eq!(summary.top_level, crate::payload_cbor::CborKind::Map);
}

#[test]
fn a_stream_rows_facts_are_its_row_without_the_tree() {
    let mut d = Dissection::new();
    let packet = tcp_packet(1000, &framed_keepalive());
    d.push_packet(LINKTYPE_ETHERNET, 0, &packet);
    d.finish();
    let file = crate::pcap::write(1, &[(0, 0, packet.as_slice())]);
    holds(&d, &file, None, &[",\"fields\":{\"name\":\"KeepAlive\""]);
}

/// Datagram rows, and the flow object around them with its `disagreements`
/// group, which the row-facts revision lists.
#[test]
fn datagram_rows_facts_are_their_rows_without_the_trees() {
    let (d, file) = crate::datagram_tests::wide_sn_dissection_with_file(&[1, 2, 3]);
    holds(
        &d,
        &file,
        None,
        &[
            ",\"fields\":{\"name\":\"Frame\"",
            "\"disagreements\":{\"count\":0",
        ],
    );
    // The same dissection over a container cut after the first frame: the
    // second read finds no packet for the others, and the group names them.
    let (_, cut) = crate::datagram_tests::wide_sn_dissection_with_file(&[1]);
    holds(&d, &cut, None, &["\"named\":[{\"at\":"]);
}

#[cfg(feature = "reassembly")]
#[test]
fn a_frames_record_keeps_its_carried_entry_and_its_payload_reading() {
    let record =
        crate::payload::tests_support::push_declaring("demo/sensor", 0, &[0x08, 0x96, 0x01]);
    let (d, file) = contiguous_record_dissection_with_file(&record);
    holds(&d, &file, None, &[",\"fields\":{\"name\":\"Frame\""]);
    // The decoded payload's own `fields` list is a fact of the row and stays.
    holds(
        &d,
        &file,
        Some("demo/sensor=protobuf\n"),
        &[",\"fields\":{\"name\":\"Frame\"", "\"state\":\"decoded\""],
    );
}

#[cfg(feature = "reassembly")]
#[test]
fn a_completed_chain_keeps_its_carried_records_without_their_trees() {
    let record =
        crate::payload::tests_support::push_declaring("demo/sensor", 0, &[0x08, 0x96, 0x01]);
    let (d, file) = reassembled_record_dissection_with_file(&record);
    let chain = "\"carried_state\":\"reassembled\",\"fields\":[";
    holds(&d, &file, None, &[chain]);
    holds(&d, &file, Some("demo/sensor=protobuf\n"), &[chain]);
    let facts = document(&d, &file, None, Trees::Left);
    assert!(
        facts.contains("\"carried_state\":\"reassembled\",\"carried\":[{\"message\":\"Push\""),
        "the chain's record is still named, keyed and sized: {facts}"
    );
}

/// The oracle's own cut, held to text it can be checked on by eye: a row tree and
/// a chain's tree go, a decoded payload's `fields` and a string that spells the
/// key stay.
#[test]
fn the_cut_takes_the_two_trees_and_nothing_else() {
    let doc = "{\"a\":[{\"name\":\"Frame\",\"fields\":{\"x\":\"}\",\"y\":[1]},\
               \"above_transport\":{\"carried_state\":\"reassembled\",\"fields\":[{\"z\":1}],\
               \"carried\":[]},\"payload_decode\":{\"format\":\"p\",\"fields\":[{\"v\":\",\\\"fields\\\":{\"}]}}]}";
    assert_eq!(
        without_trees(doc),
        "{\"a\":[{\"name\":\"Frame\",\
         \"above_transport\":{\"carried_state\":\"reassembled\",\"carried\":[]},\
         \"payload_decode\":{\"format\":\"p\",\"fields\":[{\"v\":\",\\\"fields\\\":{\"}]}}]}"
    );
}

/// The two shapes keep two memories: a document of one shape between two of the
/// other leaves the other's walk where it was, so a consumer that steps with one
/// and picks a row with the other does not make its steps begin again.
#[cfg(feature = "reassembly")]
#[test]
fn a_memory_of_one_shape_is_not_disturbed_by_the_other() {
    let record =
        crate::payload::tests_support::push_declaring("demo/sensor", 0, &[0x08, 0x96, 0x01]);
    let (d, file) = contiguous_record_dissection_with_file(&record);
    let ask = |memory: &mut FieldsMemory, after_seq: u64| {
        fields_json_since_remembering_progress(
            &d,
            &file,
            None,
            "",
            &Numbered,
            Since {
                after_seq,
                through_seq: u64::MAX,
            },
            memory,
            None,
        )
        .expect("nothing stops the call")
    };
    let mut facts = FieldsMemory::with_trees(Trees::Left);
    let mut fields = FieldsMemory::with_trees(Trees::Written);
    let first = ask(&mut facts, 0);
    assert!(first.starts_with(&alloc::format!("{{{}", envelope(ROW_FACTS))));
    let _ = ask(&mut fields, 0);
    // From the cursor the first document gave: the walk goes on.
    let next = ask(&mut facts, u64::MAX);
    assert!(
        !next.contains("\"seq\":"),
        "nothing past the cursor: {next}"
    );
    let stats = facts.stats();
    assert_eq!((stats.restarted, stats.resumed), (1, 1), "{stats:?}");
}
