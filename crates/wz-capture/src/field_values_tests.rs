// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The values document: what a record becomes, what the cursor passes, what the
//! selector keeps out, and that a call after a step folds only the step.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::datagram_tests::{frame_carrying, udp_packet};
use crate::field_values::{field_values_since, read_paths, ValuesAsk, ValuesMemory, ValuesRefusal};
use crate::fields_json::RowCoordinates;
use crate::link::{FlowKey, LINKTYPE_ETHERNET};
use crate::payload::tests_support::push_declaring;
use crate::proto_schema::ProtoFile;
use crate::Dissection;

const SCHEMA: &str = "syntax = \"proto3\"; package pkg; \
    enum Gear { GEAR_UNSPECIFIED = 0; GEAR_DRIVE = 2; } \
    message Pose { sint32 x = 1; double heading = 2; Gear gear = 3; }";

/// Every list and row numbered by its produced-index plus one, as a handle's.
struct Numbered;

impl RowCoordinates for Numbered {
    fn list_id(&self, list: usize) -> Option<u64> {
        Some(list as u64)
    }

    fn scouting_list_id(&self, _flow: &FlowKey) -> Option<u64> {
        None
    }

    fn row_seq(&self, _list: usize, produced: u64) -> Option<u64> {
        Some(produced + 1)
    }
}

fn pose(x: i64, heading: f64) -> Vec<u8> {
    crate::proto_encode::encode_message(
        "pkg.Pose",
        &[ProtoFile {
            name: "pose.proto",
            text: SCHEMA.as_bytes(),
        }],
        0,
        &alloc::format!(r#"{{"x": {x}, "heading": {heading}, "gear": "GEAR_DRIVE"}}"#),
    )
    .expect("a Pose")
}

fn declarations() -> String {
    let mut text = String::from("#@pose.proto=");
    wz_session_core::json::escape_into(SCHEMA, &mut text);
    text.push_str("\ndemo/pose=protobuf@pkg.Pose\n");
    text
}

/// Push the `i`-th sample of `key` as one datagram, at `i` milliseconds.
fn push(d: &mut Dissection, i: usize, key: &'static str, payload: &[u8]) {
    let wire = frame_carrying(&push_declaring(key, 0, payload));
    let pkt = udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &wire);
    d.push_packet_at(LINKTYPE_ETHERNET, i, Some(i as u64), &pkt);
}

fn ask<'a>(
    declarations: &'a str,
    selector: &'a str,
    filter: &'a crate::filter::Filter,
    paths: &'a str,
    after_seq: u64,
    through_seq: u64,
) -> ValuesAsk<'a> {
    ValuesAsk {
        declarations,
        selector,
        filter,
        paths,
        after_seq,
        through_seq,
    }
}

#[test]
fn each_record_writes_the_typed_values_of_the_asked_paths_only() {
    let mut d = Dissection::new();
    push(&mut d, 0, "demo/pose", &pose(-3, 0.5));
    push(&mut d, 1, "demo/pose", &pose(-4, 1.5));
    let text = declarations();
    let any = crate::filter::Filter::any();
    let mut memory = ValuesMemory::new();
    let doc = field_values_since(
        &d,
        &Numbered,
        ask(&text, "", &any, "1\n3", 0, 2),
        &mut memory,
        None,
    )
    .expect("a document");
    let head = crate::doc_revision::envelope(crate::doc_revision::FIELD_VALUES);
    assert!(doc.starts_with(&alloc::format!("{{{head}")), "{doc}");
    assert!(
        doc.contains(
            "\"window\":{\"after_seq\":0,\"through_seq\":2},\"paths\":[\"1\",\"3\"],\"records\":["
        ),
        "{doc}"
    );
    assert!(
        doc.contains(
            "{\"seq\":1,\"record\":0,\"time_ns\":0,\"keyexpr\":\"demo/pose\",\"state\":\"decoded\",\
             \"typed\":true,\"schema\":\"pkg.Pose\",\"values\":[\
             {\"path\":\"1\",\"type\":\"sint32\",\"typed_value\":-3,\"enum_number\":null},\
             {\"path\":\"3\",\"type\":\"pkg.Gear\",\"typed_value\":\"GEAR_DRIVE\",\"enum_number\":2}]}"
        ),
        "{doc}"
    );
    assert!(
        doc.contains("{\"path\":\"1\",\"type\":\"sint32\",\"typed_value\":-4,"),
        "{doc}"
    );
    // `heading` was not asked for.
    assert!(!doc.contains("double"), "{doc}");
    wz_session_core::json5::parse(&doc).expect("the document is JSON");
}

#[test]
fn the_cursor_passes_rows_and_a_step_folds_only_the_step() {
    let mut d = Dissection::new();
    push(&mut d, 0, "demo/pose", &pose(-1, 0.5));
    push(&mut d, 1, "demo/pose", &pose(-2, 0.5));
    let text = declarations();
    let any = crate::filter::Filter::any();
    let mut memory = ValuesMemory::new();
    let first = field_values_since(
        &d,
        &Numbered,
        ask(&text, "", &any, "1", 0, 2),
        &mut memory,
        None,
    )
    .expect("a document");
    assert_eq!(first.matches("\"state\":").count(), 2, "{first}");
    let folded = memory.stats().messages_folded;

    push(&mut d, 2, "demo/pose", &pose(-5, 0.5));
    let second = field_values_since(
        &d,
        &Numbered,
        ask(&text, "", &any, "1", 2, 3),
        &mut memory,
        None,
    )
    .expect("a document");
    // Only the new row, and the walk took only the new message.
    assert_eq!(second.matches("\"state\":").count(), 1, "{second}");
    assert!(second.contains("\"seq\":3,"), "{second}");
    assert!(second.contains("\"typed_value\":-5,"), "{second}");
    assert_eq!(memory.stats().messages_folded, folded + 1);
    assert_eq!(memory.stats().restarts, 1, "the first call's begin only");
    assert_eq!(memory.held(), 1, "the passed rows were given up");

    // Another path list reads the payloads the fold holds: no walk again.
    let other = field_values_since(
        &d,
        &Numbered,
        ask(&text, "", &any, "2", 2, 3),
        &mut memory,
        None,
    )
    .expect("a document");
    assert!(
        other.contains("{\"path\":\"2\",\"type\":\"double\",\"typed_value\":0.5,"),
        "{other}"
    );
    assert_eq!(memory.stats().restarts, 1);
    assert_eq!(memory.stats().messages_folded, folded + 1);

    // A cursor below the one last asked begins again, and answers rightly.
    let again = field_values_since(
        &d,
        &Numbered,
        ask(&text, "", &any, "1", 0, 3),
        &mut memory,
        None,
    )
    .expect("a document");
    assert_eq!(again.matches("\"state\":").count(), 3, "{again}");
}

#[test]
fn the_selector_and_the_rules_decide_which_records_are_written() {
    let mut d = Dissection::new();
    push(&mut d, 0, "demo/pose", &pose(-1, 0.5));
    push(&mut d, 1, "demo/other", &pose(-2, 0.5));
    push(&mut d, 2, "demo/pose", &pose(-3, 0.5));
    let text = declarations();
    // No rule covers `demo/other`, so it is not written.
    let any = crate::filter::Filter::any();
    let doc = field_values_since(
        &d,
        &Numbered,
        ask(&text, "", &any, "1", 0, 3),
        &mut ValuesMemory::new(),
        None,
    )
    .expect("a document");
    assert_eq!(doc.matches("\"state\":").count(), 2, "{doc}");
    assert!(!doc.contains("demo/other"), "{doc}");
    // A selector keeps out what it says `no` to.
    let selector = "time > 1";
    let filter = crate::filter::Filter::parse(selector).expect("a selector");
    let doc = field_values_since(
        &d,
        &Numbered,
        ask(&text, selector, &filter, "1", 0, 3),
        &mut ValuesMemory::new(),
        None,
    )
    .expect("a document");
    assert_eq!(doc.matches("\"state\":").count(), 1, "{doc}");
    assert!(doc.contains("\"seq\":3,"), "{doc}");
}

#[test]
fn bytes_that_are_not_the_message_are_a_refused_record_with_why() {
    let mut d = Dissection::new();
    // Field 1 as a length-delimited run: no `sint32` is written so.
    push(&mut d, 0, "demo/pose", &[0x0a, 0x01, 0x00]);
    let text = declarations();
    let any = crate::filter::Filter::any();
    let doc = field_values_since(
        &d,
        &Numbered,
        ask(&text, "", &any, "1", 0, 1),
        &mut ValuesMemory::new(),
        None,
    )
    .expect("a document");
    // An unknown wire type for a known number is an unknown field, not a
    // refusal: the record decodes, and the field at the asked path has no type
    // and no typed value, which a plot can tell from a number.
    assert!(doc.contains("\"state\":\"decoded\""), "{doc}");
    assert!(
        doc.contains(
            "\"values\":[{\"path\":\"1\",\"type\":null,\"typed_value\":null,\"enum_number\":null}]"
        ),
        "{doc}"
    );

    let mut d = Dissection::new();
    push(&mut d, 0, "demo/pose", &[0x08]);
    let doc = field_values_since(
        &d,
        &Numbered,
        ask(&text, "", &any, "1", 0, 1),
        &mut ValuesMemory::new(),
        None,
    )
    .expect("a document");
    assert!(doc.contains("\"state\":\"refused\",\"why\":"), "{doc}");
}

/// One values document per record `state`, for the gates that hold the
/// document's declared vocabulary and carries to what it renders.
pub(crate) fn documents_for_the_gates() -> Vec<String> {
    use crate::payload::tests_support::{push_declaring_aliased, push_with_shm_descriptor};
    const JSON: u16 = 5;
    let text = declarations();
    let any = crate::filter::Filter::any();
    let samples: [Vec<u8>; 5] = [
        push_declaring("demo/pose", 0, &pose(-3, 0.5)),
        // A truncated varint: refused.
        push_declaring("demo/pose", 0, &[0x08]),
        // Declared JSON and valid JSON under a protobuf rule: the label holds
        // and vetoes the rule.
        push_declaring("demo/pose", JSON, br#"{"a":1}"#),
        push_with_shm_descriptor("demo/pose", 0, &[1, 2, 3, 4]),
        // An id no declaration bound.
        push_declaring_aliased(9, 0, &pose(-3, 0.5)),
    ];
    samples
        .iter()
        .map(|record| {
            let mut d = Dissection::new();
            let wire = frame_carrying(record);
            let pkt = udp_packet([10, 0, 0, 1], 43210, [10, 0, 0, 2], 7447, &wire);
            d.push_packet_at(LINKTYPE_ETHERNET, 0, Some(0), &pkt);
            field_values_since(
                &d,
                &Numbered,
                ask(&text, "", &any, "1", 0, 1),
                &mut ValuesMemory::new(),
                None,
            )
            .expect("a document")
        })
        .collect()
}

#[test]
fn every_state_is_rendered_by_the_gate_population() {
    let docs = documents_for_the_gates();
    for word in crate::field_values::state_names() {
        assert!(
            docs.iter()
                .any(|d| d.contains(&alloc::format!("\"state\":\"{word}\""))),
            "{word} in {docs:?}"
        );
    }
}

#[test]
fn a_path_list_is_refused_when_it_names_nothing_too_much_or_no_path() {
    assert_eq!(read_paths(""), Err(ValuesRefusal::NoPaths));
    assert_eq!(read_paths("\n\n"), Err(ValuesRefusal::NoPaths));
    assert_eq!(
        read_paths(" 1"),
        Err(ValuesRefusal::BadPath(" 1".to_string()))
    );
    let many: String = (0..65).map(|i| alloc::format!("{i}\n")).collect();
    assert_eq!(read_paths(&many), Err(ValuesRefusal::TooManyPaths(65)));
    assert_eq!(
        read_paths("1\n4.1\n1\n"),
        Ok(alloc::vec!["1".to_string(), "4.1".to_string()])
    );
}
