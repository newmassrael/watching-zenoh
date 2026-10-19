// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Every row judged, and the row's own facts: `msg`, the endpoints, the
//! ports, the link, the flow and the packet, over records and over rows that
//! carry none.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::exchange::tests as fx;
use crate::fields_json::RowCoordinates;
use crate::filter::{
    Content, Filter, FilterErrorKind, Record, RecordKind, RecordView, RowFacts, Truth,
};
use crate::link::FlowKey;
use wz_session_core::passive::Direction;

/// A numbering that gives list `n` the number `100 + n`, as a live handle gives
/// its lists numbers of its own: what a `flow` term must be read against.
struct Numbered;

impl RowCoordinates for Numbered {
    fn list_id(&self, list: usize) -> Option<u64> {
        Some(100 + list as u64)
    }

    fn scouting_list_id(&self, _flow: &FlowKey) -> Option<u64> {
        None
    }
}

/// A `Declare` binding id 1 to `suffix`.
fn declare(suffix: &'static str) -> Vec<u8> {
    wz_codecs::declare::Declare {
        body: wz_codecs::declare::DeclareVariant::CodecZenohDeclKexpr(
            wz_codecs::decl_kexpr::DeclKexpr {
                header: wz_session_core::wire_const::D_MID_KEXPR
                    | wz_session_core::wire_const::FLAG_D_N,
                id: 1,
                keyexpr: fx::sender_space(0, Some(suffix)),
                extensions: None,
            },
        ),
        ..Default::default()
    }
    .encode_to_vec()
}

/// A capture of three one-record frames on one UDP flow between 10.0.0.1:43210
/// and 10.0.0.2:7447: a Declare and a Put from the lower end, a Put back.
fn capture() -> crate::Dissection {
    use crate::payload::tests_support::push_declaring;
    fx::dissect(&[
        (true, Some(1), declare("a/b")),
        (true, Some(2), push_declaring("a/b", 5, b"x")),
        (false, Some(3), push_declaring("a/c", 5, b"y")),
    ])
}

/// The word each row of the selection document carries, in row order.
fn words(selector: &str) -> Vec<String> {
    let filter = Filter::parse(selector).unwrap_or_else(|e| panic!("{selector}: {e}"));
    let doc =
        crate::selection_json::selection_json_where_coordinated(&capture(), &filter, &Numbered);
    doc.split("\"selected\":\"")
        .skip(1)
        .map(|s| s.split('"').next().unwrap_or_default().to_string())
        .collect()
}

#[track_caller]
fn assert_words(selector: &str, want: [&str; 3]) {
    assert_eq!(words(selector), want, "{selector}");
}

/// A row that carries no record is JUDGED: a term about a record is the
/// decided answer a field the row does not carry gives, never `unjudged`.
#[test]
fn a_row_with_no_record_is_judged_and_answers_for_a_record_as_absent() {
    assert_words("kind == put", ["no", "yes", "yes"]);
    assert_words("kind != put", ["yes", "no", "no"]);
    assert_words("bytes > 0", ["no", "yes", "yes"]);
    assert_words("key == a/b", ["no", "yes", "no"]);
    assert_words("not key == a/b", ["yes", "no", "yes"]);
}

/// `msg` is every message the row rode in: the Frame and what it carried.
#[test]
fn msg_names_each_message_a_row_rode_in() {
    assert_words("msg == Declare", ["yes", "no", "no"]);
    assert_words("msg == Push", ["no", "yes", "yes"]);
    assert_words("msg == Frame", ["yes", "yes", "yes"]);
    assert_words("msg != Frame", ["no", "no", "no"]);
    assert_words("msg in {Declare, Interest}", ["yes", "no", "no"]);
    assert!(matches!(
        Filter::parse("msg == Pushy")
            .map(|_| ())
            .expect_err("no such message")
            .kind,
        FilterErrorKind::UnknownValue { field: "msg", .. }
    ));
}

/// A path into the tree of a row the census planes leave is answered from
/// that row's own message.
#[test]
fn a_record_less_message_is_read_by_its_own_tree() {
    assert_words("decl_kexpr.keyexpr.suffix == \"a/b\"", ["yes", "no", "no"]);
    assert_words("decl_kexpr", ["yes", "no", "no"]);
    assert_words("put.payload == \"y\"", ["no", "no", "yes"]);
}

/// The endpoints, the ports and the link, by which end sent the row.
#[test]
fn the_endpoints_ports_and_link_are_the_rows_own() {
    assert_words("src == 10.0.0.1", ["yes", "yes", "no"]);
    assert_words("dst == 10.0.0.1", ["no", "no", "yes"]);
    assert_words("addr == 10.0.0.2", ["yes", "yes", "yes"]);
    assert_words("addr == 10.0.0.0/24", ["yes", "yes", "yes"]);
    assert_words("addr != 10.0.0.2", ["no", "no", "no"]);
    assert_words("addr == 10.1.0.0/16", ["no", "no", "no"]);
    assert_words("dport == 7447", ["yes", "yes", "no"]);
    assert_words("sport == 7447", ["no", "no", "yes"]);
    assert_words("port == 43210", ["yes", "yes", "yes"]);
    assert_words("port > 50000", ["no", "no", "no"]);
    assert_words("link == udp", ["yes", "yes", "yes"]);
    assert_words("link == tcp", ["no", "no", "no"]);
    assert!(Filter::parse("addr == ::1").is_ok());
    assert!(Filter::parse("addr == 30:03:c8:37:25:a1").is_ok());
    assert!(Filter::parse("addr == 10.0.0.1/33").is_err());
    assert!(Filter::parse("addr == host").is_err());
}

/// The packet is the one the document numbers the row by, and the flow is
/// the number the DOCUMENT gives the list: here a numbering of `100 + n`.
#[test]
fn packet_and_flow_are_the_documents_numbers() {
    assert_words("packet == 1", ["no", "yes", "no"]);
    assert_words("packet >= 1", ["no", "yes", "yes"]);
    assert_words("flow == 100", ["yes", "yes", "yes"]);
    assert_words("flow == 0", ["no", "no", "no"]);
    assert_words("flow != 100", ["no", "no", "no"]);
}

fn view<'a>(row: Option<RowFacts<'a>>, kind: Record) -> RecordView<'a> {
    RecordView {
        direction: Direction::A,
        keyexpr: Some("demo/a"),
        kind,
        payload_bytes: Some(1),
        value: Content::Whole(b"x"),
        observed_at_ms: None,
        elapsed_ms: None,
        unit_offset: Some(0),
        source_delay_ms: None,
        outcome: None,
        zid: None,
        tree: None,
        row,
    }
}

/// Without the row's facts a row term is undecided, and never `no`.
#[test]
fn a_plane_given_no_row_facts_decides_no_row_term() {
    for selector in [
        "msg == Push",
        "addr == 10.0.0.1",
        "port == 1",
        "link == udp",
        "flow == 0",
        "packet == 0",
    ] {
        let filter = Filter::parse(selector).expect("compiles");
        assert_eq!(
            filter.matches(&view(None, Record::Is(RecordKind::Put))),
            Truth::Unknown,
            "{selector}"
        );
        assert!(filter.reads_row(), "{selector}");
    }
    assert!(!Filter::parse("kind == put").expect("compiles").reads_row());
}

/// A link with no ports and no addresses decides every port and address term
/// `no`: the fact is absent, not unknown.
#[test]
fn a_serial_line_has_no_address_and_no_port() {
    let serial = FlowKey::serial_line();
    let names = ["Frame", "Push"];
    let facts = RowFacts::of(&names, Some(0), 0, &serial, Direction::A);
    for selector in ["addr == 10.0.0.1", "port == 0", "sport < 9"] {
        let filter = Filter::parse(selector).expect("compiles");
        assert_eq!(
            filter.matches(&view(Some(facts), Record::Is(RecordKind::Put))),
            Truth::No,
            "{selector}"
        );
    }
    let filter = Filter::parse("link == serial").expect("compiles");
    assert_eq!(filter.matches(&view(Some(facts), Record::None)), Truth::Yes);
}

/// `msg` takes exactly the dissection's own message names and the walker's
/// `Unknown`, so a message the walker learns to name is one a selector can
/// ask for, and no word is offered that no row ever carries.
#[test]
fn msg_takes_the_dissections_own_message_names() {
    let mut walked = wz_session_core::dissect::MessageName::names();
    walked.push("Unknown");
    walked.sort_unstable();
    let mut declared = crate::filter::MESSAGE_WORDS.to_vec();
    declared.sort_unstable();
    assert_eq!(declared, walked);
}

/// A record the capture cannot read (a close without its request) leaves every
/// record term undecided, where a row with no record decides it.
#[test]
fn an_unread_record_is_undecided_where_no_record_is_decided() {
    for selector in [
        "kind == query",
        "key == demo/a",
        "replies == 0",
        "value contains \"x\"",
    ] {
        let filter = Filter::parse(selector).expect("compiles");
        assert_eq!(
            filter.matches(&view(None, Record::Unread)),
            Truth::Unknown,
            "{selector}"
        );
        assert_eq!(
            filter.matches(&view(None, Record::None)),
            Truth::No,
            "{selector}"
        );
    }
    let filter = Filter::parse("kind != query").expect("compiles");
    assert_eq!(filter.matches(&view(None, Record::None)), Truth::Yes);
    assert_eq!(filter.matches(&view(None, Record::Unread)), Truth::Unknown);
}
