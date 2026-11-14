// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Pieces of a split message carried in query REPLIES, beside the same
//! sender's live pieces, over captures built packet by packet.
//!
//! The shape is a responder that answers a history query with one piece per
//! reply: each piece is a `Response` echoing the query's request id, carrying
//! a `Reply` that holds one `Put` whose payload is the piece, with a
//! `ResponseFinal` after the last. The reply's key is the query's, written out
//! whole, and the responder numbers its reply transfers anew for each query,
//! so a reply transfer and a live one (and the replies to two queries) carry
//! the same transfer number at once. Every test runs over both link kinds.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use wz_session_core::json5::{self, Json5Value};

use crate::datagram_tests::{frame_carrying, push, sender_space};
use crate::e2e_row_tests::{frame, profile_text, Link, Wire, LINKS};
use crate::exchange::tests::{request_query, response_final};
use crate::field_values::{field_values_since, ValuesAsk, ValuesMemory};
use crate::field_values_tests::Numbered;
use crate::fields_json::{fields_json, fields_json_since_coordinated, Since};
use crate::payload::formats::FormatMap;
use crate::payload_decode::Declarations;
use crate::segment_profile_tests::{demo_piece, DEMO};

/// The message the senders split: JSON, so a `json` rule reads it joined.
const MESSAGE: &[u8] = br#"{"temp":21}"#;

/// The live key, and the key a history query names and its replies carry.
const LIVE: &str = "demo/large";
const HISTORY: &str = "demo/large/@history";

/// The responder's id, as the reply's extension carries it.
const RESPONDER: [u8; 18] = [
    0x10, 0x8e, 0x7a, 0x01, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
    0x01, 0x00,
];

/// `text` on one line, as a declaration needs it.
fn one_line(text: &str) -> String {
    text.split('\n').map(str::trim).collect::<Vec<_>>().join("")
}

/// The segment profile, a segment rule for the live key and one for the
/// history key, then `extra`. `**` is not among them: a verbatim `@` chunk is
/// covered only by a pattern that names it.
fn declarations(extra: &str) -> String {
    format!(
        "#demo-split={}\n{LIVE}=demo-split\n{HISTORY}=demo-split\n{extra}",
        one_line(DEMO)
    )
}

/// Piece `range` of `message`, on stream 1, transfer `number`.
fn piece_of(message: &[u8], number: u8, range: core::ops::Range<usize>) -> Vec<u8> {
    demo_piece(
        1,
        number,
        message.len() as u32,
        range.start as u32,
        &message[range],
    )
}

/// A `Response` echoing `request_id` under the whole key `key`, carrying a
/// `Reply` with one `Put` of `payload`: no consolidation byte, no timestamp,
/// no encoding, and the two extensions a responder writes on every reply (a
/// 64-bit one at id 1 and its own id, 18 bytes, at id 3).
fn reply<'a>(request_id: u64, key: &'a str, payload: &'a [u8]) -> Vec<u8> {
    use wz_codecs::lent::{ExtEntry, ExtEntryVariant};
    use wz_session_core::ext_header::network_eid;
    let qos = ExtEntry {
        header: network_eid::QOS,
        body: ExtEntryVariant::CodecZenohExtZint(wz_codecs::ext_zint::ExtZint { value: 5 }),
    };
    let responder = ExtEntry {
        header: network_eid::RESPONDER,
        body: ExtEntryVariant::CodecZenohExtZbuf(wz_codecs::lent::ExtZbuf {
            value_len: RESPONDER.len() as u64,
            value: wz_codecs::Bounded::new(&RESPONDER[..]).unwrap(),
        }),
    };
    wz_codecs::lent::Response {
        header: wz_codecs::lent::Response::default().header | wz_codecs::wire_const::FLAG_N_N,
        request_id,
        keyexpr: sender_space(0, Some(key)),
        extensions: Some(wz_codecs::Bounded::new([qos, responder].into_iter().collect()).unwrap()),
        body: wz_codecs::lent::ResponseVariant::CodecZenohReply(wz_codecs::lent::Reply {
            body: wz_codecs::lent::ReplyVariant::CodecZenohMsgPut(wz_codecs::lent::MsgPut {
                payload_len: Some(payload.len() as u64),
                extensions_has_0x12: wz_codecs::msg_put::MsgPutExtensionsHas0x12::NotHas0x12 {
                    extensions: None,
                    payload: wz_codecs::Bounded::new(payload).unwrap(),
                },
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
    .encode_to_vec()
}

/// The querier (the low end) asks `key` under `rid`.
fn ask(wire: &mut Wire, rid: u64, key: &'static str) {
    wire.send(
        true,
        None,
        &frame_carrying(&request_query(rid, sender_space(0, Some(key)))),
    );
}

/// The responder (the high end) answers `rid` under `key` with `payload`,
/// one reply to a batch.
fn answer(wire: &mut Wire, rid: u64, key: &str, payload: &[u8]) {
    wire.send(false, None, &frame_carrying(&reply(rid, key, payload)));
}

/// The responder closes `rid`.
fn close(wire: &mut Wire, rid: u64) {
    wire.send(false, None, &frame_carrying(&response_final(rid)));
}

/// The responder publishes `payload` live on `key`.
fn publish(wire: &mut Wire, key: &'static str, payload: &[u8]) {
    wire.send(
        false,
        None,
        &frame_carrying(&push(sender_space(0, Some(key)), payload)),
    );
}

fn member<'v>(value: &'v Json5Value, key: &str) -> Option<&'v Json5Value> {
    match value {
        Json5Value::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn word(value: Option<&Json5Value>) -> Option<&str> {
    match value {
        Some(Json5Value::String(s)) => Some(s),
        _ => None,
    }
}

/// The values document over `wire` for `paths`, every row.
fn values(wire: &mut Wire, text: &str, paths: &str) -> Json5Value {
    wire.d.finish();
    let any = crate::filter::Filter::any();
    let doc = field_values_since(
        &wire.d,
        &Numbered,
        ValuesAsk {
            declarations: text,
            selector: "",
            filter: &any,
            paths,
            after_seq: 0,
            through_seq: u64::MAX,
        },
        &mut ValuesMemory::new(),
        None,
    )
    .expect("a document");
    json5::parse(&doc).expect("the values document is JSON")
}

fn value_records(doc: &Json5Value) -> Vec<Json5Value> {
    match member(doc, "records") {
        Some(Json5Value::Array(items)) => items.clone(),
        other => panic!("records: {other:?}"),
    }
}

/// The live stream and the replies to two queries, each a three-piece message
/// numbered transfer 1, interleaved piece by piece, and each query closed after
/// its last reply. Every row in the order sent: the two queries, then three
/// rounds of (live, reply to 1, reply to 2), then the two finals.
fn interleaved(wire: &mut Wire) {
    ask(wire, 1, HISTORY);
    ask(wire, 2, HISTORY);
    for range in [0..4, 4..8, 8..11] {
        publish(wire, LIVE, &piece_of(MESSAGE, 1, range.clone()));
        answer(wire, 1, HISTORY, &piece_of(MESSAGE, 1, range.clone()));
        answer(wire, 2, HISTORY, &piece_of(MESSAGE, 1, range));
    }
    close(wire, 1);
    close(wire, 2);
}

/// The values door joins the replies to each query into a message of its own,
/// beside the live one, though all three are transfer 1 of stream 1 from one
/// sender: joined as one stream, the second query's first reply would overlap
/// the first query's and the second message would never complete.
#[test]
fn the_values_door_joins_each_querys_replies_apart_from_the_live_stream() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        interleaved(&mut wire);
        let doc = values(
            &mut wire,
            &declarations(&format!("{LIVE}=json\n{HISTORY}=json")),
            "$.temp",
        );
        let recs = value_records(&doc);
        let states: Vec<&str> = recs
            .iter()
            .map(|r| word(member(r, "state")).unwrap_or("-"))
            .collect();
        assert_eq!(
            states,
            [
                "segment_piece",
                "segment_piece",
                "segment_piece",
                "segment_piece",
                "segment_piece",
                "segment_piece",
                "decoded",
                "decoded",
                "decoded"
            ],
            "{link:?}: {doc:?}"
        );
        for rec in &recs {
            let segment = member(rec, "segment").expect("a segment");
            assert!(
                matches!(member(segment, "unjoined"), Some(Json5Value::Null)),
                "{link:?}: every piece joins its own stream: {doc:?}"
            );
        }
        let keys: Vec<&str> = recs[6..]
            .iter()
            .map(|r| word(member(r, "keyexpr")).unwrap_or("-"))
            .collect();
        assert_eq!(keys, [LIVE, HISTORY, HISTORY], "{link:?}");
    }
}

// ------------------------------------------------------- the field document

fn document(wire: &mut Wire, text: &str) -> String {
    wire.d.finish();
    let mut map = FormatMap::new();
    map.declare_all(text).expect("declarations install");
    fields_json(&wire.d, &wire.file(), None, Some(&Declarations::new(&map)))
}

/// Every `carried` entry of a `Push` or a `Response`, in document order.
fn entries(doc: &str) -> Vec<Json5Value> {
    fn walk(value: &Json5Value, out: &mut Vec<Json5Value>) {
        match value {
            Json5Value::Object(entries) => {
                for (k, v) in entries {
                    if let (true, Json5Value::Array(items)) = (k == "carried", v) {
                        out.extend(
                            items
                                .iter()
                                .filter(|e| {
                                    matches!(
                                        word(member(e, "message")),
                                        Some("Push") | Some("Response")
                                    )
                                })
                                .cloned(),
                        );
                    }
                    walk(v, out);
                }
            }
            Json5Value::Array(items) => items.iter().for_each(|v| walk(v, out)),
            _ => {}
        }
    }
    let tree = json5::parse(doc).expect("the document is JSON");
    let mut out = Vec::new();
    walk(&tree, &mut out);
    out
}

/// The `message` word of each entry.
fn messages(found: &[Json5Value]) -> Vec<&str> {
    found
        .iter()
        .map(|e| word(member(e, "message")).unwrap_or("-"))
        .collect()
}

/// The `segment.place` of each entry (`-` where it has no segment or no place).
fn places(found: &[Json5Value]) -> Vec<&str> {
    found
        .iter()
        .map(|e| {
            member(e, "segment")
                .and_then(|s| word(member(s, "place")))
                .unwrap_or("-")
        })
        .collect()
}

/// Whether `value` is an array with nothing in it.
fn empty(value: Option<&Json5Value>) -> bool {
    matches!(value, Some(Json5Value::Array(items)) if items.is_empty())
}

#[test]
fn the_field_document_joins_each_querys_replies_apart_from_the_live_stream() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        interleaved(&mut wire);
        let doc = document(
            &mut wire,
            &declarations(&format!("{LIVE}=json\n{HISTORY}=json")),
        );
        let found = entries(&doc);
        assert_eq!(
            messages(&found),
            ["Push", "Response", "Response"].repeat(3),
            "{link:?}: {doc}"
        );
        assert_eq!(
            places(&found),
            [
                "first",
                "first",
                "first",
                "continuing",
                "continuing",
                "continuing",
                "closing",
                "closing",
                "closing"
            ],
            "{link:?}: {doc}"
        );
        for entry in &found {
            let segment = member(entry, "segment").expect("a piece");
            assert!(
                empty(member(segment, "ended_transfers")),
                "{link:?}: no stream ended another: {doc}"
            );
            assert!(matches!(
                member(segment, "overlap"),
                Some(Json5Value::Bool(false))
            ));
        }
        for closing in &found[6..] {
            let joined = member(member(closing, "segment").expect("a piece"), "joined")
                .expect("the message");
            let decode = member(joined, "payload_decode").expect("decoded");
            assert_eq!(
                word(member(decode, "state")),
                Some("decoded"),
                "{link:?}: {doc}"
            );
        }
        // A reply's own entry keeps its key verbatim.
        assert_eq!(word(member(&found[1], "keyexpr")), Some(HISTORY));
    }
}

/// A piece that cannot be placed, or that is not where its transfer starts,
/// is answered for a reply in the words it is answered for a published one.
#[test]
fn a_reply_piece_that_cannot_chain_is_answered_as_a_published_one_is() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        ask(&mut wire, 1, HISTORY);
        // No first piece: the chunk at 4 is the first the capture saw.
        publish(&mut wire, LIVE, &piece_of(MESSAGE, 1, 4..8));
        answer(&mut wire, 1, HISTORY, &piece_of(MESSAGE, 1, 4..8));
        // A chunk past the whole it claims.
        publish(&mut wire, LIVE, &demo_piece(1, 2, 4, 2, b"abc"));
        answer(&mut wire, 1, HISTORY, &demo_piece(1, 2, 4, 2, b"abc"));
        let doc = document(&mut wire, &declarations(""));
        let found = entries(&doc);
        assert_eq!(found.len(), 4, "{link:?}: {doc}");
        let verdict = |entry: &Json5Value| {
            let segment = member(entry, "segment").expect("a piece").clone();
            (
                member(&segment, "place").cloned(),
                member(&segment, "unjoined").cloned(),
                member(&segment, "missing_ranges").cloned(),
            )
        };
        assert_eq!(verdict(&found[0]), verdict(&found[1]), "{link:?}: {doc}");
        assert_eq!(verdict(&found[2]), verdict(&found[3]), "{link:?}: {doc}");
        assert_eq!(places(&found[..2]), ["first", "first"], "{link:?}");
        let missing = member(
            member(&found[1], "segment").expect("a piece"),
            "missing_ranges",
        );
        assert!(
            matches!(missing, Some(Json5Value::Array(r)) if r.len() == 1),
            "{link:?}: bytes 0..4 are missing: {doc}"
        );
        assert_eq!(
            word(member(
                member(&found[3], "segment").expect("a piece"),
                "unjoined"
            )),
            Some("past_total"),
            "{link:?}: {doc}"
        );
    }
}

/// A rule covers a reply by the reply's own key: a rule on the live key, or
/// one ending in `**`, does not reach `<key>/@history`, and a rule naming it
/// does. The live key is the other way round.
#[test]
fn a_reply_is_covered_by_the_rule_for_its_own_key_and_no_other() {
    let profile = one_line(DEMO);
    for link in LINKS {
        for (rules, live, replied) in [
            (
                format!("#demo-split={profile}\n{LIVE}=demo-split\ndemo/large/**=demo-split\n**=demo-split"),
                true,
                false,
            ),
            (
                format!("#demo-split={profile}\n{HISTORY}=demo-split"),
                false,
                true,
            ),
        ] {
            let mut wire = Wire::new(link, true);
            ask(&mut wire, 1, HISTORY);
            publish(&mut wire, LIVE, &piece_of(MESSAGE, 1, 0..11));
            answer(&mut wire, 1, HISTORY, &piece_of(MESSAGE, 1, 0..11));
            let doc = document(&mut wire, &rules);
            let found = entries(&doc);
            assert_eq!(messages(&found), ["Push", "Response"], "{link:?}: {doc}");
            let pieces: Vec<bool> = found
                .iter()
                .map(|e| member(e, "segment").is_some())
                .collect();
            assert_eq!(pieces, [live, replied], "{link:?} under {rules}: {doc}");
        }
    }
}

/// Every `carried` entry of a `ResponseFinal`, in document order.
fn finals(doc: &str) -> Vec<Json5Value> {
    let tree = json5::parse(doc).expect("the document is JSON");
    let mut carried = Vec::new();
    collect(&tree, "carried", &mut carried);
    carried
        .iter()
        .filter_map(|list| match list {
            Json5Value::Array(items) => Some(items.clone()),
            _ => None,
        })
        .flatten()
        .filter(|e| word(member(e, "message")) == Some("ResponseFinal"))
        .collect()
}

/// A query's `ResponseFinal` ends its own query's unfinished reply transfer,
/// and says so on its entry (`ended_by` `closed`, with what had arrived); it
/// ends nothing of the live stream it interleaves with or of another query,
/// whose transfers complete as they would have. A final whose replies all
/// completed ends nothing and says so with an empty list, and a piece of a
/// closed query that comes after its final begins afresh.
#[test]
fn a_final_ends_its_own_querys_unfinished_transfer_and_says_so() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        ask(&mut wire, 1, HISTORY);
        ask(&mut wire, 2, HISTORY);
        publish(&mut wire, LIVE, &piece_of(MESSAGE, 1, 0..4));
        answer(&mut wire, 1, HISTORY, &piece_of(MESSAGE, 1, 0..4));
        answer(&mut wire, 2, HISTORY, &piece_of(MESSAGE, 1, 0..4));
        close(&mut wire, 1);
        publish(&mut wire, LIVE, &piece_of(MESSAGE, 1, 4..11));
        answer(&mut wire, 2, HISTORY, &piece_of(MESSAGE, 1, 4..11));
        close(&mut wire, 2);
        // A straggler of the closed query.
        answer(&mut wire, 1, HISTORY, &piece_of(MESSAGE, 1, 4..8));
        let doc = document(&mut wire, &declarations(""));
        let found = entries(&doc);
        assert_eq!(
            places(&found),
            ["first", "first", "first", "closing", "closing", "first"],
            "{link:?}: {doc}"
        );
        for entry in &found {
            let segment = member(entry, "segment").expect("a piece");
            assert!(empty(member(segment, "ended_transfers")), "{link:?}: {doc}");
            // The entry's own key is a final's; here it is `null`.
            assert!(
                matches!(member(entry, "ended_transfers"), Some(Json5Value::Null)),
                "{link:?}: {doc}"
            );
        }
        let closed = finals(&doc);
        assert_eq!(closed.len(), 2, "{link:?}: {doc}");
        let Some(Json5Value::Array(ended)) = member(&closed[0], "ended_transfers") else {
            panic!("{link:?}: the first final says what it ended: {doc}");
        };
        assert_eq!(ended.len(), 1, "{link:?}: {doc}");
        assert_eq!(cell(&ended[0], "ended_by"), "closed", "{link:?}");
        assert_eq!(cell(&ended[0], "transfer"), "1", "{link:?}");
        assert_eq!(cell(&ended[0], "whole_bytes"), "11", "{link:?}");
        assert_eq!(cell(&ended[0], "received_bytes"), "4", "{link:?}");
        assert_eq!(cell(&ended[0], "evicted"), "false", "{link:?}");
        assert!(
            empty(member(&closed[1], "ended_transfers")),
            "{link:?}: the second query's reply completed: {doc}"
        );
    }
}

/// Without a segment rule nothing was ever joined, and a final's entry says
/// `null`, as every other entry does.
#[test]
fn a_final_says_nothing_where_no_piece_is_joined() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        ask(&mut wire, 1, HISTORY);
        answer(&mut wire, 1, HISTORY, &piece_of(MESSAGE, 1, 0..4));
        close(&mut wire, 1);
        let doc = document(&mut wire, &format!("{HISTORY}=json"));
        let closed = finals(&doc);
        assert_eq!(closed.len(), 1, "{link:?}: {doc}");
        assert!(
            matches!(
                member(&closed[0], "ended_transfers"),
                Some(Json5Value::Null)
            ),
            "{link:?}: {doc}"
        );
    }
}

/// The values door closes a query's replies at its final too: a piece of the
/// query after the final begins a message afresh rather than completing the
/// one the final ended.
#[test]
fn the_values_door_closes_a_querys_replies_at_its_final() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        ask(&mut wire, 1, HISTORY);
        answer(&mut wire, 1, HISTORY, &piece_of(MESSAGE, 1, 0..4));
        close(&mut wire, 1);
        answer(&mut wire, 1, HISTORY, &piece_of(MESSAGE, 1, 4..11));
        let doc = values(
            &mut wire,
            &declarations(&format!("{HISTORY}=json")),
            "$.temp",
        );
        let recs = value_records(&doc);
        let places: Vec<&str> = recs
            .iter()
            .map(|r| {
                member(r, "segment")
                    .and_then(|s| word(member(s, "place")))
                    .unwrap_or("-")
            })
            .collect();
        assert_eq!(places, ["first", "first"], "{link:?}: {doc:?}");
        let states: Vec<&str> = recs
            .iter()
            .map(|r| word(member(r, "state")).unwrap_or("-"))
            .collect();
        assert_eq!(states, ["segment_piece", "segment_piece"], "{link:?}");
    }
}

/// The rows of a reply's first pieces that a cursor passes over are still
/// joined, so the piece after the cursor completes the message.
#[test]
fn a_cursor_that_passes_a_replys_first_pieces_still_gets_the_message() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        // Rows 1 and 2 are the handshakes, 3 the query, 4 to 6 the replies.
        ask(&mut wire, 1, HISTORY);
        for range in [0..4, 4..8, 8..11] {
            answer(&mut wire, 1, HISTORY, &piece_of(MESSAGE, 1, range));
        }
        wire.d.finish();
        let mut map = FormatMap::new();
        map.declare_all(&declarations(&format!("{HISTORY}=json")))
            .expect("installs");
        let run = Declarations::new(&map);
        let doc = fields_json_since_coordinated(
            &wire.d,
            &wire.file(),
            Some(&run),
            &Numbered,
            Since {
                after_seq: 5,
                through_seq: 6,
            },
        );
        let found = entries(&doc);
        assert_eq!(places(&found), ["closing"], "{link:?}: {doc}");
        let joined =
            member(member(&found[0], "segment").expect("a piece"), "joined").expect("the message");
        assert!(
            matches!(member(joined, "whole_bytes"), Some(Json5Value::Number(n)) if n == "11"),
            "{link:?}: {doc}"
        );
    }
}

// -------------------------------------------------------- the end-to-end block

/// A profile rule on the live key and on the history key, each naming a body
/// schema, with the segment rules.
fn e2e_declarations() -> String {
    format!(
        "#prof={}\n{}",
        profile_text("prof", 3),
        declarations(&format!("{LIVE}=prof@pkg.Pose\n{HISTORY}=prof@pkg.Pose"))
    )
}

/// A live frame, a query answered with a past frame in three pieces and one
/// whole, a second query answered on the LIVE key with a frame whose counter
/// is far ahead, and a second live frame.
fn answered_history(wire: &mut Wire) {
    publish(wire, LIVE, &frame(5, b"live-a"));
    ask(wire, 1, HISTORY);
    let past = frame(3, b"from-the-past");
    let third = past.len() / 3;
    for range in [0..third, third..2 * third, 2 * third..past.len()] {
        answer(wire, 1, HISTORY, &piece_of(&past, 1, range));
    }
    answer(wire, 1, HISTORY, &frame(4, b"whole"));
    close(wire, 1);
    ask(wire, 2, LIVE);
    answer(wire, 2, LIVE, &frame(9, b"ahead"));
    close(wire, 2);
    publish(wire, LIVE, &frame(6, b"live-b"));
}

/// Every `e2e` block of the document at any depth, in document order.
fn e2e_blocks(doc: &str) -> Vec<Json5Value> {
    let tree = json5::parse(doc).expect("the document is JSON");
    let mut out = Vec::new();
    collect(&tree, "e2e", &mut out);
    out
}

fn collect(value: &Json5Value, key: &str, out: &mut Vec<Json5Value>) {
    match value {
        Json5Value::Object(entries) => {
            for (k, v) in entries {
                if k == key {
                    out.push(v.clone());
                }
                collect(v, key, out);
            }
        }
        Json5Value::Array(items) => items.iter().for_each(|v| collect(v, key, out)),
        _ => {}
    }
}

/// A cell of a block as text: a word, a number, a boolean or `null`.
fn cell(block: &Json5Value, key: &str) -> String {
    match member(block, key) {
        Some(Json5Value::String(s)) => s.clone(),
        Some(Json5Value::Number(n)) => n.clone(),
        Some(Json5Value::Bool(b)) => alloc::string::ToString::to_string(b),
        Some(Json5Value::Null) => String::from("null"),
        other => panic!("`{key}`: {other:?}"),
    }
}

/// A reply's frame, joined or whole, is read under the rule its own key falls
/// to: its CRC and length judged, its counter and timeout not, with the reason
/// `reply`; and the live slot does not move for it, even for a reply on the
/// live key whose counter is far ahead.
#[test]
fn a_replys_frame_is_read_and_its_counter_left_unjudged() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        answered_history(&mut wire);
        let doc = document(&mut wire, &e2e_declarations());
        let blocks = e2e_blocks(&doc);
        assert_eq!(blocks.len(), 5, "{link:?}: {doc}");
        let column = |key: &str| -> Vec<String> { blocks.iter().map(|b| cell(b, key)).collect() };
        assert_eq!(
            column("unjudged_reason"),
            ["null", "reply", "reply", "reply", "null"],
            "{link:?}: {doc}"
        );
        assert_eq!(column("counter"), ["5", "3", "4", "9", "6"], "{link:?}");
        assert_eq!(
            column("crc_error"),
            ["false", "false", "false", "false", "false"],
            "{link:?}: the CRC of a reply is judged"
        );
        assert_eq!(
            column("length_matches_frame"),
            ["true", "true", "true", "true", "true"],
            "{link:?}"
        );
        for key in [
            "counter_error",
            "timeout_error",
            "counter_reason",
            "silence_ms",
            "previous_counter",
            "first",
            "counter_step",
            "max_gap",
            "timeout_ms",
        ] {
            for reply in &blocks[1..4] {
                assert_eq!(
                    cell(reply, key),
                    "null",
                    "{link:?}: `{key}` of a reply: {doc}"
                );
            }
        }
        // The second live frame is judged against the first: the replies,
        // the one on the live key included, moved nothing.
        assert_eq!(
            [
                cell(&blocks[4], "counter_reason"),
                cell(&blocks[4], "previous_counter"),
                cell(&blocks[4], "counter_step"),
            ],
            ["none", "5", "1"],
            "{link:?}: {doc}"
        );
        assert_eq!(cell(&blocks[0], "first"), "true", "{link:?}");
        let slot = member(&blocks[1], "slot").expect("slot");
        assert_eq!(cell(slot, "keyexpr"), HISTORY, "{link:?}");
        // The joined message is decoded as a live one is.
        let found = entries(&doc);
        let closing = found
            .iter()
            .find(|e| {
                member(e, "segment").and_then(|s| word(member(s, "place"))) == Some("closing")
            })
            .expect("the closing piece");
        let joined =
            member(member(closing, "segment").expect("a piece"), "joined").expect("the message");
        let decode = member(joined, "payload_decode").expect("decoded");
        assert_eq!(
            word(member(decode, "format")),
            Some("prof"),
            "{link:?}: {doc}"
        );
    }
}

/// The documents the field document's pins read for what revision 66 adds: a
/// reply's pieces, the message they join to and a whole reply, each frame under
/// a rule that names a body schema, so `unjudged_reason` says `reply` in the
/// shape the end-to-end pins' `sender_unknown` arrives in.
///
/// A stream capture, for the reason `e2e_row_tests::pin_documents` gives.
///
/// And a query whose final ends its reply unfinished, so a final's
/// `ended_transfers` holds an entry and `ended_by` says `closed` beside the
/// `superseded` the segment pins render.
pub(crate) fn pin_documents() -> Vec<String> {
    let mut wire = Wire::new(Link::Tcp, true);
    answered_history(&mut wire);
    ask(&mut wire, 3, HISTORY);
    answer(&mut wire, 3, HISTORY, &piece_of(MESSAGE, 1, 0..4));
    close(&mut wire, 3);
    alloc::vec![document(&mut wire, &e2e_declarations())]
}

/// Every message row of `doc`: an object with a `direction` and an
/// `offset_space`.
fn rows(doc: &str) -> Vec<Json5Value> {
    fn walk(value: &Json5Value, out: &mut Vec<Json5Value>) {
        match value {
            Json5Value::Object(entries) => {
                if value.get("direction").is_some() && value.get("offset_space").is_some() {
                    out.push(value.clone());
                    return;
                }
                entries.iter().for_each(|(_, v)| walk(v, out));
            }
            Json5Value::Array(items) => items.iter().for_each(|v| walk(v, out)),
            _ => {}
        }
    }
    let tree = json5::parse(doc).expect("the document is JSON");
    let mut out = Vec::new();
    walk(&tree, &mut out);
    out
}

/// Whether a row carries a record of `message`.
fn carries(row: &Json5Value, message: &str) -> bool {
    let mut carried = Vec::new();
    collect(row, "carried", &mut carried);
    carried.iter().any(|list| match list {
        Json5Value::Array(items) => items
            .iter()
            .any(|e| word(member(e, "message")) == Some(message)),
        _ => false,
    })
}

/// THE SELECTOR READS A REPLY AS THE BLOCK DOES. Over one capture of live
/// frames and replies, through the door that takes declarations, a row of a
/// `Push` or a `Response` carries an `e2e` block exactly where `e2e == none`
/// says `no`; the rows of the replies' frames (the completing piece's, the
/// whole reply's, the reply on the live key) answer `e2e.counter == unjudged`
/// `yes` and `e2e.crc == ok` `yes`, as their blocks say; and a door handed no
/// declarations leaves every reply row undecided, as it leaves a published
/// sample, rather than deciding `none`.
#[test]
fn the_selector_reads_a_replys_frame_as_its_block_does() {
    for link in LINKS {
        let mut wire = Wire::new(link, true);
        answered_history(&mut wire);
        wire.d.finish();
        let mut map = FormatMap::new();
        map.declare_all(&e2e_declarations()).expect("installs");
        let run = Declarations::new(&map);
        let file = wire.file();
        let under = |selector: &str| {
            let filter = crate::filter::Filter::parse(selector).expect("a selector");
            rows(&crate::fields_json::fields_json_where(
                &wire.d,
                &file,
                None,
                Some(&run),
                &filter,
            ))
        };
        let none = under("e2e == none");
        let samples: Vec<&Json5Value> = none
            .iter()
            .filter(|r| carries(r, "Push") || carries(r, "Response"))
            .collect();
        assert_eq!(samples.len(), 7, "{link:?}: two live frames, five replies");
        for row in &samples {
            let mut blocks = Vec::new();
            collect(row, "e2e", &mut blocks);
            let word = cell(row, "selected");
            assert_eq!(
                word == "no",
                !blocks.is_empty(),
                "{link:?}: `e2e == none` says {word} of a row whose blocks are {blocks:?}"
            );
        }
        for selector in ["e2e.counter == unjudged", "e2e.crc == ok"] {
            let judged = under(selector);
            for row in judged.iter().filter(|r| carries(r, "Response")) {
                let mut blocks = Vec::new();
                collect(row, "e2e", &mut blocks);
                if blocks.is_empty() {
                    continue;
                }
                assert_eq!(cell(row, "selected"), "yes", "{link:?}: {selector}");
            }
        }
        // A door handed no declarations decides nothing about a reply.
        let filter = crate::filter::Filter::parse("e2e == none").expect("a selector");
        let plain = rows(&crate::fields_json::fields_json_where(
            &wire.d, &file, None, None, &filter,
        ));
        for row in plain.iter().filter(|r| carries(r, "Response")) {
            assert_eq!(cell(row, "selected"), "undecided", "{link:?}");
        }
    }
}

#[test]
fn the_pin_documents_say_reply_on_a_block_that_names_its_body_schema() {
    for doc in pin_documents() {
        let blocks = e2e_blocks(&doc);
        assert!(
            blocks.iter().any(
                |b| cell(b, "unjudged_reason") == "reply" && member(b, "body_schema").is_some()
            ),
            "{doc}"
        );
        let closed = finals(&doc)
            .iter()
            .any(|f| match member(f, "ended_transfers") {
                Some(Json5Value::Array(ended)) => {
                    ended.iter().any(|e| cell(e, "ended_by") == "closed")
                }
                _ => false,
            });
        assert!(closed, "a final names the transfer it ended: {doc}");
    }
}
