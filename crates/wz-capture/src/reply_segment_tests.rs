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
use crate::e2e_row_tests::{Wire, LINKS};
use crate::exchange::tests::{request_query, response_final};
use crate::field_values::{field_values_since, ValuesAsk, ValuesMemory};
use crate::field_values_tests::Numbered;
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
pub(crate) fn reply<'a>(request_id: u64, key: &'a str, payload: &'a [u8]) -> Vec<u8> {
    use wz_codecs::lent::{ExtEntry, ExtEntryVariant};
    use wz_session_core::ext_header::{EXT_ENC_Z64, EXT_ENC_ZBUF};
    let qos = ExtEntry {
        header: 0x01 | EXT_ENC_Z64,
        body: ExtEntryVariant::CodecZenohExtZint(wz_codecs::ext_zint::ExtZint { value: 5 }),
    };
    let responder = ExtEntry {
        header: 0x03 | EXT_ENC_ZBUF,
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
