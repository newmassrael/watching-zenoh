// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_dissect_transport_message_in`, held against the session document.
//!
//! # The oracle
//!
//! The door's claim is that a message handed over WITH its flow's `context`
//! reads as the session document reads it. So the oracle is the document: build
//! a whole session, take the document `wz_dissect_pcap_fields` writes for it,
//! and for EVERY message compare the door's node with the `fields` of that
//! message's row. Two doors reading one session cannot agree by construction,
//! which is what makes the comparison evidence: the document reaches its tree
//! through the session fold and the single-message door through the MID alone.
//!
//! The context handed to the door is the object the document wrote, cut out of
//! the document's own text, so what is exercised is the consumer's real path
//! and not a literal this file typed.

use super::*;
use wz_session_core::json5::{self, Json5Value};

/// Which way a message of the fixture travels. `Forward` is the side that sent
/// the first Init, which the document calls direction `a`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Way {
    Forward,
    Reverse,
}

impl Way {
    fn word(self) -> &'static str {
        match self {
            Way::Forward => "a",
            Way::Reverse => "b",
        }
    }
}

/// A session as bytes: the capture, and every message in it in wire order.
struct Session {
    capture: Vec<u8>,
    messages: Vec<(Way, Vec<u8>)>,
}

/// `body` behind a little-endian length prefix of `width` bytes.
fn prefixed(body: &[u8], width: usize) -> Vec<u8> {
    let mut wire = (body.len() as u32).to_le_bytes()[..width].to_vec();
    wire.extend_from_slice(body);
    wire
}

/// The messages' packets, one TCP segment each, in a pcap.
fn capture_of(messages: &[(Way, Vec<u8>)], widths: impl Fn(usize) -> usize) -> Vec<u8> {
    let mut seq = [1000u32, 2000u32];
    let packets: Vec<Vec<u8>> = messages
        .iter()
        .enumerate()
        .map(|(i, (way, body))| {
            let wire = prefixed(body, widths(i));
            let side = usize::from(*way == Way::Reverse);
            let packet = match way {
                Way::Forward => tcp_packet(seq[side], &wire),
                Way::Reverse => tcp_packet_reverse(seq[side], &wire),
            };
            seq[side] += wire.len() as u32;
            packet
        })
        .collect();
    let rows: Vec<_> = packets
        .iter()
        .enumerate()
        .map(|(i, packet)| (0, i as u32, packet.as_slice()))
        .collect();
    wz_capture::pcap::write(1, &rows)
}

fn declare_message() -> Vec<u8> {
    wz_session_core::declare_build::build_declare_subscriber(1, 0, Some("demo/**"))
        .expect("subscriber")
        .try_as_borrowed()
        .expect("borrow")
        .encode_to_vec()
}

fn push_message(payload: &[u8]) -> Vec<u8> {
    wz_codecs::push::Push {
        header: wz_codecs::push::Push::default().header | wz_codecs::wire_const::FLAG_N_N,
        keyexpr: literal("demo/temp"),
        body: wz_codecs::push::PushVariant::CodecZenohMsgPut(wz_codecs::msg_put::MsgPut {
            payload_len: Some(payload.len() as u64),
            payload: Some(payload),
            ..Default::default()
        }),
        ..Default::default()
    }
    .encode_to_vec()
}

fn request_message() -> Vec<u8> {
    wz_codecs::request::Request {
        header: wz_codecs::request::Request::default().header | wz_codecs::wire_const::FLAG_N_N,
        rid: 7,
        keyexpr: literal("demo/q"),
        body: wz_codecs::request::RequestVariant::CodecZenohQuery(
            wz_codecs::query::Query::default(),
        ),
        ..Default::default()
    }
    .encode_to_vec()
}

fn response_final_message() -> Vec<u8> {
    wz_codecs::response_final::ResponseFinal {
        request_id: 7,
        ..Default::default()
    }
    .encode_to_vec()
}

/// Init, InitAck, OpenSyn, OpenAck, laid out byte by byte from the transport
/// wire layout. `ext` is the Init extension chain both Inits carry, already
/// ending on a clear continuation bit.
///
/// The Inits carry `S` (so the context gets a `sn_mask`, a `batch_size` and a
/// `patch` to ignore, as a real document's does) and the InitAck carries `A`
/// with an empty cookie.
fn handshake(ext: &[u8]) -> [(Way, Vec<u8>); 4] {
    let with_ext = |head: &[u8]| {
        let mut bytes = head.to_vec();
        bytes.extend_from_slice(ext);
        bytes
    };
    // INIT: header (Z set when there is a chain, S set), version, cbyte (a
    // one-byte zid, whatami 2), zid, sn_res (32-bit both), batch size LE.
    let z = if ext.is_empty() { 0 } else { 0x80 };
    [
        (
            Way::Forward,
            with_ext(&[0x41 | z, 9, 0x02, 0x01, 0x0A, 0xFF, 0xFF]),
        ),
        (
            Way::Reverse,
            // The acknowledgement adds A, and with it a cookie length (0).
            with_ext(&[0x61 | z, 9, 0x02, 0x02, 0x0A, 0xFF, 0xFF, 0x00]),
        ),
        // OPEN syn: lease 10, initial sn 0, then (A clear) a cookie length 0.
        (Way::Forward, Vec::from([0x02, 10, 0, 0])),
        // OPEN ack: A set, lease 10, initial sn 0, no cookie.
        (Way::Reverse, Vec::from([0x22, 10, 0])),
    ]
}

/// A LowLatency session: both Inits offer it (extension id 5, a unit) beside a
/// patch level (id 7, a z64 holding 1), and everything after the handshake is
/// one bare message per unit behind a four-byte prefix, from each direction's
/// own Open on.
fn lowlatency_session() -> Session {
    // 0x85: id 5, unit, more follows. 0x27: id 7, z64, last. 0x01: patch 1.
    let mut messages = handshake(&[0x85, 0x27, 0x01]).to_vec();
    let big = vec![0x5A; 4096];
    messages.push((Way::Forward, declare_message()));
    messages.push((Way::Forward, push_message(b"hello")));
    messages.push((Way::Forward, push_message(&big)));
    messages.push((Way::Forward, push_message(b"")));
    messages.push((Way::Forward, push_message(b"x")));
    messages.push((Way::Forward, push_message(b"hello")));
    messages.push((Way::Forward, request_message()));
    messages.push((Way::Reverse, response_final_message()));
    // KeepAlive both ways and a Close: the transport messages a lean link
    // still carries bare.
    messages.push((Way::Reverse, Vec::from([0x04])));
    messages.push((Way::Forward, Vec::from([0x04])));
    messages.push((Way::Forward, Vec::from([0x03, 0x01])));
    let capture = capture_of(&messages, |i| if i < 4 { 2 } else { 4 });
    Session { capture, messages }
}

/// The control: a session that negotiated NOTHING extra. Its data travels
/// inside `Frame` and `Fragment` messages, so every message of it is a
/// transport message.
fn framed_session() -> Session {
    let mut messages = handshake(&[]).to_vec();
    let records = |parts: &[Vec<u8>]| parts.concat();
    let frame = |sn: u8, body: Vec<u8>| {
        // FRAME with R (reliable), then the sequence number, then the batch.
        let mut bytes = Vec::from([
            wz_session_core::wire_const::T_MID_FRAME | wz_session_core::wire_const::FLAG_T_FRAME_R,
            sn,
        ]);
        bytes.extend_from_slice(&body);
        bytes
    };
    messages.push((
        Way::Forward,
        frame(0, records(&[declare_message(), push_message(b"hello")])),
    ));
    messages.push((Way::Forward, frame(1, request_message())));
    messages.push((Way::Reverse, frame(0, response_final_message())));
    // One Push too large for a batch, in two fragments: the first has M (more
    // follows), the last has not.
    let long = push_message(&vec![0xA5; 3000]);
    let (head, tail) = long.split_at(1500);
    for (more, sn, part) in [(true, 2u8, head), (false, 3u8, tail)] {
        // FRAGMENT with R (reliable, 0x20) and, on all but the last, M (more
        // follows, 0x40).
        let mut bytes = Vec::from([
            wz_session_core::wire_const::T_MID_FRAGMENT | 0x20 | if more { 0x40 } else { 0 },
            sn,
        ]);
        bytes.extend_from_slice(part);
        messages.push((Way::Forward, bytes));
    }
    messages.push((Way::Reverse, Vec::from([0x04])));
    messages.push((Way::Forward, Vec::from([0x03, 0x01])));
    let capture = capture_of(&messages, |_| 2);
    Session { capture, messages }
}

fn member<'a>(value: &'a Json5Value, key: &str) -> &'a Json5Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("the document has no `{key}`"))
}

fn items(value: &Json5Value) -> &[Json5Value] {
    match value {
        Json5Value::Array(items) => items,
        other => panic!("not an array: {other:?}"),
    }
}

fn word(value: &Json5Value) -> &str {
    match value {
        Json5Value::String(s) => s,
        other => panic!("not a string: {other:?}"),
    }
}

/// The text of the first `"context":{...}` in `document`, as written.
///
/// Cut out of the text and not re-serialised from a parse, so the door is
/// handed the bytes the document wrote. The object holds no string with a brace
/// in it, which is what lets a depth count find its end.
fn context_text(document: &str) -> &str {
    let key = "\"context\":";
    let start = document.find(key).expect("a flow with a context") + key.len();
    let mut depth = 0usize;
    for (i, b) in document[start..].bytes().enumerate() {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &document[start..start + i + 1];
                }
            }
            _ => {}
        }
    }
    panic!("an unterminated context: {}", &document[start..]);
}

/// Drive the new door the way C does.
fn call_in(context: &str, bytes: &[u8], base: usize) -> Result<String, c_int> {
    let text = std::ffi::CString::new(context).expect("no interior NUL");
    let mut out: *mut c_char = core::ptr::null_mut();
    // SAFETY: a NUL-terminated context, a readable slice, a writable `out`.
    let rc = unsafe {
        wz_dissect_transport_message_in(text.as_ptr(), bytes.as_ptr(), bytes.len(), base, &mut out)
    };
    if rc != WZ_DISSECT_OK {
        assert!(out.is_null(), "an error must hand back no string");
        return Err(rc);
    }
    assert!(!out.is_null(), "OK must come with a string");
    // SAFETY: OK means a NUL-terminated string this library owns.
    let s = unsafe { std::ffi::CStr::from_ptr(out) }
        .to_str()
        .expect("the document is UTF-8")
        .to_string();
    // SAFETY: the pointer this library just handed back, freed once.
    unsafe { wz_dissect_string_free(out) };
    Ok(s)
}

/// Every span of `node` moved `by` bytes on.
fn shifted(node: &Json5Value, by: u64) -> Json5Value {
    match node {
        Json5Value::Object(entries) => Json5Value::Object(
            entries
                .iter()
                .map(|(key, child)| {
                    let moved = match (key.as_str(), child) {
                        ("start" | "end", Json5Value::Number(n)) => Json5Value::Number(
                            (n.parse::<u64>().expect("a span is an integer") + by).to_string(),
                        ),
                        _ => shifted(child, by),
                    };
                    (key.clone(), moved)
                })
                .collect(),
        ),
        Json5Value::Array(children) => {
            Json5Value::Array(children.iter().map(|c| shifted(c, by)).collect())
        }
        other => other.clone(),
    }
}

/// The document of `session`, its flow's context text, and the rows in order.
struct Read {
    context: String,
    rows: Vec<Json5Value>,
}

fn read(session: &Session) -> Read {
    let document = call_fields(&session.capture, 0).expect("the capture reads");
    let parsed = json5::parse(&document).expect("the document is JSON");
    let flows = items(member(&parsed, "stream_flows"));
    assert_eq!(flows.len(), 1, "one flow: {document}");
    Read {
        context: context_text(&document).to_string(),
        rows: items(member(&flows[0], "messages")).to_vec(),
    }
}

/// The row of each message, matched by direction and place within it.
fn rows_of<'a>(session: &Session, read: &'a Read) -> Vec<&'a Json5Value> {
    assert_eq!(
        read.rows.len(),
        session.messages.len(),
        "the document must hold one row per message built"
    );
    let mut next = [0usize; 2];
    session
        .messages
        .iter()
        .map(|(way, _)| {
            let side = usize::from(*way == Way::Reverse);
            let of_way: Vec<&Json5Value> = read
                .rows
                .iter()
                .filter(|row| word(member(row, "direction")) == way.word())
                .collect();
            let row = of_way
                .get(next[side])
                .copied()
                .unwrap_or_else(|| panic!("direction {} ran out of rows", way.word()));
            next[side] += 1;
            row
        })
        .collect()
}

/// The invariant that was broken: for EVERY message of a session, the door
/// handed the flow's context answers with the tree the document gives that
/// message's row.
fn assert_door_equals_document(session: &Session) -> Vec<String> {
    let read = read(session);
    let rows = rows_of(session, &read);
    let mut names = Vec::new();
    for (i, ((_, bytes), row)) in session.messages.iter().zip(rows).enumerate() {
        assert!(
            row.get("declined").is_none(),
            "message {i} was declined by the document, so there is nothing to compare: {row:?}"
        );
        let door = call_in(&read.context, bytes, 0)
            .unwrap_or_else(|rc| panic!("message {i} was refused: rc={rc}"));
        let door = json5::parse(&door).expect("the door answers JSON");
        assert_eq!(
            &door,
            member(row, "fields"),
            "message {i} reads differently through the door and in the document"
        );
        assert_eq!(
            word(member(&door, "name")),
            word(member(row, "name")),
            "message {i}"
        );
        names.push(word(member(&door, "name")).to_string());
    }
    names
}

/// THE DEFECT, THEN THE REPAIR. The first half is the reproduction: the
/// context-free door reads the lean session's data as `Unknown`, which is what
/// a consumer measured. The second is the invariant, over all fifteen messages.
#[test]
fn a_lowlatency_sessions_messages_read_through_the_door_as_the_document_reads_them() {
    let session = lowlatency_session();
    let read = read(&session);
    assert!(
        read.context.contains("\"lowlatency\":true")
            && read.context.contains("\"negotiated\":true"),
        "the fixture must negotiate LowLatency: {}",
        read.context
    );
    // A real document's context, not a minimal one: the keys the door ignores
    // are present and non-null, which is the case "hand over what you hold".
    for key in ["\"patch\":1", "\"version\":9", "\"phase\":\"closed\""] {
        assert!(read.context.contains(key), "{key} in {}", read.context);
    }
    for key in ["\"sn_mask\":", "\"batch_size\":"] {
        assert!(
            read.context.contains(key) && !read.context.contains(&format!("{key}null")),
            "{key} must be a number in {}",
            read.context
        );
    }

    let mut blind_unknown = 0;
    for (_, bytes) in &session.messages {
        if call_transport(bytes).is_ok_and(|tree| tree.starts_with("{\"name\":\"Unknown\"")) {
            blind_unknown += 1;
        }
    }
    assert_eq!(
        blind_unknown, 8,
        "the context-free door must read the eight data messages as Unknown: the defect"
    );

    let names = assert_door_equals_document(&session);
    assert_eq!(
        names,
        [
            "Init",
            "Init",
            "Open",
            "Open",
            "Declare",
            "Push",
            "Push",
            "Push",
            "Push",
            "Push",
            "Request",
            "ResponseFinal",
            "KeepAlive",
            "KeepAlive",
            "Close"
        ]
    );
}

/// The control. A session whose data is framed is read the same by both doors,
/// so handing it a context changes nothing: the new door equals the document AND
/// the old door, message for message, `Frame` and `Fragment` included.
#[test]
fn a_framed_sessions_messages_read_through_the_door_as_they_did_without_it() {
    let session = framed_session();
    let read = read(&session);
    assert!(
        read.context.contains("\"lowlatency\":false")
            && read.context.contains("\"negotiated\":true"),
        "the control must negotiate and not choose LowLatency: {}",
        read.context
    );
    let names = assert_door_equals_document(&session);
    for word in ["Frame", "Fragment"] {
        assert!(
            names.iter().any(|n| n == word),
            "the control must hold a {word}: {names:?}"
        );
    }
    for (i, (_, bytes)) in session.messages.iter().enumerate() {
        assert_eq!(
            call_in(&read.context, bytes, 0),
            call_transport(bytes),
            "message {i}: a framed session's context changes nothing about how a message reads"
        );
    }
}

/// Spans are in `base`'s coordinate, whatever the context.
#[test]
fn the_spans_of_the_door_follow_base() {
    let session = lowlatency_session();
    let read = read(&session);
    for (i, (_, bytes)) in session.messages.iter().enumerate() {
        let at_zero =
            json5::parse(&call_in(&read.context, bytes, 0).expect("reads")).expect("json");
        let at_base =
            json5::parse(&call_in(&read.context, bytes, 70_000).expect("reads")).expect("json");
        assert_eq!(at_base, shifted(&at_zero, 70_000), "message {i}");
        assert_ne!(at_base, at_zero, "message {i}: the base changed nothing");
    }
}

/// What the context does NOT decide: a bare network header with no lowlatency
/// agreed is exactly what the old door says. This is the documented behaviour
/// for `false`, `null` and `negotiated: false`.
#[test]
fn without_an_agreed_lowlatency_the_door_is_the_context_free_door() {
    let push = push_message(b"hello");
    let blind = call_transport(&push).expect("reads");
    assert!(blind.starts_with("{\"name\":\"Unknown\""), "{blind}");
    for context in [
        r#"{"negotiated":true,"lowlatency":false}"#,
        r#"{"negotiated":true,"lowlatency":null}"#,
        r#"{"negotiated":false,"lowlatency":null}"#,
        r#"{"negotiated":false,"lowlatency":true}"#,
    ] {
        assert_eq!(call_in(context, &push, 0), Ok(blind.clone()), "{context}");
    }
}

/// Only `negotiated` and `lowlatency` are read, and a document with the other
/// keys at any value or type still opens.
#[test]
fn keys_the_door_does_not_read_do_not_matter() {
    let push = push_message(b"hello");
    let lean = call_in(r#"{"negotiated":true,"lowlatency":true}"#, &push, 0).expect("reads");
    assert!(lean.starts_with("{\"name\":\"Push\""), "{lean}");
    for context in [
        r#"{"phase":"established","negotiated":true,"lowlatency":true,"compression":true,"qos":true,"patch":0,"sn_mask":null,"batch_size":65535,"version":9}"#,
        r#"{"negotiated":true,"lowlatency":true,"compression":"yes","qos":[],"patch":{},"phase":7,"added_later":1}"#,
    ] {
        assert_eq!(call_in(context, &push, 0), Ok(lean.clone()), "{context}");
    }
}

/// A context that is not the object the document writes is the caller's bug.
#[test]
fn a_context_that_is_not_a_context_is_the_argument_error() {
    let push = push_message(b"hello");
    for context in [
        "",
        "not json",
        "[]",
        "null",
        "{}",
        r#"{"negotiated":true}"#,
        r#"{"lowlatency":true}"#,
        r#"{"negotiated":"true","lowlatency":true}"#,
        r#"{"negotiated":true,"lowlatency":"true"}"#,
        r#"{"negotiated":true,"lowlatency":1}"#,
    ] {
        assert_eq!(
            call_in(context, &push, 0),
            Err(WZ_DISSECT_ERR_INVALID_ARG),
            "{context:?}"
        );
    }
    // Not text at all: a NUL-terminated byte string that is not UTF-8.
    let bad = [0xFFu8, 0xFE, 0];
    let mut out: *mut c_char = core::ptr::null_mut();
    let rc = unsafe {
        wz_dissect_transport_message_in(bad.as_ptr().cast(), push.as_ptr(), push.len(), 0, &mut out)
    };
    assert_eq!(rc, WZ_DISSECT_ERR_INVALID_ARG);
    assert!(out.is_null());
}

#[test]
fn null_arguments_and_undecodable_bytes_are_refused_by_code() {
    let mut out: *mut c_char = core::ptr::null_mut();
    let context = std::ffi::CString::new(r#"{"negotiated":true,"lowlatency":true}"#).unwrap();
    let bytes = [0x1Au8, 7];
    // SAFETY: the null arguments are the point; nothing is dereferenced.
    unsafe {
        assert_eq!(
            wz_dissect_transport_message_in(core::ptr::null(), bytes.as_ptr(), 2, 0, &mut out),
            WZ_DISSECT_ERR_INVALID_ARG
        );
        assert_eq!(
            wz_dissect_transport_message_in(context.as_ptr(), core::ptr::null(), 0, 0, &mut out),
            WZ_DISSECT_ERR_INVALID_ARG
        );
        assert_eq!(
            wz_dissect_transport_message_in(
                context.as_ptr(),
                bytes.as_ptr(),
                2,
                0,
                core::ptr::null_mut()
            ),
            WZ_DISSECT_ERR_INVALID_ARG
        );
    }
    let lean = r#"{"negotiated":true,"lowlatency":true}"#;
    // No bytes, and a message with a tail: both are bytes that are not one
    // message, in the one code the context-free door uses for it.
    assert_eq!(call_in(lean, &[], 0), Err(WZ_DISSECT_ERR_DECODE));
    assert_eq!(
        call_in(lean, &[0x1A, 7, 0xEE], 0),
        Err(WZ_DISSECT_ERR_DECODE)
    );
    assert!(call_in(lean, &bytes, 0).is_ok());
}

/// The old door keeps its contract: it has no session and says so.
#[test]
fn the_context_free_door_is_unchanged() {
    let tree = call_transport(&response_final_message()).expect("reads");
    assert!(tree.starts_with("{\"name\":\"Unknown\""), "{tree}");
}
