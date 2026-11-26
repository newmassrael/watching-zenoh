// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A declared extension whose length disagrees with its fields, read by upstream's codec and by the
//! decode a wz participant admits a frame's records with
//! (`wz_session_core::network_message::admit_frame_payload_lending`), the two answers recorded.
//!
//! Upstream reads the header and the length of a timestamp, a timestamp stack, a responder and a
//! source info and then reads the fields from the message's reader, so the length is never held to
//! the fields (`commons/zenoh-codec/src/network/mod.rs` @
//! `let (_, more): (ZExtZBufHeader<{ ID }>, bool) = self.read(&mut *reader)?;`). wz's contract is the
//! bounded reading: the length is the extension's extent, and a body its fields do not fill exactly
//! is a malformed extension (`wz_session_core::ext_admit`, the section on a declared extension whose
//! body its reader refuses). Each message below is built so that both readers walk all of it, so the
//! answer is the rule's and not that of a decode that lost its place:
//!
//! * a body one byte LONGER than its fields holds `UNIT_MORE` behind them, and `UNIT_LAST` follows
//!   the body and ends the chain; upstream reads that byte as an extension of its own, wz as the
//!   last byte of the body;
//! * a body one byte SHORTER than its fields leaves the last byte of the fields to be read after the
//!   body. Where that byte is free (the identity of a timestamp, the bytes of an interception) it is
//!   `UNIT_MORE` and `UNIT_LAST` ends the chain, as above. Where it is the last byte of a ZInt (the
//!   sequence number of a source info, the entity id of a responder) the extension ends the chain,
//!   and the byte is the length of the Put's payload or the header of the Err a Response carries,
//!   chosen so that wz reads the bytes after it as that payload.
//!
//! Upstream reads every such message, and reads the fields as they were written; wz refuses it as
//! `MalformedExt`. A change on either side turns its case red.

use up_buffers::{
    buffer::SplitBuffer,
    writer::{DidntWrite, HasWriter},
    ZBuf,
};
use up_codec::{RCodec, WCodec, Zenoh080};
use up_protocol::{
    core::{Encoding, EntityGlobalIdProto, ZenohIdProto},
    network::{
        id, push,
        push::ext::{TimestampType, TsStackType},
        response,
        response::ext::ResponderIdType,
        timestamp_stack::{Interception, TimestampStack},
        Push, Response,
    },
    zenoh::{
        err::Err as ErrMsg,
        put::{self, ext::SourceInfoType, Put},
        PushBody, ResponseBody,
    },
};
use wz_session_core::network_message::admit_frame_payload_lending;
use wz_session_core::parse_error::InboundParseError;

/// A unit extension that is not mandatory, of an id no carrier declares, with the bit that says
/// another follows: both readers read it and go on.
const UNIT_MORE: u8 = 0x8E;
/// The same extension without that bit: the last of a chain.
const UNIT_LAST: u8 = 0x0E;
/// The bit of an extension's header that says another follows.
const MORE: u8 = 0x80;
/// The key every message is on: scope 0 and the suffix `k`, as a length and its byte.
const KEY: [u8; 3] = [0x00, 0x01, b'k'];

/// The bytes upstream writes with `write`.
fn written<F>(write: F) -> Vec<u8>
where
    F: FnOnce(&mut &mut Vec<u8>) -> Result<(), DidntWrite>,
{
    let mut bytes = Vec::new();
    {
        let mut writer = (&mut bytes).writer();
        write(&mut writer).expect("upstream writes it");
    }
    bytes
}

/// The fields of the extension `header` in `ext`, the bytes upstream writes for it alone: what
/// follows its header and its length.
fn fields_of(header: u8, ext: Vec<u8>) -> Vec<u8> {
    assert_eq!(ext[0], header, "the extension's header");
    assert_eq!(
        usize::from(ext[1]),
        ext.len() - 2,
        "a length of one byte that covers the fields"
    );
    ext[2..].to_vec()
}

/// The extension `header` with the length `len` and the bytes `body` after it, with the bit that
/// says another follows when `more`.
fn ext(header: u8, more: bool, len: usize, body: &[u8]) -> Vec<u8> {
    let header = if more { header | MORE } else { header };
    let len = u8::try_from(len).expect("a length of one byte");
    [&[header, len][..], body].concat()
}

/// One extension's chain three ways: as written, and with its length one byte longer and one byte
/// shorter than its fields, for fields whose last byte is free. Both that disagree end the chain in
/// `UNIT_LAST`: the longer holds `UNIT_MORE` behind its fields, and the shorter leaves its fields'
/// last byte, which is `UNIT_MORE`, to be read after its body.
fn chains_of_free_fields(header: u8, fields: &[u8]) -> [Vec<u8>; 3] {
    assert_eq!(
        fields.last(),
        Some(&UNIT_MORE),
        "the fields end in a byte wz reads as an extension"
    );
    let n = fields.len();
    let over = [fields, &[UNIT_MORE][..]].concat();
    [
        ext(header, false, n, fields),
        [ext(header, true, n + 1, &over), vec![UNIT_LAST]].concat(),
        [ext(header, true, n - 1, fields), vec![UNIT_LAST]].concat(),
    ]
}

/// One extension's chain three ways, as [`chains_of_free_fields`], for fields that end in a ZInt.
/// The shorter one ends the chain, so the last byte of the fields is the first thing wz reads
/// after it.
fn chains_of_zint_fields(header: u8, fields: &[u8]) -> [Vec<u8>; 3] {
    let n = fields.len();
    let over = [fields, &[UNIT_MORE][..]].concat();
    [
        ext(header, false, n, fields),
        [ext(header, true, n + 1, &over), vec![UNIT_LAST]].concat(),
        ext(header, false, n - 1, fields),
    ]
}

/// A Push on [`KEY`] with `chain` and the body `body`.
fn push_of(chain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut header = id::PUSH | push::flag::N;
    if !chain.is_empty() {
        header |= push::flag::Z;
    }
    [&[header][..], &KEY[..], chain, body].concat()
}

/// The bytes upstream writes for the body of an empty Put.
fn empty_put() -> Vec<u8> {
    written(|w| Zenoh080.write(w, &PushBody::Put(Put::default())))
}

/// wz's answer on a frame of `bytes`: the number of records a participant may act on, or its
/// refusal.
fn wz_admits(bytes: &[u8]) -> Result<usize, InboundParseError> {
    admit_frame_payload_lending(bytes).map(|messages| messages.len())
}

/// `message` when upstream read it out of all of its bytes, else how many bytes it left in `reader`.
fn read_whole<M>(message: M, reader: &[u8]) -> Result<M, String> {
    if reader.is_empty() {
        Ok(message)
    } else {
        Err(format!("{} bytes left unread", reader.len()))
    }
}

/// Upstream's reading of the one Push in `bytes`, all of them read.
fn upstream_push(bytes: &[u8]) -> Result<Push, String> {
    let mut reader = bytes;
    let push: Push = Zenoh080.read(&mut reader).map_err(|e| format!("{e:?}"))?;
    read_whole(push, reader)
}

/// Upstream's reading of the one Response in `bytes`, all of them read.
fn upstream_response(bytes: &[u8]) -> Result<Response, String> {
    let mut reader = bytes;
    let response: Response = Zenoh080.read(&mut reader).map_err(|e| format!("{e:?}"))?;
    read_whole(response, reader)
}

/// The two readings of one extension's three messages: as written, and with a length one byte
/// longer and one byte shorter than the fields. Upstream reads all three (`upstream`, which answers
/// what it read of the extension and of what follows the chain), and reads the same in each; wz
/// admits the one written and refuses the other two as a malformed `eid`.
#[track_caller]
fn assert_upstream_reads_across_and_wz_refuses<T>(
    what: &str,
    eid: u8,
    messages: [Vec<u8>; 3],
    upstream: impl Fn(&[u8]) -> Result<T, String>,
) where
    T: PartialEq + std::fmt::Debug,
{
    let [as_written, longer, shorter] = messages;
    let control = upstream(as_written.as_slice())
        .unwrap_or_else(|e| panic!("{what}: upstream reads the message as written: {e}"));
    assert_eq!(
        wz_admits(&as_written),
        Ok(1),
        "{what}: wz admits the message as written"
    );
    for (how, bytes) in [("longer", &longer), ("shorter", &shorter)] {
        assert_eq!(
            upstream(bytes.as_slice()).as_ref(),
            Ok(&control),
            "{what}, {how}: upstream reads across the body's end, {bytes:02x?}"
        );
        assert_eq!(
            wz_admits(bytes),
            Err(InboundParseError::MalformedExt { eid }),
            "{what}, {how}: wz refuses the body its fields do not fill, {bytes:02x?}"
        );
    }
}

/// A Push's timestamp, whose identity's last byte is free.
#[test]
fn a_push_timestamp_whose_length_disagrees_is_read_across_by_upstream_and_refused_by_wz() {
    let identity = uhlc::ID::try_from([0x01u8, UNIT_MORE].as_slice()).expect("an identity");
    let timestamp = TimestampType {
        timestamp: uhlc::Timestamp::new(uhlc::NTP64(1), identity),
    };
    let fields = fields_of(0x42, written(|w| Zenoh080.write(w, (&timestamp, false))));
    let messages = chains_of_free_fields(0x42, &fields).map(|chain| push_of(&chain, &empty_put()));
    assert_upstream_reads_across_and_wz_refuses("push timestamp", 0x42, messages, |bytes| {
        upstream_push(bytes).map(|push| (push.ext_tstamp, push.payload))
    });
}

/// A Push's timestamp stack, whose last interception's last byte is free.
#[test]
fn a_push_timestamp_stack_whose_length_disagrees_is_read_across_by_upstream_and_refused_by_wz() {
    let stack = TsStackType {
        ts_stack: TimestampStack {
            conf_flags: 1,
            stack: vec![Interception {
                flags: 2,
                timestamp: vec![UNIT_MORE],
            }],
        },
    };
    let fields = fields_of(0x47, written(|w| Zenoh080.write(w, (&stack, false))));
    let messages = chains_of_free_fields(0x47, &fields).map(|chain| push_of(&chain, &empty_put()));
    assert_upstream_reads_across_and_wz_refuses("push timestamp stack", 0x47, messages, |bytes| {
        upstream_push(bytes).map(|push| (push.ext_ts_stack, push.payload))
    });
}

/// A Put's source info, whose sequence number ends its fields. Its payload is three bytes, written
/// as their length and them; the sequence number is one more than that length, so the Put whose
/// source info is one byte short has, for wz, a payload of four bytes: that length and them.
#[test]
fn a_put_source_info_whose_length_disagrees_is_read_across_by_upstream_and_refused_by_wz() {
    let payload = [0xA1u8, 0xA2, 0xA3];
    let source_info = SourceInfoType {
        id: EntityGlobalIdProto {
            zid: ZenohIdProto::try_from([0x01u8].as_slice()).expect("a zid"),
            eid: 7,
        },
        sn: 1 + payload.len() as u32,
    };
    let fields = fields_of(0x41, written(|w| Zenoh080.write(w, (&source_info, false))));
    assert_eq!(
        fields.last().copied(),
        u8::try_from(1 + payload.len()).ok(),
        "the sequence number is one byte"
    );
    let messages = chains_of_zint_fields(0x41, &fields).map(|chain| {
        let header = put::flag::Z | up_protocol::zenoh::id::PUT;
        let length = u8::try_from(payload.len()).expect("a length of one byte");
        let body = [&[header][..], &chain[..], &[length][..], &payload[..]].concat();
        push_of(&[], &body)
    });
    assert_upstream_reads_across_and_wz_refuses("put source info", 0x41, messages, |bytes| {
        upstream_push(bytes).map(|push| {
            let PushBody::Put(put) = push.payload else {
                panic!("upstream reads a Put")
            };
            (put.ext_sinfo, put.payload.contiguous().into_owned())
        })
    });
}

/// A Response's responder, whose entity id ends its fields. The entity id is the header of an Err,
/// and the Err the Response carries has a payload of four bytes, written as their length and them,
/// so the Response whose responder is one byte short carries, for wz, an Err whose payload is five
/// bytes: the Err's header and payload as upstream wrote them, less the header.
#[test]
fn a_response_responder_whose_length_disagrees_is_read_across_by_upstream_and_refused_by_wz() {
    let err = written(|w| {
        Zenoh080.write(
            w,
            &ResponseBody::Err(ErrMsg {
                encoding: Encoding::empty(),
                ext_sinfo: None,
                ext_unknown: Vec::new(),
                payload: ZBuf::from(vec![0xE1u8, 0xE2, 0xE3, 0xE4]),
            }),
        )
    });
    assert_eq!(
        err[..2],
        [up_protocol::zenoh::id::ERR, 4],
        "an Err is its header, the length of its payload and the payload"
    );
    let responder = ResponderIdType {
        zid: ZenohIdProto::try_from([0x01u8].as_slice()).expect("a zid"),
        eid: u32::from(up_protocol::zenoh::id::ERR),
    };
    let fields = fields_of(0x43, written(|w| Zenoh080.write(w, (&responder, false))));
    assert_eq!(
        fields.last(),
        Some(&up_protocol::zenoh::id::ERR),
        "the entity id is one byte"
    );
    let messages = chains_of_zint_fields(0x43, &fields).map(|chain| {
        let header = id::RESPONSE | response::flag::N | response::flag::Z;
        // The request id 1, the key, the chain and the Err.
        [&[header, 0x01][..], &KEY[..], &chain[..], &err[..]].concat()
    });
    assert_upstream_reads_across_and_wz_refuses("response responder", 0x43, messages, |bytes| {
        upstream_response(bytes).map(|response| (response.ext_respid, response.payload))
    });
}
