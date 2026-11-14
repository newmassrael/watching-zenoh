// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A Push of a Put, written by upstream's codec, read by the decode a wz participant with an
//! allocator receives a frame's records with (`wz_session_core::network_message::parse_frame_payload`)
//! and by upstream's own reader, the two readings held equal.
//!
//! * A Put whose extension chain is longer than a wz node stores inline (eight entries, the
//!   capacity `deploy/codec_node.yaml` gives it): the protocol bounds the chain by nothing and
//!   upstream keeps every entry (`commons/zenoh-codec/src/zenoh/put.rs` @ `ext_unknown.push(u)`).
//!   wz reads the same entries in the same order and the payload after them. The chain at the
//!   capacity is the control.
//! * A Put whose timestamp names an identity of seventeen bytes, the bytes upstream wrote for
//!   sixteen with the length said one longer and one byte more of it: upstream refuses it
//!   (`commons/zenoh-codec/src/core/timestamp.rs` @ `uhlc::ID::MAX_SIZE`) and so does wz, by the
//!   bound the codec's document states. The frame upstream wrote is the control, read alike.

use std::borrow::Cow;

use up_buffers::{buffer::SplitBuffer, ZBuf};
use up_codec::{RCodec, WCodec, Zenoh080};
use up_protocol::{
    common::{ZExtBody, ZExtUnknown},
    core::{Timestamp, WireExpr},
    network::{Mapping, Push},
    zenoh::{put::Put, PushBody},
};
use wz_session_core::network_message::{parse_frame_payload, NetworkMessage};
use wz_session_core::wire::PushOwnedVariant;

/// The extension chain of a Put that a wz node stores inline.
const NODE_CHAIN_CAPACITY: usize = 8;

/// What a reading of a Push of a Put is compared by: the header of each extension of the Put's
/// chain without the flag that says another follows, and the Put's payload.
type PutReading = (Vec<u8>, Vec<u8>);

fn payload() -> ZBuf {
    ZBuf::from(vec![0xAAu8, 0xBB, 0xCC])
}

/// `count` extensions none of which the Put's reader knows by its id (1 is the source info, 2 the
/// shared memory and 3 the attachment), none mandatory, each encoding in turn.
fn extensions(count: usize) -> Vec<ZExtUnknown> {
    (0..count)
        .map(|i| {
            let id = 4 + (i % 12) as u8;
            let body = match i % 3 {
                0 => ZExtBody::Unit,
                1 => ZExtBody::Z64(i as u64 * 300),
                _ => ZExtBody::ZBuf(ZBuf::from(vec![i as u8; 1 + i % 4])),
            };
            ZExtUnknown::new(id, false, body)
        })
        .collect()
}

fn push_of(put: Put) -> Push {
    Push {
        wire_expr: WireExpr {
            scope: 0,
            suffix: Cow::Borrowed("demo/chain"),
            mapping: Mapping::Receiver,
        },
        ext_qos: Default::default(),
        ext_tstamp: None,
        ext_nodeid: Default::default(),
        ext_ts_stack: None,
        payload: PushBody::Put(put),
    }
}

/// The bytes upstream writes for `push`.
fn written(push: &Push) -> Vec<u8> {
    let mut bytes = Vec::new();
    Zenoh080
        .write(&mut bytes, push)
        .expect("upstream writes the push");
    bytes
}

/// The Put of the one Push upstream reads out of `bytes`, all of them read.
fn upstream_put(bytes: &[u8]) -> Result<Put, String> {
    let mut reader = bytes;
    let push: Push = Zenoh080.read(&mut reader).map_err(|e| format!("{e:?}"))?;
    assert!(reader.is_empty(), "upstream reads all of it");
    let PushBody::Put(put) = push.payload else {
        panic!("upstream reads a Put")
    };
    Ok(put)
}

/// The Put of the one Push wz reads out of `bytes`, given to `read`.
fn wz_put<T>(
    bytes: &[u8],
    read: impl FnOnce(&wz_session_core::wire::parts::MsgPutOwned) -> T,
) -> Result<T, String> {
    let messages = parse_frame_payload(bytes).map_err(|e| format!("{e:?}"))?;
    let [NetworkMessage::Push(push)] = messages.as_slice() else {
        panic!("wz reads one Push: {messages:?}")
    };
    let PushOwnedVariant::CodecZenohMsgPut(put) = &push.body else {
        panic!("wz reads a Put")
    };
    Ok(read(put))
}

fn upstream_reading(bytes: &[u8]) -> Result<PutReading, String> {
    let put = upstream_put(bytes)?;
    Ok((
        put.ext_unknown.iter().map(|e| e.id & !0x80).collect(),
        put.payload.contiguous().into_owned(),
    ))
}

fn wz_reading(bytes: &[u8]) -> Result<PutReading, String> {
    wz_put(bytes, |put| {
        (
            wz_session_core::put_payload::chain(put)
                .iter()
                .map(|e| e.header & !0x80)
                .collect(),
            wz_session_core::put_payload::inline_bytes(put)
                .expect("the payload is inline")
                .to_vec(),
        )
    })
}

#[test]
fn a_put_chain_past_what_a_node_stores_inline_is_read_as_upstream_reads_it() {
    for count in [NODE_CHAIN_CAPACITY, NODE_CHAIN_CAPACITY + 1, 32] {
        let bytes = written(&push_of(Put {
            ext_unknown: extensions(count),
            payload: payload(),
            ..Put::default()
        }));
        let upstream = upstream_reading(&bytes).expect("upstream reads the push it wrote");
        assert_eq!(upstream.0.len(), count, "upstream keeps every extension");
        assert_eq!(wz_reading(&bytes), Ok(upstream), "{count} extensions");
    }
}

/// The identity of a timestamp each side reads out of `bytes`.
fn upstream_identity(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let timestamp = upstream_put(bytes)?
        .timestamp
        .expect("upstream reads the timestamp");
    let id = timestamp.get_id();
    Ok(id.to_le_bytes()[..id.size()].to_vec())
}

fn wz_identity(bytes: &[u8]) -> Result<Vec<u8>, String> {
    wz_put(bytes, |put| {
        put.timestamp
            .as_ref()
            .expect("wz reads the timestamp")
            .zid
            .as_bytes()
            .into_inner()
            .to_vec()
    })
}

#[test]
fn a_timestamp_identity_past_sixteen_bytes_is_refused_by_both() {
    let identity: Vec<u8> = (1..=16).collect();
    let bytes = written(&push_of(Put {
        timestamp: Some(Timestamp::new(
            uhlc::NTP64(1),
            uhlc::ID::try_from(identity.as_slice()).expect("an identity"),
        )),
        payload: payload(),
        ..Put::default()
    }));

    let upstream = upstream_identity(&bytes);
    assert_eq!(
        upstream,
        Ok(identity.clone()),
        "upstream reads what it wrote"
    );
    assert_eq!(wz_identity(&bytes), upstream, "the control: read alike");

    // The identity is its length and its bytes; say one more and add it.
    let at = bytes
        .windows(identity.len() + 1)
        .position(|w| usize::from(w[0]) == identity.len() && w[1..] == identity[..])
        .expect("the identity is in the frame");
    let mut longer = bytes.clone();
    longer[at] += 1;
    longer.insert(at + 1 + identity.len(), 0x11);

    assert!(upstream_identity(&longer).is_err(), "upstream refuses it");
    assert_eq!(
        wz_identity(&longer),
        Err("LengthOutOfRange".to_string()),
        "wz refuses it as past the field's bound"
    );
}
