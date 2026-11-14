// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A batch that holds several transport messages, as upstream's pipeline writes one: a message of
//! the other reliability goes into the open batch behind a second Frame header
//! (`io/zenoh-transport/src/common/pipeline.rs` @ `BatchError::NewFrame`), and a KeepAlive behind
//! the last record of a Frame. The same bytes, written by upstream's codec, are read by upstream's
//! codec and by wz's, and the two readings hold the same messages, in the same Frames, in the same
//! order.
//!
//! wz reads a Frame as the tail of its unit, so the reader of the batch ends the Frame's records
//! at the next transport message and reads that message next. Two readers do it, and each is held
//! to upstream here:
//!
//! * the observer's, by where the best-effort walk says the next transport message begins
//!   (`BatchParse::next_message_at`), compared record by record, byte for byte;
//! * the participant's, by the record the strict walk could not read, whose id is a transport id
//!   and whose bytes are the rest of the batch, compared Frame by Frame by the number of records.

use std::borrow::Cow;

use up_buffers::{writer::HasWriter, ZBuf};
use up_codec::{RCodec, WCodec, Zenoh080};
use up_protocol::{
    core::{Reliability, WireExpr},
    network::{ext::NodeIdType, Mapping, NetworkBody, NetworkMessage, Push},
    transport::{frame::Frame, id, keepalive::KeepAlive, TransportBody, TransportMessage},
    zenoh::{put::Put, PushBody},
};
use wz_session_core::inbound::{parse_inbound_consuming, InboundFrame};
use wz_session_core::network_message::{
    parse_frame_payload, parse_frame_payload_best_effort, NetworkMessage as WzNetworkMessage,
};

/// One transport message of a batch as the test lays it out: a Frame of a reliability with that
/// many messages, or a KeepAlive.
#[derive(Clone, Copy, Debug)]
enum Item {
    Frame { reliable: bool, messages: usize },
    KeepAlive,
}

/// One transport message as a reader read it: a Frame with its sn, its reliability and the bytes
/// of each of its messages, or a KeepAlive.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Read {
    Frame {
        reliable: bool,
        sn: u64,
        messages: Vec<Vec<u8>>,
    },
    KeepAlive,
}

impl Read {
    /// What the participant's reading is compared by: the kind, the reliability, the sn and the
    /// number of messages.
    fn shape(&self) -> (bool, bool, u64, usize) {
        match self {
            Read::Frame {
                reliable,
                sn,
                messages,
            } => (true, *reliable, *sn, messages.len()),
            Read::KeepAlive => (false, false, 0, 0),
        }
    }
}

/// The batches: one Frame, Frames of alternating reliability, an empty Frame between two, two
/// Frames of one reliability, and a KeepAlive behind the last record of a Frame.
fn layouts() -> Vec<Vec<Item>> {
    use Item::{Frame as F, KeepAlive as K};
    let f = |reliable: bool, messages: usize| F { reliable, messages };
    vec![
        vec![f(true, 2)],
        vec![f(true, 1), f(false, 1)],
        vec![f(true, 2), f(false, 1), f(true, 3)],
        vec![f(false, 0), f(true, 3)],
        vec![f(true, 1), f(false, 0), f(false, 2), f(true, 1)],
        vec![f(true, 2), K],
        vec![f(false, 1), K, f(true, 1)],
        vec![K, f(true, 1), f(false, 1)],
    ]
}

/// The `n`th message of the batch: a Put on its own key with its own payload, so a message read
/// in another place or another order reads as other bytes.
fn message(n: usize, reliability: Reliability) -> NetworkMessage {
    let push = Push {
        wire_expr: WireExpr {
            scope: 0,
            suffix: Cow::Owned(format!("demo/batch/{n}")),
            mapping: Mapping::Receiver,
        },
        ext_qos: up_protocol::network::push::ext::QoSType::DEFAULT,
        ext_tstamp: None,
        ext_nodeid: NodeIdType { node_id: 0 },
        ext_ts_stack: None,
        payload: PushBody::Put(Put {
            payload: ZBuf::from(vec![n as u8; 1 + n]),
            ..Put::default()
        }),
    };
    NetworkMessage {
        body: NetworkBody::Push(push),
        reliability,
    }
}

/// The batch of `layout`, written by upstream's codec one transport message after another, each
/// Frame at the next sn of its reliability.
fn batch(layout: &[Item]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut next = 0usize;
    let (mut reliable_sn, mut best_effort_sn) = (10u32, 20u32);
    for item in layout {
        let msg: TransportMessage = match *item {
            Item::Frame { reliable, messages } => {
                let (reliability, sn) = if reliable {
                    reliable_sn += 1;
                    (Reliability::Reliable, reliable_sn)
                } else {
                    best_effort_sn += 1;
                    (Reliability::BestEffort, best_effort_sn)
                };
                let payload = (0..messages)
                    .map(|_| {
                        next += 1;
                        message(next, reliability)
                    })
                    .collect();
                TransportBody::Frame(Frame {
                    reliability,
                    sn,
                    ext_qos: up_protocol::transport::frame::ext::QoSType::DEFAULT,
                    payload,
                })
                .into()
            }
            Item::KeepAlive => TransportBody::KeepAlive(KeepAlive).into(),
        };
        let mut writer = (&mut bytes).writer();
        Zenoh080
            .write(&mut writer, &msg)
            .expect("upstream writes the message");
    }
    bytes
}

/// The bytes upstream writes for `message`.
fn encoded(message: &NetworkMessage) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut writer = (&mut bytes).writer();
        Zenoh080
            .write(&mut writer, message)
            .expect("upstream writes the message");
    }
    bytes
}

/// Upstream's reading of `batch`: a transport message at a time to the end, as its link reads a
/// batch, each Frame's messages read until one is not a network message.
fn upstream_reads(batch: &[u8]) -> Vec<Read> {
    let mut reader = batch;
    let mut read = Vec::new();
    while !reader.is_empty() {
        let msg: TransportMessage = Zenoh080
            .read(&mut reader)
            .expect("upstream reads the batch");
        read.push(match msg.body {
            TransportBody::Frame(frame) => Read::Frame {
                reliable: frame.reliability == Reliability::Reliable,
                sn: u64::from(frame.sn),
                messages: frame.payload.iter().map(encoded).collect(),
            },
            TransportBody::KeepAlive(_) => Read::KeepAlive,
            other => panic!("upstream read a message the batch does not hold: {other:?}"),
        });
    }
    read
}

/// The observer's reading of `batch`: a Frame's records are those the best-effort walk read
/// before the next transport message, each the bytes its span names, and the reading goes on
/// where that message begins.
fn observer_reads(batch: &[u8]) -> Vec<Read> {
    let mut at = 0;
    let mut read = Vec::new();
    while at < batch.len() {
        let (frame, consumed) =
            parse_inbound_consuming(&batch[at..]).expect("wz reads a transport message");
        match frame {
            InboundFrame::Frame {
                reliable,
                sn,
                payload,
                ..
            } => {
                let payload = payload.as_slice();
                let parsed = parse_frame_payload_best_effort(payload);
                assert!(
                    parsed.is_complete(),
                    "the records of the Frame at {at} read whole: {:?}",
                    parsed.halt
                );
                let end = parsed.next_message_at.unwrap_or(payload.len());
                read.push(Read::Frame {
                    reliable,
                    sn,
                    messages: parsed
                        .spans
                        .iter()
                        .map(|&(offset, len)| payload[offset..offset + len].to_vec())
                        .collect(),
                });
                at += consumed - (payload.len() - end);
            }
            InboundFrame::KeepAlive { .. } => {
                read.push(Read::KeepAlive);
                at += consumed;
            }
            other => panic!("wz read a message the batch does not hold: {other:?}"),
        }
    }
    read
}

/// The participant's reading of `batch`: a Frame's records are those the strict walk read, and a
/// last record whose id is a transport id is the rest of the batch, read next.
fn participant_reads(batch: &[u8]) -> Vec<Read> {
    let mut unit = batch.to_vec();
    let mut read = Vec::new();
    while !unit.is_empty() {
        let (frame, consumed) =
            parse_inbound_consuming(&unit).expect("wz reads a transport message");
        let mut rest = unit[consumed..].to_vec();
        match frame {
            InboundFrame::Frame {
                reliable,
                sn,
                payload,
                ..
            } => {
                let mut messages =
                    parse_frame_payload(payload.as_slice()).expect("wz reads the Frame's records");
                if let Some(WzNetworkMessage::Unknown { mid, body }) = messages.last() {
                    if *mid <= id::JOIN {
                        rest = body.clone();
                        messages.pop();
                    }
                }
                read.push(Read::Frame {
                    reliable,
                    sn,
                    messages: vec![Vec::new(); messages.len()],
                });
            }
            InboundFrame::KeepAlive { .. } => read.push(Read::KeepAlive),
            other => panic!("wz read a message the batch does not hold: {other:?}"),
        }
        unit = rest;
    }
    read
}

#[test]
fn the_observer_reads_a_batch_of_frames_as_upstream_does() {
    let mut compared = 0;
    for layout in layouts() {
        let bytes = batch(&layout);
        let upstream = upstream_reads(&bytes);
        assert_eq!(
            upstream.len(),
            layout.len(),
            "upstream reads {layout:?} whole"
        );
        assert_eq!(
            observer_reads(&bytes),
            upstream,
            "the batch {layout:?}, {bytes:02x?}"
        );
        compared += 1;
    }
    assert_eq!(compared, layouts().len());
}

#[test]
fn the_participant_reads_a_batch_of_frames_as_upstream_does() {
    let mut compared = 0;
    for layout in layouts() {
        let bytes = batch(&layout);
        let upstream: Vec<_> = upstream_reads(&bytes).iter().map(Read::shape).collect();
        let participant: Vec<_> = participant_reads(&bytes).iter().map(Read::shape).collect();
        assert_eq!(participant, upstream, "the batch {layout:?}, {bytes:02x?}");
        compared += 1;
    }
    assert_eq!(compared, layouts().len());
}
