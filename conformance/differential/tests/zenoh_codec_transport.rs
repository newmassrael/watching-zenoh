// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-codec`, the transport messages (the fourth slice of the crate): upstream's crate
//! (`up_codec`) and wz's (`wz_codec`) given the same messages to write and the same bytes to read,
//! results equal as text, the bytes written and the bytes left unread included.
//!
//! * WRITES: a keep alive, a close of every reason and scope, an oam of every body, a frame and a
//!   fragment with every extension and every reliability, an init (syn and ack) with every set of
//!   its eight extensions and every size of identifier, an open (syn and ack) with every set of its
//!   six, a join with every set of its three, each lease on the line in seconds and in
//!   milliseconds, and the transport message and the low latency message that holds each.
//! * READS: every encoding, every prefix of it and every one of its bytes set to six values, read
//!   as the message it is and as every other, a reading that succeeds being compared with the bytes
//!   it would write back.
//! * THE BATCH: a script of writes and reads through `Zenoh080Batch` over a bounded buffer, the
//!   result of each step and the state of the batch after it, with the fragment that is made the
//!   last when the buffer holds what is left.
//!
//! Upstream is lenient in places where wz refuses what it takes in; each is a class, built by hand,
//! counted and held on both sides, and a reading upstream accepts that wz refuses must be one that
//! does not write back to the bytes it was read from:
//!
//! * a quality of service value or a patch level wider than a byte is kept by its low bits;
//! * an extension a message knows, named twice, is kept as the last of them;
//! * the length in the header of the quality of service extension of a join is not read against the
//!   bytes its sixteen sequence numbers take.
//!
//! A write differs in one place: a lease of more milliseconds than sixty-four bits hold is written
//! cut by upstream and refused by wz.
//!
//! The crates are built without `shared-memory`.

use rand::{rngs::StdRng, Rng, SeedableRng};

/// What a reading gave: its text, and for a reading that succeeded whether the value writes back to
/// the bytes it consumed.
type Outcome = (String, Option<bool>);

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const KINDS: [&str; 12] = [
    "keepalive",
    "close",
    "oam",
    "frame",
    "fragment",
    "init syn",
    "init ack",
    "open syn",
    "open ack",
    "join",
    "transport",
    "low latency",
];

macro_rules! transport_cases {
    ($name:ident, $c:ident, $p:ident, $b:ident) => {
        mod $name {
            use std::{borrow::Cow, fmt::Debug, time::Duration};

            use $b::{
                reader::{DidntRead, HasReader, Reader},
                writer::{DidntWrite, HasWriter},
                BBuf, ZBuf, ZSlice,
            };
            use $c::{transport::{batch::Zenoh080Batch, frame::FrameReader}, RCodec, WCodec, Zenoh080};
            use $p::{
                common::{ZExtBody, ZExtUnknown, ZExtZ64, ZExtZBufHeader},
                core::{Priority, Reliability, Resolution, WhatAmI, ZenohIdProto},
                network::{
                    ext::NodeIdType, Mapping, NetworkBody, NetworkMessage, NetworkMessageExt, Push,
                },
                transport::{
                    close::Close,
                    fragment::{self, Fragment},
                    frame::Frame,
                    id,
                    init::{self, InitAck, InitSyn},
                    join::{self, Join},
                    keepalive::KeepAlive,
                    oam::{self, Oam},
                    open::{self, OpenAck, OpenSyn},
                    BatchSize, FragmentHeader, FrameHeader, PrioritySn, TransportBody,
                    TransportBodyLowLatency, TransportBodyLowLatencyRef, TransportMessage,
                    TransportMessageLowLatency, TransportMessageLowLatencyRef,
                },
                zenoh::{put::Put, PushBody},
            };

            use super::{hex, Outcome};

            fn zid(n: usize) -> ZenohIdProto {
                let bytes: Vec<u8> = (0..n).map(|i| i as u8 + 1).collect();
                ZenohIdProto::try_from(bytes.as_slice()).unwrap()
            }

            fn whatami(k: usize) -> WhatAmI {
                [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client][k % 3]
            }

            /// The size parameters of an init or a join: the defaults, a resolution, a batch size.
            fn sizes(k: usize, default_batch: BatchSize) -> (Resolution, BatchSize) {
                match k % 3 {
                    0 => (Resolution::default(), default_batch),
                    1 => (Resolution::from(0b0000_0110), default_batch),
                    _ => (Resolution::default(), 1234),
                }
            }

            fn qos_ext<const ID: u8>(k: usize) -> $p::transport::ext::QoSType<ID> {
                $p::transport::ext::QoSType::new(
                    [Priority::DEFAULT, Priority::RealTime, Priority::Background][k % 3],
                )
            }

            fn enc<F>(f: F) -> Vec<u8>
            where
                F: FnOnce(&mut &mut Vec<u8>) -> Result<(), DidntWrite>,
            {
                let mut v: Vec<u8> = Vec::new();
                let r = {
                    let mut w = (&mut v).writer();
                    f(&mut w)
                };
                if r.is_err() {
                    v.extend_from_slice(b"ERR");
                }
                v
            }

            fn net(k: usize, reliability: Reliability) -> NetworkMessage {
                let wire = $p::core::WireExpr {
                    scope: k as u16,
                    suffix: Cow::Borrowed(["", "a/b", "k"][k % 3]),
                    mapping: Mapping::Receiver,
                };
                let push = Push {
                    wire_expr: wire,
                    ext_qos: ZExtZ64::<{ $p::network::push::ext::QoS::ID }>::new(0).into(),
                    ext_tstamp: None,
                    ext_nodeid: NodeIdType { node_id: 0 },
                    ext_ts_stack: None,
                    payload: PushBody::Put(Put {
                        payload: ZBuf::from(vec![0xA5u8; 1 + k]),
                        ..Put::default()
                    }),
                };
                NetworkMessage {
                    body: NetworkBody::Push(push),
                    reliability,
                }
            }

            fn zbuf(n: usize) -> ZBuf {
                ZBuf::from(vec![0x5Au8; n])
            }

            fn cookie(n: usize) -> ZSlice {
                ZSlice::from(vec![0xC0u8; n])
            }

            fn lease(k: usize) -> Duration {
                [
                    Duration::from_secs(1),
                    Duration::from_millis(1500),
                    Duration::from_secs(0),
                    Duration::from_secs(u64::MAX),
                    Duration::from_millis(u64::MAX),
                ][k]
            }

            fn init_syn(mask: usize, zid_len: usize, wai: usize, sz: usize) -> InitSyn {
                let (resolution, batch_size) = sizes(sz, BatchSize::MAX);
                InitSyn {
                    version: 9,
                    whatami: whatami(wai),
                    zid: zid(zid_len),
                    resolution,
                    batch_size,
                    ext_qos: (mask & 1 != 0).then(init::ext::QoS::new),
                    ext_qos_link: (mask & 2 != 0).then(|| init::ext::QoSLink::new(77)),
                    ext_auth: (mask & 4 != 0).then(|| init::ext::Auth::new(zbuf(3))),
                    ext_mlink: (mask & 8 != 0).then(|| init::ext::MultiLink::new(zbuf(2))),
                    ext_lowlatency: (mask & 16 != 0).then(init::ext::LowLatency::new),
                    ext_compression: (mask & 32 != 0).then(init::ext::Compression::new),
                    ext_patch: if mask & 64 != 0 {
                        init::ext::PatchType::new(1)
                    } else {
                        init::ext::PatchType::NONE
                    },
                    ext_region_name: (mask & 128 != 0)
                        .then(|| init::ext::RegionName::new(zbuf(4))),
                }
            }

            fn init_ack(mask: usize, zid_len: usize, wai: usize, sz: usize, ck: usize) -> InitAck {
                let s = init_syn(mask, zid_len, wai, sz);
                InitAck {
                    version: s.version,
                    whatami: s.whatami,
                    zid: s.zid,
                    resolution: s.resolution,
                    batch_size: s.batch_size,
                    cookie: cookie(ck),
                    ext_qos: s.ext_qos,
                    ext_qos_link: s.ext_qos_link,
                    ext_auth: s.ext_auth,
                    ext_mlink: s.ext_mlink,
                    ext_lowlatency: s.ext_lowlatency,
                    ext_compression: s.ext_compression,
                    ext_patch: s.ext_patch,
                    ext_region_name: s.ext_region_name,
                }
            }

            fn open_syn(mask: usize, ls: usize, sn: u32) -> OpenSyn {
                OpenSyn {
                    lease: lease(ls),
                    initial_sn: sn,
                    cookie: cookie(3),
                    ext_qos: (mask & 1 != 0).then(open::ext::QoS::new),
                    ext_auth: (mask & 2 != 0).then(|| open::ext::Auth::new(zbuf(3))),
                    ext_mlink: (mask & 4 != 0).then(|| open::ext::MultiLinkSyn::new(zbuf(2))),
                    ext_lowlatency: (mask & 8 != 0).then(open::ext::LowLatency::new),
                    ext_compression: (mask & 16 != 0).then(open::ext::Compression::new),
                    ext_remote_bound: (mask & 32 != 0).then(|| open::ext::RemoteBound::new(1)),
                }
            }

            fn open_ack(mask: usize, ls: usize, sn: u32) -> OpenAck {
                OpenAck {
                    lease: lease(ls),
                    initial_sn: sn,
                    ext_qos: (mask & 1 != 0).then(open::ext::QoS::new),
                    ext_auth: (mask & 2 != 0).then(|| open::ext::Auth::new(zbuf(3))),
                    ext_mlink: (mask & 4 != 0).then(open::ext::MultiLinkAck::new),
                    ext_lowlatency: (mask & 8 != 0).then(open::ext::LowLatency::new),
                    ext_compression: (mask & 16 != 0).then(open::ext::Compression::new),
                    ext_remote_bound: (mask & 32 != 0).then(|| open::ext::RemoteBound::new(1)),
                }
            }

            fn prio_sn() -> join::ext::QoSType {
                let mut q = Box::new([PrioritySn::DEFAULT; Priority::NUM]);
                for (i, p) in q.iter_mut().enumerate() {
                    p.reliable = i as u32 * 1000;
                    p.best_effort = u32::MAX - i as u32;
                }
                q
            }

            fn join_msg(mask: usize, zid_len: usize, sz: usize, ls: usize, sn: u32) -> Join {
                let (resolution, batch_size) = sizes(sz, 8_192);
                Join {
                    version: 9,
                    whatami: whatami(sz + 1),
                    zid: zid(zid_len),
                    resolution,
                    batch_size,
                    lease: lease(ls),
                    next_sn: PrioritySn {
                        reliable: sn,
                        best_effort: sn / 2,
                    },
                    ext_qos: (mask & 1 != 0).then(prio_sn),
                    ext_shm: (mask & 2 != 0).then(|| join::ext::Shm::new(zbuf(5))),
                    ext_patch: if mask & 4 != 0 {
                        join::ext::PatchType::new(1)
                    } else {
                        join::ext::PatchType::NONE
                    },
                }
            }

            fn oam_msg(mask: usize, oid: u16, body: usize) -> Oam {
                Oam {
                    id: oid,
                    body: [
                        ZExtBody::Unit,
                        ZExtBody::Z64(300),
                        ZExtBody::ZBuf(ZBuf::from(vec![1u8, 2, 3])),
                    ][body]
                        .clone(),
                    ext_qos: qos_ext(mask),
                }
            }

            fn frame_msg(rel: Reliability, sn: u32, q: usize, n: usize) -> Frame {
                Frame {
                    reliability: rel,
                    sn,
                    ext_qos: qos_ext(q),
                    payload: (0..n).map(|k| net(k, rel)).collect(),
                }
            }

            #[allow(clippy::too_many_arguments)]
            fn fragment_msg(
                rel: Reliability,
                more: bool,
                sn: u32,
                q: usize,
                first: bool,
                drop: bool,
                n: usize,
            ) -> Fragment {
                Fragment {
                    reliability: rel,
                    more,
                    sn,
                    payload: ZSlice::from(vec![0x11u8; n]),
                    ext_qos: qos_ext(q),
                    ext_first: first.then(fragment::ext::First::new),
                    ext_drop: drop.then(fragment::ext::Drop::new),
                }
            }

            /// A low latency message by reference to the one that owns it.
            fn ll_ref(m: &TransportMessageLowLatency) -> TransportMessageLowLatencyRef<'_> {
                TransportMessageLowLatencyRef {
                    body: match &m.body {
                        TransportBodyLowLatency::Network(n) => {
                            TransportBodyLowLatencyRef::Network(n.as_ref())
                        }
                        TransportBodyLowLatency::KeepAlive(k) => {
                            TransportBodyLowLatencyRef::KeepAlive(*k)
                        }
                        TransportBodyLowLatency::Close(c) => TransportBodyLowLatencyRef::Close(*c),
                    },
                }
            }

            /// Every message to write, by the kind it is read as, a name and the bytes.
            pub fn corpus() -> Vec<(&'static str, String, Vec<u8>)> {
                let mut out: Vec<(&'static str, String, Vec<u8>)> = Vec::new();
                // The message alone and wrapped in the transport message that holds it.
                macro_rules! add {
                    ($knd:expr, $nm:expr, $var:ident, $msg:expr) => {{
                        let m = $msg;
                        let name: String = $nm;
                        out.push(($knd, name.clone(), enc(|w| Zenoh080.write(w, &m))));
                        let t: TransportMessage = TransportBody::$var(m).into();
                        out.push((
                            "transport",
                            format!("transport {name}"),
                            enc(|w| Zenoh080.write(w, &t)),
                        ));
                    }};
                }
                add!("keepalive", "keepalive".to_string(), KeepAlive, KeepAlive);
                for reason in [0u8, 1, 7, 255] {
                    for session in [false, true] {
                        add!(
                            "close",
                            format!("close {reason} {session}"),
                            Close,
                            Close { reason, session }
                        );
                    }
                }
                for mask in 0..3 {
                    for oid in [0u16, 300, u16::MAX] {
                        for body in 0..3 {
                            add!(
                                "oam",
                                format!("oam {mask} {oid} {body}"),
                                OAM,
                                oam_msg(mask, oid, body)
                            );
                        }
                    }
                }
                for rel in [Reliability::Reliable, Reliability::BestEffort] {
                    for sn in [0u32, 1, u32::MAX] {
                        for q in 0..3 {
                            for n in 0..4 {
                                add!(
                                    "frame",
                                    format!("frame {rel:?} {sn} {q} {n}"),
                                    Frame,
                                    frame_msg(rel, sn, q, n)
                                );
                            }
                        }
                    }
                }
                for rel in [Reliability::Reliable, Reliability::BestEffort] {
                    for more in [false, true] {
                        for sn in [0u32, 1, u32::MAX] {
                            for q in 0..2 {
                                for mask in 0..4 {
                                    for n in [0usize, 5] {
                                        add!(
                                            "fragment",
                                            format!(
                                                "fragment {rel:?} {more} {sn} {q} {mask} {n}"
                                            ),
                                            Fragment,
                                            fragment_msg(
                                                rel,
                                                more,
                                                sn,
                                                q,
                                                mask & 1 != 0,
                                                mask & 2 != 0,
                                                n
                                            )
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                for mask in 0..256 {
                    for zid_len in [1usize, 16] {
                        let (wai, sz) = (mask % 3, mask / 3);
                        add!(
                            "init syn",
                            format!("init syn {mask} {zid_len}"),
                            InitSyn,
                            init_syn(mask, zid_len, wai, sz)
                        );
                        add!(
                            "init ack",
                            format!("init ack {mask} {zid_len}"),
                            InitAck,
                            init_ack(mask, zid_len, wai, sz, mask % 2 * 7)
                        );
                    }
                }
                for wai in 0..3 {
                    for sz in 0..3 {
                        for mask in [0usize, 255] {
                            add!(
                                "init syn",
                                format!("init syn sized {wai} {sz} {mask}"),
                                InitSyn,
                                init_syn(mask, 8, wai, sz)
                            );
                            add!(
                                "init ack",
                                format!("init ack sized {wai} {sz} {mask}"),
                                InitAck,
                                init_ack(mask, 8, wai, sz, 3)
                            );
                        }
                    }
                }
                for mask in 0..64 {
                    for ls in 0..5 {
                        for sn in [0u32, u32::MAX] {
                            add!(
                                "open syn",
                                format!("open syn {mask} {ls} {sn}"),
                                OpenSyn,
                                open_syn(mask, ls, sn)
                            );
                            add!(
                                "open ack",
                                format!("open ack {mask} {ls} {sn}"),
                                OpenAck,
                                open_ack(mask, ls, sn)
                            );
                        }
                    }
                }
                for mask in 0..8 {
                    for zid_len in [1usize, 16] {
                        for sz in 0..3 {
                            for ls in 0..4 {
                                for sn in [0u32, u32::MAX] {
                                    add!(
                                        "join",
                                        format!("join {mask} {zid_len} {sz} {ls} {sn}"),
                                        Join,
                                        join_msg(mask, zid_len, sz, ls, sn)
                                    );
                                }
                            }
                        }
                    }
                }
                // The low latency messages: the keep alive, the close and the network messages.
                let ll = |m: TransportBodyLowLatencyRef| {
                    enc(|w| Zenoh080.write(w, TransportMessageLowLatencyRef { body: m }))
                };
                out.push((
                    "low latency",
                    "low latency keepalive".to_string(),
                    ll(TransportBodyLowLatencyRef::KeepAlive(KeepAlive)),
                ));
                for reason in [0u8, 255] {
                    for session in [false, true] {
                        out.push((
                            "low latency",
                            format!("low latency close {reason} {session}"),
                            ll(TransportBodyLowLatencyRef::Close(Close { reason, session })),
                        ));
                    }
                }
                for k in 0..3 {
                    for rel in [Reliability::Reliable, Reliability::BestEffort] {
                        let n = net(k, rel);
                        out.push((
                            "low latency",
                            format!("low latency network {k} {rel:?}"),
                            ll(TransportBodyLowLatencyRef::Network(n.as_ref())),
                        ));
                    }
                }
                out
            }

            fn go<T, R, W>(bytes: &[u8], read: R, write: W) -> Outcome
            where
                T: Debug,
                R: FnOnce(&mut &[u8]) -> Result<T, DidntRead>,
                W: FnOnce(&T, &mut &mut Vec<u8>) -> Result<(), DidntWrite>,
            {
                let mut r: &[u8] = bytes;
                let out = read(&mut r);
                let rem = r.len();
                match out {
                    Ok(v) => {
                        let consumed = bytes.len() - rem;
                        let again = enc(|w| write(&v, w));
                        (
                            format!("ok {v:?} rem={rem}"),
                            Some(again == bytes[..consumed]),
                        )
                    }
                    // How far a refused reading got is not part of the answer.
                    Err(_) => ("err".to_string(), None),
                }
            }

            /// Bytes read as a message of the kind.
            pub fn read_as(kind: &str, bytes: &[u8]) -> Outcome {
                macro_rules! as_ {
                    ($t:ty) => {
                        go::<$t, _, _>(bytes, |r| Zenoh080.read(r), |v, w| Zenoh080.write(w, v))
                    };
                }
                match kind {
                    "keepalive" => as_!(KeepAlive),
                    "close" => as_!(Close),
                    "oam" => as_!(Oam),
                    "frame" => as_!(Frame),
                    "fragment" => as_!(Fragment),
                    "init syn" => as_!(InitSyn),
                    "init ack" => as_!(InitAck),
                    "open syn" => as_!(OpenSyn),
                    "open ack" => as_!(OpenAck),
                    "join" => as_!(Join),
                    "transport" => as_!(TransportMessage),
                    "low latency" => go::<TransportMessageLowLatency, _, _>(
                        bytes,
                        |r| Zenoh080.read(r),
                        |v, w| Zenoh080.write(w, ll_ref(v)),
                    ),
                    other => panic!("no such message {other}"),
                }
            }

            fn with_more(mut ext: Vec<u8>) -> Vec<u8> {
                ext[0] |= 0x80;
                ext
            }

            /// The extensions one after the other, each but the last with its more bit.
            fn chain(exts: &[Vec<u8>]) -> Vec<u8> {
                let mut b = Vec::new();
                for (i, e) in exts.iter().enumerate() {
                    b.extend(if i + 1 < exts.len() {
                        with_more(e.clone())
                    } else {
                        e.clone()
                    });
                }
                b
            }

            fn z(exts: &[Vec<u8>]) -> u8 {
                if exts.is_empty() {
                    0
                } else {
                    0x80
                }
            }

            fn frame_with(exts: &[Vec<u8>]) -> Vec<u8> {
                let mut b = vec![id::FRAME | 0x20 | z(exts), 5];
                b.extend(chain(exts));
                b
            }

            fn fragment_with(exts: &[Vec<u8>]) -> Vec<u8> {
                let mut b = vec![id::FRAGMENT | 0x20 | z(exts), 5];
                b.extend(chain(exts));
                b.extend_from_slice(&[1, 2, 3]);
                b
            }

            fn init_syn_with(exts: &[Vec<u8>]) -> Vec<u8> {
                let mut b = vec![id::INIT | z(exts), 9, 0x01, 0xAA];
                b.extend(chain(exts));
                b
            }

            fn init_ack_with(exts: &[Vec<u8>]) -> Vec<u8> {
                let mut b = vec![id::INIT | 0x20 | z(exts), 9, 0x01, 0xAA, 2, 7, 8];
                b.extend(chain(exts));
                b
            }

            fn open_syn_with(exts: &[Vec<u8>]) -> Vec<u8> {
                let mut b = vec![id::OPEN | 0x40 | z(exts), 1, 0, 0];
                b.extend(chain(exts));
                b
            }

            fn open_ack_with(exts: &[Vec<u8>]) -> Vec<u8> {
                let mut b = vec![id::OPEN | 0x20 | 0x40 | z(exts), 1, 0];
                b.extend(chain(exts));
                b
            }

            fn join_with(exts: &[Vec<u8>]) -> Vec<u8> {
                let mut b = vec![id::JOIN | 0x20 | z(exts), 9, 0x01, 0xAA, 1, 0, 0];
                b.extend(chain(exts));
                b
            }

            fn oam_with(exts: &[Vec<u8>]) -> Vec<u8> {
                let mut b = vec![id::OAM | z(exts), 1];
                b.extend(chain(exts));
                b
            }

            fn close_with(exts: &[Vec<u8>]) -> Vec<u8> {
                let mut b = vec![id::CLOSE | z(exts), 1];
                b.extend(chain(exts));
                b
            }

            fn keepalive_with(exts: &[Vec<u8>]) -> Vec<u8> {
                let mut b = vec![id::KEEP_ALIVE | z(exts)];
                b.extend(chain(exts));
                b
            }

            /// The bytes of one extension written alone, with no more bit.
            macro_rules! x {
                ($ext:expr) => {
                    enc(|w| Zenoh080.write(w, (&$ext, false)))
                };
            }

            fn init_exts() -> Vec<Vec<u8>> {
                vec![
                    x!(init::ext::QoS::new()),
                    x!(init::ext::QoSLink::new(77)),
                    x!(init::ext::Auth::new(zbuf(3))),
                    x!(init::ext::MultiLink::new(zbuf(2))),
                    x!(init::ext::LowLatency::new()),
                    x!(init::ext::Compression::new()),
                    x!(init::ext::Patch::new(1)),
                    x!(init::ext::RegionName::new(zbuf(4))),
                ]
            }

            fn open_syn_exts() -> Vec<Vec<u8>> {
                vec![
                    x!(open::ext::QoS::new()),
                    x!(open::ext::Auth::new(zbuf(3))),
                    x!(open::ext::MultiLinkSyn::new(zbuf(2))),
                    x!(open::ext::LowLatency::new()),
                    x!(open::ext::Compression::new()),
                    x!(open::ext::RemoteBound::new(1)),
                ]
            }

            fn open_ack_exts() -> Vec<Vec<u8>> {
                vec![
                    x!(open::ext::QoS::new()),
                    x!(open::ext::Auth::new(zbuf(3))),
                    x!(open::ext::MultiLinkAck::new()),
                    x!(open::ext::LowLatency::new()),
                    x!(open::ext::Compression::new()),
                    x!(open::ext::RemoteBound::new(1)),
                ]
            }

            /// The quality of service extension of a join: the header, the length it says and the
            /// bytes of the sixteen sequence numbers.
            fn join_qos(delta: i64) -> Vec<u8> {
                let mut body = Vec::new();
                for p in prio_sn().iter() {
                    body.extend(enc(|w| Zenoh080.write(w, p)));
                }
                let len = (body.len() as i64 + delta) as usize;
                let mut b = enc(|w| {
                    Zenoh080.write(
                        w,
                        (&ZExtZBufHeader::<{ join::ext::QoS::ID }>::new(len), false),
                    )
                });
                b.extend(body);
                b
            }

            fn join_exts() -> Vec<Vec<u8>> {
                vec![
                    join_qos(0),
                    x!(join::ext::Shm::new(zbuf(5))),
                    x!(join::ext::Patch::new(1)),
                ]
            }

            /// Hand-built inputs by class, each with the kind it is read as.
            pub fn classes() -> Vec<(&'static str, &'static str, Vec<u8>)> {
                let mut out = Vec::new();
                // A quality of service value and a patch level at the edges of a byte.
                let unk = |mandatory: bool| x!(ZExtUnknown::new(0x0a, mandatory, ZExtBody::Unit));
                for v in [0xffu64, 0x100, 0x1ff, 1 << 40] {
                    out.push(("qos", "frame", frame_with(&[x!(frame_qos(v))])));
                }
                for v in [0u64, 0xff, 0x100, 0x1ff, 1 << 40] {
                    out.push((
                        "patch",
                        "init syn",
                        init_syn_with(&[x!(init::ext::Patch::new(v))]),
                    ));
                    out.push((
                        "patch",
                        "join",
                        join_with(&[x!(join::ext::Patch::new(v))]),
                    ));
                }
                // An extension named twice, in every message that reads extensions.
                let (q1, q2) = (x!(frame_qos(1)), x!(frame_qos(2)));
                out.push(("duplicate", "frame", frame_with(&[q1.clone(), q2.clone()])));
                out.push((
                    "duplicate",
                    "frame",
                    frame_with(&[q1.clone(), unk(false), q2.clone()]),
                ));
                let first = x!(fragment::ext::First::new());
                let drop = x!(fragment::ext::Drop::new());
                let fq = x!(fragment_qos(1));
                for exts in [
                    vec![fq.clone(), fq.clone()],
                    vec![first.clone(), first.clone()],
                    vec![drop.clone(), drop.clone()],
                    vec![fq.clone(), first.clone(), fq.clone()],
                ] {
                    out.push(("duplicate", "fragment", fragment_with(&exts)));
                }
                let oq = x!(oam::ext::QoS::new(1));
                out.push(("duplicate", "oam", oam_with(&[oq.clone(), oq.clone()])));
                for e in init_exts() {
                    out.push(("duplicate", "init syn", init_syn_with(&[e.clone(), e.clone()])));
                    out.push(("duplicate", "init ack", init_ack_with(&[e.clone(), e.clone()])));
                }
                for e in open_syn_exts() {
                    out.push(("duplicate", "open syn", open_syn_with(&[e.clone(), e.clone()])));
                }
                for e in open_ack_exts() {
                    out.push(("duplicate", "open ack", open_ack_with(&[e.clone(), e.clone()])));
                }
                for e in join_exts() {
                    out.push(("duplicate", "join", join_with(&[e.clone(), e.clone()])));
                }
                // The quality of service extension of a join with a length that is not the length
                // of its sequence numbers.
                for delta in [-1i64, 0, 1, 5] {
                    out.push(("ext length", "join", join_with(&[join_qos(delta)])));
                }
                // An unknown extension that may be skipped and one that may not, wherever one is
                // read.
                for (kind, build) in [
                    ("frame", frame_with as fn(&[Vec<u8>]) -> Vec<u8>),
                    ("fragment", fragment_with),
                    ("init syn", init_syn_with),
                    ("init ack", init_ack_with),
                    ("open syn", open_syn_with),
                    ("open ack", open_ack_with),
                    ("join", join_with),
                    ("oam", oam_with),
                    ("close", close_with),
                    ("keepalive", keepalive_with),
                ] {
                    out.push(("unknown optional", kind, build(&[unk(false)])));
                    out.push(("unknown mandatory", kind, build(&[unk(true)])));
                }
                // Bits an init or a join leaves unused, and the size parameters sent with their
                // defaults: read alike.
                out.push(("reserved", "init syn", vec![id::INIT, 9, 0x0d, 0xAA]));
                let mut sized = vec![id::INIT | 0x40, 9, 0x01, 0xAA, 0xff];
                sized.extend_from_slice(&1234u16.to_le_bytes());
                out.push(("reserved", "init syn", sized));
                let mut default_sizes =
                    vec![id::INIT | 0x40, 9, 0x01, 0xAA, Resolution::default().as_u8()];
                default_sizes.extend_from_slice(&BatchSize::MAX.to_le_bytes());
                out.push(("reserved", "init syn", default_sizes));
                out
            }

            fn frame_qos(v: u64) -> $p::transport::frame::ext::QoS {
                $p::transport::frame::ext::QoS::new(v)
            }

            fn fragment_qos(v: u64) -> $p::transport::fragment::ext::QoS {
                $p::transport::fragment::ext::QoS::new(v)
            }

            /// Writes of a lease past what sixty-four bits of milliseconds hold, by message.
            pub fn lease_writes() -> Vec<(String, String)> {
                // One millisecond past the most, and a lease of nearly the most seconds there are.
                let over = Duration::new(18_446_744_073_709_551, 616_000_000);
                let huge = Duration::new(u64::MAX, 1_000_000);
                let cases = [
                    ("max", Duration::from_millis(u64::MAX)),
                    ("over", over),
                    ("huge", huge),
                ];
                let mut out = Vec::new();
                let text = |b: Vec<u8>| {
                    if b.ends_with(b"ERR") {
                        "err".to_string()
                    } else {
                        format!("ok {}", hex(&b))
                    }
                };
                for (case, d) in cases {
                    let m = OpenSyn {
                        lease: d,
                        ..open_syn(0, 0, 0)
                    };
                    out.push((format!("open syn {case}"), text(enc(|w| Zenoh080.write(w, &m)))));
                    let m = OpenAck {
                        lease: d,
                        ..open_ack(0, 0, 0)
                    };
                    out.push((format!("open ack {case}"), text(enc(|w| Zenoh080.write(w, &m)))));
                    let m = Join {
                        lease: d,
                        ..join_msg(0, 4, 0, 0, 0)
                    };
                    out.push((format!("join {case}"), text(enc(|w| Zenoh080.write(w, &m)))));
                }
                out
            }

            /// Writes of leases that are not what a message reads back (a part of a millisecond is
            /// not written), so only the bytes are compared: the line the seconds flag is decided
            /// by differs between an open syn (whole milliseconds) and an open ack (whole seconds).
            pub fn odd_lease_writes() -> Vec<String> {
                let text = |b: Vec<u8>| {
                    if b.ends_with(b"ERR") {
                        "err".to_string()
                    } else {
                        hex(&b)
                    }
                };
                let mut out = Vec::new();
                for d in [
                    Duration::new(1, 1),
                    Duration::new(2, 999_999),
                    Duration::new(2, 1_000_000),
                    Duration::from_micros(1500),
                    Duration::new(3, 999_999_999),
                ] {
                    let m = OpenSyn {
                        lease: d,
                        ..open_syn(0, 0, 0)
                    };
                    out.push(text(enc(|w| Zenoh080.write(w, &m))));
                    let m = OpenAck {
                        lease: d,
                        ..open_ack(0, 0, 0)
                    };
                    out.push(text(enc(|w| Zenoh080.write(w, &m))));
                    let m = Join {
                        lease: d,
                        ..join_msg(0, 4, 0, 0, 0)
                    };
                    out.push(text(enc(|w| Zenoh080.write(w, &m))));
                }
                out
            }

            /// A script of writes and reads through the batch over a bounded buffer: the result of
            /// each step and the state of the batch after it.
            pub fn batch_trace() -> Vec<String> {
                let mut out = Vec::new();
                for cap in [4usize, 24, 64, 1024] {
                    let mut b = Zenoh080Batch::new();
                    let mut bb = BBuf::with_capacity(cap);
                    out.push(format!("cap {cap} fresh {b:?}"));
                    let ka: TransportMessage = TransportBody::KeepAlive(KeepAlive).into();
                    let r = (&mut b).write(&mut bb, &ka);
                    out.push(format!("keepalive {r:?} {b:?} {}", hex(bb.as_slice())));
                    let n = net(1, Reliability::Reliable);
                    let ne = net(2, Reliability::BestEffort);
                    let r = (&mut b).write(&mut bb, n.as_ref());
                    out.push(format!("network without frame {r:?} {b:?}"));
                    let fh = FrameHeader {
                        reliability: Reliability::Reliable,
                        sn: 7,
                        ext_qos: qos_ext(1),
                    };
                    let r = (&mut b).write(&mut bb, (n.as_ref(), &fh));
                    out.push(format!("frame {r:?} {b:?} {}", hex(bb.as_slice())));
                    let r = (&mut b).write(&mut bb, n.as_ref());
                    out.push(format!("same frame {r:?} {b:?} {}", hex(bb.as_slice())));
                    let r = (&mut b).write(&mut bb, ne.as_ref());
                    out.push(format!("other reliability {r:?} {b:?}"));
                    let r = (&mut b).write(&mut bb, (ne.as_ref(), &fh));
                    out.push(format!("wrong header {r:?} {b:?}"));
                    let fh2 = FrameHeader {
                        reliability: Reliability::BestEffort,
                        sn: 9,
                        ext_qos: qos_ext(2),
                    };
                    let r = (&mut b).write(&mut bb, (ne.as_ref(), &fh2));
                    out.push(format!("best effort frame {r:?} {b:?} {}", hex(bb.as_slice())));
                    let r = (&mut b).write(&mut bb, &ka);
                    out.push(format!("keepalive again {r:?} {b:?} {}", hex(bb.as_slice())));
                    for len in [3usize, 20, 100] {
                        let payload = zbuf(len);
                        let mut reader = (&payload).reader();
                        let mut fh = FragmentHeader {
                            reliability: Reliability::Reliable,
                            more: true,
                            sn: 3,
                            ext_qos: qos_ext(0),
                            ext_first: None,
                            ext_drop: None,
                        };
                        let r = (&mut b).write(&mut bb, (&mut reader, &mut fh));
                        out.push(format!(
                            "fragment {len} {r:?} more={} left={} {}",
                            fh.more,
                            reader.remaining(),
                            hex(bb.as_slice())
                        ));
                    }
                    b.clear();
                    out.push(format!("cleared {b:?}"));
                }
                // The fragment that is the last by a byte: the buffer holds what the payload takes
                // and one byte less, exactly, and one byte more, after the header.
                for len in [1usize, 10] {
                    for room in [-1i64, 0, 1] {
                        let mut b = Zenoh080Batch::new();
                        let header = 2usize;
                        let mut bb = BBuf::with_capacity(((header + len) as i64 + room) as usize);
                        let payload = zbuf(len);
                        let mut reader = (&payload).reader();
                        let mut fh = FragmentHeader {
                            reliability: Reliability::BestEffort,
                            more: true,
                            sn: 3,
                            ext_qos: qos_ext(0),
                            ext_first: None,
                            ext_drop: None,
                        };
                        let r = (&mut b).write(&mut bb, (&mut reader, &mut fh));
                        out.push(format!(
                            "last fragment {len} {room} {r:?} more={} left={} {}",
                            fh.more,
                            reader.remaining(),
                            hex(bb.as_slice())
                        ));
                    }
                }
                // Reads: a run of transport messages, and a frame read by its reader.
                let run: Vec<Vec<u8>> = vec![
                    enc(|w| Zenoh080.write(w, &frame_msg(Reliability::Reliable, 11, 1, 2))),
                    enc(|w| {
                        Zenoh080.write(
                            w,
                            &fragment_msg(Reliability::BestEffort, true, 12, 0, true, false, 6),
                        )
                    }),
                    enc(|w| Zenoh080.write(w, &KeepAlive)),
                    enc(|w| Zenoh080.write(w, &frame_msg(Reliability::BestEffort, 13, 2, 3))),
                    enc(|w| Zenoh080.write(w, &Close { reason: 3, session: true })),
                    vec![0xff, 0xff],
                ];
                let mut b = Zenoh080Batch::new();
                for bytes in &run {
                    let mut r: &[u8] = bytes;
                    let res: Result<TransportMessage, DidntRead> = (&mut b).read(&mut r);
                    out.push(format!("read {res:?} rem={} {b:?}", r.len()));
                }
                for bytes in &run {
                    for cut in [0usize, 1, 3, 9] {
                        let bytes = &bytes[..bytes.len().saturating_sub(cut)];
                        let mut r: &[u8] = bytes;
                        // The reader holds the bytes until it is dropped, which reads what it left.
                        let text = {
                            let res: Result<FrameReader<'_, &[u8]>, DidntRead> =
                                (&mut b).read(&mut r);
                            match res {
                                Ok(mut f) => {
                                    let msgs: Vec<NetworkMessage> = f.by_ref().collect();
                                    format!(
                                        "{msgs:?} {:?} {} {:?}",
                                        f.reliability, f.sn, f.ext_qos
                                    )
                                }
                                Err(_) => "err".to_string(),
                            }
                        };
                        out.push(format!("frame reader {text} rem={} {b:?}", r.len()));
                    }
                }
                out
            }
        }
    };
}

transport_cases!(up, up_codec, up_protocol, up_buffers);
transport_cases!(wz, wz_codec, wz_protocol, wz_buffers);

fn mutations(corpus: &[(&'static str, String, Vec<u8>)]) -> Vec<(&'static str, String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rng = StdRng::seed_from_u64(0x7A11);
    for (kind, name, bytes) in corpus {
        for cut in 0..bytes.len() {
            out.push((*kind, format!("{name} cut {cut}"), bytes[..cut].to_vec()));
        }
        let positions: Vec<usize> = if bytes.len() <= 24 {
            (0..bytes.len()).collect()
        } else {
            (0..12).map(|_| rng.gen_range(0..bytes.len())).collect()
        };
        for i in positions {
            for v in [0x00u8, 0x01, 0x80, 0xff, bytes[i] ^ 0x20, bytes[i] ^ 0x40] {
                let mut b = bytes.clone();
                b[i] = v;
                out.push((*kind, format!("{name} byte {i} = {v:02x}"), b));
            }
        }
    }
    out
}

#[test]
fn both_crates_write_every_transport_message_to_the_same_bytes() {
    let (u, w) = (up::corpus(), wz::corpus());
    assert!(u.len() > 5000, "{}", u.len());
    assert_eq!(u.len(), w.len());
    let bad: Vec<_> = u.iter().zip(&w).filter(|(a, b)| a != b).take(5).collect();
    assert!(bad.is_empty(), "{bad:#?}");
    assert!(u.iter().all(|(_, _, b)| !b.ends_with(b"ERR")));
    let distinct: std::collections::BTreeSet<_> = u.iter().map(|(_, _, b)| b.clone()).collect();
    assert!(distinct.len() > 2500, "{}", distinct.len());
    // Every encoding reads back as the message it is, on both sides, to the bytes it came from.
    for (kind, name, bytes) in &u {
        let (a, b) = (up::read_as(kind, bytes), wz::read_as(kind, bytes));
        assert_eq!(a, b, "{name}");
        assert!(
            a.0.starts_with("ok") && a.0.ends_with("rem=0"),
            "{name} {}: {}",
            hex(bytes),
            a.0
        );
        assert_eq!(a.1, Some(true), "{name} {} {}", hex(bytes), a.0);
    }
}

#[test]
fn both_crates_read_every_cut_and_changed_encoding_alike_but_for_the_classes() {
    let corpus = up::corpus();
    let mut inputs = mutations(&corpus);
    // The encodings alone are read as every kind of message.
    for (_, name, bytes) in corpus.iter().step_by(7) {
        for kind in KINDS {
            inputs.push((kind, format!("{name} as {kind}"), bytes.clone()));
        }
    }
    assert!(inputs.len() > 300_000, "{}", inputs.len());
    let (mut equal, mut refused, mut ok) = (0usize, 0usize, 0usize);
    for (kind, name, bytes) in &inputs {
        let (a, b) = (up::read_as(kind, bytes), wz::read_as(kind, bytes));
        if a.0 == b.0 {
            equal += 1;
            ok += a.0.starts_with("ok") as usize;
            continue;
        }
        // The only difference: upstream accepted a reading that does not write back to its bytes,
        // and wz refused it.
        assert!(
            a.0.starts_with("ok") && a.1 == Some(false) && b.0.starts_with("err"),
            "{kind} {name} {}\nup {a:?}\nwz {b:?}",
            hex(bytes)
        );
        refused += 1;
    }
    assert!(equal > 280_000 && ok > 60_000, "{equal} {ok}");
    assert!(refused > 0, "{refused}");
}

/// The hand-built inputs of a class read as one of the kinds: how many are read alike and how many
/// differ, where a difference is a reading upstream accepts that does not write back to its bytes
/// and wz refuses.
fn class_counts(class: &str, kinds: &[&str]) -> (usize, usize) {
    let (u, w) = (up::classes(), wz::classes());
    assert_eq!(u, w);
    let (mut alike, mut differ) = (0, 0);
    for (c, kind, bytes) in &u {
        if *c != class || !kinds.contains(kind) {
            continue;
        }
        let (a, b) = (up::read_as(kind, bytes), wz::read_as(kind, bytes));
        if a.0 == b.0 {
            alike += 1;
            continue;
        }
        differ += 1;
        assert!(
            a.0.starts_with("ok") && a.1 == Some(false) && b.0.starts_with("err"),
            "{class} {kind} {}\nup {a:?}\nwz {b:?}",
            hex(bytes)
        );
    }
    (alike, differ)
}

// Each class has inputs on which they differ and, where it has an edge, inputs at the edge on which
// they do not. One test to a class and a message, so that a change to the reader of one is seen by
// the test that owns it.

#[test]
fn a_quality_of_service_wider_than_a_byte_is_refused_by_wz_only() {
    // 255 is read alike, and the three wider values are not.
    assert_eq!(class_counts("qos", &["frame"]), (1, 3));
}

#[test]
fn a_patch_level_wider_than_a_byte_is_refused_by_wz_only() {
    // A level of 0 and one of 255 are read alike, the three wider ones are refused, in an init and
    // in a join.
    assert_eq!(class_counts("patch", &["init syn", "join"]), (4, 6));
}

// An extension named twice is refused by wz and kept as the last by upstream, in each message that
// reads extensions. The counts are the extensions each message knows: a frame has one (and is also
// read with a foreign extension between the two), a fragment three (and the quality of service
// around another), an oam one, an init eight, an open six, a join three.
macro_rules! duplicate_test {
    ($test:ident, $kind:expr, $count:expr) => {
        #[test]
        fn $test() {
            assert_eq!(class_counts("duplicate", &[$kind]), (0, $count));
        }
    };
}

duplicate_test!(
    a_frame_extension_named_twice_is_refused_by_wz_only,
    "frame",
    2
);
duplicate_test!(
    a_fragment_extension_named_twice_is_refused_by_wz_only,
    "fragment",
    4
);
duplicate_test!(an_oam_extension_named_twice_is_refused_by_wz_only, "oam", 1);
duplicate_test!(
    an_init_syn_extension_named_twice_is_refused_by_wz_only,
    "init syn",
    8
);
duplicate_test!(
    an_init_ack_extension_named_twice_is_refused_by_wz_only,
    "init ack",
    8
);
duplicate_test!(
    an_open_syn_extension_named_twice_is_refused_by_wz_only,
    "open syn",
    6
);
duplicate_test!(
    an_open_ack_extension_named_twice_is_refused_by_wz_only,
    "open ack",
    6
);
duplicate_test!(
    a_join_extension_named_twice_is_refused_by_wz_only,
    "join",
    3
);

#[test]
fn the_length_of_the_quality_of_service_of_a_join_is_checked_by_wz_only() {
    // A length one short or one over or five over is refused; the exact one is read alike.
    assert_eq!(class_counts("ext length", &["join"]), (1, 3));
}

#[test]
fn an_unknown_extension_and_the_unused_bits_are_read_alike() {
    // An optional one is skipped and a mandatory one refuses, by both, in each of the ten
    // messages; the bits an init leaves unused are read alike.
    assert_eq!(class_counts("unknown optional", &KINDS), (10, 0));
    assert_eq!(class_counts("unknown mandatory", &KINDS), (10, 0));
    assert_eq!(class_counts("reserved", &KINDS), (3, 0));
    for (class, kind, bytes) in &up::classes() {
        let a = up::read_as(kind, bytes);
        match *class {
            "unknown optional" => assert!(a.0.starts_with("ok"), "{kind} {}", a.0),
            "unknown mandatory" => assert!(a.0.starts_with("err"), "{kind} {}", a.0),
            _ => {}
        }
    }
}

#[test]
fn a_lease_past_sixty_four_bits_of_milliseconds_is_refused_by_wz_only() {
    // A lease of more milliseconds than sixty-four bits hold: upstream writes it cut, wz refuses;
    // the most there is, is written by both.
    let (a, b) = (up::lease_writes(), wz::lease_writes());
    assert_eq!(a.len(), 9);
    let (mut same, mut differ) = (0, 0);
    for ((name, x), (_, y)) in a.iter().zip(&b) {
        if x == y {
            same += 1;
            assert!(name.ends_with("max") && x.starts_with("ok"), "{name} {x}");
        } else {
            differ += 1;
            assert!(x.starts_with("ok") && y == "err", "{name} {x} {y}");
        }
    }
    assert_eq!((same, differ), (3, 6));
    // A part of a millisecond that is not written is cut by both, in the same places: the second
    // and the third of each message differ from each other by the flag that is decided by whole
    // milliseconds in an open syn and a join and by whole seconds in an open ack.
    let (a, b) = (up::odd_lease_writes(), wz::odd_lease_writes());
    assert_eq!(a, b);
    assert_eq!(a.len(), 15);
    assert!(a.iter().all(|t| t != "err"));
    let distinct: std::collections::BTreeSet<_> = a.iter().collect();
    assert_eq!(distinct.len(), 15);
}

#[test]
fn both_crates_batch_the_same_messages_in_the_same_states() {
    let (u, w) = (up::batch_trace(), wz::batch_trace());
    assert_eq!(u, w);
    assert!(u.len() > 80, "{}", u.len());
    let distinct: std::collections::BTreeSet<_> = u.iter().collect();
    assert!(distinct.len() > 50, "{}", distinct.len());
    // Both of the errors a batch gives, a frame to start and a buffer that is full, are among them.
    assert!(u.iter().any(|l| l.contains("Err(NewFrame)")));
    assert!(u.iter().any(|l| l.contains("Err(DidntWrite)")));
    assert!(u
        .iter()
        .any(|l| l.starts_with("frame reader") && l.contains("Push")));
}

/// The control: the comparison is on text, so a message that differs gives a row that differs.
#[test]
fn the_comparison_sees_a_message_that_differs() {
    let c = wz::corpus();
    let get = |n: &str| c.iter().find(|(_, name, _)| name == n).unwrap().2.clone();
    assert_ne!(get("close 0 false"), get("close 0 true"));
    assert_ne!(get("frame Reliable 0 0 0"), get("frame BestEffort 0 0 0"));
    assert_ne!(
        wz::read_as("frame", &get("frame Reliable 0 0 1")).0,
        wz::read_as("frame", &get("frame Reliable 0 0 2")).0
    );
    let t = wz::batch_trace();
    assert_ne!(t[1], t[2]);
}
