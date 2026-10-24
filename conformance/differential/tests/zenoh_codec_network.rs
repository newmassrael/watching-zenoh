// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-codec`, the network messages (the third slice of the crate): upstream's crate (`up_codec`)
//! and wz's (`wz_codec`) given the same messages to write and the same bytes to read, results equal
//! as text, the bytes written and the bytes left unread included.
//!
//! * WRITES: every combination of the extensions of each message (a mask of present ones, each with a
//!   value that is not its default) over four key expressions and two ids, for a push, a request, a
//!   response, a final response, an interest of every mode, a declare of every body, an oam of every
//!   body, and the network message that holds each; and the iterator over a run of encoded messages,
//!   with garbage after them.
//! * READS: every encoding, every prefix of it and every one of its bytes set to six values, read as
//!   the message it is and as every other, a reading that succeeds being compared with the bytes it
//!   would write back.
//!
//! Upstream is lenient in places where wz refuses what it takes in; each is a class, built by hand,
//! counted and held on both sides, and a reading upstream accepts that wz refuses must be one that
//! does not write back to the bytes it was read from:
//!
//! * a QoS value wider than a byte, a node id wider than sixteen bits, a queryable distance wider
//!   than sixteen bits, and a budget that is zero or wider than thirty-two bits, are kept by their
//!   low bits or lost;
//! * an extension a message knows, named twice, is kept as the last of them;
//! * the length in the header of a timestamp, a responder id or a timestamp stack extension is not
//!   read against the bytes its fields take;
//! * the extension that carries a key expression in an undeclaration ignores the bytes left after
//!   a scope that has no suffix, and keeps the low sixteen bits of a wider scope.
//!
//! A write differs in one place: a timeout of more milliseconds than sixty-four bits hold is written
//! cut by upstream and refused by wz. And an interest read with the name or mapping flag and no key
//! expression is read alike and written back differently, which the protocol crate decides.
//!
//! The crates are built without `shared-memory`.

use rand::{rngs::StdRng, Rng, SeedableRng};

/// What a reading gave: its text, and for a reading that succeeded whether the value writes back to
/// the bytes it consumed.
type Outcome = (String, Option<bool>);

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const KINDS: [&str; 9] = [
    "push",
    "request",
    "response",
    "response final",
    "interest",
    "declare",
    "declare body",
    "oam",
    "network",
];

macro_rules! network_cases {
    ($name:ident, $c:ident, $p:ident, $b:ident) => {
        mod $name {
            use std::{borrow::Cow, fmt::Debug, num::NonZeroU32, time::Duration};

            use $b::{
                reader::DidntRead,
                writer::{DidntWrite, HasWriter},
                ZBuf, ZSlice,
            };
            use $c::{network::NetworkMessageIter, RCodec, WCodec, Zenoh080};
            use $p::{
                common::{ZExtBody, ZExtZ64, ZExtZBufHeader},
                core::{Reliability, Timestamp, WireExpr, ZenohIdProto},
                network::{
                    declare::{
                        common::ext::WireExprType,
                        queryable::ext::QueryableInfoType,
                        Declare, DeclareBody, DeclareFinal, DeclareKeyExpr, DeclareQueryable,
                        DeclareSubscriber, DeclareToken, UndeclareKeyExpr, UndeclareQueryable,
                        UndeclareSubscriber, UndeclareToken,
                    },
                    interest::{Interest, InterestMode, InterestOptions},
                    request::ext::QueryTarget,
                    timestamp_stack::{Interception, TimestampStack, TsStackType},
                    ext::{EntityGlobalIdType, NodeIdType, TimestampType},
                    Mapping, NetworkBody, NetworkMessage, Oam, Push, Request, Response,
                    ResponseFinal,
                },
                zenoh::{err::Err as ErrMsg, put::Put, query::Query, reply::Reply, PushBody,
                    RequestBody, ResponseBody},
            };

            use super::{hex, Outcome};

            fn zid(n: usize) -> ZenohIdProto {
                let bytes: Vec<u8> = (0..n).map(|i| i as u8 + 1).collect();
                ZenohIdProto::try_from(bytes.as_slice()).unwrap()
            }

            fn wire(k: usize) -> WireExpr<'static> {
                match k {
                    0 => WireExpr {
                        scope: 0,
                        suffix: Cow::Borrowed(""),
                        mapping: Mapping::Receiver,
                    },
                    1 => WireExpr {
                        scope: 5,
                        suffix: Cow::Borrowed("a/b"),
                        mapping: Mapping::Sender,
                    },
                    2 => WireExpr {
                        scope: u16::MAX,
                        suffix: Cow::Borrowed(""),
                        mapping: Mapping::Sender,
                    },
                    _ => WireExpr {
                        scope: 0,
                        suffix: Cow::Borrowed("k"),
                        mapping: Mapping::Receiver,
                    },
                }
            }

            fn tstamp<const ID: u8>() -> TimestampType<ID> {
                let id = uhlc::ID::try_from(&zid(8).to_le_bytes()[..8]).unwrap();
                TimestampType {
                    timestamp: Timestamp::new(uhlc::NTP64(0x1234_5678_9ABC), id),
                }
            }

            fn tsstack<const ID: u8>(k: usize) -> TsStackType<ID> {
                TsStackType {
                    ts_stack: TimestampStack {
                        conf_flags: 5,
                        stack: (0..k)
                            .map(|i| Interception {
                                flags: i as u8 + 1,
                                timestamp: vec![i as u8; i * 3],
                            })
                            .collect(),
                    },
                }
            }

            fn respid<const ID: u8>() -> EntityGlobalIdType<ID> {
                EntityGlobalIdType {
                    zid: zid(5),
                    eid: 300,
                }
            }

            fn qos<const ID: u8>(on: bool) -> $p::network::ext::QoSType<ID> {
                ZExtZ64::<ID>::new(if on { 0x2a } else { 0 }).into()
            }

            fn nodeid<const ID: u8>(on: bool) -> NodeIdType<ID> {
                NodeIdType {
                    node_id: if on { 300 } else { 0 },
                }
            }

            fn push_body(k: usize) -> PushBody {
                if k == 0 {
                    PushBody::Put(Put {
                        payload: ZBuf::from(vec![0xA5u8; 3]),
                        ..Put::default()
                    })
                } else {
                    PushBody::Del($p::zenoh::del::Del::default())
                }
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

            fn push(mask: usize, w: usize, body: usize) -> Push {
                Push {
                    wire_expr: wire(w),
                    ext_qos: qos(mask & 1 != 0),
                    ext_tstamp: (mask & 2 != 0).then(tstamp),
                    ext_nodeid: nodeid(mask & 4 != 0),
                    ext_ts_stack: (mask & 8 != 0).then(|| tsstack(2)),
                    payload: push_body(body),
                }
            }

            fn request(mask: usize, w: usize, id: u32) -> Request {
                Request {
                    id,
                    wire_expr: wire(w),
                    ext_qos: qos(mask & 1 != 0),
                    ext_tstamp: (mask & 2 != 0).then(tstamp),
                    ext_nodeid: nodeid(mask & 4 != 0),
                    ext_target: if mask & 8 != 0 {
                        QueryTarget::AllComplete
                    } else {
                        QueryTarget::BestMatching
                    },
                    ext_budget: (mask & 16 != 0).then(|| NonZeroU32::new(u32::MAX).unwrap()),
                    ext_timeout: (mask & 32 != 0).then(|| Duration::from_millis(1500)),
                    ext_ts_stack: (mask & 64 != 0).then(|| tsstack(1)),
                    payload: RequestBody::Query(Query::default()),
                }
            }

            fn response(mask: usize, w: usize, rid: u32, body: usize) -> Response {
                Response {
                    rid,
                    wire_expr: wire(w),
                    payload: if body == 0 {
                        ResponseBody::Reply(Reply {
                            consolidation: $p::zenoh::query::ConsolidationMode::DEFAULT,
                            ext_unknown: Vec::new(),
                            payload: push_body(0),
                        })
                    } else {
                        ResponseBody::Err(ErrMsg {
                            encoding: $p::core::Encoding::empty(),
                            ext_sinfo: None,
                            ext_unknown: Vec::new(),
                            payload: ZBuf::from(vec![9u8; 2]),
                        })
                    },
                    ext_qos: qos(mask & 1 != 0),
                    ext_tstamp: (mask & 2 != 0).then(tstamp),
                    ext_respid: (mask & 4 != 0).then(respid),
                    ext_ts_stack: (mask & 8 != 0).then(|| tsstack(0)),
                }
            }

            fn response_final(mask: usize, rid: u32) -> ResponseFinal {
                ResponseFinal {
                    rid,
                    ext_qos: qos(mask & 1 != 0),
                    ext_tstamp: (mask & 2 != 0).then(tstamp),
                }
            }

            fn interest(mode: usize, opts: u8, w: usize, mask: usize) -> Interest {
                let mode = [
                    InterestMode::Final,
                    InterestMode::Current,
                    InterestMode::Future,
                    InterestMode::CurrentFuture,
                ][mode];
                let is_final = mode == InterestMode::Final;
                Interest {
                    id: 7,
                    mode,
                    options: if is_final {
                        InterestOptions::empty()
                    } else {
                        InterestOptions::from(opts)
                    },
                    wire_expr: (!is_final && w != 0).then(|| wire(w)),
                    ext_qos: qos(mask & 1 != 0),
                    ext_tstamp: (mask & 2 != 0).then(tstamp),
                    ext_nodeid: nodeid(mask & 4 != 0),
                }
            }

            fn declare_body(k: usize) -> DeclareBody {
                match k {
                    0 => DeclareBody::DeclareKeyExpr(DeclareKeyExpr {
                        id: 3,
                        wire_expr: wire(1),
                    }),
                    1 => DeclareBody::DeclareKeyExpr(DeclareKeyExpr {
                        id: u16::MAX,
                        wire_expr: wire(2),
                    }),
                    2 => DeclareBody::UndeclareKeyExpr(UndeclareKeyExpr { id: 3 }),
                    3..=6 => DeclareBody::DeclareSubscriber(DeclareSubscriber {
                        id: 9,
                        wire_expr: wire(k - 3),
                    }),
                    7 => DeclareBody::UndeclareSubscriber(UndeclareSubscriber {
                        id: 9,
                        ext_wire_expr: WireExprType::null(),
                    }),
                    8 => DeclareBody::UndeclareSubscriber(UndeclareSubscriber {
                        id: 9,
                        ext_wire_expr: WireExprType { wire_expr: wire(1) },
                    }),
                    9..=12 => DeclareBody::DeclareQueryable(DeclareQueryable {
                        id: 4,
                        wire_expr: wire(1),
                        ext_info: [
                            QueryableInfoType::DEFAULT,
                            QueryableInfoType {
                                complete: true,
                                distance: 0,
                            },
                            QueryableInfoType {
                                complete: true,
                                distance: u16::MAX,
                            },
                            QueryableInfoType {
                                complete: false,
                                distance: 3,
                            },
                        ][k - 9],
                    }),
                    13 => DeclareBody::UndeclareQueryable(UndeclareQueryable {
                        id: 4,
                        ext_wire_expr: WireExprType::null(),
                    }),
                    14 => DeclareBody::UndeclareQueryable(UndeclareQueryable {
                        id: 4,
                        ext_wire_expr: WireExprType { wire_expr: wire(3) },
                    }),
                    15..=18 => DeclareBody::DeclareToken(DeclareToken {
                        id: 6,
                        wire_expr: wire(k - 15),
                    }),
                    19 => DeclareBody::UndeclareToken(UndeclareToken {
                        id: 6,
                        ext_wire_expr: WireExprType::null(),
                    }),
                    20 => DeclareBody::UndeclareToken(UndeclareToken {
                        id: 6,
                        ext_wire_expr: WireExprType { wire_expr: wire(1) },
                    }),
                    _ => DeclareBody::DeclareFinal(DeclareFinal),
                }
            }

            fn declare(mask: usize, interest_id: bool, body: usize) -> Declare {
                Declare {
                    interest_id: interest_id.then_some(7),
                    ext_qos: qos(mask & 1 != 0),
                    ext_tstamp: (mask & 2 != 0).then(tstamp),
                    ext_nodeid: nodeid(mask & 4 != 0),
                    body: declare_body(body),
                }
            }

            fn oam(mask: usize, id: u16, body: usize) -> Oam {
                Oam {
                    id,
                    body: [
                        ZExtBody::Unit,
                        ZExtBody::Z64(300),
                        ZExtBody::ZBuf(ZBuf::from(vec![1u8, 2, 3])),
                    ][body]
                        .clone(),
                    ext_qos: qos(mask & 1 != 0),
                    ext_tstamp: (mask & 2 != 0).then(tstamp),
                }
            }

            /// Every message to write, by the kind it is read as, a name and the bytes.
            pub fn corpus() -> Vec<(&'static str, String, Vec<u8>)> {
                let mut out: Vec<(&'static str, String, Vec<u8>)> = Vec::new();
                for mask in 0..16 {
                    for w in 0..4 {
                        for body in 0..2 {
                            let m = push(mask, w, body);
                            out.push((
                                "push",
                                format!("push {mask} {w} {body}"),
                                enc(|wr| Zenoh080.write(wr, &m)),
                            ));
                            let n: NetworkMessage = NetworkBody::Push(m).into();
                            out.push((
                                "network",
                                format!("network push {mask} {w} {body}"),
                                enc(|wr| Zenoh080.write(wr, &n)),
                            ));
                        }
                    }
                }
                for mask in 0..128 {
                    for w in 0..4 {
                        for id in [0u32, u32::MAX] {
                            let m = request(mask, w, id);
                            out.push((
                                "request",
                                format!("request {mask} {w} {id}"),
                                enc(|wr| Zenoh080.write(wr, &m)),
                            ));
                            if mask % 16 == 5 {
                                let n: NetworkMessage = NetworkBody::Request(m).into();
                                out.push((
                                    "network",
                                    format!("network request {mask} {w} {id}"),
                                    enc(|wr| Zenoh080.write(wr, &n)),
                                ));
                            }
                        }
                    }
                }
                for mask in 0..16 {
                    for w in 0..4 {
                        for rid in [0u32, u32::MAX] {
                            for body in 0..2 {
                                let m = response(mask, w, rid, body);
                                out.push((
                                    "response",
                                    format!("response {mask} {w} {rid} {body}"),
                                    enc(|wr| Zenoh080.write(wr, &m)),
                                ));
                                if mask % 4 == 3 {
                                    let n: NetworkMessage = NetworkBody::Response(m).into();
                                    out.push((
                                        "network",
                                        format!("network response {mask} {w} {rid} {body}"),
                                        enc(|wr| Zenoh080.write(wr, &n)),
                                    ));
                                }
                            }
                        }
                    }
                }
                for mask in 0..4 {
                    for rid in [0u32, u32::MAX] {
                        let m = response_final(mask, rid);
                        out.push((
                            "response final",
                            format!("response final {mask} {rid}"),
                            enc(|wr| Zenoh080.write(wr, &m)),
                        ));
                        let n: NetworkMessage = NetworkBody::ResponseFinal(m).into();
                        out.push((
                            "network",
                            format!("network response final {mask} {rid}"),
                            enc(|wr| Zenoh080.write(wr, &n)),
                        ));
                    }
                }
                for mode in 0..4 {
                    for opts in [0x01u8, 0x0f, 0x80, 0x8a] {
                        for w in 0..3 {
                            for mask in 0..8 {
                                if mode == 0 && (opts != 0x01 || w != 0) {
                                    continue;
                                }
                                let m = interest(mode, opts, w, mask);
                                out.push((
                                    "interest",
                                    format!("interest {mode} {opts} {w} {mask}"),
                                    enc(|wr| Zenoh080.write(wr, &m)),
                                ));
                                if mask == 3 {
                                    let n: NetworkMessage = NetworkBody::Interest(m).into();
                                    out.push((
                                        "network",
                                        format!("network interest {mode} {opts} {w}"),
                                        enc(|wr| Zenoh080.write(wr, &n)),
                                    ));
                                }
                            }
                        }
                    }
                }
                for mask in 0..8 {
                    for iid in [false, true] {
                        for body in 0..22 {
                            let m = declare(mask, iid, body);
                            out.push((
                                "declare",
                                format!("declare {mask} {iid} {body}"),
                                enc(|wr| Zenoh080.write(wr, &m)),
                            ));
                            if mask == 7 {
                                let n: NetworkMessage = NetworkBody::Declare(m).into();
                                out.push((
                                    "network",
                                    format!("network declare {iid} {body}"),
                                    enc(|wr| Zenoh080.write(wr, &n)),
                                ));
                            }
                        }
                    }
                }
                for body in 0..22 {
                    let b = declare_body(body);
                    out.push((
                        "declare body",
                        format!("declare body {body}"),
                        enc(|wr| Zenoh080.write(wr, &b)),
                    ));
                }
                for mask in 0..4 {
                    for id in [0u16, u16::MAX] {
                        for body in 0..3 {
                            let m = oam(mask, id, body);
                            out.push((
                                "oam",
                                format!("oam {mask} {id} {body}"),
                                enc(|wr| Zenoh080.write(wr, &m)),
                            ));
                            let n: NetworkMessage = NetworkBody::OAM(m).into();
                            out.push((
                                "network",
                                format!("network oam {mask} {id} {body}"),
                                enc(|wr| Zenoh080.write(wr, &n)),
                            ));
                        }
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
                    "push" => as_!(Push),
                    "request" => as_!(Request),
                    "response" => as_!(Response),
                    "response final" => as_!(ResponseFinal),
                    "interest" => as_!(Interest),
                    "declare" => as_!(Declare),
                    "declare body" => as_!(DeclareBody),
                    "oam" => as_!(Oam),
                    "network" => as_!(NetworkMessage),
                    other => panic!("no such message {other}"),
                }
            }

            /// The text of the messages an iterator over `bytes` gives and of the bytes left.
            pub fn iterate(bytes: &[u8]) -> String {
                let mut it = NetworkMessageIter::new(Reliability::BestEffort, bytes);
                let msgs: Vec<_> = it.by_ref().collect();
                format!("{msgs:?} {it:?}")
            }

            /// A 64-bit extension of a push or a request by its short id: 1 QoS, 3 node id, 4 target,
            /// 5 budget.
            fn ext64(id: u8, value: u64) -> Vec<u8> {
                use $p::network::{push, request};
                match id {
                    1 => enc(|w| Zenoh080.write(w, (&push::ext::QoS::new(value), false))),
                    3 => enc(|w| Zenoh080.write(w, (&push::ext::NodeId::new(value), false))),
                    4 => enc(|w| Zenoh080.write(w, (&request::ext::Target::new(value), false))),
                    5 => enc(|w| Zenoh080.write(w, (&request::ext::Budget::new(value), false))),
                    _ => unreachable!(),
                }
            }

            fn with_more(mut ext: Vec<u8>) -> Vec<u8> {
                ext[0] |= 0x80;
                ext
            }

            /// A buffer extension by its short id (2 timestamp, 7 timestamp stack, 15 key expression)
            /// with a header that says `len` bytes follow and then `body`.
            fn zbuf_ext(id: u8, len: usize, body: &[u8]) -> Vec<u8> {
                let mut b = match id {
                    2 => enc(|w| {
                        Zenoh080.write(
                            w,
                            (&ZExtZBufHeader::<{ ZExtZBufHeader::<2>::id(false) }>::new(len), false),
                        )
                    }),
                    7 => enc(|w| {
                        Zenoh080.write(
                            w,
                            (&ZExtZBufHeader::<{ ZExtZBufHeader::<7>::id(false) }>::new(len), false),
                        )
                    }),
                    0x0f => enc(|w| {
                        Zenoh080.write(
                            w,
                            (&ZExtZBufHeader::<{ ZExtZBufHeader::<0x0f>::id(true) }>::new(len), false),
                        )
                    }),
                    _ => unreachable!(),
                };
                b.extend_from_slice(body);
                b
            }

            fn ts_body() -> Vec<u8> {
                let t: $p::network::push::ext::TimestampType = tstamp();
                let full = enc(|w| Zenoh080.write(w, (&t, false)));
                full[2..].to_vec()
            }

            /// The bytes of a push with the extensions in `exts` (the last has no more bit).
            fn push_with(exts: &[Vec<u8>]) -> Vec<u8> {
                let mut b = vec![$p::network::id::PUSH | if exts.is_empty() { 0 } else { 0x80 }, 0];
                for (i, e) in exts.iter().enumerate() {
                    b.extend(if i + 1 < exts.len() {
                        with_more(e.clone())
                    } else {
                        e.clone()
                    });
                }
                b.extend(enc(|w| Zenoh080.write(w, &push_body(0))));
                b
            }

            fn request_with(exts: &[Vec<u8>]) -> Vec<u8> {
                let mut b = vec![$p::network::id::REQUEST | if exts.is_empty() { 0 } else { 0x80 }, 1, 0];
                for (i, e) in exts.iter().enumerate() {
                    b.extend(if i + 1 < exts.len() {
                        with_more(e.clone())
                    } else {
                        e.clone()
                    });
                }
                b.extend(enc(|w| Zenoh080.write(w, &RequestBody::Query(Query::default()))));
                b
            }

            fn undeclare_token_with(ext: Vec<u8>) -> Vec<u8> {
                let mut b = vec![
                    $p::network::declare::id::U_TOKEN | 0x80,
                    6,
                ];
                b.extend(ext);
                b
            }

            /// Hand-built inputs by class, each with the kind it is read as.
            pub fn classes() -> Vec<(&'static str, &'static str, Vec<u8>)> {
                let mut out = Vec::new();
                // A QoS value, a node id and a budget at the edges of their widths.
                for v in [0xffu64, 0x100, 0x1ff, 1 << 40] {
                    out.push(("qos", "push", push_with(&[ext64(1, v)])));
                }
                for v in [0xffffu64, 0x10000, 0x12345] {
                    out.push(("node id", "push", push_with(&[ext64(3, v)])));
                }
                for v in [1u64, u32::MAX as u64, 0, 1 << 32, (1 << 32) + 1] {
                    out.push(("budget", "request", request_with(&[ext64(5, v)])));
                }
                // The target of a request: three values and one past them, read alike.
                for v in [0u64, 2, 3] {
                    out.push(("target", "request", request_with(&[ext64(4, v)])));
                }
                // An extension named twice.
                out.push(("duplicate", "push", push_with(&[ext64(1, 1), ext64(1, 2)])));
                out.push((
                    "duplicate",
                    "push",
                    push_with(&[ext64(3, 1), ext64(1, 2), ext64(3, 4)]),
                ));
                out.push((
                    "duplicate",
                    "request",
                    request_with(&[ext64(5, 1), ext64(5, 2)]),
                ));
                out.push((
                    "duplicate",
                    "request",
                    request_with(&[ext64(1, 1), ext64(4, 1), ext64(1, 3)]),
                ));
                let we = |flags: u8, rest: &[u8]| {
                    let mut body = vec![flags];
                    body.extend_from_slice(rest);
                    zbuf_ext(0x0f, body.len(), &body)
                };
                let dup = [with_more(we(1, &[5, b'a'])), we(1, &[6, b'b'])];
                out.push((
                    "duplicate",
                    "declare body",
                    undeclare_token_with([dup[0].clone(), dup[1].clone()].concat()),
                ));
                // A length in the header of an extension that is not the length of its fields.
                for delta in [-1i64, 1, 5] {
                    let body = ts_body();
                    let len = (body.len() as i64 + delta) as usize;
                    out.push((
                        "ext length",
                        "push",
                        push_with(&[zbuf_ext(2, len, &body)]),
                    ));
                }
                let stack = enc(|w| {
                    let t: $p::network::push::ext::TsStackType = tsstack(1);
                    Zenoh080.write(w, (&t, false))
                });
                let body = stack[2..].to_vec();
                for delta in [-1i64, 0, 1] {
                    let len = (body.len() as i64 + delta) as usize;
                    out.push((
                        "ext length",
                        "push",
                        push_with(&[zbuf_ext(7, len, &body)]),
                    ));
                }
                // A timestamp stack of the most interceptions a stack may hold and of more.
                for count in [255usize, 256, 257] {
                    let mut body = vec![1u8];
                    body.extend(enc(|w| Zenoh080.write(w, count)));
                    for _ in 0..count {
                        body.extend_from_slice(&[1, 0]);
                    }
                    out.push((
                        "ts stack count",
                        "push",
                        push_with(&[zbuf_ext(7, body.len(), &body)]),
                    ));
                }
                // A queryable's distance at the edge of sixteen bits.
                let qinfo = |v: u64| {
                    let mut b = vec![$p::network::declare::id::D_QUERYABLE | 0x80, 4, 0];
                    b.extend(enc(|w| {
                        Zenoh080.write(
                            w,
                            (
                                &$p::network::declare::queryable::ext::QueryableInfo::new(v),
                                false,
                            ),
                        )
                    }));
                    b
                };
                for v in [65535u64 << 8, 65536 << 8, (1 << 8) | 1, 0xfe] {
                    out.push(("distance", "declare body", qinfo(v)));
                }
                // The extension of an undeclaration that carries a key expression.
                out.push((
                    "wire expr ext",
                    "declare body",
                    undeclare_token_with(we(1, &[5, b'a', b'b'])),
                ));
                out.push((
                    "wire expr ext",
                    "declare body",
                    undeclare_token_with(we(0, &[5])),
                ));
                out.push((
                    "wire expr ext",
                    "declare body",
                    undeclare_token_with(we(0, &[5, 0x77])),
                ));
                out.push((
                    "wire expr ext",
                    "declare body",
                    undeclare_token_with(we(1, &[5])),
                ));
                out.push((
                    "wire expr ext",
                    "declare body",
                    undeclare_token_with(we(0, &[0x80, 0x80, 0x04])),
                ));
                // An unknown extension that may be skipped and one that may not, in a push.
                let unk = |mandatory: bool| {
                    enc(|w| {
                        Zenoh080.write(
                            w,
                            (
                                &$p::common::ZExtUnknown::new(0x0a, mandatory, ZExtBody::Unit),
                                false,
                            ),
                        )
                    })
                };
                out.push(("unknown optional", "push", push_with(&[unk(false)])));
                out.push(("unknown mandatory", "push", push_with(&[unk(true)])));
                // An interest that sets the name or mapping flag with no key expression.
                let interest_bytes = |opts: u8| vec![$p::network::id::INTEREST | (0b01 << 5), 7, opts];
                for opts in [0x01u8, 0x21, 0x41, 0x61, 0x10 | 0x01 | 0x20 | 0x40] {
                    out.push(("stray interest flags", "interest", interest_bytes(opts)));
                }
                out
            }

            /// A write of a request with a timeout past what sixty-four bits of milliseconds hold.
            pub fn long_timeout_write() -> String {
                let mut m = request(0, 0, 1);
                m.ext_timeout = Some(Duration::from_secs(u64::MAX));
                let b = enc(|w| Zenoh080.write(w, &m));
                if b.ends_with(b"ERR") {
                    "err".to_string()
                } else {
                    format!("ok {}", hex(&b))
                }
            }

            /// The text of an iteration over the encodings of several messages and garbage.
            pub fn iteration_texts() -> Vec<String> {
                let mut out = Vec::new();
                let msgs: Vec<Vec<u8>> = vec![
                    enc(|w| {
                        let n: NetworkMessage = NetworkBody::Push(push(15, 1, 0)).into();
                        Zenoh080.write(w, &n)
                    }),
                    enc(|w| {
                        let n: NetworkMessage = NetworkBody::Request(request(127, 1, 9)).into();
                        Zenoh080.write(w, &n)
                    }),
                    enc(|w| {
                        let n: NetworkMessage = NetworkBody::Declare(declare(7, true, 20)).into();
                        Zenoh080.write(w, &n)
                    }),
                ];
                for take in 0..=3 {
                    for tail in [&b""[..], &[0xff, 0xff][..], &[0x1d][..], &[0x1d, 0x00, 0x01][..]] {
                        let mut bytes: Vec<u8> = msgs.iter().take(take).flatten().copied().collect();
                        bytes.extend_from_slice(tail);
                        out.push(iterate(&bytes));
                    }
                }
                // A run cut at every byte.
                let all: Vec<u8> = msgs.iter().flatten().copied().collect();
                for cut in 0..all.len() {
                    out.push(iterate(&all[..cut]));
                }
                let _ = ZSlice::empty();
                out
            }
        }
    };
}

network_cases!(up, up_codec, up_protocol, up_buffers);
network_cases!(wz, wz_codec, wz_protocol, wz_buffers);

fn mutations(corpus: &[(&'static str, String, Vec<u8>)]) -> Vec<(&'static str, String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rng = StdRng::seed_from_u64(0x2E41);
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
fn both_crates_write_every_network_message_to_the_same_bytes() {
    let (u, w) = (up::corpus(), wz::corpus());
    assert!(u.len() > 2000, "{}", u.len());
    assert_eq!(u.len(), w.len());
    let bad: Vec<_> = u.iter().zip(&w).filter(|(a, b)| a != b).take(5).collect();
    assert!(bad.is_empty(), "{bad:#?}");
    assert!(u.iter().all(|(_, _, b)| !b.ends_with(b"ERR")));
    let distinct: std::collections::BTreeSet<_> = u.iter().map(|(_, _, b)| b.clone()).collect();
    assert!(distinct.len() > 1800, "{}", distinct.len());
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
    // The iterator over runs of messages, cut and followed by garbage.
    let (a, b) = (up::iteration_texts(), wz::iteration_texts());
    assert_eq!(a, b);
    assert!(a.len() > 60, "{}", a.len());
    let distinct: std::collections::BTreeSet<_> = a.iter().collect();
    assert!(distinct.len() > 10, "{}", distinct.len());
}

#[test]
fn both_crates_read_every_cut_and_changed_encoding_alike_but_for_the_classes() {
    let corpus = up::corpus();
    let mut inputs = mutations(&corpus);
    // The encodings alone are read as every kind of message.
    for (_, name, bytes) in corpus.iter().step_by(3) {
        for kind in KINDS {
            inputs.push((kind, format!("{name} as {kind}"), bytes.clone()));
        }
    }
    assert!(inputs.len() > 150_000, "{}", inputs.len());
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
    assert!(equal > 140_000 && ok > 30_000, "{equal} {ok}");
    assert!(refused > 0, "{refused}");
}

#[test]
fn both_crates_differ_on_the_classes_and_on_nothing_beside_them() {
    let (u, w) = (up::classes(), wz::classes());
    assert_eq!(u, w);
    let mut seen = std::collections::BTreeMap::<&str, (usize, usize)>::new();
    let mut details = Vec::new();
    for (class, kind, bytes) in &u {
        let (a, b) = (up::read_as(kind, bytes), wz::read_as(kind, bytes));
        let entry = seen.entry(class).or_default();
        if *class == "wire expr ext" {
            details.push((
                hex(bytes),
                a.0.chars().take(70).collect::<String>(),
                b.0.chars().take(30).collect::<String>(),
            ));
        }
        if a.0 == b.0 {
            entry.0 += 1;
            continue;
        }
        entry.1 += 1;
        assert!(
            a.0.starts_with("ok") && a.1 == Some(false) && b.0.starts_with("err"),
            "{class} {kind} {}\nup {a:?}\nwz {b:?}",
            hex(bytes)
        );
    }
    // Each class has inputs on which they differ and inputs at its edge on which they do not.
    assert_eq!(seen["qos"], (1, 3), "{seen:?}");
    assert_eq!(seen["node id"], (1, 2), "{seen:?}");
    assert_eq!(seen["budget"], (2, 3), "{seen:?}");
    // A target of 3 is past the last: both refuse it.
    assert_eq!(seen["target"], (3, 0), "{seen:?}");
    assert_eq!(seen["duplicate"], (0, 5), "{seen:?}");
    assert_eq!(seen["ext length"], (1, 5), "{seen:?}");
    assert_eq!(seen["distance"], (3, 1), "{seen:?}");
    // Two valid ones and a flag with no suffix behind it (upstream's read of nothing refuses it
    // too) are read alike; a leftover byte and a scope past sixteen bits are not.
    assert_eq!(seen["wire expr ext"], (3, 2), "{seen:?} {details:#?}");
    // A stack of 255 interceptions is read, one of 256 or 257 is refused, by both.
    assert_eq!(seen["ts stack count"], (3, 0), "{seen:?}");
    let counts: Vec<_> = u
        .iter()
        .filter(|(class, _, _)| *class == "ts stack count")
        .map(|(_, kind, bytes)| up::read_as(kind, bytes).0.starts_with("ok"))
        .collect();
    assert_eq!(counts, [true, false, false]);
    assert_eq!(seen["unknown optional"], (1, 0), "{seen:?}");
    assert_eq!(seen["unknown mandatory"], (1, 0), "{seen:?}");
    assert_eq!(seen["stray interest flags"], (5, 0), "{seen:?}");
    // The mandatory unknown extension is refused by both, the optional one read by both.
    for (class, kind, bytes) in &u {
        let a = up::read_as(kind, bytes);
        match *class {
            "unknown optional" => assert!(a.0.starts_with("ok"), "{}", a.0),
            "unknown mandatory" => assert!(a.0.starts_with("err"), "{}", a.0),
            _ => {}
        }
    }
    // An interest with the name or mapping flag and no key expression is read alike and written
    // back differently: upstream as it came in, wz as its definition has it.
    let (mut kept, mut cleared) = (0, 0);
    for (class, kind, bytes) in &u {
        if *class == "stray interest flags" {
            let (a, b) = (up::read_as(kind, bytes), wz::read_as(kind, bytes));
            assert_eq!(a.0, b.0);
            kept += (a.1 == Some(true)) as usize;
            cleared += (b.1 == Some(false)) as usize;
        }
    }
    // Four of the five inputs are read (the fifth sets the restricted flag with no key expression
    // behind it and both refuse it): upstream writes all four back as read, wz the three that set a
    // flag it has no use for without it.
    assert_eq!((kept, cleared), (4, 3));
    // A timeout of more milliseconds than sixty-four bits hold: upstream writes it cut, wz refuses.
    let (a, b) = (up::long_timeout_write(), wz::long_timeout_write());
    assert!(a.starts_with("ok") && b == "err", "{a} {b}");
}

/// The control: the comparison is on text, so a message that differs gives a row that differs.
#[test]
fn the_comparison_sees_a_message_that_differs() {
    let c = wz::corpus();
    let get = |n: &str| c.iter().find(|(_, name, _)| name == n).unwrap().2.clone();
    assert_ne!(get("push 0 0 0"), get("push 1 0 0"));
    assert_ne!(get("request 0 0 0"), get("request 0 0 4294967295"));
    assert_ne!(
        wz::read_as("push", &get("push 0 0 0")).0,
        wz::read_as("push", &get("push 0 1 0")).0
    );
    assert_ne!(wz::iteration_texts()[0], wz::iteration_texts()[4]);
}
