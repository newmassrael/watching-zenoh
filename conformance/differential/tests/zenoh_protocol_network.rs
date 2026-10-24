// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-protocol`, the `network` module (what is declared, pushed, requested and answered, and
//! the extensions those carry): upstream's crate (`up_protocol`) and wz's (`wz_protocol`) given
//! the same inputs, outputs equal.
//!
//! The QoS extension is driven over every one of its 256 raw values, every priority, congestion
//! control and express flag it is built from and every setter applied to every starting value;
//! the interest options over every byte, their operators and their hash; the options an interest
//! reports over every options byte and every key expression it may or may not carry; each kind of
//! network message, with every field set, through every question the `NetworkMessageExt` trait
//! asks; and the ids, flags and extension ids of every message. What each returns is compared as
//! text (the `Debug` and `Display` of a value, the message of a failure without the place it was
//! raised at).
//!
//! The `test` feature's random constructors are held by SHAPE: the set of classes of value that
//! 20 000 draws reach is the same for both crates, a composite being reported by the classes of
//! each of its fields and a length by its first value, its last and the middle. That includes what
//! upstream's constructors never make (a network message that is an interest, an interest option
//! that is a queryable, an interest with a key expression), which wz's do not make either.
//!
//! The crates are built without `shared-memory`; that arm is held by the surface gate.
//!
//! One place is not compared, because upstream is wrong in it and wz follows the definition: an
//! interest with no key expression reports, in `Interest::options`, the name and mapping flags it
//! was given, where its definition has them at 0 when there is no key expression. It is shown on
//! upstream's crate and held to the definition on wz's.

use std::fmt::Display;

macro_rules! network_cases {
    ($name:ident, $p:ident, $b:ident) => {
        mod $name {
            use std::{
                borrow::Cow,
                collections::{hash_map::DefaultHasher, BTreeSet},
                hash::{Hash, Hasher},
                num::NonZeroU32,
                time::Duration,
            };

            use $b::{buffer::Buffer, ZBuf};
            use $p::{
                common::ZExtBody,
                core::{CongestionControl, Encoding, Priority, Reliability, WireExpr, ZenohIdProto},
                network::{
                    declare::{self, DeclareBody},
                    interest::{self, InterestMode, InterestOptions},
                    oam, push, request, response,
                    timestamp_stack::{self, Interception, TimestampStack},
                    Declare, DeclareFinal, DeclareKeyExpr, DeclareQueryable, DeclareSubscriber,
                    DeclareToken, Interest, Mapping, NetworkBody, NetworkMessage,
                    NetworkMessageExt, Oam, Push, Request, Response, ResponseFinal,
                    UndeclareKeyExpr, UndeclareQueryable, UndeclareSubscriber, UndeclareToken,
                },
                zenoh::{
                    self, ConsolidationMode, Del, Err as ErrMessage, Put, PushBody, Query, Reply,
                    RequestBody, ResponseBody,
                },
            };

            use super::text;

            type Qos = push::ext::QoSType;

            fn bytes(fill: u8, n: usize) -> ZBuf {
                ZBuf::from(vec![fill; n])
            }

            fn zid() -> ZenohIdProto {
                ZenohIdProto::try_from([1u8, 2, 3, 4].as_slice()).unwrap()
            }

            fn we(scope: u16, suffix: &'static str, mapping: Mapping) -> WireExpr<'static> {
                WireExpr {
                    scope,
                    suffix: Cow::Borrowed(suffix),
                    mapping,
                }
            }

            fn stamp() -> uhlc::Timestamp {
                uhlc::Timestamp::new(
                    uhlc::NTP64(0x1234_5678_9ABC_DEF0),
                    uhlc::ID::try_from([1u8, 2, 3]).unwrap(),
                )
            }

            fn tstamp() -> push::ext::TimestampType {
                push::ext::TimestampType { timestamp: stamp() }
            }

            fn nodeid(node_id: u16) -> push::ext::NodeIdType {
                push::ext::NodeIdType { node_id }
            }

            fn tsstack() -> push::ext::TsStackType {
                push::ext::TsStackType {
                    ts_stack: TimestampStack {
                        conf_flags: 7,
                        stack: vec![
                            Interception {
                                flags: timestamp_stack::interception_point::SEND,
                                timestamp: vec![1, 2, 3],
                            },
                            Interception {
                                flags: timestamp_stack::interception_point::RECEIVE
                                    | timestamp_stack::interception_point::IS_CUSTOM_TS,
                                timestamp: vec![],
                            },
                        ],
                    },
                }
            }

            fn raw(q: Qos) -> u64 {
                push::ext::QoS::from(q).value
            }

            fn qos_from(raw: u64) -> Qos {
                Qos::from(push::ext::QoS::new(raw))
            }

            fn priorities() -> Vec<Priority> {
                (0..8u8).map(|v| Priority::try_from(v).unwrap()).collect()
            }

            fn controls() -> [CongestionControl; 3] {
                [
                    CongestionControl::Drop,
                    CongestionControl::Block,
                    CongestionControl::BlockFirst,
                ]
            }

            /// The QoS extension over every raw value, every way to build one and every setter
            /// applied to every starting value.
            pub fn qos_table() -> Vec<String> {
                let mut out = Vec::new();
                for v in 0..=255u64 {
                    let q = qos_from(v);
                    out.push(format!(
                        "{v}: {q:?} {:?} {:?} {} {}",
                        q.get_priority(),
                        q.get_congestion_control(),
                        q.is_express(),
                        raw(q)
                    ));
                }
                for p in priorities() {
                    for c in controls() {
                        for e in [false, true] {
                            let q = Qos::new(p, c, e);
                            out.push(format!("new {p:?} {c:?} {e}: {q:?} {}", raw(q)));
                        }
                    }
                }
                for v in 0..=255u64 {
                    for p in priorities() {
                        let mut q = qos_from(v);
                        q.set_priority(p);
                        out.push(format!("{v} set_priority {p:?}: {}", raw(q)));
                    }
                    for c in controls() {
                        let mut q = qos_from(v);
                        q.set_congestion_control(c);
                        out.push(format!("{v} set_congestion_control {c:?}: {}", raw(q)));
                    }
                    for e in [false, true] {
                        let mut q = qos_from(v);
                        q.set_is_express(e);
                        out.push(format!("{v} set_is_express {e}: {}", raw(q)));
                    }
                }
                for (label, q) in [
                    ("DEFAULT", Qos::DEFAULT),
                    ("DECLARE", Qos::DECLARE),
                    ("INTEREST", Qos::INTEREST),
                    ("PUSH", Qos::PUSH),
                    ("REQUEST", Qos::REQUEST),
                    ("OAM", Qos::OAM),
                    ("default()", Qos::default()),
                ] {
                    out.push(format!("{label}: {q:?} {}", raw(q)));
                }
                out
            }

            /// The other extension types: the node id (and what a value wider than it becomes),
            /// the timestamp and the entity id.
            pub fn other_extensions() -> Vec<String> {
                let mut out = Vec::new();
                for v in [0u64, 1, 0xFFFF, 0x1_0000, 0x1_2345, u64::MAX] {
                    let n: push::ext::NodeIdType = push::ext::NodeId::new(v).into();
                    out.push(format!(
                        "node id {v:#x}: {n:?} {} {}",
                        n.node_id,
                        push::ext::NodeId::from(n).value
                    ));
                }
                out.push(format!(
                    "node id DEFAULT {:?} {:?}",
                    push::ext::NodeIdType::DEFAULT,
                    push::ext::NodeIdType::default()
                ));
                out.push(format!(
                    "timestamp {:?} {}",
                    tstamp(),
                    tstamp() == push::ext::TimestampType { timestamp: stamp() }
                ));
                out.push(format!(
                    "entity {:?}",
                    response::ext::ResponderIdType {
                        zid: zid(),
                        eid: 77
                    }
                ));
                out.push(format!("ts stack {:?}", tsstack()));
                out.push(format!(
                    "queryable info {:?} {:?} {:?}",
                    declare::queryable::ext::QueryableInfoType::DEFAULT,
                    declare::queryable::ext::QueryableInfoType::default(),
                    declare::queryable::ext::QueryableInfoType {
                        complete: true,
                        distance: 9
                    }
                ));
                out.push(format!(
                    "wire expr ext {:?} {} {}",
                    declare::common::ext::WireExprType::null(),
                    declare::common::ext::WireExprType::null().is_null(),
                    declare::common::ext::WireExprType {
                        wire_expr: we(1, "", Mapping::Receiver)
                    }
                    .is_null()
                ));
                out
            }

            /// The ids of the messages, their flags and the ids of their extensions.
            pub fn network_constants() -> Vec<String> {
                use $p::network::id;
                vec![
                    format!(
                        "id {} {} {} {} {} {} {}",
                        id::OAM,
                        id::DECLARE,
                        id::PUSH,
                        id::REQUEST,
                        id::RESPONSE,
                        id::RESPONSE_FINAL,
                        id::INTEREST
                    ),
                    format!(
                        "flags push {} {} {} | request {} {} {} | response {} {} {} | interest {} \
                         | oam {} {} {}",
                        push::flag::N,
                        push::flag::M,
                        push::flag::Z,
                        request::flag::N,
                        request::flag::M,
                        request::flag::Z,
                        response::flag::N,
                        response::flag::M,
                        response::flag::Z,
                        interest::flag::Z,
                        oam::flag::T,
                        oam::flag::Z,
                        oam::id::OAM_LINKSTATE
                    ),
                    format!(
                        "declare flags {} {} | keyexpr {} {} | subscriber {} {} {} | queryable {} \
                         {} {} {} | token {} {} {}",
                        declare::flag::I,
                        declare::flag::Z,
                        declare::keyexpr::flag::N,
                        declare::keyexpr::flag::Z,
                        declare::subscriber::flag::N,
                        declare::subscriber::flag::M,
                        declare::subscriber::flag::Z,
                        declare::queryable::flag::N,
                        declare::queryable::flag::M,
                        declare::queryable::flag::Z,
                        declare::queryable::ext::flag::C,
                        declare::token::flag::N,
                        declare::token::flag::M,
                        declare::token::flag::Z
                    ),
                    format!(
                        "declare ids {} {} {} {} {} {} {} {} {}",
                        declare::id::D_KEYEXPR,
                        declare::id::U_KEYEXPR,
                        declare::id::D_SUBSCRIBER,
                        declare::id::U_SUBSCRIBER,
                        declare::id::D_QUERYABLE,
                        declare::id::U_QUERYABLE,
                        declare::id::D_TOKEN,
                        declare::id::U_TOKEN,
                        declare::id::D_FINAL
                    ),
                    format!(
                        "push ext {} {} {} {} | request ext {} {} {} {} {} {} {} | response ext {} \
                         {} {} {}",
                        push::ext::QoS::ID,
                        push::ext::Timestamp::ID,
                        push::ext::NodeId::ID,
                        push::ext::TsStack::ID,
                        request::ext::QoS::ID,
                        request::ext::Timestamp::ID,
                        request::ext::NodeId::ID,
                        request::ext::Target::ID,
                        request::ext::Budget::ID,
                        request::ext::Timeout::ID,
                        request::ext::TsStack::ID,
                        response::ext::QoS::ID,
                        response::ext::Timestamp::ID,
                        response::ext::ResponderId::ID,
                        response::ext::TsStack::ID
                    ),
                    format!(
                        "interest ext {} {} {} | declare ext {} {} {} | oam ext {} {} | declare \
                         wire expr {} | queryable info {}",
                        interest::ext::QoS::ID,
                        interest::ext::Timestamp::ID,
                        interest::ext::NodeId::ID,
                        declare::ext::QoS::ID,
                        declare::ext::Timestamp::ID,
                        declare::ext::NodeId::ID,
                        oam::ext::QoS::ID,
                        oam::ext::Timestamp::ID,
                        declare::common::ext::WireExprExt::ID,
                        declare::queryable::ext::QueryableInfo::ID
                    ),
                    format!(
                        "timestamp stack {} {} {} {} {}",
                        timestamp_stack::MAX_STACK_SIZE,
                        timestamp_stack::interception_point::SEND,
                        timestamp_stack::interception_point::ROUTE,
                        timestamp_stack::interception_point::RECEIVE,
                        timestamp_stack::interception_point::IS_CUSTOM_TS
                    ),
                ]
            }

            fn hash_of(o: &InterestOptions) -> u64 {
                let mut h = DefaultHasher::new();
                o.hash(&mut h);
                h.finish()
            }

            /// The interest options over every byte, the constants, the operators over a spread of
            /// pairs, equality and hash.
            pub fn interest_options() -> Vec<String> {
                let mut out = Vec::new();
                for v in 0..=255u8 {
                    let o = InterestOptions::from(v);
                    out.push(format!(
                        "{v}: k={} s={} q={} t={} r={} n={} m={} a={} | {o:?} | {o} | hash {}",
                        o.keyexprs(),
                        o.subscribers(),
                        o.queryables(),
                        o.tokens(),
                        o.restricted(),
                        o.named(),
                        o.mapping(),
                        o.aggregate(),
                        hash_of(&o)
                    ));
                }
                for (label, o) in [
                    ("KEYEXPRS", InterestOptions::KEYEXPRS),
                    ("SUBSCRIBERS", InterestOptions::SUBSCRIBERS),
                    ("QUERYABLES", InterestOptions::QUERYABLES),
                    ("TOKENS", InterestOptions::TOKENS),
                    ("AGGREGATE", InterestOptions::AGGREGATE),
                    ("ALL", InterestOptions::ALL),
                    ("empty", InterestOptions::empty()),
                ] {
                    out.push(format!(
                        "{label}: {o:?} {o} k={} s={} q={} t={} a={}",
                        o.keyexprs(),
                        o.subscribers(),
                        o.queryables(),
                        o.tokens(),
                        o.aggregate()
                    ));
                }
                const SPREAD: [u8; 12] = [0, 1, 2, 4, 8, 16, 32, 64, 128, 0x0F, 0x70, 0xFF];
                for a in SPREAD {
                    for b in SPREAD {
                        let (x, y) = (InterestOptions::from(a), InterestOptions::from(b));
                        let mut added = x;
                        added += y;
                        let mut subtracted = x;
                        subtracted -= y;
                        out.push(format!(
                            "{a}/{b}: {:?} {:?} | {:?} {:?} | eq {} | hash eq {}",
                            x + y,
                            x - y,
                            added,
                            subtracted,
                            x == y,
                            hash_of(&x) == hash_of(&y)
                        ));
                    }
                }
                out
            }

            /// What an interest reports as its options, for every options byte and every key
            /// expression it may carry. `unspecified` adds the cases the definition does not
            /// give an answer to in upstream's code: the name or mapping flag set with no key
            /// expression.
            pub fn interest_flags(unspecified: bool) -> Vec<String> {
                let exprs: [(&str, Option<WireExpr<'static>>); 5] = [
                    ("none", None),
                    ("plain", Some(we(0, "", Mapping::Receiver))),
                    ("suffix", Some(we(0, "a", Mapping::Receiver))),
                    ("sender", Some(we(0, "", Mapping::Sender))),
                    ("both", Some(we(0, "a", Mapping::Sender))),
                ];
                let mut out = Vec::new();
                for v in 0..=255u8 {
                    for (label, expr) in &exprs {
                        if !unspecified && expr.is_none() && v & 0b0110_0000 != 0 {
                            continue;
                        }
                        let i = Interest {
                            id: 1,
                            mode: InterestMode::Current,
                            options: InterestOptions::from(v),
                            wire_expr: expr.clone(),
                            ext_qos: Qos::DEFAULT,
                            ext_tstamp: None,
                            ext_nodeid: push::ext::NodeIdType::DEFAULT,
                        };
                        out.push(format!("{v:08b} {label}: {:08b}", i.options()));
                    }
                }
                out
            }

            pub fn interest_options_of(options: u8, with_key_expr: bool) -> u8 {
                Interest {
                    id: 1,
                    mode: InterestMode::Current,
                    options: InterestOptions::from(options),
                    wire_expr: with_key_expr.then(|| we(0, "", Mapping::Receiver)),
                    ext_qos: Qos::DEFAULT,
                    ext_tstamp: None,
                    ext_nodeid: push::ext::NodeIdType::DEFAULT,
                }
                .options()
            }

            fn put() -> Put {
                Put {
                    timestamp: Some(stamp()),
                    payload: bytes(0xAB, 5),
                    ext_attachment: Some(zenoh::put::ext::AttachmentType {
                        buffer: bytes(1, 3),
                    }),
                    ..Put::default()
                }
            }

            fn query() -> Query {
                Query {
                    parameters: "a=1".to_string(),
                    consolidation: ConsolidationMode::Latest,
                    ext_body: Some(zenoh::query::ext::QueryBodyType {
                        encoding: Encoding::default(),
                        payload: bytes(3, 4),
                    }),
                    ext_attachment: Some(zenoh::query::ext::AttachmentType {
                        buffer: bytes(4, 2),
                    }),
                    ..Query::default()
                }
            }

            /// One network message of each kind (the declaration of each kind among them), with
            /// every field set and a QoS that is none of the defaults.
            fn messages() -> Vec<NetworkMessage> {
                let q = Qos::new(Priority::InteractiveHigh, CongestionControl::Block, true);
                let q2 = Qos::new(Priority::Background, CongestionControl::BlockFirst, false);
                let q3 = Qos::new(Priority::Control, CongestionControl::Drop, false);
                let expr = || we(5, "a/b", Mapping::Sender);
                let info = declare::queryable::ext::QueryableInfoType {
                    complete: true,
                    distance: 7,
                };
                let wext = || declare::common::ext::WireExprType {
                    wire_expr: we(6, "c", Mapping::Receiver),
                };
                let decl = |body: DeclareBody, qos: Qos| Declare {
                    interest_id: Some(11),
                    ext_qos: qos,
                    ext_tstamp: Some(tstamp()),
                    ext_nodeid: nodeid(3),
                    body,
                };
                let mut all = vec![
                    NetworkBody::Push(Push {
                        wire_expr: expr(),
                        ext_qos: q,
                        ext_tstamp: Some(tstamp()),
                        ext_nodeid: nodeid(2),
                        ext_ts_stack: Some(tsstack()),
                        payload: PushBody::Put(put()),
                    }),
                    NetworkBody::Push(Push {
                        wire_expr: expr(),
                        ext_qos: q2,
                        ext_tstamp: None,
                        ext_nodeid: nodeid(0),
                        ext_ts_stack: None,
                        payload: PushBody::Del(Del {
                            ext_attachment: Some(zenoh::del::ext::AttachmentType {
                                buffer: bytes(9, 6),
                            }),
                            ..Del::default()
                        }),
                    }),
                    NetworkBody::Request(Request {
                        id: 77,
                        wire_expr: expr(),
                        ext_qos: q,
                        ext_tstamp: Some(tstamp()),
                        ext_nodeid: nodeid(1),
                        ext_target: request::ext::QueryTarget::AllComplete,
                        ext_budget: NonZeroU32::new(5),
                        ext_timeout: Some(Duration::from_millis(1500)),
                        ext_ts_stack: Some(tsstack()),
                        payload: RequestBody::Query(query()),
                    }),
                    NetworkBody::Response(Response {
                        rid: 78,
                        wire_expr: expr(),
                        payload: ResponseBody::Reply(Reply {
                            consolidation: ConsolidationMode::Monotonic,
                            ext_unknown: vec![],
                            payload: PushBody::Put(put()),
                        }),
                        ext_qos: q2,
                        ext_tstamp: Some(tstamp()),
                        ext_respid: Some(response::ext::ResponderIdType {
                            zid: zid(),
                            eid: 5,
                        }),
                        ext_ts_stack: Some(tsstack()),
                    }),
                    NetworkBody::Response(Response {
                        rid: 79,
                        wire_expr: expr(),
                        payload: ResponseBody::Err(ErrMessage {
                            encoding: Encoding::default(),
                            ext_sinfo: None,
                            ext_unknown: vec![],
                            payload: bytes(5, 7),
                        }),
                        ext_qos: q3,
                        ext_tstamp: None,
                        ext_respid: None,
                        ext_ts_stack: None,
                    }),
                    NetworkBody::ResponseFinal(ResponseFinal {
                        rid: 80,
                        ext_qos: q,
                        ext_tstamp: Some(tstamp()),
                    }),
                    NetworkBody::Interest(Interest {
                        id: 12,
                        mode: InterestMode::CurrentFuture,
                        options: InterestOptions::ALL,
                        wire_expr: Some(expr()),
                        ext_qos: q2,
                        ext_tstamp: Some(tstamp()),
                        ext_nodeid: nodeid(4),
                    }),
                    NetworkBody::Interest(Interest {
                        id: 13,
                        mode: InterestMode::Final,
                        options: InterestOptions::empty(),
                        wire_expr: None,
                        ext_qos: q3,
                        ext_tstamp: None,
                        ext_nodeid: nodeid(0),
                    }),
                    NetworkBody::OAM(Oam {
                        id: oam::id::OAM_LINKSTATE,
                        body: ZExtBody::Z64(3),
                        ext_qos: q,
                        ext_tstamp: Some(tstamp()),
                    }),
                ];
                for (n, body) in [
                    DeclareBody::DeclareKeyExpr(DeclareKeyExpr {
                        id: 3,
                        wire_expr: expr(),
                    }),
                    DeclareBody::UndeclareKeyExpr(UndeclareKeyExpr { id: 3 }),
                    DeclareBody::DeclareSubscriber(DeclareSubscriber {
                        id: 4,
                        wire_expr: expr(),
                    }),
                    DeclareBody::UndeclareSubscriber(UndeclareSubscriber {
                        id: 4,
                        ext_wire_expr: wext(),
                    }),
                    DeclareBody::DeclareQueryable(DeclareQueryable {
                        id: 5,
                        wire_expr: expr(),
                        ext_info: info,
                    }),
                    DeclareBody::UndeclareQueryable(UndeclareQueryable {
                        id: 5,
                        ext_wire_expr: wext(),
                    }),
                    DeclareBody::DeclareToken(DeclareToken {
                        id: 6,
                        wire_expr: expr(),
                    }),
                    DeclareBody::UndeclareToken(UndeclareToken {
                        id: 6,
                        ext_wire_expr: declare::common::ext::WireExprType::null(),
                    }),
                    DeclareBody::DeclareFinal(DeclareFinal),
                ]
                .into_iter()
                .enumerate()
                {
                    all.push(NetworkBody::Declare(decl(
                        body,
                        if n % 2 == 0 { q } else { q3 },
                    )));
                }
                let mut out = Vec::new();
                for (i, body) in all.into_iter().enumerate() {
                    out.push(NetworkMessage {
                        body: body.clone(),
                        reliability: if i % 2 == 0 {
                            Reliability::Reliable
                        } else {
                            Reliability::BestEffort
                        },
                    });
                    if i == 0 {
                        out.push(NetworkMessage::from(body));
                    }
                }
                out
            }

            /// Every question of `NetworkMessageExt` put to each message, and the forms a message
            /// is shown and borrowed in.
            pub fn message_table() -> Vec<String> {
                let mut out = Vec::new();
                for m in messages() {
                    let mut owned = m.clone();
                    let shown_mut = format!("{}", owned.as_mut());
                    out.push(format!(
                        "{m} | {m:?} | rel={} express={} cc={:?} drop={} prio={:?} we={:?} size={:?} \
                         | ref {} | mut {shown_mut} | owned eq {} | ref eq {}",
                        m.is_reliable(),
                        m.is_express(),
                        m.congestion_control(),
                        m.is_droppable(),
                        m.priority(),
                        m.wire_expr(),
                        m.payload_size(),
                        NetworkMessageExt::as_ref(&m),
                        NetworkMessageExt::to_owned(&m) == m,
                        NetworkMessageExt::as_ref(&m) == NetworkMessageExt::as_ref(&owned)
                    ));
                }
                out
            }

            /// The messages' own questions put through the references the trait is implemented
            /// for, which a call on the value does not reach.
            pub fn message_through_references() -> Vec<String> {
                let mut out = Vec::new();
                for m in messages() {
                    let by_ref = &m;
                    let mut copy = m.clone();
                    let by_mut = &mut copy;
                    out.push(format!(
                        "{} {} {:?} | {} {} {:?}",
                        by_ref.is_express(),
                        by_ref.is_reliable(),
                        by_ref.priority(),
                        by_mut.is_express(),
                        by_mut.is_reliable(),
                        by_mut.priority()
                    ));
                }
                out
            }

            /// The modes, targets and mappings: values, text, defaults and what a reader of JSON
            /// makes of each name and of names that are none.
            pub fn enumerations() -> Vec<String> {
                let mut out = Vec::new();
                for m in [
                    InterestMode::Final,
                    InterestMode::Current,
                    InterestMode::Future,
                    InterestMode::CurrentFuture,
                ] {
                    out.push(format!("{m:?} future={} current={}", m.is_future(), m.is_current()));
                }
                for t in [
                    request::ext::QueryTarget::BestMatching,
                    request::ext::QueryTarget::All,
                    request::ext::QueryTarget::AllComplete,
                ] {
                    out.push(format!(
                        "{t:?} {} {} {}",
                        t as u8,
                        t == request::ext::QueryTarget::DEFAULT,
                        t == request::ext::QueryTarget::default()
                    ));
                }
                for s in [
                    "\"BestMatching\"",
                    "\"All\"",
                    "\"AllComplete\"",
                    "\"all\"",
                    "\"Complete\"",
                    "0",
                    "1",
                    "null",
                ] {
                    out.push(format!(
                        "{s}: {}",
                        match serde_json::from_str::<request::ext::QueryTarget>(s) {
                            Ok(t) => format!("ok {t:?}"),
                            Err(e) => format!("err {}", text(e)),
                        }
                    ));
                }
                for m in [Mapping::Receiver, Mapping::Sender] {
                    out.push(format!(
                        "{m:?} {} {} {}",
                        m as u8,
                        m == Mapping::DEFAULT,
                        m == Mapping::default()
                    ));
                }
                out.push(format!(
                    "request id {} {}",
                    request::RequestId::MAX,
                    std::mem::size_of::<request::AtomicRequestId>()
                ));
                out.push(format!(
                    "ids {} {}",
                    std::mem::size_of::<interest::InterestId>(),
                    std::mem::size_of::<interest::DeclareRequestId>()
                ));
                out
            }

            /// What the `test` feature's random constructors can make, as the set of classes of
            /// value seen over many draws.
            pub fn rand_shapes() -> Vec<(&'static str, BTreeSet<String>)> {
                const DRAWS: usize = 20_000;
                fn axes<T>(
                    draw: impl Fn() -> T,
                    classes: impl Fn(&T) -> Vec<String>,
                ) -> BTreeSet<String> {
                    let mut set = BTreeSet::new();
                    for _ in 0..DRAWS {
                        set.extend(classes(&draw()));
                    }
                    set
                }
                // A length as its first value, its last, the ones between, or `OUT`: outside.
                fn span(n: usize, first: usize, last: usize) -> &'static str {
                    if n == first {
                        "first"
                    } else if n == last {
                        "last"
                    } else if n < first || n > last {
                        "OUT"
                    } else {
                        "mid"
                    }
                }
                let some = |label: &str, present: bool| format!("{label} {present}");
                let kind = |b: &NetworkBody| {
                    let s: &str = match b {
                        NetworkBody::Push(_) => "push",
                        NetworkBody::Request(_) => "request",
                        NetworkBody::Response(_) => "response",
                        NetworkBody::ResponseFinal(_) => "response final",
                        NetworkBody::Interest(_) => "interest",
                        NetworkBody::Declare(_) => "declare",
                        NetworkBody::OAM(_) => "oam",
                    };
                    s.to_string()
                };
                let declare_kind = |b: &DeclareBody| {
                    let s: &str = match b {
                        DeclareBody::DeclareKeyExpr(_) => "declare key expression",
                        DeclareBody::UndeclareKeyExpr(_) => "undeclare key expression",
                        DeclareBody::DeclareSubscriber(_) => "declare subscriber",
                        DeclareBody::UndeclareSubscriber(_) => "undeclare subscriber",
                        DeclareBody::DeclareQueryable(_) => "declare queryable",
                        DeclareBody::UndeclareQueryable(_) => "undeclare queryable",
                        DeclareBody::DeclareToken(_) => "declare token",
                        DeclareBody::UndeclareToken(_) => "undeclare token",
                        DeclareBody::DeclareFinal(_) => "declare final",
                    };
                    s.to_string()
                };
                let qos_axes = |q: &Qos| {
                    vec![
                        format!("priority {:?}", q.get_priority()),
                        format!("congestion {:?}", q.get_congestion_control()),
                        format!("express {}", q.is_express()),
                        format!("raw high bits {}", raw(*q) >> 6),
                    ]
                };
                vec![
                    ("qos", axes(Qos::rand, |q| qos_axes(q))),
                    (
                        "node id",
                        axes(push::ext::NodeIdType::rand, |n| {
                            vec![format!("high {}", n.node_id >> 15)]
                        }),
                    ),
                    (
                        "timestamp type",
                        axes(push::ext::TimestampType::rand, |t| {
                            vec![format!("time high {}", t.timestamp.get_time().0 >> 63)]
                        }),
                    ),
                    (
                        "entity id",
                        axes(response::ext::ResponderIdType::rand, |e| {
                            vec![
                                format!("eid high {}", e.eid >> 31),
                                format!(
                                    "zid {}",
                                    if e.zid.size() == 16 { "full" } else { "trimmed" }
                                ),
                            ]
                        }),
                    ),
                    (
                        "ts stack",
                        axes(push::ext::TsStackType::rand, |t| {
                            let mut v = vec![
                                format!("conf {}", t.ts_stack.conf_flags),
                                format!("len {}", t.ts_stack.stack.len()),
                            ];
                            for i in &t.ts_stack.stack {
                                v.push(format!(
                                    "point {} custom {} ts {}",
                                    i.flags & 0b111,
                                    i.flags >> 7,
                                    span(i.timestamp.len(), 0, 16)
                                ));
                                v.push(format!("flags ok {}", i.flags & 0b0111_1000 == 0));
                            }
                            v
                        }),
                    ),
                    (
                        "query target",
                        axes(request::ext::QueryTarget::rand, |t| vec![format!("{t:?}")]),
                    ),
                    (
                        "interest mode",
                        axes(InterestMode::rand, |m| vec![format!("{m:?}")]),
                    ),
                    (
                        "interest options",
                        axes(InterestOptions::rand, |o| {
                            vec![
                                some("keyexprs", o.keyexprs()),
                                some("subscribers", o.subscribers()),
                                some("queryables", o.queryables()),
                                some("tokens", o.tokens()),
                                some("aggregate", o.aggregate()),
                                some("restricted", o.restricted()),
                                some("named", o.named()),
                                some("mapping", o.mapping()),
                            ]
                        }),
                    ),
                    (
                        "interest",
                        axes(Interest::rand, |i| {
                            vec![
                                format!("mode {:?}", i.mode),
                                some("key expression", i.wire_expr.is_some()),
                                format!(
                                    "final has no options {}",
                                    i.mode != InterestMode::Final
                                        || i.options == InterestOptions::empty()
                                ),
                                format!("node id high {}", i.ext_nodeid.node_id >> 15),
                                some("timestamp", i.ext_tstamp.is_some()),
                                format!("id high {}", i.id >> 31),
                            ]
                        }),
                    ),
                    (
                        "push",
                        axes(Push::rand, |p| {
                            let mut v = qos_axes(&p.ext_qos);
                            v.push(some("timestamp", p.ext_tstamp.is_some()));
                            v.push(some("ts stack", p.ext_ts_stack.is_some()));
                            v.push(format!("node id high {}", p.ext_nodeid.node_id >> 15));
                            v.push(format!("suffix {}", !p.wire_expr.suffix.is_empty()));
                            v.push(format!(
                                "payload {}",
                                match &p.payload {
                                    PushBody::Put(_) => "put",
                                    PushBody::Del(_) => "del",
                                }
                            ));
                            v
                        }),
                    ),
                    (
                        "request",
                        axes(Request::rand, |r| {
                            vec![
                                format!("id high {}", r.id >> 31),
                                format!("target {:?}", r.ext_target),
                                some("budget", r.ext_budget.is_some()),
                                match r.ext_timeout {
                                    None => "timeout none".to_string(),
                                    Some(t) => format!("timeout high {}", t.as_millis() >> 63),
                                },
                                some("timestamp", r.ext_tstamp.is_some()),
                                some("ts stack", r.ext_ts_stack.is_some()),
                                format!("node id high {}", r.ext_nodeid.node_id >> 15),
                                format!("priority {:?}", r.ext_qos.get_priority()),
                                format!("suffix {}", !r.wire_expr.suffix.is_empty()),
                            ]
                        }),
                    ),
                    (
                        "response",
                        axes(Response::rand, |r| {
                            vec![
                                format!("rid high {}", r.rid >> 31),
                                some("timestamp", r.ext_tstamp.is_some()),
                                some("responder", r.ext_respid.is_some()),
                                some("ts stack", r.ext_ts_stack.is_some()),
                                format!(
                                    "payload {}",
                                    match &r.payload {
                                        ResponseBody::Reply(_) => "reply",
                                        ResponseBody::Err(_) => "err",
                                    }
                                ),
                                format!("express {}", r.ext_qos.is_express()),
                            ]
                        }),
                    ),
                    (
                        "response final",
                        axes(ResponseFinal::rand, |r| {
                            vec![
                                format!("rid high {}", r.rid >> 31),
                                some("timestamp", r.ext_tstamp.is_some()),
                                format!("express {}", r.ext_qos.is_express()),
                            ]
                        }),
                    ),
                    (
                        "oam",
                        axes(Oam::rand, |o| {
                            vec![
                                format!("id high {}", o.id >> 15),
                                kind_of_body(&o.body),
                                some("timestamp", o.ext_tstamp.is_some()),
                            ]
                        }),
                    ),
                    (
                        "declare",
                        axes(Declare::rand, |d| {
                            vec![
                                some("interest id", d.interest_id.is_some()),
                                some("timestamp", d.ext_tstamp.is_some()),
                                declare_kind(&d.body),
                                format!("node id high {}", d.ext_nodeid.node_id >> 15),
                            ]
                        }),
                    ),
                    (
                        "declare body",
                        axes(DeclareBody::rand, |b| vec![declare_kind(b)]),
                    ),
                    (
                        "declare queryable",
                        axes(DeclareQueryable::rand, |q| {
                            vec![
                                some("complete", q.ext_info.complete),
                                format!("distance high {}", q.ext_info.distance >> 15),
                                format!("suffix {}", !q.wire_expr.suffix.is_empty()),
                            ]
                        }),
                    ),
                    (
                        "wire expression extension",
                        axes(declare::common::ext::WireExprType::rand, |w| {
                            vec![some("null", w.is_null())]
                        }),
                    ),
                    (
                        "network message",
                        axes(NetworkMessage::rand, |m| {
                            vec![
                                kind(&m.body),
                                format!("reliability {:?}", m.reliability),
                            ]
                        }),
                    ),
                ]
            }

            fn kind_of_body(b: &ZExtBody) -> String {
                match b {
                    ZExtBody::Unit => "unit".to_string(),
                    ZExtBody::Z64(v) => format!("z64 high {}", v >> 63),
                    ZExtBody::ZBuf(z) => format!(
                        "zbuf {}",
                        if (8..=64).contains(&z.len()) { "in range" } else { "OUT" }
                    ),
                }
            }

            pub fn qos_raw(express: bool) -> u64 {
                raw(Qos::new(Priority::Data, CongestionControl::Drop, express))
            }

            pub fn one_message_text(rid: u32, express: bool) -> String {
                let r = ResponseFinal {
                    rid,
                    ext_qos: Qos::new(Priority::Data, CongestionControl::Drop, express),
                    ext_tstamp: None,
                };
                format!("{r:?}")
            }
        }
    };
}

fn text(e: impl Display) -> String {
    let t = e.to_string();
    t.split(" at ").next().unwrap().to_string()
}

network_cases!(up, up_protocol, up_buffers);
network_cases!(wz, wz_protocol, wz_buffers);

fn same(label: &str, a: Vec<String>, b: Vec<String>) -> usize {
    assert_eq!(a.len(), b.len(), "{label}");
    for (i, (x, y)) in a.iter().zip(&b).enumerate() {
        assert_eq!(x, y, "{label}, line {i}");
    }
    a.len()
}

#[test]
fn both_crates_make_and_read_the_qos_extension_alike() {
    let n = same("qos", up::qos_table(), wz::qos_table());
    // 256 raw values, 48 built, 256 * (8 + 3 + 2) set, 7 constants.
    assert_eq!(n, 256 + 48 + 256 * 13 + 7);
}

#[test]
fn both_crates_build_the_other_extension_types_alike() {
    let n = same(
        "other extensions",
        up::other_extensions(),
        wz::other_extensions(),
    );
    assert_eq!(n, 6 + 1 + 5);
}

#[test]
fn both_crates_name_the_ids_flags_and_extension_ids_of_the_network_messages_alike() {
    let n = same(
        "network constants",
        up::network_constants(),
        wz::network_constants(),
    );
    assert_eq!(n, 7);
    // Not empty: the first line says each of the seven ids.
    assert!(wz::network_constants()[0].starts_with("id 31 30 29 28 27 26 25"));
}

#[test]
fn both_crates_combine_and_read_interest_options_alike() {
    let n = same(
        "interest options",
        up::interest_options(),
        wz::interest_options(),
    );
    assert_eq!(n, 256 + 7 + 12 * 12);
}

#[test]
fn both_crates_report_the_options_of_an_interest_alike() {
    // The cases upstream answers by the definition and the ones that are not in dispute.
    let n = same(
        "interest flags",
        up::interest_flags(false),
        wz::interest_flags(false),
    );
    assert!(n > 1_000);
}

#[test]
fn both_crates_build_and_ask_network_messages_alike() {
    let n = same("messages", up::message_table(), wz::message_table());
    // Seven kinds, the declaration of each of nine kinds, and the one made by `From`.
    assert_eq!(n, 9 + 9 + 1);
    same(
        "references",
        up::message_through_references(),
        wz::message_through_references(),
    );
    same("enumerations", up::enumerations(), wz::enumerations());
    assert_eq!(up::one_message_text(1, true), wz::one_message_text(1, true));
}

#[test]
fn both_crates_make_the_same_shapes_with_the_test_feature_constructors() {
    let (up, wz) = (up::rand_shapes(), wz::rand_shapes());
    assert_eq!(up.len(), wz.len());
    for ((name, a), (_, b)) in up.iter().zip(&wz) {
        assert_eq!(a, b, "random {name}");
        assert!(
            !a.iter().any(|class| class.contains("OUT")),
            "random {name} made a value outside its range: {a:?}"
        );
        // A constructor that only ever made one shape would pass by being constant. One does by
        // upstream's definition: the extension that holds a key expression is drawn from random
        // scopes and suffixes, so it is never the null one.
        assert!(
            a.len() > 1 || *name == "wire expression extension",
            "random {name} made one shape"
        );
    }
    let count = |n: &str| up.iter().find(|(m, _)| *m == n).unwrap().1.len();
    // The classes are many where upstream's draws are: 8 priorities, 3 congestion controls, 2
    // express flags and 4 values of the two high bits; 6 kinds of network message (an interest is
    // not one), and 9 of declaration.
    assert_eq!(count("qos"), 17);
    assert_eq!(count("declare body"), 9);
    assert_eq!(count("interest mode"), 4);
    assert_eq!(count("query target"), 3);
    // An option that is a queryable is never made, nor is a restricted, named or mapped one.
    assert!(!up
        .iter()
        .find(|(m, _)| *m == "interest options")
        .unwrap()
        .1
        .contains("queryables true"));
    // A network message that is an interest is never made: six kinds and two reliabilities.
    let kinds: Vec<_> = up
        .iter()
        .find(|(m, _)| *m == "network message")
        .unwrap()
        .1
        .iter()
        .filter(|c| !c.starts_with("reliability"))
        .collect();
    assert_eq!(kinds.len(), 6);
    assert!(!kinds.iter().any(|c| c.as_str() == "interest"));
}

/// The places upstream is wrong, shown on upstream's crate and held to the definition on wz's.
#[test]
fn the_places_upstream_is_wrong_are_pinned_on_both_sides() {
    // No key expression, and the name flag or the mapping flag given: upstream reports them.
    for flag in [0b0010_0000u8, 0b0100_0000, 0b0110_0000] {
        let given = flag | 0b0000_0010;
        assert_eq!(up::interest_options_of(given, false), given);
        assert_eq!(
            wz::interest_options_of(given, false),
            0b0000_0010,
            "{flag:08b}"
        );
    }
    // With a key expression the two agree, and wz's is the definition: restricted, not named, not
    // mapped, whatever the byte said of the latter two.
    for v in 0..=255u8 {
        let defined = (v | 0b0001_0000) & !0b0110_0000;
        assert_eq!(wz::interest_options_of(v, true), defined, "{v:08b}");
        assert_eq!(up::interest_options_of(v, true), defined, "{v:08b}");
        // Without one, wz clears the three, and upstream only the first.
        let none = v & !0b0111_0000;
        assert_eq!(wz::interest_options_of(v, false), none, "{v:08b}");
        assert_eq!(
            up::interest_options_of(v, false),
            v & !0b0001_0000,
            "{v:08b}"
        );
    }
}

/// The control: the comparison is on text, so an input that changes the answer changes the line.
#[test]
fn the_comparison_sees_a_network_message_that_differs() {
    assert_ne!(wz::one_message_text(1, true), wz::one_message_text(2, true));
    assert_ne!(
        wz::one_message_text(1, true),
        wz::one_message_text(1, false)
    );
    assert_eq!(up::qos_raw(true), wz::qos_raw(true));
    assert_ne!(wz::qos_raw(true), wz::qos_raw(false));
}
