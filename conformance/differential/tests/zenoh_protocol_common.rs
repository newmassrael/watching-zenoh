// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-protocol`, the `common` module (header bits and extensions) and the `zenoh` module (the
//! put, delete, query, reply and error messages): upstream's crate (`up_protocol`) and wz's
//! (`wz_protocol`) given the same inputs, outputs equal.
//!
//! The header bits are driven over every byte, with each flag and every contiguous bitfield; the
//! extensions over a spread of ids that includes the ones whose bits overlap the flags and the
//! encoding, with each kind of body, each conversion between a typed extension and an unknown one
//! and every refusal of it; the messages by their constants, their defaults and a message built
//! with every field set. What each returns is compared as text (the `Debug` of a value, the message
//! of a failure without the place it was raised at).
//!
//! The `test` feature's random constructors are held by SHAPE: the set of classes of value that
//! 20 000 draws reach is the same for both crates, the classes being chosen so that the draws cover
//! them (a length is its first value, its last and the middle).
//!
//! The crates are built without `shared-memory`, so the messages have no shared-memory extension
//! here; that arm is held by the surface gate.
//!
//! One place is not compared, because upstream is wrong in it and wz follows the definition: a value
//! given to `imsg::set_bitfield` that is wider than its mask is OR-ed in whole by upstream, so it
//! sets the bits of the neighbouring fields, and masked by wz. It is shown on upstream's crate and
//! held to the definition on wz's.

use std::fmt::Display;

macro_rules! message_cases {
    ($name:ident, $p:ident, $b:ident) => {
        mod $name {
            use std::collections::BTreeSet;

            use $b::{buffer::Buffer, ZBuf};
            use $p::{
                common::{
                    iext, imsg, ZExtBody, ZExtUnit, ZExtUnknown, ZExtZ64, ZExtZBuf,
                    ZExtZBufHeader,
                },
                core::{Encoding, EntityGlobalIdProto, ZenohIdProto},
                zenoh::{
                    self, del, err, id, put, query, reply, ConsolidationMode, DataInfo, Del,
                    Err as ErrMessage, Put, PushBody, Query, Reply, RequestBody, ResponseBody,
                },
                zextunit, zextz64, zextzbuf,
            };

            use super::text;

            fn bytes(fill: u8, n: usize) -> ZBuf {
                ZBuf::from(vec![fill; n])
            }

            /// The header constants, and for every byte the parts of it and the effect of each flag.
            pub fn header_bits() -> Vec<String> {
                let mut out = vec![format!(
                    "consts {} {} | iext {} {} {} {} {} {} {} {}",
                    imsg::HEADER_BITS,
                    imsg::HEADER_MASK,
                    iext::ID_BITS,
                    iext::ID_MASK,
                    iext::FLAG_M,
                    iext::ENC_UNIT,
                    iext::ENC_Z64,
                    iext::ENC_ZBUF,
                    iext::ENC_MASK,
                    iext::FLAG_Z
                )];
                const FLAGS: [u8; 8] = [0x00, 0x01, 0x10, 0x20, 0x40, 0x80, 0xE0, 0xFF];
                for b in 0..=255u8 {
                    out.push(format!(
                        "{b}: mid={} flags={} eid={} imid={}",
                        imsg::mid(b),
                        imsg::flags(b),
                        iext::eid(b),
                        iext::mid(b)
                    ));
                    for f in FLAGS {
                        out.push(format!(
                            "{b}/{f}: has={} unset={} set={}",
                            imsg::has_flag(b, f),
                            imsg::unset_flag(b, f),
                            imsg::set_flag(b, f)
                        ));
                    }
                }
                const OPTIONS: [u64; 6] = [0, 1, 2, 1 << 63, u64::MAX, 0x0F0F_0F0F_0F0F_0F0F];
                for o in OPTIONS {
                    for f in OPTIONS {
                        out.push(format!("{o:#x}/{f:#x}: {}", imsg::has_option(o, f)));
                    }
                }
                out
            }

            /// `set_bitfield` over every byte, every contiguous mask and every value the mask holds.
            pub fn bitfields() -> Vec<String> {
                let mut out = Vec::new();
                for start in 0..8u32 {
                    for len in 1..=(8 - start) {
                        let mask = (((1u16 << len) - 1) << start) as u8;
                        for byte in 0..=255u8 {
                            for value in 0..=255u8 {
                                if value & !mask == 0 {
                                    out.push(format!(
                                        "{byte:08b}/{mask:08b}/{value:08b}: {:08b}",
                                        imsg::set_bitfield(byte, value, mask)
                                    ));
                                }
                            }
                        }
                    }
                }
                out
            }

            pub fn bitfield(byte: u8, value: u8, mask: u8) -> u8 {
                imsg::set_bitfield(byte, value, mask)
            }

            /// The three kinds of typed extension and the header one, for one id: what each says of
            /// itself, in both mandatory forms, and each transmuted to another id.
            fn extension_row<const ID: u8>(out: &mut Vec<String>) {
                let u = ZExtUnit::<ID>::new();
                let z = ZExtZ64::<ID>::new(0x0123_4567_89AB_CDEF);
                let b = ZExtZBuf::<ID>::new(bytes(1, 3));
                let h = ZExtZBufHeader::<ID>::new(3);
                out.push(format!(
                    "<{ID}> unit {} {} {} {} {:?} {:?} {:?}",
                    ZExtUnit::<ID>::ID,
                    ZExtUnit::<ID>::id(false),
                    ZExtUnit::<ID>::id(true),
                    u.is_mandatory(),
                    u,
                    ZExtUnit::<ID>::default(),
                    u.transmute::<0x21>()
                ));
                out.push(format!(
                    "<{ID}> z64 {} {} {} {} {:?} {:?} {}",
                    ZExtZ64::<ID>::ID,
                    ZExtZ64::<ID>::id(false),
                    ZExtZ64::<ID>::id(true),
                    z.is_mandatory(),
                    z,
                    z.transmute::<0x41>(),
                    z == ZExtZ64::<ID>::new(5)
                ));
                out.push(format!(
                    "<{ID}> zbuf {} {} {} {} {:?} {:?} {}",
                    ZExtZBuf::<ID>::ID,
                    ZExtZBuf::<ID>::id(false),
                    ZExtZBuf::<ID>::id(true),
                    b.is_mandatory(),
                    b,
                    b.clone().transmute::<0x41>(),
                    b == b.clone()
                ));
                out.push(format!(
                    "<{ID}> header {} {} {} {} {:?}",
                    ZExtZBufHeader::<ID>::ID,
                    ZExtZBufHeader::<ID>::id(false),
                    ZExtZBufHeader::<ID>::id(true),
                    h.is_mandatory(),
                    h
                ));
            }

            /// An unknown extension of the id, of ids a bit away from it and of each body, turned
            /// into each typed extension, and each typed extension turned into an unknown one.
            fn conversion_row<const ID: u8>(out: &mut Vec<String>) {
                let body = |k: u8| match k {
                    0 => ZExtBody::Unit,
                    1 => ZExtBody::Z64(7),
                    _ => ZExtBody::ZBuf(bytes(4, 2)),
                };
                for id in [ID, ID ^ 1, ID ^ 0x10, ID ^ 0x20, ID ^ 0x40] {
                    for k in 0..3u8 {
                        let u = ZExtUnknown {
                            id,
                            body: body(k),
                        };
                        out.push(format!(
                            "<{ID}> {u:?}: unit {:?} z64 {:?} zbuf {:?}",
                            ZExtUnit::<ID>::try_from(u.clone()),
                            ZExtZ64::<ID>::try_from(u.clone()),
                            ZExtZBuf::<ID>::try_from(u.clone())
                        ));
                    }
                }
                out.push(format!(
                    "<{ID}> from {:?} {:?} {:?}",
                    ZExtUnknown::from(ZExtUnit::<ID>::new()),
                    ZExtUnknown::from(ZExtZ64::<ID>::new(5)),
                    ZExtUnknown::from(ZExtZBuf::<ID>::new(bytes(9, 1)))
                ));
            }

            pub fn typed_extensions() -> Vec<String> {
                let mut out = Vec::new();
                extension_row::<0x00>(&mut out);
                extension_row::<0x01>(&mut out);
                extension_row::<0x03>(&mut out);
                extension_row::<0x0F>(&mut out);
                extension_row::<0x10>(&mut out);
                extension_row::<0x11>(&mut out);
                extension_row::<0x21>(&mut out);
                extension_row::<0x31>(&mut out);
                extension_row::<0x45>(&mut out);
                extension_row::<0x5F>(&mut out);
                extension_row::<0x7F>(&mut out);
                extension_row::<0x80>(&mut out);
                extension_row::<0xFF>(&mut out);
                out
            }

            pub fn conversions() -> Vec<String> {
                let mut out = Vec::new();
                conversion_row::<0x00>(&mut out);
                conversion_row::<0x01>(&mut out);
                conversion_row::<0x0F>(&mut out);
                conversion_row::<0x21>(&mut out);
                conversion_row::<0x31>(&mut out);
                conversion_row::<0x45>(&mut out);
                conversion_row::<0x5F>(&mut out);
                conversion_row::<0xFF>(&mut out);
                out
            }

            /// `ZExtUnknown::new` for every id, both mandatory forms and each kind of body.
            pub fn unknown_extensions() -> Vec<String> {
                let bodies = [
                    ZExtBody::Unit,
                    ZExtBody::Z64(0),
                    ZExtBody::Z64(u64::MAX),
                    ZExtBody::ZBuf(ZBuf::default()),
                    ZExtBody::ZBuf(bytes(9, 4)),
                ];
                let mut out = vec![format!("default body {:?}", ZExtBody::default())];
                for id in 0..=255u8 {
                    for m in [false, true] {
                        for body in &bodies {
                            let e = ZExtUnknown::new(id, m, body.clone());
                            out.push(format!(
                                "{id} {m}: {e:?} {} {:?} {}",
                                e.is_mandatory(),
                                e.body,
                                e == e.clone()
                            ));
                        }
                    }
                }
                for (i, a) in bodies.iter().enumerate() {
                    for (j, b) in bodies.iter().enumerate() {
                        out.push(format!("body {i} {j}: {}", a == b));
                    }
                }
                out
            }

            pub fn unknown_line(id: u8, mandatory: bool, kind: u8) -> String {
                let body = match kind {
                    0 => ZExtBody::Unit,
                    1 => ZExtBody::Z64(1),
                    _ => ZExtBody::ZBuf(bytes(1, 1)),
                };
                format!("{:?}", ZExtUnknown::new(id, mandatory, body))
            }

            /// The id the macros make, for the forms the messages use and ones past the id mask.
            pub fn macro_ids() -> String {
                type A = zextunit!(0x2, true);
                type B = zextunit!(0x2, false);
                type C = zextz64!(0x7, true);
                type D = zextz64!(0x7, false);
                type E = zextzbuf!(0x3, false);
                type F = zextzbuf!(0xF, true);
                type G = zextzbuf!(0x13, true);
                format!(
                    "{} {} {} {} {} {} {}",
                    A::ID,
                    B::ID,
                    C::ID,
                    D::ID,
                    E::ID,
                    F::ID,
                    G::ID
                )
            }

            /// The ids, the flags and the ids of the extensions of each message.
            pub fn message_constants() -> String {
                format!(
                    "id {} {} {} {} {} {} | put {} {} {} | del {} {} | query {} {} {} | reply {} {} \
                     | err {} {} | put ext {} {} {} | del ext {} {} | query ext {} {} {} {} {} \
                     | err ext {} | value {} {}",
                    id::OAM,
                    id::PUT,
                    id::DEL,
                    id::QUERY,
                    id::REPLY,
                    id::ERR,
                    put::flag::T,
                    put::flag::E,
                    put::flag::Z,
                    del::flag::T,
                    del::flag::Z,
                    query::flag::C,
                    query::flag::P,
                    query::flag::Z,
                    reply::flag::C,
                    reply::flag::Z,
                    err::flag::E,
                    err::flag::Z,
                    put::ext::SourceInfo::ID,
                    put::ext::Attachment::ID,
                    iext::mid(put::ext::Attachment::ID),
                    del::ext::SourceInfo::ID,
                    del::ext::Attachment::ID,
                    query::ext::SourceInfo::ID,
                    query::ext::Attachment::ID,
                    query::ext::QueryBodyType::VID,
                    query::ext::QueryBodyType::SID,
                    iext::mid(query::ext::Attachment::ID),
                    err::ext::SourceInfo::ID,
                    zenoh::ext::ValueType::<3, 4>::VID,
                    zenoh::ext::ValueType::<3, 4>::SID,
                )
            }

            /// The modes of consolidation: their values, their text, their defaults and what a
            /// reader of JSON makes of each name and of names that are none.
            pub fn consolidation() -> Vec<String> {
                let mut out = Vec::new();
                for m in [
                    ConsolidationMode::Auto,
                    ConsolidationMode::None,
                    ConsolidationMode::Monotonic,
                    ConsolidationMode::Latest,
                ] {
                    out.push(format!(
                        "{m:?} {} {} {}",
                        m as u8,
                        m == ConsolidationMode::DEFAULT,
                        m == ConsolidationMode::default()
                    ));
                }
                for s in [
                    "\"Auto\"",
                    "\"None\"",
                    "\"Monotonic\"",
                    "\"Latest\"",
                    "\"auto\"",
                    "\"Unique\"",
                    "0",
                    "1",
                    "\"\"",
                    "null",
                    "[]",
                ] {
                    out.push(format!(
                        "{s}: {}",
                        match serde_json::from_str::<ConsolidationMode>(s) {
                            Ok(m) => format!("ok {m:?}"),
                            Err(e) => format!("err {}", text(e)),
                        }
                    ));
                }
                out
            }

            /// The messages as they are made by default and with every field set, the bodies they
            /// are put in and what is equal to what.
            pub fn messages() -> Vec<String> {
                let ts = uhlc::Timestamp::new(
                    uhlc::NTP64(0x1234_5678_9ABC_DEF0),
                    uhlc::ID::try_from([1u8, 2, 3]).unwrap(),
                );
                let sinfo = || zenoh::ext::SourceInfoType::<0x41> {
                    id: EntityGlobalIdProto {
                        // Not `default()`: that is a random id, and a random one differs per crate.
                        zid: ZenohIdProto::try_from([1u8, 2, 3, 4].as_slice()).unwrap(),
                        eid: 7,
                    },
                    sn: 9,
                };
                let unknown = || vec![ZExtUnknown::new(6, false, ZExtBody::Unit)];
                let put_full = Put {
                    timestamp: Some(ts),
                    encoding: Encoding::default(),
                    ext_sinfo: Some(sinfo()),
                    ext_attachment: Some(put::ext::AttachmentType {
                        buffer: bytes(1, 3),
                    }),
                    ext_unknown: unknown(),
                    payload: bytes(0xAB, 5),
                };
                let del_full = Del {
                    timestamp: Some(ts),
                    ext_sinfo: Some(sinfo()),
                    ext_attachment: Some(del::ext::AttachmentType {
                        buffer: bytes(2, 3),
                    }),
                    ext_unknown: unknown(),
                };
                let query_full = Query {
                    consolidation: ConsolidationMode::Latest,
                    parameters: "a=1;b=2".to_string(),
                    ext_sinfo: Some(sinfo()),
                    ext_body: Some(query::ext::QueryBodyType {
                        encoding: Encoding::default(),
                        payload: bytes(3, 2),
                    }),
                    ext_attachment: Some(query::ext::AttachmentType {
                        buffer: bytes(4, 3),
                    }),
                    ext_unknown: unknown(),
                };
                let reply_full = Reply {
                    consolidation: ConsolidationMode::Monotonic,
                    ext_unknown: unknown(),
                    payload: PushBody::from(put_full.clone()),
                };
                let err_full = ErrMessage {
                    encoding: Encoding::default(),
                    ext_sinfo: Some(sinfo()),
                    ext_unknown: unknown(),
                    payload: bytes(5, 2),
                };
                let mut out = Vec::new();
                out.push(format!("put default {:?}", Put::default()));
                out.push(format!("put full {put_full:?}"));
                out.push(format!(
                    "put eq {} {} {}",
                    put_full == put_full.clone(),
                    put_full == Put::default(),
                    Put::default() == Put::default()
                ));
                out.push(format!("del default {:?}", Del::default()));
                out.push(format!("del full {del_full:?}"));
                out.push(format!(
                    "del eq {} {}",
                    del_full == del_full.clone(),
                    del_full == Del::default()
                ));
                out.push(format!("query default {:?}", Query::default()));
                out.push(format!("query full {query_full:?}"));
                out.push(format!(
                    "query eq {} {}",
                    query_full == query_full.clone(),
                    query_full == Query::default()
                ));
                out.push(format!("reply full {reply_full:?}"));
                out.push(format!("err full {err_full:?}"));
                out.push(format!(
                    "data info {:?}",
                    DataInfo {
                        encoding: Encoding::default()
                    }
                ));
                out.push(format!("push put {:?}", PushBody::from(put_full.clone())));
                out.push(format!("push del {:?}", PushBody::from(del_full.clone())));
                out.push(format!(
                    "push eq {} {}",
                    PushBody::from(Put::default()) == PushBody::from(Del::default()),
                    PushBody::from(Put::default()) == PushBody::from(Put::default())
                ));
                out.push(format!(
                    "request {:?}",
                    RequestBody::from(query_full.clone())
                ));
                out.push(format!(
                    "response reply {:?}",
                    ResponseBody::from(reply_full.clone())
                ));
                out.push(format!(
                    "response err {:?}",
                    ResponseBody::from(err_full.clone())
                ));
                out.push(format!(
                    "response eq {}",
                    ResponseBody::from(reply_full) == ResponseBody::from(err_full)
                ));
                out
            }

            /// What the `test` feature's random constructors can make, as the set of classes of
            /// value seen over many draws. A composite is reported by the classes of each of its
            /// fields and not by their product, which 20 000 draws would not cover.
            pub fn rand_shapes() -> Vec<(&'static str, BTreeSet<String>)> {
                const DRAWS: usize = 20_000;
                fn axes<T>(draw: impl Fn() -> T, classes: impl Fn(&T) -> Vec<String>) -> BTreeSet<String> {
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
                let ids_from = |v: &[ZExtUnknown], min: u8| {
                    v.iter().all(|e| (e.id & iext::ID_MASK) >= min)
                };
                let schema = |e: &Encoding| format!("schema {}", e.schema.is_some());
                let kind = |b: &ZExtBody| match b {
                    ZExtBody::Unit => "unit".to_string(),
                    ZExtBody::Z64(v) => format!("z64 high={}", v >> 63),
                    ZExtBody::ZBuf(z) => format!("zbuf {}", span(z.len(), 8, 64)),
                };
                vec![
                    (
                        "ext unit",
                        axes(ZExtUnit::<0x21>::rand, |u| vec![format!("{u:?}")]),
                    ),
                    (
                        "ext z64",
                        axes(ZExtZ64::<0x41>::rand, |z| {
                            vec![format!("high={}", z.value >> 62)]
                        }),
                    ),
                    (
                        "ext zbuf",
                        axes(ZExtZBuf::<0x41>::rand, |z| {
                            vec![span(z.value.len(), 8, 64).to_string()]
                        }),
                    ),
                    ("ext body", axes(ZExtBody::rand, |b| vec![kind(b)])),
                    (
                        "ext unknown",
                        axes(ZExtUnknown::rand, |u| {
                            let enc = u.id & iext::ENC_MASK;
                            let agrees = matches!(
                                (&u.body, enc),
                                (ZExtBody::Unit, iext::ENC_UNIT)
                                    | (ZExtBody::Z64(_), iext::ENC_Z64)
                                    | (ZExtBody::ZBuf(_), iext::ENC_ZBUF)
                            );
                            vec![format!(
                                "id={} m={} enc={enc} agrees={agrees}",
                                u.id & iext::ID_MASK,
                                u.is_mandatory()
                            )]
                        }),
                    ),
                    (
                        "ext unknown from",
                        axes(
                            || {
                                (
                                    ZExtUnknown::rand2(4, false),
                                    ZExtUnknown::rand2(6, true),
                                    ZExtUnknown::rand2(15, false),
                                )
                            },
                            |(a, b, c)| {
                                [(4, a), (6, b), (15, c)]
                                    .iter()
                                    .map(|(start, e)| {
                                        format!(
                                            "start {start}: id={} m={}",
                                            e.id & iext::ID_MASK,
                                            e.is_mandatory()
                                        )
                                    })
                                    .collect()
                            },
                        ),
                    ),
                    (
                        "source info",
                        axes(put::ext::SourceInfoType::rand, |s| {
                            vec![
                                format!("sn high={}", s.sn >> 31),
                                format!("eid high={}", s.id.eid >> 31),
                                format!(
                                    "zid {}",
                                    if s.id.zid.size() == 16 { "full" } else { "trimmed" }
                                ),
                            ]
                        }),
                    ),
                    (
                        "value type",
                        axes(zenoh::ext::ValueType::<3, 4>::rand, |v| {
                            vec![
                                format!("payload {}", span(v.payload.len(), 1, 64)),
                                schema(&v.encoding),
                            ]
                        }),
                    ),
                    (
                        "attachment",
                        axes(zenoh::ext::AttachmentType::<5>::rand, |a| {
                            vec![format!("len {}", span(a.buffer.len(), 3, 1_024))]
                        }),
                    ),
                    (
                        "put",
                        axes(Put::rand, |p| {
                            vec![
                                format!("timestamp {}", p.timestamp.is_some()),
                                schema(&p.encoding),
                                format!("sinfo {}", p.ext_sinfo.is_some()),
                                format!("attachment {}", p.ext_attachment.is_some()),
                                format!("unknown {}", p.ext_unknown.len()),
                                format!("unknown ids ok {}", ids_from(&p.ext_unknown, 4)),
                                format!("payload {}", span(p.payload.len(), 1, 64)),
                            ]
                        }),
                    ),
                    (
                        "del",
                        axes(Del::rand, |d| {
                            vec![
                                format!("timestamp {}", d.timestamp.is_some()),
                                format!("sinfo {}", d.ext_sinfo.is_some()),
                                format!("attachment {}", d.ext_attachment.is_some()),
                                format!("unknown {}", d.ext_unknown.len()),
                                format!("unknown ids ok {}", ids_from(&d.ext_unknown, 3)),
                            ]
                        }),
                    ),
                    (
                        "consolidation",
                        axes(ConsolidationMode::rand, |m| vec![format!("{m:?}")]),
                    ),
                    (
                        "query",
                        axes(Query::rand, |q| {
                            vec![
                                format!("consolidation {:?}", q.consolidation),
                                if q.parameters.is_empty() {
                                    "parameters empty".to_string()
                                } else {
                                    format!(
                                        "parameters {} alphanumeric {}",
                                        span(q.parameters.len(), 2, 15),
                                        q.parameters.chars().all(|c| c.is_ascii_alphanumeric())
                                    )
                                },
                                format!("sinfo {}", q.ext_sinfo.is_some()),
                                match &q.ext_body {
                                    None => "body none".to_string(),
                                    Some(v) => format!(
                                        "body payload {} {}",
                                        span(v.payload.len(), 1, 64),
                                        schema(&v.encoding)
                                    ),
                                },
                                format!("attachment {}", q.ext_attachment.is_some()),
                                format!("unknown {}", q.ext_unknown.len()),
                                format!("unknown ids ok {}", ids_from(&q.ext_unknown, 6)),
                            ]
                        }),
                    ),
                    (
                        "reply",
                        axes(Reply::rand, |r| {
                            vec![
                                format!("consolidation {:?}", r.consolidation),
                                format!(
                                    "payload {}",
                                    match &r.payload {
                                        PushBody::Put(_) => "put",
                                        PushBody::Del(_) => "del",
                                    }
                                ),
                                format!("unknown {}", r.ext_unknown.len()),
                                format!("unknown ids ok {}", ids_from(&r.ext_unknown, 1)),
                            ]
                        }),
                    ),
                    (
                        "err",
                        axes(ErrMessage::rand, |e| {
                            vec![
                                schema(&e.encoding),
                                format!("sinfo {}", e.ext_sinfo.is_some()),
                                format!("unknown {}", e.ext_unknown.len()),
                                format!("unknown ids ok {}", ids_from(&e.ext_unknown, 2)),
                                format!("payload {}", span(e.payload.len(), 0, 64)),
                            ]
                        }),
                    ),
                    (
                        "push body",
                        axes(PushBody::rand, |b| {
                            vec![match b {
                                PushBody::Put(_) => "put".to_string(),
                                PushBody::Del(_) => "del".to_string(),
                            }]
                        }),
                    ),
                    (
                        "request body",
                        axes(RequestBody::rand, |b| {
                            vec![match b {
                                RequestBody::Query(_) => "query".to_string(),
                            }]
                        }),
                    ),
                    (
                        "response body",
                        axes(ResponseBody::rand, |b| {
                            vec![match b {
                                ResponseBody::Reply(_) => "reply".to_string(),
                                ResponseBody::Err(_) => "err".to_string(),
                            }]
                        }),
                    ),
                ]
            }
        }
    };
}

fn text(e: impl Display) -> String {
    let t = e.to_string();
    t.split(" at ").next().unwrap().to_string()
}

message_cases!(up, up_protocol, up_buffers);
message_cases!(wz, wz_protocol, wz_buffers);

fn same(label: &str, a: Vec<String>, b: Vec<String>) -> usize {
    assert_eq!(a.len(), b.len(), "{label}");
    for (i, (x, y)) in a.iter().zip(&b).enumerate() {
        assert_eq!(x, y, "{label}, line {i}");
    }
    a.len()
}

#[test]
fn both_crates_read_and_set_header_bits_alike() {
    let n = same("header bits", up::header_bits(), wz::header_bits());
    assert!(n > 2_000);
    let n = same("bitfields", up::bitfields(), wz::bitfields());
    assert!(n > 200_000);
}

#[test]
fn both_crates_build_extensions_and_convert_them_alike() {
    let n = same(
        "typed extensions",
        up::typed_extensions(),
        wz::typed_extensions(),
    );
    assert_eq!(n, 13 * 4);
    let n = same("conversions", up::conversions(), wz::conversions());
    assert_eq!(n, 8 * (5 * 3 + 1));
    let n = same(
        "unknown extensions",
        up::unknown_extensions(),
        wz::unknown_extensions(),
    );
    assert!(n > 2_500);
    assert_eq!(up::macro_ids(), wz::macro_ids());
}

#[test]
fn both_crates_name_the_ids_flags_and_extension_ids_of_the_zenoh_messages_alike() {
    assert_eq!(up::message_constants(), wz::message_constants());
    // Not empty: the line says each of the numbers.
    assert!(wz::message_constants().contains("id 0 1 2 3 4 5"));
}

#[test]
fn both_crates_build_and_show_zenoh_messages_alike() {
    same("consolidation", up::consolidation(), wz::consolidation());
    let n = same("messages", up::messages(), wz::messages());
    assert_eq!(n, 19);
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
        // A constructor that only ever made one shape would pass by being constant. Two do by
        // upstream's definition: the unit extension has one value, and a request is always a query.
        assert!(
            a.len() > 1 || ["ext unit", "request body"].contains(name),
            "random {name} made one shape"
        );
    }
    let count = |n: &str| up.iter().find(|(m, _)| *m == n).unwrap().1.len();
    // The classes are many where upstream's draws are: 16 ids, 2 mandatory forms and 3 bodies;
    // 4 modes of consolidation.
    assert_eq!(count("ext unknown"), 96);
    assert_eq!(count("consolidation"), 4);
}

/// The places upstream is wrong, shown on upstream's crate and held to the definition on wz's.
#[test]
fn the_places_upstream_is_wrong_are_pinned_on_both_sides() {
    // A value wider than its mask: upstream ORs it in whole.
    assert_eq!(up::bitfield(0b0000_0000, 0xFF, 0b0000_0011), 0xFF);
    assert_eq!(wz::bitfield(0b0000_0000, 0xFF, 0b0000_0011), 0b0000_0011);
    for byte in [0x00u8, 0x5A, 0xFF] {
        for mask in [0x01u8, 0x06, 0x1F, 0xE0, 0xFF] {
            for value in 0..=255u8 {
                let defined = (byte & !mask) | (value & mask);
                assert_eq!(
                    wz::bitfield(byte, value, mask),
                    defined,
                    "{byte} {value} {mask}"
                );
                if value & !mask == 0 {
                    assert_eq!(up::bitfield(byte, value, mask), defined);
                }
            }
        }
    }
}

/// The control: the comparison is on text, so an input that changes the answer changes the line.
#[test]
fn the_comparison_sees_an_extension_that_differs() {
    assert_eq!(up::unknown_line(1, false, 0), wz::unknown_line(1, false, 0));
    assert_ne!(wz::unknown_line(1, false, 0), wz::unknown_line(2, false, 0));
    assert_ne!(wz::unknown_line(1, false, 0), wz::unknown_line(1, true, 0));
    assert_ne!(wz::unknown_line(1, false, 0), wz::unknown_line(1, false, 1));
    assert_ne!(wz::bitfield(0, 1, 1), wz::bitfield(0, 0, 1));
}
