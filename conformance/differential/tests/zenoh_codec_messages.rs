// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-codec`, the scouting and zenoh messages (the second slice of the crate): upstream's crate
//! (`up_codec`) and wz's (`wz_codec`) given the same messages to write and the same bytes to read,
//! results equal as text, the bytes written and the bytes left unread included.
//!
//! * WRITES: every combination of the parts of each message (a put: timestamp, encoding, source
//!   info, attachment, unknown extensions, payload; a query: consolidation, parameters, the three
//!   extensions, a body; a reply, an error, a delete, a scout, a hello) through its own codec and
//!   through the codec of the body it travels in, the bytes compared.
//! * READS: every one of those encodings, then every prefix of it and every one of its bytes set to
//!   each of six values, read as the message it is and (the encodings alone) as every other message.
//!   Two readings are equal as text, or the difference is one of the three classes below.
//!
//! Upstream is lenient in three places, and wz refuses what it takes in. Each is a class that is
//! counted, built by hand and held on both sides:
//!
//! * the length in the header of a source-info extension is not read against the bytes its fields
//!   take, so an extension that says it is longer or shorter than it is is read as the fields it
//!   holds and the bytes it claims beyond them are taken for what follows;
//! * an extension a message knows, named twice, is kept as the last of them and the first dropped;
//! * a scout and a hello skip an extension they do not know whether or not it is mandatory, where
//!   every other message refuses a mandatory one.
//!
//! A reading upstream accepts that wz refuses is held to the class: it must be a reading whose value
//! does not write back to the bytes it was read from (a message that lost something in the reading).
//!
//! The crates are built without `shared-memory`; that arm waits for the member of the shared-memory
//! buffers and is held by the surface gate.

use rand::{rngs::StdRng, Rng, SeedableRng};

/// What a reading gave: its text, and for a reading that succeeded whether the value writes back to
/// the bytes it consumed.
type Outcome = (String, Option<bool>);

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const KINDS: [&str; 11] = [
    "put", "del", "query", "reply", "err", "scout", "hello", "scouting", "push", "request",
    "response",
];

macro_rules! message_cases {
    ($name:ident, $c:ident, $p:ident, $b:ident) => {
        mod $name {
            use std::fmt::Debug;

            use $b::{
                reader::{DidntRead, Reader},
                writer::{DidntWrite, HasWriter},
                ZBuf, ZSlice,
            };
            use $c::{LCodec, RCodec, WCodec, Zenoh080};
            use $p::{
                common::{ZExtBody, ZExtUnknown},
                core::{
                    whatami::WhatAmIMatcher, Encoding, EntityGlobalIdProto, Locator, Timestamp,
                    WhatAmI, ZenohIdProto,
                },
                scouting::{hello::HelloProto, scout::Scout, ScoutingBody, ScoutingMessage},
                zenoh::{
                    del::Del,
                    err::Err as ErrMsg,
                    ext::{AttachmentType, SourceInfoType, ValueType},
                    put::Put,
                    query::{ConsolidationMode, Query},
                    reply::Reply,
                    PushBody, RequestBody, ResponseBody,
                },
            };

            use super::{hex, Outcome};

            fn zid(n: usize) -> ZenohIdProto {
                let bytes: Vec<u8> = (0..n).map(|i| i as u8 + 1).collect();
                ZenohIdProto::try_from(bytes.as_slice()).unwrap()
            }

            fn ts(k: usize) -> Option<Timestamp> {
                (k == 1).then(|| {
                    let id = uhlc::ID::try_from(&zid(8).to_le_bytes()[..8]).unwrap();
                    Timestamp::new(uhlc::NTP64(0x1234_5678_9ABC), id)
                })
            }

            fn encoding(k: usize) -> Encoding {
                match k {
                    0 => Encoding::empty(),
                    1 => Encoding {
                        id: 5,
                        schema: None,
                    },
                    _ => Encoding {
                        id: 300,
                        schema: Some(ZSlice::from(vec![b's'; 3])),
                    },
                }
            }

            fn sinfo<const ID: u8>(k: usize) -> Option<SourceInfoType<ID>> {
                match k {
                    0 => None,
                    1 => Some(SourceInfoType {
                        id: EntityGlobalIdProto {
                            zid: zid(1),
                            eid: 0,
                        },
                        sn: 0,
                    }),
                    _ => Some(SourceInfoType {
                        id: EntityGlobalIdProto {
                            zid: zid(16),
                            eid: u32::MAX,
                        },
                        sn: u32::MAX,
                    }),
                }
            }

            fn attachment<const ID: u8>(k: usize) -> Option<AttachmentType<ID>> {
                (k == 1).then(|| AttachmentType {
                    buffer: ZBuf::from(vec![7u8; 5]),
                })
            }

            fn unknown(k: usize) -> Vec<ZExtUnknown> {
                match k {
                    0 => vec![],
                    1 => vec![ZExtUnknown::new(0x0a, false, ZExtBody::Unit)],
                    _ => vec![
                        ZExtUnknown::new(0x0b, false, ZExtBody::Z64(300)),
                        ZExtUnknown::new(0x0c, false, ZExtBody::ZBuf(ZBuf::from(vec![1u8, 2, 3]))),
                    ],
                }
            }

            fn payload(k: usize) -> ZBuf {
                ZBuf::from(vec![0xA5u8; [0, 1, 300][k]])
            }

            fn consolidation(k: usize) -> ConsolidationMode {
                [
                    ConsolidationMode::Auto,
                    ConsolidationMode::None,
                    ConsolidationMode::Monotonic,
                    ConsolidationMode::Latest,
                ][k]
            }

            fn put(ts_k: usize, e: usize, s: usize, a: usize, u: usize, p: usize) -> Put {
                Put {
                    timestamp: ts(ts_k),
                    encoding: encoding(e),
                    ext_sinfo: sinfo(s),
                    ext_attachment: attachment(a),
                    ext_unknown: unknown(u),
                    payload: payload(p),
                }
            }

            fn del(ts_k: usize, s: usize, a: usize, u: usize) -> Del {
                Del {
                    timestamp: ts(ts_k),
                    ext_sinfo: sinfo(s),
                    ext_attachment: attachment(a),
                    ext_unknown: unknown(u),
                }
            }

            fn query(c: usize, params: usize, s: usize, body: usize, a: usize, u: usize) -> Query {
                Query {
                    consolidation: consolidation(c),
                    parameters: ["", "a=b;c=d"][params].to_string(),
                    ext_sinfo: sinfo(s),
                    ext_body: (body == 1).then(|| ValueType {
                        encoding: encoding(2),
                        payload: payload(1),
                    }),
                    ext_attachment: attachment(a),
                    ext_unknown: unknown(u),
                }
            }

            fn err(e: usize, s: usize, u: usize, p: usize) -> ErrMsg {
                ErrMsg {
                    encoding: encoding(e),
                    ext_sinfo: sinfo(s),
                    ext_unknown: unknown(u),
                    payload: payload(p),
                }
            }

            fn reply(c: usize, u: usize, body: usize) -> Reply {
                Reply {
                    consolidation: consolidation(c),
                    ext_unknown: unknown(u),
                    payload: if body == 0 {
                        PushBody::Put(put(1, 1, 1, 0, 0, 1))
                    } else {
                        PushBody::Del(del(1, 1, 0, 0))
                    },
                }
            }

            fn scout(version: u8, what: u8, z: usize) -> Scout {
                Scout {
                    version,
                    what: WhatAmIMatcher::try_from(what).unwrap(),
                    zid: (z != 0).then(|| zid(z)),
                }
            }

            fn hello(version: u8, w: usize, z: usize, locs: usize) -> HelloProto {
                let locators = ["tcp/127.0.0.1:7447", "udp/[::1]:7447?iface=lo", "tcp/h:1"]
                    .iter()
                    .take(locs)
                    .map(|s| Locator::try_from(s.to_string()).unwrap())
                    .collect();
                HelloProto {
                    version,
                    zid: zid(z),
                    whatami: [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client][w],
                    locators,
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

            /// Every message to write, by name and the bytes it was written as.
            pub fn corpus() -> Vec<(&'static str, String, Vec<u8>)> {
                let mut out: Vec<(&'static str, String, Vec<u8>)> = Vec::new();
                for t in 0..2 {
                    for e in 0..3 {
                        for s in 0..3 {
                            for a in 0..2 {
                                for u in 0..3 {
                                    for p in 0..3 {
                                        let m = put(t, e, s, a, u, p);
                                        out.push((
                                            "put",
                                            format!("put {t}{e}{s}{a}{u}{p}"),
                                            enc(|w| Zenoh080.write(w, &m)),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
                for t in 0..2 {
                    for s in 0..3 {
                        for a in 0..2 {
                            for u in 0..3 {
                                let m = del(t, s, a, u);
                                out.push((
                                    "del",
                                    format!("del {t}{s}{a}{u}"),
                                    enc(|w| Zenoh080.write(w, &m)),
                                ));
                            }
                        }
                    }
                }
                for c in 0..4 {
                    for ps in 0..2 {
                        for s in 0..2 {
                            for body in 0..2 {
                                for a in 0..2 {
                                    for u in 0..2 {
                                        let m = query(c, ps, s, body, a, u);
                                        out.push((
                                            "query",
                                            format!("query {c}{ps}{s}{body}{a}{u}"),
                                            enc(|w| Zenoh080.write(w, &m)),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
                for c in 0..4 {
                    for u in 0..3 {
                        for body in 0..2 {
                            let m = reply(c, u, body);
                            out.push((
                                "reply",
                                format!("reply {c}{u}{body}"),
                                enc(|w| Zenoh080.write(w, &m)),
                            ));
                        }
                    }
                }
                for e in 0..3 {
                    for s in 0..3 {
                        for u in 0..3 {
                            for p in 0..3 {
                                let m = err(e, s, u, p);
                                out.push((
                                    "err",
                                    format!("err {e}{s}{u}{p}"),
                                    enc(|w| Zenoh080.write(w, &m)),
                                ));
                            }
                        }
                    }
                }
                for version in [0u8, 9, 255] {
                    for what in 1..=7u8 {
                        for z in [0usize, 1, 16] {
                            let m = scout(version, what, z);
                            out.push((
                                "scout",
                                format!("scout {version} {what} {z}"),
                                enc(|w| Zenoh080.write(w, &m)),
                            ));
                            let sm: ScoutingMessage = ScoutingBody::Scout(m).into();
                            out.push((
                                "scouting",
                                format!("scouting scout {version} {what} {z}"),
                                enc(|w| Zenoh080.write(w, &sm)),
                            ));
                        }
                    }
                }
                for version in [0u8, 255] {
                    for w in 0..3 {
                        for z in [1usize, 16] {
                            for locs in 0..3 {
                                let m = hello(version, w, z, locs);
                                out.push((
                                    "hello",
                                    format!("hello {version} {w} {z} {locs}"),
                                    enc(|wr| Zenoh080.write(wr, &m)),
                                ));
                                let sm: ScoutingMessage = ScoutingBody::Hello(m).into();
                                out.push((
                                    "scouting",
                                    format!("scouting hello {version} {w} {z} {locs}"),
                                    enc(|wr| Zenoh080.write(wr, &sm)),
                                ));
                            }
                        }
                    }
                }
                for k in 0..2 {
                    let p = if k == 0 {
                        PushBody::Put(put(1, 2, 2, 1, 2, 2))
                    } else {
                        PushBody::Del(del(1, 2, 1, 2))
                    };
                    out.push(("push", format!("push {k}"), enc(|w| Zenoh080.write(w, &p))));
                    let q = RequestBody::Query(query(3, 1, 1, 1, 1, 1));
                    out.push((
                        "request",
                        format!("request {k}"),
                        enc(|w| Zenoh080.write(w, &q)),
                    ));
                    let r = if k == 0 {
                        ResponseBody::Reply(reply(1, 1, 0))
                    } else {
                        ResponseBody::Err(err(2, 2, 1, 1))
                    };
                    out.push((
                        "response",
                        format!("response {k}"),
                        enc(|w| Zenoh080.write(w, &r)),
                    ));
                }
                // The lengths of the source-info extension, as the codec measures them.
                for s in 1..3 {
                    let m = sinfo::<1>(s).unwrap();
                    out.push((
                        "sinfo",
                        format!("sinfo {s} w_len"),
                        format!("{}", Zenoh080.w_len(&m)).into_bytes(),
                    ));
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
                match kind {
                    "put" => {
                        go::<Put, _, _>(bytes, |r| Zenoh080.read(r), |v, w| Zenoh080.write(w, v))
                    }
                    "del" => {
                        go::<Del, _, _>(bytes, |r| Zenoh080.read(r), |v, w| Zenoh080.write(w, v))
                    }
                    "query" => {
                        go::<Query, _, _>(bytes, |r| Zenoh080.read(r), |v, w| Zenoh080.write(w, v))
                    }
                    "reply" => {
                        go::<Reply, _, _>(bytes, |r| Zenoh080.read(r), |v, w| Zenoh080.write(w, v))
                    }
                    "err" => {
                        go::<ErrMsg, _, _>(bytes, |r| Zenoh080.read(r), |v, w| Zenoh080.write(w, v))
                    }
                    "scout" => {
                        go::<Scout, _, _>(bytes, |r| Zenoh080.read(r), |v, w| Zenoh080.write(w, v))
                    }
                    "hello" => go::<HelloProto, _, _>(
                        bytes,
                        |r| Zenoh080.read(r),
                        |v, w| Zenoh080.write(w, v),
                    ),
                    "scouting" => go::<ScoutingMessage, _, _>(
                        bytes,
                        |r| Zenoh080.read(r),
                        |v, w| Zenoh080.write(w, v),
                    ),
                    "push" => go::<PushBody, _, _>(
                        bytes,
                        |r| Zenoh080.read(r),
                        |v, w| Zenoh080.write(w, v),
                    ),
                    "request" => go::<RequestBody, _, _>(
                        bytes,
                        |r| Zenoh080.read(r),
                        |v, w| Zenoh080.write(w, v),
                    ),
                    "response" => go::<ResponseBody, _, _>(
                        bytes,
                        |r| Zenoh080.read(r),
                        |v, w| Zenoh080.write(w, v),
                    ),
                    other => panic!("no such message {other}"),
                }
            }

            /// The bytes of the three hand-built classes, by class and the message they are read as.
            pub fn classes() -> Vec<(&'static str, &'static str, Vec<u8>)> {
                let mut out = Vec::new();
                // A put with a source-info extension only: header, extension header, length, then
                // the fields, then the payload (empty). The length is the third byte.
                let base = put(0, 0, 1, 0, 0, 0);
                let good = enc(|w| Zenoh080.write(w, &base));
                // flags, one byte of id, the entity id and the sequence number, a byte each
                assert_eq!(good[2] as usize, 4, "{}", hex(&good));
                for len in [0u8, 1, 3, 5, 7, 40] {
                    let mut b = good.clone();
                    b[2] = len;
                    out.push(("sinfo length", "put", b));
                }
                // The same extension in a delete, a query and an error, with the length off by one.
                let d = enc(|w| Zenoh080.write(w, &del(0, 1, 0, 0)));
                let mut b = d.clone();
                b[2] += 1;
                out.push(("sinfo length", "del", b));
                let q = enc(|w| Zenoh080.write(w, &query(0, 0, 1, 0, 0, 0)));
                let mut b = q.clone();
                b[2] += 1;
                out.push(("sinfo length", "query", b));
                let e = enc(|w| Zenoh080.write(w, &err(0, 1, 0, 0)));
                let mut b = e.clone();
                b[2] += 1;
                out.push(("sinfo length", "err", b));
                // An extension named twice: two of the same extension, the first saying more follows.
                let si: $p::zenoh::put::ext::SourceInfoType = sinfo(1).unwrap();
                let at: $p::zenoh::put::ext::AttachmentType = attachment(1).unwrap();
                let dup = |header: u8, exts: Vec<Vec<u8>>, tail: &[u8]| -> Vec<u8> {
                    let mut b = vec![header | 0x80];
                    for e in exts {
                        b.extend(e);
                    }
                    b.extend_from_slice(tail);
                    b
                };
                let si1 = enc(|w| Zenoh080.write(w, (&si, true)));
                let si2 = enc(|w| Zenoh080.write(w, (&si, false)));
                out.push((
                    "duplicate",
                    "put",
                    dup(0x01, vec![si1.clone(), si2.clone()], &[0]),
                ));
                let at1 = enc(|w| Zenoh080.write(w, (&at, true)));
                let at2 = enc(|w| Zenoh080.write(w, (&at, false)));
                out.push(("duplicate", "put", dup(0x01, vec![at1, at2], &[0])));
                let sid: $p::zenoh::del::ext::SourceInfoType = sinfo(1).unwrap();
                let s1 = enc(|w| Zenoh080.write(w, (&sid, true)));
                let s2 = enc(|w| Zenoh080.write(w, (&sid, false)));
                out.push((
                    "duplicate",
                    "del",
                    dup(0x02, vec![s1.clone(), s2.clone()], &[]),
                ));
                out.push((
                    "duplicate",
                    "query",
                    dup(0x03, vec![s1.clone(), s2.clone()], &[]),
                ));
                out.push(("duplicate", "err", dup(0x05, vec![s1, s2], &[0])));
                // A scout and a hello with an extension they do not know, and it is mandatory, or
                // it is not.
                for mandatory in [true, false] {
                    let u = ZExtUnknown::new(0x0a, mandatory, ZExtBody::Unit);
                    let ub = enc(|w| Zenoh080.write(w, (&u, false)));
                    let mut scout = vec![0x01 | 0x80, 9, 0x03];
                    scout.extend(&ub);
                    out.push((
                        if mandatory {
                            "mandatory scouting"
                        } else {
                            "optional scouting"
                        },
                        "scout",
                        scout,
                    ));
                    let mut hello = vec![0x02 | 0x80, 9, 0x00, 1];
                    hello.extend(&ub);
                    out.push((
                        if mandatory {
                            "mandatory scouting"
                        } else {
                            "optional scouting"
                        },
                        "hello",
                        hello,
                    ));
                }
                // A consolidation mode past the last is read as the default, by both.
                out.push(("consolidation", "query", vec![0x03 | 0x20, 77]));
                out
            }
        }
    };
}

message_cases!(up, up_codec, up_protocol, up_buffers);
message_cases!(wz, wz_codec, wz_protocol, wz_buffers);

/// The bytes read, as the prefixes of each encoding and each of its bytes set to six values.
fn mutations(corpus: &[(&'static str, String, Vec<u8>)]) -> Vec<(&'static str, String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rng = StdRng::seed_from_u64(0x2E40);
    for (kind, name, bytes) in corpus {
        if *kind == "sinfo" {
            continue;
        }
        for cut in 0..bytes.len() {
            out.push((*kind, format!("{name} cut {cut}"), bytes[..cut].to_vec()));
        }
        // Every byte of the short encodings and a draw of the long ones.
        let positions: Vec<usize> = if bytes.len() <= 48 {
            (0..bytes.len()).collect()
        } else {
            (0..24).map(|_| rng.gen_range(0..bytes.len())).collect()
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
fn both_crates_write_every_scouting_and_zenoh_message_to_the_same_bytes() {
    let (u, w) = (up::corpus(), wz::corpus());
    assert!(u.len() > 700, "{}", u.len());
    assert_eq!(u.len(), w.len());
    let bad: Vec<_> = u.iter().zip(&w).filter(|(a, b)| a != b).take(5).collect();
    assert!(bad.is_empty(), "{bad:#?}");
    // The bytes are not all alike and none is the marker of a write that failed.
    assert!(u.iter().all(|(_, _, b)| !b.ends_with(b"ERR")));
    let distinct: std::collections::BTreeSet<_> = u.iter().map(|(_, _, b)| b.clone()).collect();
    assert!(distinct.len() > 600, "{}", distinct.len());
    // Every encoding reads back as the message it is, on both sides, to the bytes it came from.
    for (kind, name, bytes) in &u {
        if *kind == "sinfo" {
            continue;
        }
        let (a, b) = (up::read_as(kind, bytes), wz::read_as(kind, bytes));
        assert_eq!(a, b, "{name}");
        assert!(
            a.0.starts_with("ok") && a.0.ends_with("rem=0"),
            "{name}: {}",
            a.0
        );
        assert_eq!(a.1, Some(true), "{name} {} {}", hex(bytes), a.0);
    }
}

#[test]
fn both_crates_read_every_cut_and_changed_encoding_alike_but_for_the_three_classes() {
    let corpus = up::corpus();
    let mut inputs = mutations(&corpus);
    // The encodings alone are read as every message.
    for (own, name, bytes) in &corpus {
        if *own == "sinfo" {
            continue;
        }
        for kind in KINDS {
            inputs.push((kind, format!("{name} as {kind}"), bytes.clone()));
        }
    }
    assert!(inputs.len() > 100_000, "{}", inputs.len());
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
    assert!(equal > 90_000 && ok > 20_000, "{equal} {ok}");
    // The classes are reached by the draws too, not only by the hand-built inputs.
    assert!(refused > 0, "{refused}");
}

#[test]
fn both_crates_differ_on_the_three_classes_and_on_nothing_beside_them() {
    let (u, w) = (up::classes(), wz::classes());
    assert_eq!(u, w);
    let mut seen = std::collections::BTreeMap::<&str, (usize, usize)>::new();
    for (class, kind, bytes) in &u {
        let (a, b) = (up::read_as(kind, bytes), wz::read_as(kind, bytes));
        let entry = seen.entry(class).or_default();
        match *class {
            "optional scouting" | "consolidation" => {
                // Not a class: both read it, alike.
                assert_eq!(a, b, "{class} {kind} {}", hex(bytes));
                assert!(a.0.starts_with("ok"), "{class} {kind}: {}", a.0);
                entry.0 += 1;
            }
            _ => {
                if a.0 == b.0 {
                    // A length that is the right one for the fields is read alike.
                    assert!(*class == "sinfo length", "{class} {kind} {}", hex(bytes));
                    entry.0 += 1;
                } else {
                    assert!(
                        a.0.starts_with("ok") && a.1 == Some(false) && b.0.starts_with("err"),
                        "{class} {kind} {}\nup {a:?}\nwz {b:?}",
                        hex(bytes)
                    );
                    entry.1 += 1;
                }
            }
        }
    }
    // Every class has inputs on which they differ, the others have inputs on which they do not.
    assert!(seen["sinfo length"].1 >= 6, "{seen:?}");
    assert!(seen["duplicate"].1 >= 5, "{seen:?}");
    assert!(seen["mandatory scouting"].1 == 2, "{seen:?}");
    assert!(
        seen["optional scouting"].0 == 2 && seen["consolidation"].0 == 1,
        "{seen:?}"
    );
    // The mode past the last is the default, which is not written.
    let a = up::read_as("query", &[0x03 | 0x20, 77]);
    assert!(a.0.contains("consolidation: Auto"), "{}", a.0);
}

/// The control: the comparison is on text, so a message that differs gives a row that differs.
#[test]
fn the_comparison_sees_a_message_that_differs() {
    let c = wz::corpus();
    let get = |n: &str| c.iter().find(|(_, name, _)| name == n).unwrap().2.clone();
    assert_ne!(get("put 000000"), get("put 000001"));
    assert_ne!(get("scout 9 3 0"), get("scout 9 3 1"));
    let a = wz::read_as("put", &get("put 000000"));
    let b = wz::read_as("put", &get("put 000010"));
    assert_ne!(a.0, b.0);
    assert_ne!(
        wz::read_as("scout", &[0x01, 9, 0x03]).0,
        wz::read_as("scout", &[0x01, 9, 0x02]).0
    );
}
