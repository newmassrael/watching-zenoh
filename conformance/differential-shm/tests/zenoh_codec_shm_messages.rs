// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-codec`, the shared-memory arm of the messages: upstream's crate (`up_codec`) and wz's
//! (`wz_codec`), built with `shared-memory`, given the same messages to write and the same bytes to
//! read, results equal as text (the kind of each slice of a buffer included), the bytes written and
//! the bytes left unread included.
//!
//! The arm adds to a message the extension that says its payload is sliced (a put, an error, the
//! body of a query), the codec that writes the payload by slices, and, to the four messages of a
//! transport's opening, the extension that carries what the two ends say of their shared memory.
//!
//! * WRITES: every combination of the parts of a put (timestamp, encoding, source info, attachment,
//!   unknown extensions, the shared-memory extension, a payload of no, one and two slices), of an
//!   error and of a query body, then a reply, a push and a response around them, and the four
//!   messages of the opening with the extension and without, the bytes compared.
//! * READS: every one of those encodings, then every prefix of it and every one of its bytes set to
//!   six values, read as the message it is and (the encodings alone) as every other message. Two
//!   readings are equal as text, or the difference is one of the classes below.
//!
//! Upstream is lenient in the places the comparison of the arm that every build has found
//! (`../differential`), and wz refuses what it takes in. The classes are counted, built by hand and
//! held on both sides:
//!
//! * the length in the header of a source-info extension is not read against the bytes its fields
//!   take;
//! * an extension a message knows, named twice, is kept as the last of them and the first dropped:
//!   the shared-memory extension of a put, of an error, and of the four messages of the opening
//!   included.
//!
//! A reading upstream accepts that wz refuses is held to the class: it must be a reading whose value
//! does not write back to the bytes it was read from.

#![cfg(target_os = "linux")]

use std::{
    cell::Cell,
    panic::{catch_unwind, set_hook, take_hook, AssertUnwindSafe},
    sync::Once,
};

use rand::{rngs::StdRng, Rng, SeedableRng};

thread_local! {
    static QUIET: Cell<bool> = const { Cell::new(false) };
}

/// Runs `f`, and says `None` if it panicked, without the report of the panic: a writer that panics
/// is a result of this comparison, and the report would be noise.
fn guarded<T>(f: impl FnOnce() -> T) -> Option<T> {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = take_hook();
        set_hook(Box::new(move |info| {
            if !QUIET.with(Cell::get) {
                previous(info)
            }
        }));
    });
    QUIET.with(|q| q.set(true));
    let out = catch_unwind(AssertUnwindSafe(f)).ok();
    QUIET.with(|q| q.set(false));
    out
}

/// What a reading gave: its text, and for a reading that succeeded whether the value writes back to
/// the bytes it consumed.
type Outcome = (String, Option<bool>);

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const KINDS: [&str; 10] = [
    "put", "err", "query", "reply", "push", "response", "init syn", "init ack", "open syn",
    "open ack",
];

macro_rules! message_cases {
    ($name:ident, $c:ident, $p:ident, $b:ident) => {
        mod $name {
            use std::fmt::Debug;

            use $b::{
                buffer::Buffer,
                reader::DidntRead,
                writer::{DidntWrite, HasWriter},
                ZBuf, ZSlice, ZSliceKind,
            };
            use $c::{RCodec, WCodec, Zenoh080};
            use $p::{
                common::{ZExtBody, ZExtUnknown},
                core::{Encoding, EntityGlobalIdProto, Resolution, Timestamp, WhatAmI, ZenohIdProto},
                transport::{
                    init::{self, InitAck, InitSyn},
                    open::{self, OpenAck, OpenSyn},
                    BatchSize,
                },
                zenoh::{
                    err::Err as ErrMsg,
                    ext::{AttachmentType, SourceInfoType, ValueType},
                    put::Put,
                    query::{ConsolidationMode, Query},
                    reply::Reply,
                    PushBody, ResponseBody,
                },
            };

            use super::{guarded, hex, Outcome};

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
                    _ => Encoding {
                        id: 300,
                        schema: Some(ZSlice::from(vec![b's'; 3])),
                    },
                }
            }

            fn sinfo<const ID: u8>(k: usize) -> Option<SourceInfoType<ID>> {
                match k {
                    0 => None,
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
                    _ => vec![ZExtUnknown::new(0x0a, false, ZExtBody::Unit)],
                }
            }

            fn shm<const ID: u8>(k: usize) -> Option<$p::zenoh::ext::ShmType<ID>> {
                (k == 1).then(Default::default)
            }

            /// A payload of no, one and two slices.
            fn payload(k: usize) -> ZBuf {
                let mut z = ZBuf::empty();
                for (i, n) in [&[][..], &[5][..], &[3, 300][..]][k].iter().enumerate() {
                    z.push_zslice(ZSlice::from(vec![0xA5u8 ^ i as u8; *n]));
                }
                z
            }

            fn put(t: usize, e: usize, s: usize, a: usize, u: usize, m: usize, p: usize) -> Put {
                Put {
                    timestamp: ts(t),
                    encoding: encoding(e),
                    ext_sinfo: sinfo(s),
                    ext_shm: shm(m),
                    ext_attachment: attachment(a),
                    ext_unknown: unknown(u),
                    payload: payload(p),
                }
            }

            fn err(e: usize, s: usize, u: usize, m: usize, p: usize) -> ErrMsg {
                ErrMsg {
                    encoding: encoding(e),
                    ext_sinfo: sinfo(s),
                    ext_shm: shm(m),
                    ext_unknown: unknown(u),
                    payload: payload(p),
                }
            }

            fn query(m: usize, p: usize, body: usize) -> Query {
                Query {
                    consolidation: ConsolidationMode::Auto,
                    parameters: "a=b".to_string(),
                    ext_sinfo: None,
                    ext_body: (body == 1).then(|| ValueType {
                        encoding: encoding(1),
                        payload: payload(p),
                        ext_shm: shm(m),
                    }),
                    ext_attachment: None,
                    ext_unknown: vec![],
                }
            }

            fn reply(m: usize, p: usize) -> Reply {
                Reply {
                    consolidation: ConsolidationMode::Auto,
                    ext_unknown: vec![],
                    payload: PushBody::Put(put(1, 1, 1, 0, 0, m, p)),
                }
            }

            fn zbuf(n: usize) -> ZBuf {
                ZBuf::from(vec![0x5Au8; n])
            }

            fn init_syn(mask: usize, zid_len: usize) -> InitSyn {
                InitSyn {
                    version: 9,
                    whatami: WhatAmI::Peer,
                    zid: zid(zid_len),
                    resolution: Resolution::default(),
                    batch_size: BatchSize::MAX,
                    ext_qos: (mask & 1 != 0).then(init::ext::QoS::new),
                    ext_qos_link: (mask & 2 != 0).then(|| init::ext::QoSLink::new(77)),
                    ext_shm: (mask & 256 != 0).then(|| init::ext::Shm::new(zbuf(6))),
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

            fn init_ack(mask: usize, zid_len: usize) -> InitAck {
                let s = init_syn(mask, zid_len);
                InitAck {
                    version: s.version,
                    whatami: s.whatami,
                    zid: s.zid,
                    resolution: s.resolution,
                    batch_size: s.batch_size,
                    cookie: ZSlice::from(vec![0xC0u8; 3]),
                    ext_qos: s.ext_qos,
                    ext_qos_link: s.ext_qos_link,
                    ext_shm: s.ext_shm,
                    ext_auth: s.ext_auth,
                    ext_mlink: s.ext_mlink,
                    ext_lowlatency: s.ext_lowlatency,
                    ext_compression: s.ext_compression,
                    ext_patch: s.ext_patch,
                    ext_region_name: s.ext_region_name,
                }
            }

            fn open_syn(mask: usize, sn: u32) -> OpenSyn {
                OpenSyn {
                    lease: std::time::Duration::from_secs(1),
                    initial_sn: sn,
                    cookie: ZSlice::from(vec![0xC0u8; 3]),
                    ext_qos: (mask & 1 != 0).then(open::ext::QoS::new),
                    ext_shm: (mask & 64 != 0).then(|| open::ext::Shm::new(zbuf(6))),
                    ext_auth: (mask & 2 != 0).then(|| open::ext::Auth::new(zbuf(3))),
                    ext_mlink: (mask & 4 != 0).then(|| open::ext::MultiLinkSyn::new(zbuf(2))),
                    ext_lowlatency: (mask & 8 != 0).then(open::ext::LowLatency::new),
                    ext_compression: (mask & 16 != 0).then(open::ext::Compression::new),
                    ext_remote_bound: (mask & 32 != 0).then(|| open::ext::RemoteBound::new(1)),
                }
            }

            fn open_ack(mask: usize, sn: u32) -> OpenAck {
                OpenAck {
                    lease: std::time::Duration::from_secs(1),
                    initial_sn: sn,
                    ext_qos: (mask & 1 != 0).then(open::ext::QoS::new),
                    ext_shm: (mask & 64 != 0).then(|| open::ext::Shm::new(zbuf(6))),
                    ext_auth: (mask & 2 != 0).then(|| open::ext::Auth::new(zbuf(3))),
                    ext_mlink: (mask & 4 != 0).then(open::ext::MultiLinkAck::new),
                    ext_lowlatency: (mask & 8 != 0).then(open::ext::LowLatency::new),
                    ext_compression: (mask & 16 != 0).then(open::ext::Compression::new),
                    ext_remote_bound: (mask & 32 != 0).then(|| open::ext::RemoteBound::new(1)),
                }
            }

            /// The bytes a write gives, `ERR` after them if it was refused and `PANIC` if it
            /// panicked.
            pub fn enc<F>(f: F) -> Vec<u8>
            where
                F: FnOnce(&mut &mut Vec<u8>) -> Result<(), DidntWrite>,
            {
                let mut v: Vec<u8> = Vec::new();
                let r = guarded(|| {
                    let mut w = (&mut v).writer();
                    f(&mut w)
                });
                match r {
                    Some(Ok(())) => {}
                    Some(Err(_)) => v.extend_from_slice(b"ERR"),
                    None => v.extend_from_slice(b"PANIC"),
                }
                v
            }

            /// The kind of each slice of a buffer, a letter each.
            fn kinds(z: &ZBuf) -> String {
                z.zslices()
                    .map(|s| match s.kind {
                        ZSliceKind::Raw => 'r',
                        ZSliceKind::ShmPtr => 's',
                    })
                    .collect()
            }

            fn kinds_of_body(b: &PushBody) -> String {
                match b {
                    PushBody::Put(p) => kinds(&p.payload),
                    PushBody::Del(_) => String::new(),
                }
            }

            /// Every message to write, by name and the bytes it was written as.
            pub fn corpus() -> Vec<(&'static str, String, Vec<u8>)> {
                let mut out: Vec<(&'static str, String, Vec<u8>)> = Vec::new();
                for t in 0..2 {
                    for e in 0..2 {
                        for s in 0..2 {
                            for a in 0..2 {
                                for u in 0..2 {
                                    for m in 0..2 {
                                        for p in 0..3 {
                                            let msg = put(t, e, s, a, u, m, p);
                                            out.push((
                                                "put",
                                                format!("put {t}{e}{s}{a}{u}{m}{p}"),
                                                enc(|w| Zenoh080.write(w, &msg)),
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                for e in 0..2 {
                    for s in 0..2 {
                        for u in 0..2 {
                            for m in 0..2 {
                                for p in 0..3 {
                                    let msg = err(e, s, u, m, p);
                                    out.push((
                                        "err",
                                        format!("err {e}{s}{u}{m}{p}"),
                                        enc(|w| Zenoh080.write(w, &msg)),
                                    ));
                                }
                            }
                        }
                    }
                }
                for body in 0..2 {
                    for m in 0..2 {
                        for p in 0..3 {
                            let msg = query(m, p, body);
                            out.push((
                                "query",
                                format!("query {body}{m}{p}"),
                                enc(|w| Zenoh080.write(w, &msg)),
                            ));
                        }
                    }
                }
                for m in 0..2 {
                    for p in 0..3 {
                        let msg = reply(m, p);
                        out.push((
                            "reply",
                            format!("reply {m}{p}"),
                            enc(|w| Zenoh080.write(w, &msg)),
                        ));
                        let push = PushBody::Put(put(1, 1, 1, 1, 1, m, p));
                        out.push((
                            "push",
                            format!("push {m}{p}"),
                            enc(|w| Zenoh080.write(w, &push)),
                        ));
                        let resp = ResponseBody::Err(err(1, 1, 1, m, p));
                        out.push((
                            "response",
                            format!("response {m}{p}"),
                            enc(|w| Zenoh080.write(w, &resp)),
                        ));
                    }
                }
                for mask in [0usize, 256, 256 | 1, 256 | 4 | 8, 255 | 256, 255] {
                    for zid_len in [1usize, 16] {
                        let s = init_syn(mask, zid_len);
                        out.push((
                            "init syn",
                            format!("init syn {mask} {zid_len}"),
                            enc(|w| Zenoh080.write(w, &s)),
                        ));
                        let a = init_ack(mask, zid_len);
                        out.push((
                            "init ack",
                            format!("init ack {mask} {zid_len}"),
                            enc(|w| Zenoh080.write(w, &a)),
                        ));
                    }
                }
                for mask in [0usize, 64, 64 | 1, 64 | 2 | 4, 63 | 64, 63] {
                    for sn in [0u32, u32::MAX] {
                        let s = open_syn(mask, sn);
                        out.push((
                            "open syn",
                            format!("open syn {mask} {sn}"),
                            enc(|w| Zenoh080.write(w, &s)),
                        ));
                        let a = open_ack(mask, sn);
                        out.push((
                            "open ack",
                            format!("open ack {mask} {sn}"),
                            enc(|w| Zenoh080.write(w, &a)),
                        ));
                    }
                }
                out
            }

            fn go<T, R, W, K>(bytes: &[u8], read: R, write: W, kinds_of: K) -> Outcome
            where
                T: Debug,
                R: FnOnce(&mut &[u8]) -> Result<T, DidntRead>,
                W: FnOnce(&T, &mut &mut Vec<u8>) -> Result<(), DidntWrite>,
                K: FnOnce(&T) -> String,
            {
                let mut r: &[u8] = bytes;
                let out = read(&mut r);
                let rem = r.len();
                match out {
                    Ok(v) => {
                        let consumed = bytes.len() - rem;
                        let again = enc(|w| write(&v, w));
                        (
                            format!("ok {v:?} kinds={} rem={rem}", kinds_of(&v)),
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
                    ($t:ty, $k:expr) => {
                        go::<$t, _, _, _>(
                            bytes,
                            |r| Zenoh080.read(r),
                            |v, w| Zenoh080.write(w, v),
                            $k,
                        )
                    };
                }
                match kind {
                    "put" => as_!(Put, |v: &Put| kinds(&v.payload)),
                    "err" => as_!(ErrMsg, |v: &ErrMsg| kinds(&v.payload)),
                    "query" => as_!(Query, |v: &Query| v
                        .ext_body
                        .as_ref()
                        .map(|b| kinds(&b.payload))
                        .unwrap_or_default()),
                    "reply" => as_!(Reply, |v: &Reply| kinds_of_body(&v.payload)),
                    "push" => as_!(PushBody, kinds_of_body),
                    "response" => as_!(ResponseBody, |v: &ResponseBody| match v {
                        ResponseBody::Err(e) => kinds(&e.payload),
                        ResponseBody::Reply(r) => kinds_of_body(&r.payload),
                    }),
                    "init syn" => as_!(InitSyn, |_: &InitSyn| String::new()),
                    "init ack" => as_!(InitAck, |_: &InitAck| String::new()),
                    "open syn" => as_!(OpenSyn, |_: &OpenSyn| String::new()),
                    "open ack" => as_!(OpenAck, |_: &OpenAck| String::new()),
                    other => panic!("no such message {other}"),
                }
            }

            /// The bytes of the hand-built classes, by class and the message they are read as.
            pub fn classes() -> Vec<(&'static str, &'static str, Vec<u8>)> {
                let mut out = Vec::new();
                // The source-info extension of a put, an error and a query, with a length that is
                // not the fields': the third byte of a put with only that extension.
                let good = enc(|w| Zenoh080.write(w, &put(0, 0, 0, 0, 0, 0, 0)));
                assert_eq!(good, vec![0x01, 0]);
                let si: $p::zenoh::put::ext::SourceInfoType = SourceInfoType {
                    id: EntityGlobalIdProto {
                        zid: zid(1),
                        eid: 0,
                    },
                    sn: 0,
                };
                let sib = enc(|w| Zenoh080.write(w, (&si, false)));
                for len in [0u8, 1, 3, 5, 7, 40] {
                    let mut b = vec![0x01 | 0x80];
                    b.extend(&sib);
                    b[2] = len;
                    b.push(0);
                    out.push(("sinfo length", "put", b));
                }
                // The shared-memory extension named twice, the first saying more follows, in a put
                // (a unit extension: its header only), and a payload sliced after it.
                // The id of the extension is the message's own, mandatory flag included: any other
                // id is an extension the message does not know, which both skip.
                let put_shm = shm::<{ $p::zenoh::put::ext::Shm::ID }>(1).unwrap();
                let (put_more, put_last) = (
                    enc(|w| Zenoh080.write(w, (&put_shm, true))),
                    enc(|w| Zenoh080.write(w, (&put_shm, false))),
                );
                let mut b = vec![0x01 | 0x80];
                b.extend(&put_more);
                b.extend(&put_last);
                b.extend([0u8]);
                out.push(("duplicate shm", "put", b));
                let err_shm = shm::<{ $p::zenoh::err::ext::Shm::ID }>(1).unwrap();
                let (err_more, err_last) = (
                    enc(|w| Zenoh080.write(w, (&err_shm, true))),
                    enc(|w| Zenoh080.write(w, (&err_shm, false))),
                );
                let mut b = vec![0x05 | 0x80];
                b.extend(&err_more);
                b.extend(&err_last);
                b.extend([0u8]);
                out.push(("duplicate shm", "err", b));
                // The extension of the opening, named twice: a message whose only extension is that
                // one, which is the end of its bytes, written again with the first saying more
                // follows.
                let init_ext = init::ext::Shm::new(zbuf(6));
                let (init_more, init_last) = (
                    enc(|w| Zenoh080.write(w, (&init_ext, true))),
                    enc(|w| Zenoh080.write(w, (&init_ext, false))),
                );
                let open_ext = open::ext::Shm::new(zbuf(6));
                let (open_more, open_last) = (
                    enc(|w| Zenoh080.write(w, (&open_ext, true))),
                    enc(|w| Zenoh080.write(w, (&open_ext, false))),
                );
                let twice = |whole: Vec<u8>, more: &[u8], last: &[u8]| -> Vec<u8> {
                    assert!(whole.ends_with(last), "{}", hex(&whole));
                    let mut b = whole[..whole.len() - last.len()].to_vec();
                    b.extend_from_slice(more);
                    b.extend_from_slice(last);
                    b
                };
                out.push((
                    "duplicate shm",
                    "init syn",
                    twice(
                        enc(|w| Zenoh080.write(w, &init_syn(256, 1))),
                        &init_more,
                        &init_last,
                    ),
                ));
                out.push((
                    "duplicate shm",
                    "init ack",
                    twice(
                        enc(|w| Zenoh080.write(w, &init_ack(256, 1))),
                        &init_more,
                        &init_last,
                    ),
                ));
                out.push((
                    "duplicate shm",
                    "open syn",
                    twice(
                        enc(|w| Zenoh080.write(w, &open_syn(64, 0))),
                        &open_more,
                        &open_last,
                    ),
                ));
                out.push((
                    "duplicate shm",
                    "open ack",
                    twice(
                        enc(|w| Zenoh080.write(w, &open_ack(64, 0))),
                        &open_more,
                        &open_last,
                    ),
                ));
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
    let mut rng = StdRng::seed_from_u64(0x5111);
    for (kind, name, bytes) in corpus {
        for cut in 0..bytes.len() {
            out.push((*kind, format!("{name} cut {cut}"), bytes[..cut].to_vec()));
        }
        let positions: Vec<usize> = if bytes.len() <= 40 {
            (0..bytes.len()).collect()
        } else {
            (0..20).map(|_| rng.gen_range(0..bytes.len())).collect()
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
fn both_crates_write_every_shared_memory_message_to_the_same_bytes() {
    let (u, w) = (up::corpus(), wz::corpus());
    assert!(u.len() > 300, "{}", u.len());
    assert_eq!(u.len(), w.len());
    // The messages that differ, counted by kind, so a difference is attributed to the codec of a
    // message and not to the first row that shows it.
    let mut bad = std::collections::BTreeMap::<&str, Vec<&str>>::new();
    for (a, b) in u.iter().zip(&w) {
        if a != b {
            bad.entry(a.0).or_default().push(&a.1);
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
    // None is the marker of a write that failed or panicked, and the bytes are not all alike.
    assert!(u
        .iter()
        .all(|(_, _, b)| !b.ends_with(b"ERR") && !b.ends_with(b"PANIC")));
    let distinct: std::collections::BTreeSet<_> = u.iter().map(|(_, _, b)| b.clone()).collect();
    assert!(distinct.len() > 250, "{}", distinct.len());
}

#[test]
fn both_crates_read_every_shared_memory_message_back_as_the_message_it_is() {
    let corpus = up::corpus();
    let mut bad = std::collections::BTreeMap::<&str, Vec<String>>::new();
    for (kind, name, bytes) in &corpus {
        let (a, b) = (up::read_as(kind, bytes), wz::read_as(kind, bytes));
        // On both sides, to the bytes it came from.
        let fine = a == b && a.0.starts_with("ok") && a.0.ends_with("rem=0") && a.1 == Some(true);
        if !fine {
            bad.entry(kind)
                .or_default()
                .push(format!("{name} {}", hex(bytes)));
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
}

#[test]
fn the_extension_changes_what_a_put_writes() {
    let c = wz::corpus();
    let get = |n: &str| c.iter().find(|(_, name, _)| name == n).unwrap().2.clone();
    // A put with the extension and one without differ by the extension, and the payload with the
    // extension is framed by slices (a count, a tag, a length) where the plain one is a length.
    assert_ne!(get("put 0000001"), get("put 0000011"));
    assert_ne!(get("put 0000002"), get("put 0000012"));
    assert_ne!(get("init syn 0 1"), get("init syn 256 1"));
    assert_ne!(get("open syn 0 0"), get("open syn 64 0"));
}

#[test]
fn both_crates_read_every_cut_and_changed_encoding_alike_but_for_the_classes() {
    let corpus = up::corpus();
    let mut inputs = mutations(&corpus);
    // The encodings alone are read as every message.
    for (own, name, bytes) in &corpus {
        for kind in KINDS {
            inputs.push((kind, format!("{name} as {kind} (own {own})"), bytes.clone()));
        }
    }
    assert!(inputs.len() > 50_000, "{}", inputs.len());
    let (mut equal, mut refused, mut ok) = (0usize, 0usize, 0usize);
    let mut by_kind = std::collections::BTreeMap::<&str, usize>::new();
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
        *by_kind.entry(kind).or_default() += 1;
    }
    println!("equal={equal} ok={ok} refused={refused} by kind {by_kind:?}");
    assert!(equal > 40_000 && ok > 10_000, "{equal} {ok}");
    assert!(refused > 0, "{refused}");
}

#[test]
fn both_crates_differ_on_the_classes_and_on_nothing_beside_them() {
    let (u, w) = (up::classes(), wz::classes());
    assert_eq!(u, w);
    let mut seen = std::collections::BTreeMap::<&str, (usize, usize)>::new();
    for (class, kind, bytes) in &u {
        let (a, b) = (up::read_as(kind, bytes), wz::read_as(kind, bytes));
        let entry = seen.entry(class).or_default();
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
    assert!(seen["sinfo length"].1 >= 5, "{seen:?}");
    assert!(seen["duplicate shm"].1 == 6, "{seen:?}");
}

/// The control: the comparison is on text, so a message that differs gives a row that differs.
#[test]
fn the_comparison_sees_a_message_that_differs() {
    let c = wz::corpus();
    let get = |n: &str| c.iter().find(|(_, name, _)| name == n).unwrap().2.clone();
    let a = wz::read_as("put", &get("put 0000001"));
    let b = wz::read_as("put", &get("put 0000011"));
    assert_ne!(a.0, b.0);
    assert_ne!(
        wz::read_as("init syn", &get("init syn 0 1")).0,
        wz::read_as("init syn", &get("init syn 256 1")).0
    );
}
