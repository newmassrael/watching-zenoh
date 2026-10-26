// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh`, the `sample`, `qos` and `timestamp_stack` modules (the sixth part of the top crate):
//! upstream's crate (`up_zenoh`) and wz's (`wz_zenoh`) given the same inputs, results equal as text.
//!
//! * the priority of a message: all 256 values of a byte through `TryFrom<u8>`, the three
//!   `internal` constants, the default, the conversions to and from the configuration's priority and
//!   the protocol's (the `Control` priority refused), serde from every name and from a name that is
//!   not one, text and hash;
//! * the locality, the kind of a sample, their text, defaults, serde and conversions;
//! * the builders of a sample: a put and a delete through every setter (payload, key expression, the
//!   three quality-of-service traits, timestamp, attachment, encoding, reliability, source
//!   information, instrumentation of the timestamp stack), the refusals of a sample of the other
//!   kind, the conversions in and out, and the sample read back through every getter and through its
//!   text, `SampleFields` and `Sample::empty`;
//! * the sample of a frame: `from_message` of a put and of a delete with every combination of
//!   timestamp, source information, attachment, quality of service, reliability and timestamp stack
//!   (one that is well formed, one with a record that is not, one of custom bytes, one with no
//!   instrumentation), as the runtime of a session makes it;
//! * the timestamp stack itself: the interception points, the instrumentation builder and its
//!   refusal of an empty set, the records of a stack made of a frame's.
//!
//! No difference from upstream was seen.

use std::{
    cell::Cell,
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    panic::{catch_unwind, set_hook, take_hook, AssertUnwindSafe},
    sync::Once,
};

thread_local! {
    static QUIET: Cell<bool> = const { Cell::new(false) };
}

/// What a call that may panic made, as text, without the report of the panic.
fn caught(f: impl FnOnce() -> String) -> String {
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
    let r = catch_unwind(AssertUnwindSafe(f));
    QUIET.with(|q| q.set(false));
    match r {
        Ok(v) => v,
        Err(p) => format!(
            "PANIC {}",
            p.downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default()
        ),
    }
}

/// An error as text without the places of the crates that made it.
fn plain(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(j) = rest.find(".rs:") {
        match rest[..j].rfind(" at ") {
            Some(i) => {
                out.push_str(&rest[..i]);
                let after = &rest[j + 4..];
                let digits = after.chars().take_while(char::is_ascii_digit).count();
                rest = &after[digits..];
            }
            None => {
                out.push_str(&rest[..j + 4]);
                rest = &rest[j + 4..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

macro_rules! sample_cases {
    ($name:ident, $z:ident, $cfg:ident, $p:ident, $codec:ident, $buf:ident) => {
        mod $name {
            use super::*;
            use $z::{
                handlers::CallbackParameter,
                internal::traits::{
                    EncodingBuilderTrait, QoSBuilderTrait, SampleBuilderTrait,
                    TimestampBuilderTrait, TimestampInstrumentationBuilderTrait,
                },
                key_expr::KeyExpr,
                qos::{CongestionControl, Priority, Reliability},
                sample::{
                    Locality, Sample, SampleBuilder, SampleBuilderAny, SampleBuilderDelete,
                    SampleBuilderPut, SampleFields, SampleKind, SourceInfo,
                },
                session::{EntityGlobalId, ZenohId},
                time::{Timestamp, TimestampId, NTP64},
                timestamp_stack::{
                    InstrumentationTimestamp, InterceptionPoint, TimestampInstrumentation,
                    TimestampInstrumentationBuilder, TimestampStack,
                },
            };

            pub fn priority() -> Vec<String> {
                let mut out = vec![];
                for b in 0..=255u8 {
                    out.push(format!(
                        "try_from({b}): {}",
                        match Priority::try_from(b) {
                            Ok(p) => format!("Ok({p:?})"),
                            Err(e) => format!("Err({})", plain(&e.to_string())),
                        }
                    ));
                }
                out.push(format!("default: {:?} {:?}", Priority::default(), Priority::DEFAULT));
                out.push(format!(
                    "internal: {:?} {:?} {}",
                    Priority::MIN,
                    Priority::MAX,
                    Priority::NUM
                ));
                for b in 1..=7u8 {
                    let p = Priority::try_from(b).unwrap();
                    let conf: $cfg::qos::PriorityConf = p.into();
                    let back: Priority = conf.into();
                    let proto: $p::core::Priority = p.into();
                    out.push(format!(
                        "{p:?}: conf={conf:?} back={back:?} proto={proto:?} proto_back={:?} copy_eq={} hash={}",
                        Priority::try_from(proto).map_err(|e| plain(&e.to_string())),
                        p == back,
                        hash_of(&p) == hash_of(&back)
                    ));
                    let json = format!("\"{p:?}\"");
                    out.push(format!(
                        "serde {json}: {:?}",
                        serde_json::from_str::<Priority>(&json).map_err(|e| e.to_string())
                    ));
                }
                out.push(format!(
                    "control: {:?}",
                    Priority::try_from($p::core::Priority::Control).map_err(|e| plain(&e.to_string()))
                ));
                for j in ["\"Nope\"", "\"realtime\"", "5", "null", "\"\""] {
                    out.push(format!(
                        "serde {j}: {:?}",
                        serde_json::from_str::<Priority>(j).map_err(|e| e.to_string())
                    ));
                }
                out
            }

            pub fn locality_and_kind() -> Vec<String> {
                let mut out = vec![];
                out.push(format!("locality default: {:?}", Locality::default()));
                for l in [Locality::SessionLocal, Locality::Remote, Locality::Any] {
                    let conf: $cfg::qos::PublisherLocalityConf = l.into();
                    let back: Locality = conf.into();
                    let json = serde_json::to_string(&l).unwrap();
                    out.push(format!(
                        "{l:?}: conf={conf:?} back={back:?} json={json} from_json={:?} eq={}",
                        serde_json::from_str::<Locality>(&json).unwrap(),
                        l == back
                    ));
                }
                out.push(format!(
                    "locality from nothing: {:?}",
                    serde_json::from_str::<Locality>("\"Nowhere\"").map_err(|e| e.to_string())
                ));
                out.push(format!("kind default: {:?}", SampleKind::default()));
                for k in [SampleKind::Put, SampleKind::Delete] {
                    let json = serde_json::to_string(&k).unwrap();
                    out.push(format!("{k:?}: display={k} as_u8={} json={json}", k as u8));
                }
                for n in [0u64, 1, 2, 255, u64::MAX] {
                    out.push(format!("kind try_from({n}): {:?}", SampleKind::try_from(n)));
                }
                out
            }

            fn show(s: &Sample) -> String {
                format!(
                    "key={} payload={:?} kind={} encoding={} timestamp={:?} cc={:?} prio={:?} express={} rel={:?} sinfo={:?} tstack={:?} att={:?} | {:?}",
                    s.key_expr(),
                    s.payload().to_bytes(),
                    s.kind(),
                    s.encoding(),
                    s.timestamp().map(|t| t.to_string()),
                    s.congestion_control(),
                    s.priority(),
                    s.express(),
                    s.reliability(),
                    s.source_info().map(|i| (format!("{:?}", i.source_id()), i.source_sn())),
                    s.timestamp_stack(),
                    s.attachment().map(|a| a.to_bytes().to_vec()),
                    s
                )
            }

            fn ts(n: u64) -> Timestamp {
                Timestamp::new(NTP64(n), TimestampId::try_from([1u8, 2, 3, 4]).unwrap())
            }

            pub fn builders() -> Vec<String> {
                let mut out = vec![];
                let ke = |s: &str| KeyExpr::try_from(s.to_string()).unwrap();
                let eid = EntityGlobalId::new("a1b2c3".parse::<ZenohId>().unwrap(), 7);
                let instr = TimestampInstrumentationBuilder::new()
                    .set_send(true)
                    .set_receive(true)
                    .build()
                    .unwrap();
                let put = SampleBuilder::put(ke("a/b"), "hello");
                out.push(format!("put plain: {}", show(&put.clone().into())));
                let full = SampleBuilder::put(ke("a/b"), "hello")
                    .payload(vec![1u8, 2, 3])
                    .keyexpr(ke("c/d"))
                    .congestion_control(CongestionControl::Block)
                    .priority(Priority::RealTime)
                    .express(true)
                    .timestamp(Some(ts(42)))
                    .attachment("att")
                    .encoding($z::bytes::Encoding::TEXT_PLAIN)
                    .reliability(Reliability::BestEffort)
                    .source_info(Some(SourceInfo::new(eid, 9)))
                    .timestamp_instrumentation(Some(instr));
                out.push(format!("put full: {}", show(&full.clone().into())));
                let cleared = full
                    .clone()
                    .timestamp(None::<Timestamp>)
                    .attachment(None::<$z::bytes::ZBytes>)
                    .source_info(None::<SourceInfo>)
                    .timestamp_instrumentation(None::<TimestampInstrumentation>);
                out.push(format!("put cleared: {}", show(&cleared.into())));
                let del = SampleBuilder::delete(ke("x/y"));
                out.push(format!("delete plain: {}", show(&del.clone().into())));
                let del_full = del
                    .keyexpr(ke("x/z"))
                    .congestion_control(CongestionControl::Drop)
                    .priority(Priority::Background)
                    .express(false)
                    .timestamp(Some(ts(7)))
                    .attachment(vec![9u8])
                    .reliability(Reliability::Reliable);
                out.push(format!("delete full: {}", show(&del_full.clone().into())));

                let put_sample: Sample = full.into();
                let del_sample: Sample = del_full.into();
                let any: SampleBuilder<SampleBuilderAny> = put_sample.clone().into();
                out.push(format!("any: {}", show(&any.into())));
                out.push(format!(
                    "put from a put: {}",
                    match SampleBuilder::<SampleBuilderPut>::try_from(put_sample.clone()) {
                        Ok(b) => show(&b.into()),
                        Err(e) => format!("Err({})", plain(&e.to_string())),
                    }
                ));
                out.push(format!(
                    "put from a delete: {}",
                    match SampleBuilder::<SampleBuilderPut>::try_from(del_sample.clone()) {
                        Ok(b) => show(&b.into()),
                        Err(e) => format!("Err({})", plain(&e.to_string())),
                    }
                ));
                out.push(format!(
                    "delete from a delete: {}",
                    match SampleBuilder::<SampleBuilderDelete>::try_from(del_sample.clone()) {
                        Ok(b) => show(&b.into()),
                        Err(e) => format!("Err({})", plain(&e.to_string())),
                    }
                ));
                out.push(format!(
                    "delete from a put: {}",
                    match SampleBuilder::<SampleBuilderDelete>::try_from(put_sample.clone()) {
                        Ok(b) => show(&b.into()),
                        Err(e) => format!("Err({})", plain(&e.to_string())),
                    }
                ));
                let mut mutated = put_sample.clone();
                mutated.payload_mut().clone_from(&$z::bytes::ZBytes::from("changed"));
                if let Some(a) = mutated.attachment_mut() {
                    *a = $z::bytes::ZBytes::from("changed attachment");
                }
                out.push(format!("mutated: {}", show(&mutated)));
                out.push(format!("original untouched: {}", show(&put_sample)));
                let fields: SampleFields = put_sample.clone().into();
                out.push(format!("fields: {fields:?}"));
                let empty = Sample::empty();
                out.push(format!("empty: {}", show(&empty)));
                out.push(format!("empty fields: {:?}", SampleFields::from(empty)));
                out
            }

            /// The id of an entity, the same in both crates: a random one would differ by nothing but luck.
            fn fixed_id(eid: u32) -> $p::core::EntityGlobalIdProto {
                $p::core::EntityGlobalIdProto {
                    zid: "a1b2c3".parse().unwrap(),
                    eid,
                }
            }

            fn body_put(
                timestamp: bool,
                sinfo: bool,
                attachment: bool,
                payload: &[u8],
            ) -> $p::zenoh::PushBody {
                use $buf::ZBuf;
                $p::zenoh::PushBody::Put($p::zenoh::Put {
                    timestamp: timestamp.then(|| ts(100)),
                    encoding: Default::default(),
                    ext_sinfo: sinfo.then(|| $p::zenoh::ext::SourceInfoType {
                        id: fixed_id(1),
                        sn: 5,
                    }),
                    ext_attachment: attachment.then(|| $p::zenoh::ext::AttachmentType {
                        buffer: ZBuf::from(vec![7u8, 8]),
                    }),
                    ext_unknown: vec![],
                    payload: ZBuf::from(payload.to_vec()),
                })
            }

            fn body_del(timestamp: bool, sinfo: bool, attachment: bool) -> $p::zenoh::PushBody {
                use $buf::ZBuf;
                $p::zenoh::PushBody::Del($p::zenoh::Del {
                    timestamp: timestamp.then(|| ts(200)),
                    ext_sinfo: sinfo.then(|| $p::zenoh::ext::SourceInfoType {
                        id: fixed_id(2),
                        sn: 6,
                    }),
                    ext_attachment: attachment.then(|| $p::zenoh::ext::AttachmentType {
                        buffer: ZBuf::from(vec![9u8]),
                    }),
                    ext_unknown: vec![],
                })
            }

            fn proto_stack(flags: &[(u8, Vec<u8>)], conf: u8) -> $p::network::timestamp_stack::TimestampStack {
                $p::network::timestamp_stack::TimestampStack {
                    conf_flags: conf,
                    stack: flags
                        .iter()
                        .map(|(f, t)| $p::network::timestamp_stack::Interception {
                            flags: *f,
                            timestamp: t.clone(),
                        })
                        .collect(),
                }
            }

            fn uhlc_bytes(n: u64) -> Vec<u8> {
                use $codec::{WCodec, Zenoh080};
                let mut buf = Vec::new();
                Zenoh080.write(&mut buf, &ts(n)).unwrap();
                buf
            }

            pub fn from_frames() -> Vec<String> {
                use $buf::buffer::Buffer;
                let mut out = vec![];
                let ke = || KeyExpr::try_from("f/g".to_string()).unwrap();
                let qos_types = [
                    $p::network::push::ext::QoSType::DEFAULT,
                    $p::network::push::ext::QoSType::new(
                        $p::core::Priority::RealTime,
                        $p::core::CongestionControl::Block,
                        true,
                    ),
                    $p::network::push::ext::QoSType::new(
                        $p::core::Priority::Background,
                        $p::core::CongestionControl::Drop,
                        false,
                    ),
                    $p::network::push::ext::QoSType::new(
                        $p::core::Priority::Control,
                        $p::core::CongestionControl::Block,
                        false,
                    ),
                ];
                let stacks: Vec<Option<$p::network::timestamp_stack::TimestampStack>> = vec![
                    None,
                    Some(proto_stack(&[(1, uhlc_bytes(11)), (2, uhlc_bytes(12)), (4, uhlc_bytes(13))], 7)),
                    Some(proto_stack(&[(1 | 0x80, b"custom".to_vec()), (4, uhlc_bytes(3))], 5)),
                    Some(proto_stack(&[(1, vec![0xFF])], 1)),
                    Some(proto_stack(&[(0x10, uhlc_bytes(1)), (1, uhlc_bytes(2))], 1)),
                    Some(proto_stack(&[], 0)),
                    Some(proto_stack(&[], 3)),
                ];
                for (qi, qos) in qos_types.iter().enumerate() {
                    for rel in [$p::core::Reliability::Reliable, $p::core::Reliability::BestEffort] {
                        for (si, stack) in stacks.iter().enumerate() {
                            for (t, i, a) in [(false, false, false), (true, true, true), (true, false, true)] {
                                let mut body = body_put(t, i, a, &[1, 2, 3, 4]);
                                let s = caught(|| {
                                    show(&Sample::from_message((ke(), *qos, &mut body, rel, stack.clone())))
                                });
                                out.push(format!("put q{qi} {rel:?} s{si} {t}{i}{a}: {s}"));
                                let mut body = body_del(t, i, a);
                                let s = caught(|| {
                                    show(&Sample::from_message((ke(), *qos, &mut body, rel, stack.clone())))
                                });
                                out.push(format!("del q{qi} {rel:?} s{si} {t}{i}{a}: {s}"));
                            }
                        }
                    }
                }
                let mut body = body_put(true, true, true, &[]);
                let sample = Sample::from_message((ke(), qos_types[0], &mut body, $p::core::Reliability::Reliable, None));
                let left = match &body {
                    $p::zenoh::PushBody::Put(p) => format!("payload left: {} attachment left: {}", p.payload.len(), p.ext_attachment.is_some()),
                    _ => unreachable!(),
                };
                out.push(format!("what the frame keeps: {left}; {}", show(&sample)));
                out
            }

            pub fn timestamp_stack() -> Vec<String> {
                let mut out = vec![];
                for b in 0..=255u8 {
                    out.push(format!(
                        "point({b}): {:?}",
                        InterceptionPoint::try_from(b).map_err(|e| plain(&e.to_string()))
                    ));
                }
                for p in [InterceptionPoint::Send, InterceptionPoint::Route, InterceptionPoint::Receive] {
                    out.push(format!("{p:?} as u8: {}", u8::from(p)));
                }
                for mask in 0..8u8 {
                    let r = TimestampInstrumentationBuilder::new()
                        .set_send(mask & 1 != 0)
                        .set_route(mask & 2 != 0)
                        .set_receive(mask & 4 != 0)
                        .build();
                    out.push(format!(
                        "builder {mask:03b}: {:?}",
                        match r {
                            Ok(i) => format!(
                                "Ok({i:?} send={} route={} receive={})",
                                i.is_instrumented(InterceptionPoint::Send),
                                i.is_instrumented(InterceptionPoint::Route),
                                i.is_instrumented(InterceptionPoint::Receive)
                            ),
                            Err(e) => format!("Err({})", plain(&e.to_string())),
                        }
                    ));
                }
                let b = TimestampInstrumentationBuilder::new()
                    .set_send(true)
                    .set_route(true)
                    .set_send(false)
                    .set_route(false);
                out.push(format!("all cleared again: {:?}", b.build().map_err(|e| plain(&e.to_string()))));
                out.push(format!("default instrumentation: {:?}", TimestampInstrumentation::default()));
                let sample = {
                    let mut body = body_put(false, false, false, &[]);
                    let stack = proto_stack(
                        &[(1, uhlc_bytes(21)), (2 | 0x80, b"x".to_vec()), (4, uhlc_bytes(22))],
                        7,
                    );
                    Sample::from_message((
                        KeyExpr::try_from("t/s".to_string()).unwrap(),
                        $p::network::push::ext::QoSType::DEFAULT,
                        &mut body,
                        $p::core::Reliability::Reliable,
                        Some(stack),
                    ))
                };
                let stack: &TimestampStack = sample.timestamp_stack().unwrap();
                out.push(format!("stack: {stack:?}"));
                out.push(format!("instrumentation: {:?}", stack.instrumentation()));
                for r in stack.records() {
                    out.push(format!(
                        "record: {:?} custom={} {:?} uhlc={}",
                        r.point(),
                        r.is_custom(),
                        r.timestamp(),
                        matches!(r.timestamp(), InstrumentationTimestamp::UHLC(_))
                    ));
                }
                let back: $p::network::timestamp_stack::TimestampStack = stack.into();
                out.push(format!("back to the wire: {back:?}"));
                out
            }
        }
    };
}

sample_cases!(up, up_zenoh, up_config, up_protocol, up_codec, up_buffers);
sample_cases!(wz, wz_zenoh, wz_config, wz_protocol, wz_codec, wz_buffers);

fn compare(group: &str, up: &[String], wz: &[String]) {
    assert!(up.len() > 2, "{group} holds {} line(s)", up.len());
    assert_eq!(up.len(), wz.len(), "{group}: the groups differ in length");
    if let Some((x, y)) = up.iter().zip(wz).find(|(x, y)| x != y) {
        panic!("{group}\nupstream: {x}\nwz:       {y}");
    }
    if std::env::var_os("WZ_SAMPLE_TRANSCRIPT").is_some() {
        for line in up {
            println!("{group}: {line}");
        }
    }
}

#[test]
fn the_priority_of_a_message() {
    let (u, w) = (up::priority(), wz::priority());
    assert!(u.iter().any(|l| l == "try_from(5): Ok(Data)"), "{u:#?}");
    assert!(u.iter().any(|l| l.starts_with("try_from(0): Err(0 is not a valid priority")), "{u:#?}");
    compare("priority", &u, &w);
}

#[test]
fn the_locality_and_the_kind_of_a_sample() {
    let (u, w) = (up::locality_and_kind(), wz::locality_and_kind());
    assert!(u.iter().any(|l| l.contains("display=DELETE")), "{u:#?}");
    compare("locality and kind", &u, &w);
}

#[test]
fn the_builders_of_a_sample() {
    let (u, w) = (up::builders(), wz::builders());
    assert!(u.iter().any(|l| l.starts_with("put from a delete: Err(")), "{u:#?}");
    compare("builders", &u, &w);
}

#[test]
fn the_sample_of_a_frame() {
    let (u, w) = (up::from_frames(), wz::from_frames());
    assert!(u.len() > 200, "{}", u.len());
    compare("frames", &u, &w);
}

#[test]
fn the_timestamp_stack() {
    let (u, w) = (up::timestamp_stack(), wz::timestamp_stack());
    assert!(u.iter().any(|l| l.starts_with("builder 000: \"Err(")), "{u:#?}");
    compare("timestamp stack", &u, &w);
}

#[test]
fn the_comparison_sees_a_sample_that_differs() {
    let u = up::builders();
    let mut w = wz::builders();
    let i = w.iter().position(|l| l.starts_with("put plain:")).unwrap();
    w[i] = format!("{} changed", w[i]);
    assert!(u.iter().zip(&w).any(|(x, y)| x != y));
    assert_ne!(up::builders(), up::priority());
}
