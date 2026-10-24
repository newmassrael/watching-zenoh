// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-protocol`, the core types and the scouting messages: upstream's crate (`up_protocol`) and
//! wz's (`wz_protocol`) given the same inputs, outputs equal.
//!
//! Each family of types is driven by the inputs it takes in practice and then by the inputs that
//! are made to break it: identifiers as every short string of a small alphabet and every length of
//! bytes, priorities and reliabilities as every `u8`, node kinds as every combination, key
//! expression references as every scope, suffix and mapping, parameters, endpoints, locators and
//! regions as every sequence of up to four pieces of their own vocabulary (which includes the
//! separators, the empty piece, a key with no value and a value with no key), and the resolution of
//! a transport as every byte. What each returns is compared as text (the `Display` and `Debug` of
//! a success, the message of a failure without the place it was raised at), so a difference in
//! what is refused, in what it says, or in what is built, is a difference here.
//!
//! Four places are not compared, because upstream is wrong in them and wz follows the documented
//! definition; each is shown on upstream's crate and held to the definition on wz's:
//! * `ProtocolMut::as_str` answers the address of the endpoint, not its protocol;
//! * `PriorityRange::len` of a range whose end is before its start subtracts below zero, and
//!   `is_empty` answers `false` for every range;
//! * a `WhatAmIMatcher` that is `|`-ed with an integer carrying bits that are not a node kind keeps
//!   them, and its `to_str` then reaches an `unreachable!()`;
//! * `Parameters` sorted by key are not in a defined order for equal keys in a long list (an
//!   unstable sort); wz's is stable. Not shown on upstream, whose order is merely unspecified.
//! And one that cannot be shown by running it: `CowStr` made from a `String` with spare capacity
//! and then added to is undefined behaviour in upstream (a boxed string whose recorded capacity is
//! not the allocation's), so upstream is only given strings without spare capacity and wz both.

use std::fmt::Display;

/// The pieces strings are made of for each family, in every sequence up to a length.
fn sequences(pieces: &[&str], max: usize) -> Vec<String> {
    let mut all = vec![String::new()];
    let mut layer = vec![String::new()];
    for _ in 0..max {
        let mut next = Vec::new();
        for s in &layer {
            for p in pieces {
                next.push(format!("{s}{p}"));
            }
        }
        all.extend(next.iter().cloned());
        layer = next;
    }
    all
}

macro_rules! protocol_cases {
    ($name:ident, $p:ident) => {
        mod $name {
            use std::{collections::BTreeSet, fmt::Write as _, str::FromStr};

            use $p::{
                core::{
                    parameters, whatami::WhatAmIMatcher, Address, Bits, Channel, CongestionControl,
                    Encoding, EndPoint, EndPoints, Field, Locator, Parameters, Priority,
                    PriorityRange, Region, RegionName, Reliability, Resolution, WhatAmI, WireExpr,
                    ZenohIdProto,
                },
                network::Mapping,
                scouting::{HelloProto, Scout, ScoutingMessage},
            };

            use super::text;

            fn show<T: std::fmt::Debug, E: std::fmt::Display>(r: Result<T, E>) -> String {
                match r {
                    Ok(v) => format!("ok {v:?}"),
                    Err(e) => format!("err {}", text(e)),
                }
            }

            pub fn zid(s: &str) -> String {
                match s.parse::<ZenohIdProto>() {
                    Ok(z) => format!(
                        "ok {z} {} {:?} {} {} {}",
                        z.size(),
                        z.to_le_bytes(),
                        z.short(),
                        serde_json::to_string(&z).unwrap(),
                        z.into_keyexpr()
                    ),
                    Err(e) => format!("err {}", text(e)),
                }
            }

            pub fn zid_from_bytes(bytes: &[u8]) -> String {
                match ZenohIdProto::try_from(bytes) {
                    Ok(z) => format!("ok {z} {}", z.size()),
                    Err(e) => format!("err {}", text(e)),
                }
            }

            pub fn zid_json(s: &str) -> String {
                show(serde_json::from_str::<ZenohIdProto>(s))
            }

            pub fn priorities() -> Vec<String> {
                let mut out = Vec::new();
                for v in 0..=255u8 {
                    out.push(match Priority::try_from(v) {
                        Ok(p) => {
                            format!("{v}: ok {p} {p:?} {}", serde_json::to_string(&p).unwrap())
                        }
                        Err(e) => format!("{v}: err {}", text(e)),
                    });
                    out.push(format!(
                        "{v}: {}",
                        show(Reliability::from_str(&v.to_string()))
                    ));
                }
                out.push(format!(
                    "consts {:?} {:?} {:?} {} {:?} {:?}",
                    Priority::DEFAULT,
                    Priority::MIN,
                    Priority::MAX,
                    Priority::NUM,
                    Channel::DEFAULT,
                    Channel::default()
                ));
                out.push(format!(
                    "{:?} {:?} {} {} {}",
                    Reliability::DEFAULT,
                    Reliability::default(),
                    bool::from(Reliability::BestEffort),
                    Reliability::from(true),
                    serde_json::to_string(&Reliability::BestEffort).unwrap()
                ));
                out.push(format!(
                    "{:?} {:?} {:?}",
                    CongestionControl::DEFAULT,
                    serde_json::from_str::<CongestionControl>("\"Block\"").unwrap(),
                    serde_json::from_str::<CongestionControl>("\"BlockFirst\"").unwrap()
                ));
                out
            }

            /// A range as text, without its length when it is inverted (the length is a class).
            pub fn priority_range(s: &str) -> String {
                match s.parse::<PriorityRange>() {
                    Ok(r) => {
                        let mut line = format!("ok {r} {r:?}");
                        if r.start() <= r.end() {
                            write!(line, " len={} empty={}", r.len(), r.is_empty()).unwrap();
                        }
                        let all = PriorityRange::new(Priority::Control..=Priority::Background);
                        write!(
                            line,
                            " in-all={} all-in={}",
                            all.includes(&r),
                            r.includes(&all)
                        )
                        .unwrap();
                        line
                    }
                    Err(e) => format!("err {}", text(format!("{e:?} / {e}"))),
                }
            }

            pub fn node_kinds() -> Vec<String> {
                let mut out = Vec::new();
                for v in 0..=255u8 {
                    out.push(format!(
                        "{v}: {} {}",
                        show(WhatAmI::try_from(v).map_err(|_| "no")),
                        show(
                            WhatAmIMatcher::try_from(v)
                                .map(|m| (m.to_str(), m.is_empty()))
                                .map_err(|_| "no")
                        )
                    ));
                }
                let kinds = [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client];
                for a in kinds {
                    out.push(format!(
                        "{a} {a:?} {} {} {} {}",
                        a.to_str(),
                        serde_json::to_string(&a).unwrap(),
                        a.is_router(),
                        a.is_peer() as u8 + 2 * a.is_client() as u8
                    ));
                    for b in kinds {
                        let m = a | b;
                        out.push(format!(
                            "{a}|{b} = {m} {} {} {}",
                            u8::from(m),
                            serde_json::to_string(&m).unwrap(),
                            kinds.iter().filter(|k| m.matches(**k)).count()
                        ));
                        for c in kinds {
                            let m3 = (m | c) | WhatAmIMatcher::from(a);
                            out.push(format!("{m3} {:?}", m3));
                        }
                    }
                }
                out
            }

            pub fn kind_strings(s: &str) -> String {
                format!(
                    "{} | {} | {} | {}",
                    show(s.parse::<WhatAmI>()),
                    show(s.parse::<WhatAmIMatcher>().map_err(|_| "no")),
                    show(serde_json::from_str::<WhatAmI>(s)),
                    show(serde_json::from_str::<WhatAmIMatcher>(s)),
                )
            }

            /// The matcher `|`-ed with an integer: its text, or that it panicked.
            pub fn matcher_or_raw(bits: u8) -> String {
                std::panic::catch_unwind(|| (WhatAmIMatcher::empty() | bits).to_str().to_string())
                    .unwrap_or_else(|_| "panicked".to_string())
            }

            pub fn wire_exprs() -> Vec<String> {
                let mut out = Vec::new();
                for scope in [0u16, 1, 300] {
                    for suffix in ["", "a/b", "*"] {
                        for mapping in [Mapping::Sender, Mapping::Receiver] {
                            let w = WireExpr {
                                scope,
                                suffix: suffix.into(),
                                mapping,
                            };
                            let mut line = format!("{w} {w:?} {} {}", w.is_empty(), w.has_suffix());
                            write!(line, " str={} id={}", w.as_str(), w.as_id()).unwrap();
                            write!(line, " {} {}", show(w.try_as_str()), show(w.try_as_id()))
                                .unwrap();
                            write!(line, " {:?}", w.as_id_and_suffix()).unwrap();
                            let suffixed = w.clone().with_suffix("/x");
                            write!(line, " {suffixed} {}", w.to_owned() == w).unwrap();
                            let into: Result<String, _> = w.clone().try_into();
                            write!(line, " {}", show(into)).unwrap();
                            let id: Result<u16, _> = w.clone().try_into();
                            write!(line, " {}", show(id)).unwrap();
                            out.push(line);
                        }
                    }
                }
                out.push(format!(
                    "{} {} {:?} {:?} {:?}",
                    WireExpr::empty(),
                    WireExpr::from(7u16),
                    WireExpr::from("k"),
                    WireExpr::from(String::from("s")),
                    WireExpr::from(&String::from("t")),
                ));
                out
            }

            pub fn params(s: &str) -> String {
                let mut line = String::new();
                let pairs: Vec<_> = parameters::iter(s).collect();
                write!(
                    line,
                    "{pairs:?} wf={} ord={}",
                    parameters::is_well_formed(s),
                    parameters::is_ordered(s)
                )
                .unwrap();
                for key in ["a", "b", "c", ""] {
                    write!(
                        line,
                        " [{key}: {:?} {:?}]",
                        parameters::get(s, key),
                        parameters::values(s, key).collect::<Vec<_>>()
                    )
                    .unwrap();
                }
                write!(
                    line,
                    " ins={:?} sort={:?} rm={:?}",
                    parameters::insert(s, "a", "9"),
                    parameters::insert_sort(s, "b", "8"),
                    parameters::remove(s, "a")
                )
                .unwrap();
                write!(
                    line,
                    " sorted={}",
                    parameters::from_iter(parameters::sort(parameters::iter(s)))
                )
                .unwrap();
                write!(
                    line,
                    " joined={}",
                    parameters::from_iter(parameters::join(
                        parameters::iter(s),
                        parameters::iter("a=Z;q=1")
                    ))
                )
                .unwrap();
                let mut p = Parameters::from(s);
                write!(line, " P={p} empty={} ord={}", p.is_empty(), p.is_ordered()).unwrap();
                let old = p.insert("a", "7");
                let gone = p.remove("b");
                p.extend(&Parameters::from("c=5;d"));
                write!(line, " -> {old:?} {gone:?} {p}").unwrap();
                line
            }

            /// The endpoint after an edit, or why the edit was refused.
            fn edited<E: std::fmt::Display>(
                ep: &EndPoint,
                edit: impl FnOnce(&mut EndPoint) -> Result<(), E>,
            ) -> String {
                let mut m = ep.clone();
                match edit(&mut m) {
                    Ok(()) => format!("ok {m}"),
                    Err(e) => format!("err {}", text(e)),
                }
            }

            fn endpoint_line(ep: &EndPoint) -> String {
                let (pr, ad, md, cf) = ep.split();
                format!(
                    "{ep} {ep:?} [{pr}|{ad}|{md}|{cf}] md={:?} cf={:?} loc={}",
                    md.iter().collect::<Vec<_>>(),
                    cf.iter().collect::<Vec<_>>(),
                    ep.to_locator()
                )
            }

            pub fn endpoint(s: &str) -> String {
                match EndPoint::from_str(s) {
                    Ok(ep) => {
                        let mut line = format!("ok {}", endpoint_line(&ep));
                        write!(
                            line,
                            " | md+ {}",
                            edited(&ep, |m| m.metadata_mut().insert("c", "3"))
                        )
                        .unwrap();
                        write!(
                            line,
                            " | md- {}",
                            edited(&ep, |m| m.metadata_mut().remove("a"))
                        )
                        .unwrap();
                        write!(
                            line,
                            " | cf+ {}",
                            edited(&ep, |m| m.config_mut().insert("Z", "1"))
                        )
                        .unwrap();
                        write!(
                            line,
                            " | cf- {}",
                            edited(&ep, |m| m.config_mut().remove("A"))
                        )
                        .unwrap();
                        write!(
                            line,
                            " | proto {}",
                            edited(&ep, |m| m.protocol_mut().set("p"))
                        )
                        .unwrap();
                        write!(
                            line,
                            " | addr {}",
                            edited(&ep, |m| m.address_mut().set("z:1"))
                        )
                        .unwrap();
                        write!(
                            line,
                            " | ext {}",
                            edited(&ep, |m| m
                                .metadata_mut()
                                .extend_from_iter([("b", "0"), ("a", "1")].iter().copied()))
                        )
                        .unwrap();
                        let mut m = ep.clone();
                        let address = m.address_mut().as_str().to_string();
                        let meta = m.metadata_mut().as_str().to_string();
                        let config = m.config_mut().as_str().to_string();
                        write!(line, " | views {address} {meta} {config}").unwrap();
                        line
                    }
                    Err(e) => format!("err {}", text(e)),
                }
            }

            /// The text `ProtocolMut::as_str` answers for an endpoint: the class.
            pub fn protocol_mut_text(s: &str) -> String {
                let mut ep = EndPoint::from_str(s).unwrap();
                ep.protocol_mut().as_str().to_string()
            }

            pub fn locator(s: &str) -> String {
                match Locator::from_str(s) {
                    Ok(l) => format!(
                        "ok {l} {l:?} {} {} {:?} {} {}",
                        l.protocol(),
                        l.address(),
                        l.metadata().iter().collect::<Vec<_>>(),
                        l.to_endpoint(),
                        serde_json::to_string(&l).unwrap()
                    ),
                    Err(e) => format!("err {}", text(e)),
                }
            }

            pub fn endpoints(s: &str) -> String {
                format!(
                    "{} | {}",
                    show(EndPoints::from_str(s)),
                    show(serde_json::from_str::<EndPoints>(s))
                )
            }

            pub fn constructed() -> Vec<String> {
                let mut out = Vec::new();
                for (p, a, m, c) in [
                    ("tcp", "h:1", "", ""),
                    ("tcp", "h:1", "rel=1", "A=1"),
                    ("", "h", "", ""),
                    ("tcp", "", "", ""),
                    ("tcp", "h", "b=1;a=2", "z"),
                ] {
                    out.push(show(EndPoint::new(p, a, m, c)));
                    out.push(show(Locator::new(p, a, m)));
                }
                out.push(show(EndPoint::new("t", "a".repeat(300), "", "")));
                out.push(format!(
                    "{:?} {:?}",
                    Address::from("x"),
                    EndPoint::from_str("a/b").unwrap().address()
                ));
                out
            }

            pub fn resolutions() -> Vec<String> {
                let mut out = Vec::new();
                for v in 0..=255u8 {
                    let r = Resolution::from(v);
                    let mut line = format!(
                        "{v}: {:?} {:?} {}",
                        r.get(Field::FrameSN),
                        r.get(Field::RequestID),
                        r.as_u8()
                    );
                    for field in [Field::FrameSN, Field::RequestID] {
                        for bits in [Bits::U8, Bits::U16, Bits::U32, Bits::U64] {
                            let mut m = r;
                            m.set(field, bits);
                            write!(line, " {}", m.as_u8()).unwrap();
                        }
                    }
                    out.push(line);
                }
                out.push(format!("{:?}", Resolution::default()));
                for b in [Bits::U8, Bits::U16, Bits::U32, Bits::U64] {
                    out.push(format!(
                        "{b} {b:?} {} {} {} {}",
                        b.bits(),
                        b.mask(),
                        serde_json::to_string(&b).unwrap(),
                        show(b.to_string().parse::<Bits>())
                    ));
                }
                for s in ["8bit", "9bit", "", "64BIT"] {
                    out.push(format!(
                        "{s}: {} {}",
                        show(s.parse::<Bits>()),
                        show(serde_json::from_str::<Bits>(&format!("\"{s}\"")))
                    ));
                }
                out.push(format!(
                    "{:?} {:?} {:?} {:?}",
                    Bits::from(1u8),
                    Bits::from(1u16),
                    Bits::from(1u32),
                    Bits::from(1u64)
                ));
                out
            }

            pub fn region(s: &str) -> String {
                match Region::from_str(s) {
                    Ok(r) => format!(
                        "ok {r} {r:?} {:?} {:?} {}",
                        r.bound(),
                        r.mode(),
                        serde_json::to_string(&r).unwrap()
                    ),
                    Err(e) => format!("err {}", text(e)),
                }
            }

            pub fn region_order() -> String {
                let mut regions: Vec<Region> = Vec::new();
                for r in [
                    "south:2:client",
                    "north",
                    "local",
                    "south:1:router",
                    "south:1:peer",
                ] {
                    regions.push(Region::from_str(r).unwrap());
                }
                regions.sort();
                format!("{regions:?}")
            }

            pub fn region_name(s: &str) -> String {
                match RegionName::from_str(s) {
                    Ok(n) => format!("ok {n:?} {}", n.as_str()),
                    Err(e) => format!("err {}", text(e)),
                }
            }

            pub fn scouting() -> Vec<String> {
                let mut out = Vec::new();
                let zid: ZenohIdProto = "a1b2c3".parse().unwrap();
                for what in [
                    WhatAmI::Router | WhatAmI::Client,
                    WhatAmIMatcher::empty().peer(),
                ] {
                    for z in [None, Some(zid)] {
                        let s = Scout {
                            version: 9,
                            what,
                            zid: z,
                        };
                        out.push(format!("{:?}", ScoutingMessage::from(s)));
                    }
                }
                let h = HelloProto {
                    version: 9,
                    whatami: WhatAmI::Peer,
                    zid,
                    locators: vec![Locator::from_str("tcp/h:1?rel=1").unwrap()],
                };
                out.push(format!("{:?}", ScoutingMessage::from(h)));
                out
            }

            pub fn encoding_hash() -> Vec<String> {
                use std::hash::{Hash, Hasher};
                [
                    Encoding::empty(),
                    Encoding {
                        id: 3,
                        schema: None,
                    },
                    Encoding {
                        id: 3,
                        schema: Some(vec![1u8, 2, 3].into()),
                    },
                ]
                .iter()
                .map(|e| {
                    let mut h = std::collections::hash_map::DefaultHasher::new();
                    e.hash(&mut h);
                    format!("{e:?} {}", h.finish())
                })
                .collect()
            }

            /// `CowStr` over an owned and a borrowed string: equality, text, clone, length, and
            /// the borrowed one added to. The owned one is NOT added to here: upstream frees its
            /// allocation twice when it is (see `an_owned_cowstr_added_to_aborts_in_upstream`).
            pub fn cowstr_tight(s: &str) -> String {
                use $p::core::CowStr;
                let owned = CowStr::from(s.to_string());
                let borrowed = CowStr::from(s);
                let (same, cloned) = (owned == borrowed, owned.clone().as_str().to_string());
                let head = format!("{owned} {borrowed:?} {same} {cloned} {}", borrowed.len());
                // Not a clone of the borrowed one: a clone owns its text, and adding to that is
                // the double free.
                let grown_borrowed = CowStr::from(s) + "-";
                format!("{head} {grown_borrowed}")
            }

            /// An owned `CowStr` added to, with spare capacity or without: the class.
            pub fn cowstr_owned_add(s: &str, spare: usize) -> String {
                use $p::core::CowStr;
                let mut text = String::with_capacity(s.len() + spare);
                text.push_str(s);
                let owned = CowStr::from(text);
                format!("{}", owned + "+")
            }

            /// What the `test` feature's random constructors can make, as the set of classes of
            /// value seen over many draws (the draws themselves differ, so what is held equal is
            /// the set of shapes each constructor reaches).
            pub fn rand_shapes() -> Vec<(&'static str, BTreeSet<String>)> {
                const DRAWS: usize = 20_000;
                fn shapes<T>(
                    draw: impl Fn() -> T,
                    class: impl Fn(T) -> String,
                ) -> BTreeSet<String> {
                    (0..DRAWS).map(|_| class(draw())).collect()
                }
                let key = |s: &str| format!("{s}");
                vec![
                    (
                        "zid",
                        shapes(ZenohIdProto::rand, |z| {
                            let s = z.to_string();
                            let back = ZenohIdProto::from_str(&s).map(|b| b == z).unwrap_or(false);
                            // The id is 128 uniform bits written without leading zeros, so each
                            // length below 32 is a tail one that 20 000 draws may miss: the classes
                            // are the full width (15 in 16) and a trimmed one (1 in 16).
                            let width = if s.len() == 32 { "full" } else { "trimmed" };
                            format!("hex={width} back={back}")
                        }),
                    ),
                    ("whatami", shapes(WhatAmI::rand, |w| format!("{w:?}"))),
                    (
                        "matcher",
                        shapes(WhatAmIMatcher::rand, |m| key(&m.to_str())),
                    ),
                    (
                        "reliability",
                        shapes(Reliability::rand, |r| format!("{r:?}")),
                    ),
                    (
                        "priority range",
                        shapes(PriorityRange::rand, |r| r.to_string()),
                    ),
                    ("resolution", shapes(Resolution::rand, |r| format!("{r:?}"))),
                    (
                        "endpoint",
                        shapes(EndPoint::rand, |e| {
                            let back = EndPoint::from_str(e.as_str())
                                .map(|b| b == e)
                                .unwrap_or(false);
                            format!(
                                "proto={} address-ok={} meta={} config={} back={back}",
                                e.protocol().as_str().len(),
                                (2..8).contains(&e.address().as_str().len()),
                                !e.metadata().as_str().is_empty(),
                                !e.config().as_str().is_empty()
                            )
                        }),
                    ),
                    (
                        "locator",
                        shapes(Locator::rand, |l| {
                            let back = Locator::from_str(l.as_str())
                                .map(|b| b == l)
                                .unwrap_or(false);
                            format!("proto={} back={back}", l.protocol().as_str().len())
                        }),
                    ),
                    (
                        "region name",
                        shapes(RegionName::rand, |r| format!("len={}", r.as_str().len())),
                    ),
                    (
                        "wire expression",
                        shapes(WireExpr::rand, |w| {
                            format!("scope={} suffix={}", w.scope, !w.suffix.is_empty())
                        }),
                    ),
                    (
                        "encoding",
                        shapes(Encoding::rand, |e| match &e.schema {
                            None => "no schema".to_string(),
                            Some(s) => format!("schema of {}", s.len()),
                        }),
                    ),
                    (
                        "scout",
                        shapes(Scout::rand, |s| {
                            // The version is a uniform byte, so its class is the high bit: the
                            // 256 values times the other axes are more than the draws reach.
                            format!(
                                "v-high={} {:?} id={}",
                                s.version >= 128,
                                s.what,
                                s.zid.is_some()
                            )
                        }),
                    ),
                    (
                        "hello",
                        shapes(HelloProto::rand, |h| {
                            format!(
                                "v-high={} {:?} locators={}",
                                h.version >= 128,
                                h.whatami,
                                h.locators.len()
                            )
                        }),
                    ),
                    (
                        "scouting message",
                        shapes(ScoutingMessage::rand, |m| {
                            format!("{:?}", m.body)
                                .split('(')
                                .next()
                                .unwrap()
                                .to_string()
                        }),
                    ),
                ]
            }

            /// The range's length and emptiness for a range made inverted: the class.
            pub fn inverted_range() -> (Option<usize>, Option<bool>) {
                let r = PriorityRange::new(Priority::Background..=Priority::Control);
                let len = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| r.len())).ok();
                (len, Some(r.is_empty()))
            }
        }
    };
}

fn text(e: impl Display) -> String {
    let t = e.to_string();
    t.split(" at ").next().unwrap().to_string()
}

protocol_cases!(up, up_protocol);
protocol_cases!(wz, wz_protocol);

/// The two crates over every input, equal, returning how many inputs there were. For a family whose
/// outputs start with `ok` or `err`, `split` asks that both outcomes were seen.
fn compare_with(
    label: &str,
    inputs: &[String],
    split: bool,
    up: impl Fn(&str) -> String,
    wz: impl Fn(&str) -> String,
) -> usize {
    let (mut ok, mut err) = (0, 0);
    for s in inputs {
        let (a, b) = (up(s), wz(s));
        assert_eq!(a, b, "{label}: `{s}`");
        if a.starts_with("ok") {
            ok += 1;
        } else {
            err += 1;
        }
    }
    if split {
        assert!(ok > 0 && err > 0, "{label}: {ok} accepted, {err} refused");
    }
    inputs.len()
}

fn compare(
    label: &str,
    inputs: &[String],
    up: impl Fn(&str) -> String,
    wz: impl Fn(&str) -> String,
) -> usize {
    compare_with(label, inputs, true, up, wz)
}

fn same(label: &str, a: Vec<String>, b: Vec<String>) -> usize {
    assert_eq!(a.len(), b.len(), "{label}");
    for (i, (x, y)) in a.iter().zip(&b).enumerate() {
        assert_eq!(x, y, "{label}, line {i}");
    }
    a.len()
}

#[test]
fn both_crates_read_and_write_an_id_alike() {
    let mut inputs = sequences(&["a", "1", "f", "0", "A", "g", "-"], 4);
    for len in 0..40 {
        inputs.push("ab".repeat(len));
        inputs.push("0".repeat(len));
    }
    let n = compare("zid", &inputs, up::zid, wz::zid);
    assert!(n > 2000);
    for len in 0..20usize {
        let bytes: Vec<u8> = (0..len as u8).map(|b| b.wrapping_mul(37)).collect();
        assert_eq!(
            up::zid_from_bytes(&bytes),
            wz::zid_from_bytes(&bytes),
            "{len} bytes"
        );
    }
    for json in ["\"a1b2\"", "\"A1\"", "1", "\"\"", "\"zz\"", "null"] {
        assert_eq!(up::zid_json(json), wz::zid_json(json), "{json}");
    }
}

#[test]
fn both_crates_name_priorities_reliabilities_and_defaults_alike() {
    let n = same("priorities", up::priorities(), wz::priorities());
    assert!(n > 500);
    let mut inputs = sequences(&["0", "7", "8", "-", "1", "x"], 4);
    inputs.push("3-3".into());
    let n = compare(
        "priority range",
        &inputs,
        up::priority_range,
        wz::priority_range,
    );
    assert!(n > 500);
}

#[test]
fn both_crates_combine_and_read_node_kinds_alike() {
    same("node kinds", up::node_kinds(), wz::node_kinds());
    let inputs = sequences(&["router", "peer", "client", "|", " ", "x"], 3);
    compare_with(
        "kind strings",
        &inputs,
        false,
        up::kind_strings,
        wz::kind_strings,
    );
    let json = [
        "\"router\"",
        "\"peer\"",
        "\"gateway\"",
        "[\"router\",\"client\"]",
        "[]",
        "[\"x\"]",
        "3",
    ];
    for j in json {
        assert_eq!(up::kind_strings(j), wz::kind_strings(j), "{j}");
    }
}

#[test]
fn both_crates_make_key_expression_references_alike() {
    same("wire expressions", up::wire_exprs(), wz::wire_exprs());
}

#[test]
fn both_crates_manipulate_parameter_strings_alike() {
    let inputs = sequences(
        &["a", "b", "c", "=", "1", ";", "|", "a=1", "b=2;", "c=3|4"],
        4,
    );
    let n = compare_with("parameters", &inputs, false, up::params, wz::params);
    assert!(n > 10_000, "{n} strings");
}

#[test]
fn both_crates_parse_and_edit_endpoints_alike() {
    let pieces = [
        "udp",
        "/",
        "?",
        "#",
        "a=1",
        "b=2",
        "A=1",
        ";",
        "=",
        "127.0.0.1:7447",
        "x",
    ];
    let inputs = sequences(&pieces, 4);
    let n = compare("endpoint", &inputs, up::endpoint, wz::endpoint);
    assert!(n > 10_000, "{n} strings");
    let n = compare("locator", &inputs, up::locator, wz::locator);
    assert!(n > 10_000);
    // Four pieces cannot spell a metadata and a config that are each out of order, which needs
    // seven, so the orderings are a grid of their own: every metadata against every config, with
    // repeated keys, a key with no value and a key that sorts either side of another.
    let metadata = [
        "",
        "a=1",
        "b=2;a=1",
        "c=3;b=2;a=1",
        "b;a",
        "a=2;a=1",
        "m=1;a=1;z=1;b=1",
    ];
    let configs = [
        "",
        "B=2;A=1",
        "z;Y=1;x",
        "A=1;A=2",
        "d=4;c=3;b=2;a=1",
        "k=v|w;a",
    ];
    let mut grid = Vec::new();
    for m in metadata {
        for c in configs {
            let mut s = String::from("udp/127.0.0.1:7447");
            if !m.is_empty() {
                s.push('?');
                s.push_str(m);
            }
            if !c.is_empty() {
                s.push('#');
                s.push_str(c);
            }
            grid.push(s);
        }
    }
    // All of these are endpoints, so there is no refusal to look for.
    let n = compare_with(
        "endpoint orderings",
        &grid,
        false,
        up::endpoint,
        wz::endpoint,
    );
    assert_eq!(n, 42);
    assert!(grid.iter().all(|s| wz::endpoint(s).starts_with("ok")));
    compare_with("locator orderings", &grid, false, up::locator, wz::locator);
    same("constructed", up::constructed(), wz::constructed());
    let mut lists = vec![
        "udp/h:1".to_string(),
        "{\"strategy\":\"allOf\",\"locators\":[\"udp/h:1?rel=0\"]}".into(),
        "{\"strategy\":\"oneOf\",\"locators\":[]}".into(),
        "{\"strategy\":\"some\",\"locators\":[]}".into(),
        "\"udp/h:1\"".into(),
        "[]".into(),
        "".into(),
    ];
    lists.extend(sequences(&["udp", "/", "h", "?"], 3));
    for s in &lists {
        assert_eq!(up::endpoints(s), wz::endpoints(s), "{s}");
    }
}

#[test]
fn both_crates_agree_on_the_resolution_of_every_byte() {
    let n = same("resolution", up::resolutions(), wz::resolutions());
    assert!(n > 256);
}

#[test]
fn both_crates_name_regions_alike() {
    let pieces = [
        "north", "local", "south", ":", "0", "12", "router", "peer", "client", "x",
    ];
    let inputs = sequences(&pieces, 4);
    let n = compare("region", &inputs, up::region, wz::region);
    assert!(n > 5000);
    assert_eq!(up::region_order(), wz::region_order());
    let mut names = vec![
        String::new(),
        "a".repeat(32),
        "a".repeat(33),
        "é".repeat(16),
        "é".repeat(17),
    ];
    names.extend(sequences(&["a", "é"], 3));
    compare("region name", &names, up::region_name, wz::region_name);
}

#[test]
fn both_crates_build_scouting_messages_and_encodings_alike() {
    same("scouting", up::scouting(), wz::scouting());
    let (a, b) = (up::encoding_hash(), wz::encoding_hash());
    assert_eq!(a, b);
    for s in ["", "a", "key/expr", "é", "a longer piece of text"] {
        assert_eq!(up::cowstr_tight(s), wz::cowstr_tight(s), "{s:?}");
        for spare in [0, 1, 64] {
            assert_eq!(
                wz::cowstr_owned_add(s, spare),
                format!("{s}+"),
                "{s:?} {spare}"
            );
        }
    }
}

#[test]
fn both_crates_make_the_same_shapes_with_the_test_feature_constructors() {
    let (up, wz) = (up::rand_shapes(), wz::rand_shapes());
    assert_eq!(up.len(), wz.len());
    for ((name, a), (_, b)) in up.iter().zip(&wz) {
        assert_eq!(a, b, "random {name}");
        // A constructor that only ever made one shape would pass by being constant. A region
        // name is the one that does by upstream's definition: always as long as a name may be.
        assert!(
            a.len() > 1 || *name == "region name",
            "random {name} made one shape"
        );
    }
    // The classes are many where upstream's draws are: 7 node-kind sets and 16 resolutions.
    let count = |n: &str| up.iter().find(|(m, _)| *m == n).unwrap().1.len();
    assert_eq!(count("matcher"), 8);
    assert_eq!(count("resolution"), 16);
}

/// The child half of the test below: it runs the upstream operation only when it is asked to by
/// the parent, through the environment, and is a no-op in a normal run.
#[test]
fn cowstr_child() {
    if std::env::var_os("WZ_COWSTR_CHILD").is_some() {
        let added = up::cowstr_owned_add("some text", 0);
        // Reached only if the double free did not stop the process.
        println!("ADDED {added}");
    }
}

/// Upstream's `CowStr + &str` on an owned string rebuilds a `Vec` from the pointer of a `Box<str>`
/// it then drops, so the allocation is freed twice. A double free cannot be caught and compared in
/// the process that does it, so the test binary runs itself as a child to do it and the parent
/// reads that the child did not finish. wz's, which keeps the `String`, runs in this process.
#[test]
fn an_owned_cowstr_added_to_aborts_in_upstream() {
    if std::env::var_os("WZ_COWSTR_CHILD").is_some() {
        return;
    }
    let me = std::env::current_exe().unwrap();
    let out = std::process::Command::new(me)
        .args(["--exact", "cowstr_child", "--nocapture", "--test-threads=1"])
        .env("WZ_COWSTR_CHILD", "1")
        .output()
        .unwrap();
    // The child may print the sum before the free that is the second one of the allocation is
    // detected, so its output says nothing; that it did not finish is the fact.
    assert!(
        !out.status.success(),
        "upstream finished: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(wz::cowstr_owned_add("some text", 0), "some text+");
}

/// The places upstream is wrong, shown on upstream's crate and held to the definition on wz's.
#[test]
fn the_places_upstream_is_wrong_are_pinned_on_both_sides() {
    // `ProtocolMut::as_str` is the endpoint's address in upstream, its protocol in wz.
    assert_eq!(
        up::protocol_mut_text("udp/127.0.0.1:7447"),
        "127.0.0.1:7447"
    );
    assert_eq!(wz::protocol_mut_text("udp/127.0.0.1:7447"), "udp");

    // A range whose end is before its start: upstream's length subtracts below zero (a panic in a
    // build that checks overflow) and it is never empty; wz's is zero and empty.
    let (up_len, up_empty) = up::inverted_range();
    let (wz_len, wz_empty) = wz::inverted_range();
    assert_eq!((wz_len, wz_empty), (Some(0), Some(true)));
    assert_eq!(up_empty, Some(false));
    assert_ne!(
        up_len,
        Some(0),
        "upstream's length of an inverted range is not 0"
    );

    // A matcher `|`-ed with an integer with bits that are not a node kind.
    assert_eq!(wz::matcher_or_raw(0xFF), "router|peer|client");
    assert_eq!(up::matcher_or_raw(0xFF), "panicked");
    for bits in 0..=7u8 {
        assert_eq!(up::matcher_or_raw(bits), wz::matcher_or_raw(bits), "{bits}");
    }
}

/// The control: the comparison is on text, so an input that changes the answer changes the line.
#[test]
fn the_comparison_sees_an_endpoint_that_differs() {
    assert_ne!(wz::endpoint("udp/h:1?a=1"), wz::endpoint("udp/h:1?a=2"));
    assert_ne!(wz::zid("ab"), wz::zid("ac"));
    assert_ne!(wz::params("a=1;b=2"), wz::params("a=1;b=3"));
}
