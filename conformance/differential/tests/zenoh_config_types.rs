// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-config`, the types of its keys (the third slice of the crate): upstream's crate
//! (`up_config`) and wz's (`wz_config`) given the same text to read as each type, results equal as
//! text.
//!
//! * The values that depend on the mode of the node (`ModeDependentValue` of a bool, an integer, a
//!   float, a matcher of nodes, a list of endpoints, a list of groups of endpoints, a strategy of
//!   connection by target), each read from JSON5, JSON and YAML, with the answer for each mode,
//!   the text it writes back and what a change of it does.
//! * The quality of service: the update of a priority (a name or an increment), the conversions of
//!   the other enumerations, the tree a list of publisher rules makes, and the range of payload
//!   sizes (`ConfRange`) read, written, written back and read again.
//! * The connection retry: the periods a configuration gives in a row, the timeouts of listening
//!   and connecting, and the configuration an endpoint's own parameters change.
//! * The gateway, the wrappers around the identifiers of the protocol and the constants of
//!   `defaults`.
//!
//! Upstream has two places where a value a user wrote does not come back as it was written. Each is
//! a class, built by hand, counted and held on both sides:
//!
//! * a priority that is a positive integer, in a format whose parser reads one as an unsigned
//!   integer (JSON and YAML): upstream's visitor answers to a signed one only, so `priority: 1` is
//!   refused there while `priority: -1` is taken, and wz takes both;
//! * a range of payload sizes with a bound that is left out: upstream writes the missing bound as
//!   0 (`100..` is written `100..0`, which reads back as the empty range from 100 to 0), and wz
//!   writes it as it was written, so the range reads back as the one that was written.

use std::fmt::Debug;

use serde::{de::DeserializeOwned, Serialize};

fn plain(s: &str) -> String {
    s.split(" at ").next().unwrap_or("").to_string()
}

/// A value read from the three formats, one line each: what it is, or why it is not.
fn read_all<T: DeserializeOwned + Debug + Serialize>(input: &str) -> Vec<String> {
    let line = |what: &str, r: Result<T, String>| match r {
        Ok(v) => format!(
            "{what}: Ok({v:?}) as {}",
            serde_json::to_string(&v).unwrap_or_else(|e| format!("<{e}>"))
        ),
        Err(e) => format!("{what}: Err({})", plain(&e)),
    };
    vec![
        line("json5", json5::from_str::<T>(input).map_err(|e| e.to_string())),
        line("json", serde_json::from_str::<T>(input).map_err(|e| e.to_string())),
        line("yaml", serde_yaml::from_str::<T>(input).map_err(|e| e.to_string())),
    ]
}

const BOOLS: &[&str] = &[
    "true", "false", "{ router: true }", "{ peer: true, client: false }", "{}", "1", "\"x\"",
    "null", "[]", "{ router: 1 }", "{ bogus: true }", "{ router: true, router: false }",
];
const INTS: &[&str] = &[
    "0", "-5", "5", "9223372036854775807", "9223372036854775808", "18446744073709551615",
    "18446744073709551616", "1.5", "-1.5", "\"1\"", "{ router: -1, peer: 2 }", "{ client: \"x\" }",
    "true", "null", "{}", "{ router: 9223372036854775808 }",
];
const FLOATS: &[&str] = &[
    "0", "1", "-1", "2.5", "1e308", "18446744073709551615", "{ router: 1.5 }", "{ peer: 3, client: 0.5 }",
    "\"x\"", "true", "null", "{}", "[]",
];
const MATCHERS: &[&str] = &[
    "[]", "[\"router\"]", "[\"router\", \"peer\", \"client\"]", "[\"peer\", \"peer\"]", "[\"alien\"]",
    "\"router\"", "{ router: [] }", "{ router: [\"peer\"], client: [\"router\", \"peer\"] }",
    "{ peer: \"router\" }", "null", "{}", "[1]", "{ bogus: [] }",
];
const ENDPOINTS: &[&str] = &[
    "[]", "[\"tcp/a:1\"]", "[\"tcp/a:1\", \"udp/b:2\"]", "[\"bad\"]", "{ router: [\"tcp/a:1\"] }",
    "{ router: [], peer: [\"udp/b:2\"], client: [\"tcp/c:3\"] }", "\"tcp/a:1\"", "[1]", "null", "{}",
    "[\"tcp/a:1?rel=0\"]", "[\"tcp/a:1#iface=lo\"]", "[\"tcp/[::1]:7447\"]",
];
const GROUPS: &[&str] = &[
    "[]", "[\"tcp/a:1\"]", "[{ strategy: \"allOf\", locators: [\"tcp/a:1\", \"tcp/b:2\"] }]",
    "[{ strategy: \"oneOf\", locators: [] }]", "[{ strategy: \"both\", locators: [\"tcp/a:1\"] }]",
    "[{ locators: [\"tcp/a:1\"] }]", "{ router: [\"tcp/a:1\"] }", "{ client: [{ strategy: \"allOf\", locators: [\"tcp/a:1\"] }] }",
    "null", "{}", "[\"bad\"]",
];
const STRATEGIES: &[&str] = &[
    "\"always\"", "\"greater-zid\"", "{ router: \"always\" }", "{ to_router: \"always\", to_peer: \"greater-zid\" }",
    "{ router: { to_peer: \"always\" } }", "{ peer: { to_router: \"greater-zid\", to_client: \"always\" } }",
    "\"x\"", "{}", "{ to_x: \"always\" }", "{ router: \"always\", to_peer: \"always\" }", "null", "1",
    "{ router: \"always\", peer: \"always\", client: \"greater-zid\" }",
];
const PRIORITIES: &[&str] = &[
    "\"data\"", "\"real_time\"", "\"background\"", "\"foo\"", "\"+1\"", "+1", "1", "7", "8", "0", "-1",
    "-7", "-8", "1.5", "null", "[]", "{}", "3", "100", "-100", "255", "256",
];
const RANGES: &[&str] = &[
    "\"0..99\"", "\"100..\"", "\"..100\"", "\"..\"", "\"5..5\"", "\"9..1\"", "\"x..9\"", "\"9..y\"", "\"9\"",
    "\"\"", "\"-1..5\"", "\"1..-5\"", "\"18446744073709551615..\"", "\"..18446744073709551616\"",
    "\" 1..2\"", "\"1 ..2\"", "\"1...2\"", "\"1..2..3\"", "5", "null",
];

macro_rules! types_cases {
    ($name:ident, $cfg:ident, $proto:ident, $keyexpr:ident) => {
        mod $name {
            use super::*;
            use $cfg::ModeDependent;

            const MODES: [$cfg::WhatAmI; 3] =
                [$cfg::WhatAmI::Router, $cfg::WhatAmI::Peer, $cfg::WhatAmI::Client];

            /// Reads every input as a mode dependent value of `T`, and asks it for each mode.
            fn dependent<U: Debug, T>(inputs: &[&str]) -> Vec<String>
            where
                T: DeserializeOwned + Debug + Serialize + ModeDependent<U>,
            {
                let mut out = vec![];
                for input in inputs {
                    for line in read_all::<T>(input) {
                        out.push(format!("{input} -> {line}"));
                    }
                    if let Ok(v) = json5::from_str::<T>(input) {
                        for m in MODES {
                            out.push(format!("{input} @ {m:?} -> {:?}", v.get(m)));
                        }
                    }
                }
                out
            }

            pub fn mode_dependent() -> Vec<String> {
                let mut out = vec![];
                out.extend(dependent::<bool, $cfg::ModeDependentValue<bool>>(BOOLS));
                out.extend(dependent::<i64, $cfg::ModeDependentValue<i64>>(INTS));
                out.extend(dependent::<f64, $cfg::ModeDependentValue<f64>>(FLOATS));
                out.extend(dependent::<$cfg::WhatAmIMatcher, $cfg::ModeDependentValue<$cfg::WhatAmIMatcher>>(MATCHERS));
                out.extend(dependent::<Vec<$cfg::EndPoint>, $cfg::ModeDependentValue<Vec<$cfg::EndPoint>>>(ENDPOINTS).into_iter().map(|l| format!("endpoint {l}")));
                out.extend(dependent::<Vec<$cfg::EndPoints>, $cfg::ModeDependentValue<Vec<$cfg::EndPoints>>>(GROUPS));
                out.extend(dependent::<
                    $cfg::TargetDependentValue<$cfg::AutoConnectStrategy>,
                    $cfg::ModeDependentValue<$cfg::TargetDependentValue<$cfg::AutoConnectStrategy>>,
                >(STRATEGIES));
                out
            }

            /// The values a change of a mode dependent value does.
            pub fn changes() -> Vec<String> {
                let mut out = vec![];
                let mut unique = $cfg::ModeDependentValue::Unique(5i64);
                out.push(format!("set on unique: {:?} then {unique:?}", unique.set(6)));
                let mut dep = $cfg::ModeDependentValue::Dependent($cfg::ModeValues {
                    router: Some(1i64),
                    peer: None,
                    client: Some(3),
                });
                for m in MODES {
                    out.push(format!("get_mut {m:?}: {:?}", dep.get_mut(m).map(|v| {
                        *v += 10;
                        *v
                    })));
                }
                out.push(format!("after: {dep:?} as {}", serde_json::to_string(&dep).unwrap()));
                out.push(format!("set on dependent: {:?} then {dep:?}", dep.set(7)));
                let mut opt: Option<$cfg::ModeDependentValue<i64>> = None;
                for m in MODES {
                    let read = opt.get(m).copied();
                    out.push(format!("none option {m:?}: {read:?} {:?}", opt.get_mut(m)));
                }
                let mut opt = Some($cfg::ModeDependentValue::Unique(2i64));
                let router = opt.router().copied();
                out.push(format!("some option: {router:?} {:?}", opt.get_mut($cfg::WhatAmI::Client)));
                let tv = $cfg::TargetValues { values: $cfg::ModeValues { router: Some(1u8), peer: Some(2), client: None } };
                out.push(format!("target values: {} {:?} {:?} {:?}", serde_json::to_string(&tv).unwrap(), tv.router(), tv.peer(), tv.client()));
                let mut tdv = $cfg::TargetDependentValue::Dependent(tv);
                let peer = tdv.get_mut($cfg::WhatAmI::Peer).copied();
                out.push(format!("target dependent: {peer:?} {:?}", tdv.get_mut($cfg::WhatAmI::Client)));
                out.push(format!("target unique: {}", serde_json::to_string(&$cfg::TargetDependentValue::Unique(4u8)).unwrap()));
                out
            }

            pub fn priorities() -> Vec<String> {
                let mut out = vec![];
                for input in PRIORITIES {
                    for line in read_all::<$cfg::qos::PriorityUpdateConf>(input) {
                        out.push(format!("{input} -> {line}"));
                    }
                }
                out
            }

            pub fn conversions() -> Vec<String> {
                use $cfg::qos::*;
                let mut out = vec![];
                for p in [
                    PriorityConf::RealTime, PriorityConf::InteractiveHigh, PriorityConf::InteractiveLow,
                    PriorityConf::DataHigh, PriorityConf::Data, PriorityConf::DataLow, PriorityConf::Background,
                ] {
                    let proto: $proto::core::Priority = p.into();
                    out.push(format!("priority {p:?} {} -> {proto:?}", p as u8));
                }
                for c in [CongestionControlConf::Drop, CongestionControlConf::Block, CongestionControlConf::BlockFirst] {
                    let proto: $proto::core::CongestionControl = c.into();
                    let back: CongestionControlConf = proto.into();
                    out.push(format!("congestion {c:?} -> {proto:?} -> {back:?} {}", serde_json::to_string(&c).unwrap()));
                }
                for r in [ReliabilityConf::BestEffort, ReliabilityConf::Reliable] {
                    let proto: $proto::core::Reliability = r.into();
                    let back: ReliabilityConf = proto.into();
                    out.push(format!("reliability {r:?} -> {proto:?} -> {back:?} {}", serde_json::to_string(&r).unwrap()));
                }
                for l in [PublisherLocalityConf::SessionLocal, PublisherLocalityConf::Remote, PublisherLocalityConf::Any] {
                    out.push(format!("locality {l:?} {}", serde_json::to_string(&l).unwrap()));
                }
                for m in [QosOverwriteMessage::Put, QosOverwriteMessage::Delete, QosOverwriteMessage::Query] {
                    out.push(format!("overwrite message {m:?} {}", serde_json::to_string(&m).unwrap()));
                }
                for text in ["{}", "{ congestion_control: 'drop', priority: 'data', express: true, reliability: 'reliable' }", "{ priority: 1 }", "{ nonsense: 1 }"] {
                    out.extend(read_all::<QosFilter>(text).into_iter().map(|l| format!("filter {text} -> {l}")));
                }
                for text in ["{}", "{ congestion_control: 'block_first', priority: -3, express: false }", "{ priority: 'x' }", "{ reliability: 'reliable' }"] {
                    out.extend(read_all::<QosOverwrites>(text).into_iter().map(|l| format!("overwrites {text} -> {l}")));
                }
                for text in [
                    "{ congestion_control: 'block_first', priority: 'data', express: true, reliability: 'reliable', allowed_destination: 'remote' }",
                    "{ allowed_destination: 'elsewhere' }",
                    "{}",
                ] {
                    out.extend(read_all::<PublisherQoSConfig>(text).into_iter().map(|l| format!("publisher {text} -> {l}")));
                }
                out
            }

            /// The tree a list of publisher rules makes, asked about keys.
            pub fn publisher_tree() -> Vec<String> {
                use $keyexpr::keyexpr_tree::{IKeyExprTree, IKeyExprTreeNode};
                let mut out = vec![];
                let list: $cfg::qos::PublisherQoSConfList = json5::from_str(
                    "[ { key_exprs: ['a/**', 'b/c'], config: { priority: 'data_high' } },
                       { key_exprs: ['a/**'], config: { express: true } },
                       { key_exprs: [], config: { priority: 'background' } },
                       { key_exprs: ['d/*'], config: { congestion_control: 'block' } } ]",
                )
                .unwrap();
                out.push(format!("list: {}", serde_json::to_string(&list).unwrap()));
                let tree: $keyexpr::keyexpr_tree::KeBoxTree<$cfg::qos::PublisherQoSConfig> = list.into();
                for key in ["a/**", "b/c", "d/*", "a/x", "b/c/d", "nothing"] {
                    let ke = $proto::core::key_expr::OwnedKeyExpr::new(key).unwrap();
                    out.push(format!("weight {key}: {:?}", tree.weight_at(&ke)));
                    let mut hits: Vec<String> = tree
                        .intersecting_nodes(&ke)
                        .map(|n| format!("{:?}", n.weight()))
                        .collect();
                    hits.sort();
                    out.push(format!("intersecting {key}: {hits:?}"));
                }
                for text in ["[]", "[{ key_exprs: ['a'], config: {} }]", "[{ key_exprs: 'a', config: {} }]", "[{ key_exprs: ['a//b'], config: {} }]", "[{ config: {} }]"] {
                    out.extend(read_all::<$cfg::qos::PublisherQoSConfList>(text).into_iter().map(|l| format!("rules {text} -> {l}")));
                }
                out
            }

            pub fn ranges() -> Vec<String> {
                use std::ops::RangeBounds;
                let mut out = vec![];
                for input in RANGES {
                    for line in read_all::<$cfg::ConfRange>(input) {
                        out.push(format!("{input} -> {line}"));
                    }
                }
                let values = [None, Some(0u64), Some(1), Some(100), Some(u64::MAX)];
                for a in values {
                    for b in values {
                        let r = $cfg::ConfRange::new(a, b);
                        let text = serde_json::to_string(&r).unwrap();
                        let back = serde_json::from_str::<$cfg::ConfRange>(&text);
                        out.push(format!(
                            "{a:?}..{b:?}: {r:?} bounds {:?} {:?} text {text} back {:?} contains {:?}",
                            r.start_bound(),
                            r.end_bound(),
                            back.as_ref().map(|r| (r.start_bound().cloned(), r.end_bound().cloned())).map_err(|e| plain(&e.to_string())),
                            [0u64, 1, 50, 100, 101, u64::MAX].map(|v| r.contains(&v)),
                        ));
                    }
                }
                out
            }

            /// The range read back after it was written, as the pair of its bounds.
            pub fn ranges_come_back() -> Vec<String> {
                use std::ops::RangeBounds;
                let mut out = vec![];
                let values = [None, Some(0u64), Some(7), Some(u64::MAX)];
                for a in values {
                    for b in values {
                        let r = $cfg::ConfRange::new(a, b);
                        let text = serde_json::to_string(&r).unwrap();
                        let back: $cfg::ConfRange = serde_json::from_str(&text).unwrap();
                        out.push(format!(
                            "{a:?}..{b:?} written {text} read back {:?}..{:?} equal {}",
                            back.start_bound().cloned(),
                            back.end_bound().cloned(),
                            back == r
                        ));
                    }
                }
                out
            }

            fn period(c: &$cfg::ConnectionRetryConf, steps: usize) -> Vec<String> {
                let mut p = c.period();
                (0..steps).map(|_| format!("{:?}", p.next_duration())).collect()
            }

            pub fn retry() -> Vec<String> {
                let mut out = vec![];
                let inits = [-1i64, 0, 1, 1000, i64::MAX / 4];
                let maxes = [-1i64, 0, 500, 4000];
                let factors = [-2.0f64, 0.0, 0.5, 1.0, 2.0, f64::NAN, f64::INFINITY];
                for init in inits {
                    for max in maxes {
                        for factor in factors {
                            let c = $cfg::ConnectionRetryConf {
                                exit_on_failure: false,
                                period_init_ms: init,
                                period_max_ms: max,
                                period_increase_factor: factor,
                            };
                            out.push(format!(
                                "{init} {max} {factor}: timeout {:?} duration {:?} steps {:?}",
                                c.timeout(),
                                c.period().duration(),
                                period(&c, 6)
                            ));
                        }
                    }
                }
                out
            }

            pub fn timeouts() -> Vec<String> {
                let mut out = vec![];
                for text in [
                    "{}",
                    "{ mode: 'router' }",
                    "{ mode: 'client' }",
                    "{ mode: 'peer', connect: { timeout_ms: 7 }, listen: { timeout_ms: 8 } }",
                    "{ mode: 'client', connect: { timeout_ms: { client: 11, router: 12 } } }",
                    "{ mode: 'client', connect: { timeout_ms: { router: 12 } } }",
                    "{ mode: 'router', listen: { timeout_ms: -1 } }",
                    "{ connect: { exit_on_failure: { peer: true } }, listen: { exit_on_failure: false } }",
                    "{ connect: { retry: { period_init_ms: 5, period_max_ms: 50, period_increase_factor: 3 } } }",
                    "{ mode: 'router', connect: { retry: { period_init_ms: { router: 5 } } } }",
                    "{ mode: 'client', listen: { retry: { period_max_ms: { client: 9 } } } }",
                ] {
                    let c: $cfg::Config = json5::from_str(text).unwrap();
                    out.push(format!(
                        "{text}: listen {:?} connect {:?}",
                        $cfg::get_global_listener_timeout(&c),
                        $cfg::get_global_connect_timeout(&c)
                    ));
                    for endpoint in [None, Some("tcp/a:1"), Some("tcp/a:1?exit_on_failure=true"), Some("tcp/a:1?exit_on_failure=maybe;retry_period_init_ms=3;retry_period_max_ms=30;retry_period_increase_factor=1.5"), Some("tcp/a:1?retry_period_init_ms=x;retry_period_increase_factor=y"), Some("tcp/a:1?retry_period_init_ms=-1")] {
                        let ep: Option<$cfg::EndPoint> = endpoint.map(|e| e.parse().unwrap());
                        for listen in [true, false] {
                            out.push(format!(
                                "  {endpoint:?} listen {listen}: {:?}",
                                $cfg::get_retry_config(&c, ep.as_ref(), listen)
                            ));
                        }
                    }
                }
                out
            }

            pub fn gateway() -> Vec<String> {
                let mut out = vec![];
                for text in [
                    "{}",
                    "{ south: 'auto' }",
                    "{ south: 'other' }",
                    "{ south: [] }",
                    "{ south: [{}] }",
                    "{ south: [{ filters: [] }] }",
                    "{ south: [{ filters: [{ modes: ['peer'], interfaces: ['lo'], zids: ['abc'], region_names: ['r1'], negated: true }] }] }",
                    "{ south: [{ filters: [{ interfaces: [] }] }] }",
                    "{ south: [{ filters: [{ zids: ['zzz'] }] }] }",
                    "{ south: [{ filters: [{ region_names: ['bad name!'] }] }] }",
                    "{ south: [{ filters: [{ modes: 'peer' }] }] }",
                    "{ south: [{ filters: [{ negated: 'yes' }] }] }",
                    "{ south: [{ unknown: 1 }] }",
                    "{ north: 1 }",
                    "null",
                    "[]",
                ] {
                    for line in read_all::<$cfg::gateway::GatewayConf>(text) {
                        out.push(format!("{text} -> {line}"));
                    }
                }
                out.push(format!("default south: {:?}", $cfg::gateway::GatewayConf::default()));
                out.push(format!("default preset: {:?}", $cfg::gateway::GatewaySouthConf::default()));
                out
            }

            /// The names and the enumerations of the rules (the access control, the interceptors,
            /// the weights of the links), read from text and written back.
            pub fn names() -> Vec<String> {
                let mut out = vec![];
                out.push(format!(
                    "{} {} {} {:?}",
                    $cfg::Interface("lo".into()),
                    $cfg::CertCommonName("c".into()),
                    $cfg::Username("u".into()),
                    $cfg::Interface("lo".into())
                ));
                for l in [
                    $cfg::InterceptorLink::Tcp, $cfg::InterceptorLink::Udp, $cfg::InterceptorLink::Tls,
                    $cfg::InterceptorLink::Quic, $cfg::InterceptorLink::Serial, $cfg::InterceptorLink::Unixpipe,
                    $cfg::InterceptorLink::UnixsockStream, $cfg::InterceptorLink::Vsock, $cfg::InterceptorLink::Ws,
                ] {
                    out.push(format!("link {l} {l:?} {}", serde_json::to_string(&l).unwrap()));
                }
                fn enums<T: DeserializeOwned + Debug + Serialize>(out: &mut Vec<String>, what: &str, names: &[&str]) {
                    for n in names {
                        for line in read_all::<T>(&format!("\"{n}\"")) {
                            out.push(format!("{what} {n} -> {line}"));
                        }
                    }
                }
                enums::<$cfg::AclMessage>(&mut out, "acl message", &["put", "delete", "declare_subscriber", "query", "declare_queryable", "reply", "liveliness_token", "declare_liveliness_subscriber", "liveliness_query", "Put", "declare-subscriber", "nope"]);
                enums::<$cfg::Permission>(&mut out, "permission", &["allow", "deny", "Allow", "maybe"]);
                enums::<$cfg::AutoConnectStrategy>(&mut out, "strategy", &["always", "greater-zid", "greater_zid", "Always"]);
                enums::<$cfg::InterceptorFlow>(&mut out, "flow", &["egress", "ingress", "both"]);
                enums::<$cfg::InterceptorLink>(&mut out, "link", &["tcp", "udp", "tls", "quic", "serial", "unixpipe", "unixsock-stream", "unixsock_stream", "vsock", "ws", "wss"]);
                enums::<$cfg::DataMessage>(&mut out, "data message", &["put", "delete", "query", "reply", "declare"]);
                enums::<$cfg::QueueAllocMode>(&mut out, "alloc mode", &["init", "lazy", "eager"]);
                enums::<$cfg::ShmInitMode>(&mut out, "shm mode", &["init", "lazy", "eager"]);
                for text in [
                    "{ dst_zid: 'abc', weight: 5 }", "{ dst_zid: 'abc', weight: 0 }", "{ dst_zid: 'abc', weight: 65535 }",
                    "{ dst_zid: 'abc', weight: 65536 }", "{ dst_zid: 'abc' }", "{ weight: 5 }", "{ dst_zid: '', weight: 5 }",
                ] {
                    out.extend(read_all::<$cfg::TransportWeight>(text).into_iter().map(|l| format!("weight {text} -> {l}")));
                }
                for text in [
                    "{ key_expr: 'a/**', freq: 10 }", "{ key_expr: 'a/**', freq: 0 }", "{ key_expr: 'a/**', freq: -1 }",
                    "{ key_expr: 'a//b', freq: 1 }", "{ freq: 1 }", "{ key_expr: 'a', freq: 1, more: 2 }",
                ] {
                    out.extend(read_all::<$cfg::DownsamplingRuleConf>(text).into_iter().map(|l| format!("rule {text} -> {l}")));
                }
                for text in [
                    "{ subject_id: 1, key_expr: 'a', message: 'put', permission: 'allow', flow: 'egress' }",
                    "{ subject_id: -1, key_expr: 'a', message: 'put', permission: 'allow', flow: 'egress' }",
                    "{ subject_id: 1, key_expr: 'a', message: 'put', permission: 'allow' }",
                ] {
                    out.extend(read_all::<$cfg::PolicyRule>(text).into_iter().map(|l| format!("policy rule {text} -> {l}")));
                }
                for text in ["{ key: 'a/b' }", "{ key: '' }", "{}", "{ key: 'a', extra: 1 }"] {
                    out.extend(read_all::<$cfg::StatsFilterConfig>(text).into_iter().map(|l| format!("stats {text} -> {l}")));
                }
                for text in ["{ rules: [], subjects: [] }", "{ id: 'p', rules: ['r'], subjects: ['s'] }", "{ rules: ['r'] }"] {
                    out.extend(read_all::<$cfg::AclConfigPolicyEntry>(text).into_iter().map(|l| format!("policy entry {text} -> {l}")));
                }
                out
            }

            pub fn wrappers() -> Vec<String> {
                let mut out = vec![];
                for text in ["a", "A", "0", "00", "abc", "0123456789abcdef", "0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef0", "", "xyz", "-1", " 1", "1 "] {
                    let z = text.parse::<$cfg::ZenohId>();
                    out.push(format!(
                        "parse {text:?}: {}",
                        match &z {
                            Ok(z) => format!("Ok({z:?}) display {z} le {:?} json {} key {}", z.to_le_bytes(), serde_json::to_string(z).unwrap(), z.into_keyexpr()),
                            Err(e) => format!("Err({})", plain(&e.to_string())),
                        }
                    ));
                }
                for bytes in [vec![], vec![1u8], vec![0u8], vec![1, 2, 3], vec![7u8; 16], vec![7u8; 17], vec![0u8; 16]] {
                    let z = $cfg::ZenohId::try_from(bytes.as_slice());
                    out.push(format!("bytes {bytes:?}: {:?}", z.map_err(|e| plain(&e.to_string()))));
                }
                let z: $cfg::ZenohId = "abc".parse().unwrap();
                let proto: $proto::core::ZenohIdProto = z.into();
                out.push(format!("proto {proto:?} back {:?}", $cfg::ZenohId::from(proto)));
                let uhlc: uhlc::ID = z.into();
                out.push(format!("uhlc {uhlc:?}"));
                let ke: $proto::core::key_expr::OwnedKeyExpr = (&z).into();
                out.push(format!("keyexpr {ke}"));
                out.push(format!("order {:?}", "1".parse::<$cfg::ZenohId>().unwrap().cmp(&"2".parse().unwrap())));
                let hello: $cfg::wrappers::Hello = $proto::scouting::HelloProto {
                    version: 9,
                    whatami: $cfg::WhatAmI::Router,
                    zid: z.into(),
                    locators: vec!["tcp/a:1".parse().unwrap(), "udp/b:2".parse().unwrap()],
                }
                .into();
                out.push(format!("hello {hello} {hello:?} {:?} {:?} {}", hello.locators(), hello.whatami(), hello.zid()));
                let empty = $cfg::wrappers::Hello::empty();
                // the identifier of an empty Hello is drawn, so the rest of it is read
                out.push(format!("hello empty {:?} {:?}", empty.whatami(), empty.locators()));
                let id = $cfg::wrappers::EntityGlobalId::new(z, 42);
                out.push(format!("entity {id:?} {} {}", id.zid(), id.eid()));
                let proto_id: $proto::core::EntityGlobalIdProto = id.into();
                out.push(format!("entity proto {proto_id:?} back {:?}", $cfg::wrappers::EntityGlobalId::from(proto_id)));
                // the identifier of a default one is drawn, so its entity is read
                out.push(format!("entity default {}", $cfg::wrappers::EntityGlobalId::default().eid()));
                out
            }

            pub fn defaults() -> Vec<String> {
                use $cfg::{defaults::*, ModeDependent};
                let mut out = vec![];
                out.push(format!("mode {mode:?}"));
                out.push(format!("connect {:?} {:?}", connect::timeout_ms, connect::exit_on_failure));
                out.push(format!("listen {:?} {:?}", listen::timeout_ms, listen::exit_on_failure));
                out.push(format!("open {} {}", open::return_conditions::connect_scouted, open::return_conditions::declares));
                out.push(format!("scouting {} {}", scouting::timeout, scouting::delay));
                out.push(format!("multicast {} {:?} {} {}", scouting::multicast::enabled, scouting::multicast::address, scouting::multicast::interface, scouting::multicast::ttl));
                for m in [$cfg::WhatAmI::Router, $cfg::WhatAmI::Peer, $cfg::WhatAmI::Client] {
                    out.push(format!(
                        "{m:?}: multicast autoconnect {:?} strategy {:?} listen {} | gossip target {:?} autoconnect {:?} strategy {:?} | timestamping {}",
                        scouting::multicast::autoconnect::get(m),
                        scouting::multicast::autoconnect_strategy::get(m),
                        scouting::multicast::listen::get(m),
                        scouting::gossip::target::get(m),
                        scouting::gossip::autoconnect::get(m),
                        scouting::gossip::autoconnect_strategy::get(m),
                        timestamping::enabled::get(m),
                    ));
                    out.push(format!("{m:?}: connect timeout {:?} exit {:?} listen timeout {:?} exit {:?}", connect::timeout_ms.get(m), connect::exit_on_failure.get(m), listen::timeout_ms.get(m), listen::exit_on_failure.get(m)));
                }
                out.push(format!("gossip {} {}", scouting::gossip::enabled, scouting::gossip::multihop));
                out.push(format!("timestamping {}", timestamping::drop_future_timestamp));
                out.push(format!("queries {queries_default_timeout}"));
                out.push(format!("routing {} {}", routing::peer::mode, routing::interests::timeout));
                out.push(format!("queue bounds {} {}", $cfg::QueueSizeConf::MIN, $cfg::QueueSizeConf::MAX));
                out.push(format!("retry default {:?}", $cfg::ConnectionRetryModeDependentConf::default()));
                out.push(format!("listen config {:?}", $cfg::ListenConfig::default()));
                out.push(format!("connect config {:?}", $cfg::ConnectConfig::default()));
                out.push(format!("shm {:?}", $cfg::ShmConf::default()));
                out.push(format!("acl {:?}", $cfg::AclConfig::default()));
                out.push(format!("permissions {:?}", $cfg::PermissionsConf::default()));
                out
            }
        }
    };
}

types_cases!(up, up_config, up_protocol, up_keyexpr);
types_cases!(wz, wz_config, wz_protocol, wz_keyexpr);

fn compare(group: &str, up: &[String], wz: &[String]) {
    assert!(up.len() > 3, "{group} holds {} line(s)", up.len());
    assert_eq!(up.len(), wz.len(), "{group}: the groups differ in length");
    if let Some((x, y)) = up.iter().zip(wz).find(|(x, y)| x != y) {
        panic!("{group}\nupstream: {x}\nwz:       {y}");
    }
    if std::env::var_os("WZ_CONFIG_TRANSCRIPT").is_some() {
        for line in up {
            println!("{group}: {line}");
        }
    }
}

#[test]
fn mode_dependent_values() {
    let (u, w) = (up::mode_dependent(), wz::mode_dependent());
    assert!(u.iter().any(|l| l.contains("Ok(")), "no value read");
    assert!(u.iter().any(|l| l.contains("Err(")), "no value refused");
    compare("mode dependent", &u, &w);
}

#[test]
fn changes_of_mode_dependent_values() {
    compare("changes", &up::changes(), &wz::changes());
}

#[test]
fn priority_updates_where_the_formats_agree() {
    // the class below is held by its own test; here the cases in which it is not touched
    let (u, w) = (up::priorities(), wz::priorities());
    // the lines of the text formats that read an integer that is not negative are the class
    let positive = |l: &String| {
        let (input, rest) = l.split_once(" -> ").unwrap();
        (rest.starts_with("json: ") || rest.starts_with("yaml: "))
            && input.parse::<i64>().map(|n| n >= 0).unwrap_or(false)
    };
    let (u2, w2): (Vec<_>, Vec<_>) = u
        .iter()
        .zip(&w)
        .filter(|(x, _)| !positive(x))
        .map(|(x, y)| (x.clone(), y.clone()))
        .unzip();
    compare("priorities", &u2, &w2);
}

/// The class: a positive integer priority in JSON and YAML, whose parser reads it as unsigned.
#[test]
fn a_positive_priority_in_json_and_yaml_is_taken_by_wz() {
    use std::collections::BTreeMap;
    let lines = |v: Vec<String>| -> BTreeMap<String, String> {
        v.into_iter()
            .map(|l| {
                let (k, rest) = l.split_once(" -> ").unwrap();
                (format!("{k} {}", rest.split(':').next().unwrap()), rest.to_string())
            })
            .collect()
    };
    let (u, w) = (lines(up::priorities()), lines(wz::priorities()));
    let mut seen = 0;
    for input in ["0", "1", "3", "7"] {
        for fmt in ["json", "yaml"] {
            let key = format!("{input} {fmt}");
            let (x, y) = (&u[&key], &w[&key]);
            assert!(x.contains("Err("), "upstream took {key}: {x}");
            assert!(y.contains("Ok(Increment("), "wz refused {key}: {y}");
            seen += 1;
        }
    }
    // an increment past +7 is refused by both, upstream for the type of the integer and wz for
    // the size of the increment
    for input in ["8", "100", "255", "256"] {
        for fmt in ["json", "yaml"] {
            let key = format!("{input} {fmt}");
            let (x, y) = (&u[&key], &w[&key]);
            assert!(x.contains("invalid type"), "upstream: {key}: {x}");
            assert!(y.contains("invalid priority increment (> +7)"), "wz: {key}: {y}");
            seen += 1;
        }
    }
    assert_eq!(seen, 16);
    // the formats agree on the integers that no unsigned parser reads
    for fmt in ["json", "yaml"] {
        let key = format!("-1 {fmt}");
        assert_eq!(u[&key], w[&key]);
        assert!(u[&key].contains("Ok(Increment(-1))"));
    }
}

#[test]
fn quality_of_service_conversions() {
    compare("conversions", &up::conversions(), &wz::conversions());
}

#[test]
fn the_tree_of_publisher_rules() {
    compare("publisher tree", &up::publisher_tree(), &wz::publisher_tree());
}

#[test]
fn ranges_of_payload_sizes() {
    // the bounds that are left out are written differently, which is the class below: the lines
    // that do not involve a missing bound are held equal here
    let (u, w) = (up::ranges(), wz::ranges());
    assert_eq!(u.len(), w.len());
    let mut compared = 0;
    for (x, y) in u.iter().zip(&w) {
        let involves_none = x.contains("None");
        let input_open = {
            let input = x.split(" -> ").next().unwrap();
            input.starts_with("\"..") || input.ends_with("..\"")
        };
        if involves_none || input_open {
            continue;
        }
        assert_eq!(x, y, "upstream: {x}\nwz:       {y}");
        compared += 1;
    }
    assert!(compared > 40, "{compared}");
}

/// The class: a range with a bound left out does not come back as it was written in upstream.
#[test]
fn a_range_with_a_missing_bound_comes_back_in_wz() {
    let (u, w) = (up::ranges_come_back(), wz::ranges_come_back());
    let mut broken_up = 0;
    for (x, y) in u.iter().zip(&w) {
        assert!(y.ends_with("equal true"), "wz: {y}");
        if x.ends_with("equal false") {
            broken_up += 1;
            assert!(x.starts_with("None..") || x.contains("..None "), "{x}");
        }
    }
    // None..None, None..x and x..None for each x, but a range whose written text is one of the two
    // forms upstream reads back as it was is not broken
    assert!(broken_up >= 5, "{broken_up}");
}

#[test]
fn connection_retry_periods() {
    compare("retry", &up::retry(), &wz::retry());
}

#[test]
fn timeouts_and_the_retry_of_an_endpoint() {
    compare("timeouts", &up::timeouts(), &wz::timeouts());
}

#[test]
fn the_gateway() {
    let (u, w) = (up::gateway(), wz::gateway());
    assert!(u.iter().any(|l| l.contains("Ok(")), "no gateway read");
    compare("gateway", &u, &w);
}

#[test]
fn names_and_enumerations_of_the_rules() {
    let (u, w) = (up::names(), wz::names());
    assert!(u.iter().any(|l| l.contains("Ok(")), "nothing read");
    assert!(u.iter().any(|l| l.contains("Err(")), "nothing refused");
    compare("names", &u, &w);
}

#[test]
fn wrappers_of_the_identifiers() {
    compare("wrappers", &up::wrappers(), &wz::wrappers());
}

#[test]
fn constants_of_defaults() {
    compare("defaults", &up::defaults(), &wz::defaults());
}

#[test]
fn the_comparison_sees_a_type_that_differs() {
    let u = up::defaults();
    let mut w = wz::defaults();
    w[2] = format!("{} changed", w[2]);
    assert!(u.iter().zip(&w).any(|(x, y)| x != y));
    assert_ne!(up::ranges_come_back(), wz::ranges_come_back());
}
