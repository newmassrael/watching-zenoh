// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-config`, the keys (the second slice of the crate): upstream's crate (`up_config`) and
//! wz's (`wz_config`) given the same operations on a `Config`, results equal as text.
//!
//! * EVERY KEY of the default configuration (the list is upstream's, and wz's must be the same) is
//!   read as JSON and given each of a set of JSON5 values, and what the key holds afterwards is
//!   read again: the values the type takes, the ones it refuses and the texts of the refusals.
//! * The validators (the sizes of the queues, the user and the password that come in a pair, the
//!   resolution of the sequence numbers) and the keys that are not there.
//! * The array items addressed by a field (`qos/network/id=rule1`): inserted, replaced, appended,
//!   removed, and refused for each reason they can be.
//! * The plugin section: insertion by a path with indices, `+` and nulls, removal, a validator that
//!   accepts, rejects or rewrites, the requests to load a plugin and the panics they make on a
//!   section that is wrongly typed, the private keys that are sifted out.
//! * The constructors (`empty`, `default`, `peer`, `client`), `expanded`, the text of a `Config`,
//!   and a `GenericConfig` over a type of its own.
//!
//! The macro `unwrap_or_default!` names the crate as `zenoh_config`, which neither of the two is
//! called here, so it is not run.

use std::{
    cell::Cell,
    panic::{catch_unwind, set_hook, take_hook, AssertUnwindSafe},
    sync::{Arc, Mutex, Once},
};

/// What `zenoh_result::ZResult` is in both crates: a box of an error that can cross threads. The
/// two crates have a `zenoh-result` of their own, and the type is the same text.
type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

thread_local! {
    static QUIET: Cell<bool> = const { Cell::new(false) };
}

/// Runs `f` and says what it made, or the words of its panic, without the report of the panic: a
/// function that panics is a result of this comparison, and the report would be noise.
fn caught<T>(f: impl FnOnce() -> T) -> Result<T, String> {
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
    let out = catch_unwind(AssertUnwindSafe(f));
    QUIET.with(|q| q.set(false));
    out.map_err(|p| {
        let text = p
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default();
        format!("PANIC {text}")
    })
}

/// A text without the place of the crate that made an error.
fn plain(s: &str) -> String {
    s.split(" at ").next().unwrap_or("").to_string()
}

/// The values every key is given, as JSON5.
const VALUES: &[&str] = &[
    "true",
    "false",
    "0",
    "1",
    "-1",
    "70000",
    "18446744073709551615",
    "1.5",
    "\"x\"",
    "\"router\"",
    "\"16bit\"",
    "\"tcp/localhost:7447\"",
    "[]",
    "[\"tcp/localhost:7447\"]",
    "{}",
    "{ router: 1 }",
    "null",
];

/// A validator of a plugin's configuration, one kind per behaviour.
#[derive(Clone, Copy)]
enum Mode {
    Accept,
    Reject,
    Rewrite,
}

macro_rules! map_cases {
    ($name:ident, $cfg:ident) => {
        mod $name {
            use super::*;

            pub struct Validator {
                pub mode: Mode,
                pub seen: Mutex<Vec<String>>,
            }

            impl $cfg::ConfigValidator for Validator {
                fn check_config(
                    &self,
                    plugin_name: &str,
                    path: &str,
                    current: &serde_json::Map<String, serde_json::Value>,
                    new: &serde_json::Map<String, serde_json::Value>,
                ) -> Res<Option<serde_json::Map<String, serde_json::Value>>> {
                    self.seen.lock().unwrap().push(format!(
                        "{plugin_name}|{path}|{}|{}",
                        serde_json::Value::Object(current.clone()),
                        serde_json::Value::Object(new.clone())
                    ));
                    match self.mode {
                        Mode::Accept => Ok(None),
                        Mode::Reject => Err("rejected by the validator".into()),
                        Mode::Rewrite => {
                            let mut m = new.clone();
                            m.insert("rewritten".into(), true.into());
                            Ok(Some(m))
                        }
                    }
                }
            }

            pub fn keys() -> Vec<String> {
                let mut k: Vec<String> = $cfg::Config::default().keys().collect();
                k.sort();
                k
            }

            fn dbg_ok<T, E: std::fmt::Debug>(r: Result<T, E>) -> String {
                match r {
                    Ok(_) => "Ok".to_string(),
                    Err(e) => format!("Err({})", plain(&format!("{e:?}"))),
                }
            }

            /// Every key given every value: the result, and what the key holds after.
            pub fn grid() -> Vec<String> {
                let mut out = vec![];
                for key in keys() {
                    for value in VALUES {
                        let mut c = $cfg::Config::default();
                        let r = caught(|| c.insert_json5(&key, value));
                        let line = match r {
                            Ok(r) => {
                                let after = caught(|| c.get_json(&key))
                                    .map(|g| match g {
                                        Ok(j) => j,
                                        Err(e) => format!("Err({e:?})"),
                                    })
                                    .unwrap_or_else(|p| p);
                                format!("{key} <- {value}: {} => {after}", dbg_ok(r))
                            }
                            Err(p) => format!("{key} <- {value}: {p}"),
                        };
                        out.push(line);
                    }
                }
                out
            }

            /// Every key read, on the default configuration.
            pub fn reads() -> Vec<String> {
                let c = $cfg::Config::default();
                let mut out = vec![];
                for key in keys().iter().map(String::as_str).chain([
                    "",
                    "/",
                    "nothing",
                    "connect/nothing",
                    "connect/endpoints/0",
                    "connect//endpoints",
                    "/connect/endpoints",
                    "transport/link/tx/queue/size/data/x",
                    "plugins",
                    "plugins/x",
                ]) {
                    let j = caught(|| c.get_json(key));
                    out.push(format!(
                        "{key}: {}",
                        match j {
                            Ok(Ok(j)) => j,
                            Ok(Err(e)) => format!("Err({e:?})"),
                            Err(p) => p,
                        }
                    ));
                }
                out
            }

            /// Operations that need a validator or a sequence, one line per step.
            pub fn validators() -> Vec<String> {
                let mut out = vec![];
                let mut c = $cfg::Config::default();
                let mut step = |c: &mut $cfg::Config, key: &str, value: &str| {
                    let r = c.insert_json5(key, value);
                    out.push(format!("{key} <- {value}: {}", dbg_ok(r)));
                };
                step(&mut c, "transport/link/tx/queue/size/data", "0");
                step(&mut c, "transport/link/tx/queue/size/data", "1");
                step(&mut c, "transport/link/tx/queue/size/data", "16");
                step(&mut c, "transport/link/tx/queue/size/data", "17");
                step(&mut c, "transport/link/tx/queue/size/control", "3");
                step(&mut c, "transport/link/tx/queue/size", "{ control: 2, real_time: 2, interactive_high: 2, interactive_low: 2, data_high: 2, data: 2, data_low: 2, background: 2 }");
                step(&mut c, "transport/link/tx/queue/size", "{ control: 2, real_time: 2, interactive_high: 2, interactive_low: 2, data_high: 2, data: 2, data_low: 2, background: 99 }");
                // the bounds of the queue sizes are asked of the whole group, which is what the
                // validator reads: every size at the top bound, at the bottom bound, and one under
                // and over each
                step(&mut c, "transport/link/tx/queue/size", "{ control: 16, real_time: 16, interactive_high: 16, interactive_low: 16, data_high: 16, data: 16, data_low: 16, background: 16 }");
                step(&mut c, "transport/link/tx/queue/size", "{ control: 1, real_time: 1, interactive_high: 1, interactive_low: 1, data_high: 1, data: 1, data_low: 1, background: 1 }");
                step(&mut c, "transport/link/tx/queue/size", "{ control: 17, real_time: 2, interactive_high: 2, interactive_low: 2, data_high: 2, data: 2, data_low: 2, background: 2 }");
                step(&mut c, "transport/link/tx/queue/size", "{ control: 0, real_time: 2, interactive_high: 2, interactive_low: 2, data_high: 2, data: 2, data_low: 2, background: 2 }");
                step(&mut c, "transport/auth/usrpwd", "{ user: 'a' }");
                step(&mut c, "transport/auth/usrpwd", "{ user: 'a', password: 'b' }");
                step(&mut c, "transport/auth/usrpwd", "{ password: 'b' }");
                step(&mut c, "transport/auth/usrpwd", "{}");
                step(&mut c, "transport/auth/usrpwd/user", "'solo'");
                step(&mut c, "transport/auth/usrpwd/user", "null");
                step(&mut c, "transport/link/tx/sequence_number_resolution", "'8bit'");
                step(&mut c, "transport/link/tx/sequence_number_resolution", "'64bit'");
                step(&mut c, "transport/link/tx/sequence_number_resolution", "'32bit'");
                step(&mut c, "transport/link/tx/sequence_number_resolution", "'bad'");
                step(&mut c, "transport/link/tx/batch_size", "70000");
                step(&mut c, "transport/link/tx/batch_size", "65535");
                step(&mut c, "transport/shared_memory/transport_optimization/pool_size", "0");
                step(&mut c, "transport/shared_memory/transport_optimization/pool_size", "4096");
                step(&mut c, "transport/shared_memory/transport_optimization/messages", "['put', 'delete']");
                step(&mut c, "transport/shared_memory/transport_optimization/messages", "['nope']");
                step(&mut c, "namespace", "'a/b'");
                step(&mut c, "namespace", "'a/*'");
                step(&mut c, "namespace", "''");
                step(&mut c, "id", "'abc'");
                step(&mut c, "id", "'ABC'");
                step(&mut c, "id", "'0'");
                step(&mut c, "id", "'00112233445566778899aabbccddeeff'");
                step(&mut c, "id", "'00112233445566778899aabbccddeeff00'");
                step(&mut c, "mode", "'peer'");
                step(&mut c, "mode", "'Peer'");
                step(&mut c, "scouting/multicast/address", "'224.0.0.224:7446'");
                step(&mut c, "scouting/multicast/address", "'[ff02::1]:7446'");
                step(&mut c, "scouting/multicast/address", "'nowhere'");
                step(&mut c, "scouting/multicast/autoconnect", "['peer', 'router']");
                step(&mut c, "scouting/multicast/autoconnect", "{ router: [], peer: ['client'] }");
                step(&mut c, "scouting/multicast/autoconnect", "['alien']");
                step(&mut c, "scouting/multicast/autoconnect_strategy", "'greater-zid'");
                step(&mut c, "scouting/multicast/autoconnect_strategy", "{ router: 'always', to_peer: 'greater-zid' }");
                step(&mut c, "scouting/multicast/autoconnect_strategy", "{ to_router: 'always' }");
                step(&mut c, "scouting/multicast/autoconnect_strategy", "'sometimes'");
                step(&mut c, "listen/endpoints", "['tcp/[::]:7447']");
                step(&mut c, "listen/endpoints", "{ router: ['tcp/[::]:7447'], peer: [] }");
                step(&mut c, "listen/endpoints", "['not an endpoint']");
                step(&mut c, "connect/endpoints", "[{ strategy: 'allOf', locators: ['tcp/a:1', 'tcp/b:2'] }]");
                step(&mut c, "connect/endpoints", "[{ strategy: 'oneOf', locators: [] }]");
                step(&mut c, "connect/endpoints", "[{ strategy: 'both', locators: ['tcp/a:1'] }]");
                step(&mut c, "connect/retry", "{ period_init_ms: 10, period_max_ms: 100, period_increase_factor: 3 }");
                step(&mut c, "connect/retry", "{ period_init_ms: { router: 1 } }");
                step(&mut c, "connect/retry", "{ period_init_ms: 'soon' }");
                step(&mut c, "qos/network", "[{ messages: ['put'], overwrite: { priority: +1 } }]");
                step(&mut c, "qos/network", "[{ messages: ['put'], overwrite: { priority: 7 } }]");
                step(&mut c, "qos/network", "[{ messages: ['put'], overwrite: { priority: -8 } }]");
                step(&mut c, "qos/network", "[{ messages: ['put'], overwrite: { priority: 'data_low' } }]");
                step(&mut c, "qos/network", "[{ messages: ['put'], overwrite: {}, payload_size: '1..9' }]");
                step(&mut c, "qos/network", "[{ messages: ['put'], overwrite: {}, payload_size: '9..1' }]");
                // a range with a bound left out is written differently by the two crates (a class
                // of `zenoh_config_types.rs`), so the ranges here have both bounds
                step(&mut c, "qos/network", "[{ messages: ['put'], overwrite: {}, payload_size: '0..0' }]");
                step(&mut c, "qos/network", "[{ messages: ['put'], overwrite: {}, payload_size: 'x..9' }]");
                step(&mut c, "qos/network", "[{ messages: ['put'], overwrite: {}, payload_size: '9' }]");
                step(&mut c, "qos/network", "[{ messages: [], overwrite: {} }]");
                step(&mut c, "qos/publication", "[{ key_exprs: ['a/**'], config: { congestion_control: 'block', priority: 'data', express: true } }]");
                step(&mut c, "qos/publication", "[{ key_exprs: ['a/**'], config: { congestion_control: 'block_first' } }]");
                step(&mut c, "qos/publication", "[{ key_exprs: ['a/**'], config: { reliability: 'reliable', allowed_destination: 'remote' } }]");
                step(&mut c, "downsampling", "[{ messages: ['put'], rules: [{ key_expr: 'a/**', freq: 10 }] }]");
                step(&mut c, "downsampling", "[{ messages: [], rules: [{ key_expr: 'a/**', freq: 10 }] }]");
                step(&mut c, "low_pass_filter", "[{ messages: ['put'], key_exprs: ['a/**'], size_limit: 10 }]");
                step(&mut c, "access_control/rules", "[{ id: 'r', key_exprs: ['a/**'], messages: ['put'], permission: 'allow' }]");
                step(&mut c, "access_control/subjects", "[{ id: 's', interfaces: ['lo'] }]");
                step(&mut c, "access_control/policies", "[{ rules: ['r'], subjects: ['s'] }]");
                step(&mut c, "access_control/default_permission", "'allow'");
                step(&mut c, "gateway/south", "'auto'");
                step(&mut c, "gateway/south", "[{ filters: [{ modes: ['peer'], negated: true }] }]");
                step(&mut c, "gateway/south", "[{ filters: [{ interfaces: [] }] }]");
                step(&mut c, "stats/filters", "[{ key: 'a/b' }]");
                step(&mut c, "plugins_loading/search_dirs", "['/a', { kind: 'current_exe_parent', value: 'lib' }]");
                step(&mut c, "plugins_loading/search_dirs", "[{ kind: 'none' }]");
                step(&mut c, "routing/router/peers_failover_brokering", "true");
                step(&mut c, "routing/peer", "{ mode: 'x' }");
                out.push(format!("final: {}", c));
                out
            }

            /// The array items addressed by a field of the item.
            pub fn array_items() -> Vec<String> {
                let mut out = vec![];
                let mut c = $cfg::Config::default();
                let item = |id: &str, prio: &str| {
                    format!("{{ id: '{id}', messages: ['put'], key_exprs: ['**'], overwrite: {{ priority: '{prio}' }} }}")
                };
                let ops: Vec<(&str, String)> = vec![
                    ("qos/network/id=r1", item("r1", "data")),
                    ("qos/network/id=r2", item("r2", "data_low")),
                    ("qos/network/id=r1", item("r1", "real_time")),
                    ("qos/network/id=r3", item("r1", "data")),
                    ("qos/network/id=r4", "[1, 2]".into()),
                    ("qos/network/id=r4", "{ id: 4 }".into()),
                    ("qos/network/id=r4", "not json".into()),
                    ("qos/network/id=", "{ id: '' , messages: ['put'], overwrite: {} }".into()),
                    ("qos/network/=r5", "{ messages: ['put'], overwrite: {} }".into()),
                    ("qos/network/id=r5=extra", item("r5=extra", "data")),
                    ("id=r6", item("r6", "data")),
                    ("/id=r6", item("r6", "data")),
                    ("mode/id=r6", item("r6", "data")),
                    ("nothing/id=r6", item("r6", "data")),
                    ("qos/publication/id=r7", item("r7", "data")),
                    ("downsampling/id=d1", "{ id: 'd1', messages: ['put'], rules: [{ key_expr: 'a/**', freq: 5 }] }".into()),
                    ("downsampling/id=d1", "{ id: 'd1', messages: ['put'], rules: [{ key_expr: 'a/**', freq: 6 }] }".into()),
                    ("access_control/rules/id=a1", "{ id: 'a1', key_exprs: ['a'], messages: ['put'], permission: 'deny' }".into()),
                    ("plain/key", "1".into()),
                ];
                for (key, value) in &ops {
                    let r = caught(|| c.try_insert_json5_array_item(key, value));
                    out.push(format!(
                        "insert {key} <- {value}: {}",
                        match r {
                            Ok(Ok(b)) => format!("Ok({b})"),
                            Ok(Err(e)) => format!("Err({})", plain(&format!("{e:?}"))),
                            Err(p) => p,
                        }
                    ));
                    out.push(format!("  qos/network: {}", c.get_json("qos/network").unwrap_or_default()));
                }
                for key in [
                    "qos/network/id=r2",
                    "qos/network/id=nobody",
                    "qos/network/id=r1",
                    "qos/network/id",
                    "qos/network",
                    "id=r1",
                    "mode/id=x",
                    "nothing/id=x",
                    "downsampling/id=d1",
                    "downsampling/messages=put",
                    "access_control/rules/id=a1",
                ] {
                    let r = caught(|| c.try_remove_json5_array_item(key));
                    out.push(format!(
                        "remove {key}: {}",
                        match r {
                            Ok(Ok(b)) => format!("Ok({b})"),
                            Ok(Err(e)) => format!("Err({})", plain(&e.to_string())),
                            Err(p) => p,
                        }
                    ));
                    out.push(format!("  qos/network: {}", c.get_json("qos/network").unwrap_or_default()));
                    out.push(format!("  downsampling: {}", c.get_json("downsampling").unwrap_or_default()));
                }
                out
            }

            /// The plugin section, with a validator of each behaviour and without.
            pub fn plugins() -> Vec<String> {
                let mut out = vec![];
                for mode in [None, Some(Mode::Accept), Some(Mode::Reject), Some(Mode::Rewrite)] {
                    let tag = match mode {
                        None => "none",
                        Some(Mode::Accept) => "accept",
                        Some(Mode::Reject) => "reject",
                        Some(Mode::Rewrite) => "rewrite",
                    };
                    let validator = mode.map(|m| Arc::new(Validator { mode: m, seen: Mutex::new(vec![]) }));
                    let mut c = $cfg::Config::default();
                    if let Some(v) = &validator {
                        c.set_plugin_validator(Arc::downgrade(v));
                    }
                    let ops: &[(&str, &str)] = &[
                        ("plugins/rest", "{ http_port: 8000 }"),
                        ("plugins/rest/http_port", "9000"),
                        ("plugins/rest/list", "[1, 2, 3]"),
                        ("plugins/rest/list/1", "20"),
                        ("plugins/rest/list/+", "4"),
                        ("plugins/rest/list/9", "4"),
                        ("plugins/rest/list/x", "4"),
                        ("plugins/rest/new/deep/er", "'v'"),
                        ("plugins/rest/http_port/x", "1"),
                        ("plugins/rest//double", "1"),
                        ("plugins/fresh/0", "1"),
                        ("plugins/fresh2/+", "1"),
                        ("plugins/null", "null"),
                        ("plugins/null/key", "1"),
                        ("plugins/scalar", "5"),
                        ("plugins/rest/private", "'hidden'"),
                        ("plugins/rest/nested", "{ private: 1, shown: 2 }"),
                        ("plugins/rest/arr", "[{ private: 1, shown: 2 }, [{ private: 3, kept: 4 }]]"),
                        ("plugins/storage_manager", "{ __required__: true, __path__: ['/a', '/b'], __plugin__: 'storages' }"),
                    ];
                    for (key, value) in ops {
                        let r = caught(|| c.insert_json5(key, value));
                        out.push(format!(
                            "{tag} insert {key} <- {value}: {}",
                            match r {
                                Ok(r) => dbg_ok(r),
                                Err(p) => p,
                            }
                        ));
                    }
                    for key in [
                        "plugins/rest",
                        "plugins/rest/http_port",
                        "plugins/rest/list",
                        "plugins/rest/list/1",
                        "plugins/rest/nested",
                        "plugins/nothing",
                        "plugins/rest/list/x",
                        "plugins/rest/new/deep",
                        "plugins",
                    ] {
                        let r = caught(|| c.get_json(key));
                        out.push(format!(
                            "{tag} get {key}: {}",
                            match r {
                                Ok(Ok(j)) => j,
                                Ok(Err(e)) => format!("Err({e:?})"),
                                Err(p) => p,
                            }
                        ));
                    }
                    for key in [
                        "plugins/rest/list/0",
                        "plugins/rest/list/99",
                        "plugins/rest/nested/shown",
                        "plugins/rest/nested/gone",
                        "plugins/rest/http_port/x",
                        "plugins/rest/new/deep/er",
                        "plugins/nothing/x",
                        "/plugins/rest/nested",
                        "plugins/null",
                        "mode",
                        "plugins",
                        "plugins/",
                        "plugins/scalar/x",
                    ] {
                        let r = caught(|| c.remove(key));
                        out.push(format!(
                            "{tag} remove {key}: {}",
                            match r {
                                Ok(Ok(())) => "Ok".to_string(),
                                Ok(Err(e)) => format!("Err({})", plain(&e.to_string())),
                                Err(p) => p,
                            }
                        ));
                    }
                    // the inserts that name the whole section, which replace what it held, come last
                    for (key, value) in [("plugins/", "{ again: { n: 1 } }"), ("plugins", "{ whole: {} }")] {
                        let r = caught(|| c.insert_json5(key, value));
                        out.push(format!(
                            "{tag} insert {key} <- {value}: {}",
                            match r {
                                Ok(r) => dbg_ok(r),
                                Err(p) => p,
                            }
                        ));
                        out.push(format!("{tag} then plugins: {:?}", c.get_json("plugins")));
                    }
                    out.push(format!("{tag} plugin rest: {:?}", c.plugin("rest")));
                    out.push(format!("{tag} plugin nothing: {:?}", c.plugin("nothing")));
                    out.push(format!("{tag} sifted: {}", c.sift_privates()));
                    out.push(format!("{tag} display: {c}"));
                    out.push(format!("{tag} debug plugins: {:?}", c.get("plugins/rest").map(|_| ())));
                    if let Some(v) = &validator {
                        out.push(format!("{tag} validator saw: {:#?}", v.seen.lock().unwrap()));
                    }
                    // the requests to load plugins, on sections of every shape
                    let sections = [
                        "{ a: {} }",
                        "{ a: { __required__: true } }",
                        "{ a: { __required__: 'yes' } }",
                        "{ a: { __path__: '/x' } }",
                        "{ a: { __path__: ['/x', '/y'] } }",
                        "{ a: { __path__: [1] } }",
                        "{ a: { __path__: 1 } }",
                        "{ a: { __plugin__: 'b' } }",
                        "{ a: { __plugin__: 7 } }",
                        "{ a: 5 }",
                        "{ a: {}, b: { __required__: false } }",
                    ];
                    for section in sections {
                        let mut c = $cfg::Config::default();
                        c.insert_json5("plugins", section).ok();
                        let r = caught(|| {
                            c.plugins()
                                .load_requests()
                                .map(|l| format!("{l:?}"))
                                .collect::<Vec<_>>()
                        });
                        out.push(format!(
                            "{tag} load {section}: {}",
                            match r {
                                Ok(v) => v.join(";"),
                                Err(p) => p,
                            }
                        ));
                    }
                }
                out
            }

            /// The keys that hold a secret, which are read and are not written, and the insertion
            /// through a deserializer of the caller's own.
            pub fn secrets() -> Vec<String> {
                let mut out = vec![];
                let mut c = $cfg::Config::default();
                for key in [
                    "transport/link/tls/root_ca_certificate_base64",
                    "transport/link/tls/listen_private_key_base64",
                    "transport/link/tls/listen_certificate_base64",
                    "transport/link/tls/connect_private_key_base64",
                    "transport/link/tls/connect_certificate_base64",
                ] {
                    let r = c.insert_json5(key, "'c2VjcmV0'");
                    out.push(format!("{key}: {}", dbg_ok(r)));
                    out.push(format!("  get {:?}", c.get_json(key)));
                }
                let r = c.insert_json5("transport/link/tls/root_ca_certificate_base64", "5");
                out.push(format!("number: {}", dbg_ok(r)));
                let debug = format!("{c:?}");
                let shown = c.to_string();
                out.push(format!(
                    "secret in debug {} in text {} redacted {}",
                    debug.contains("c2VjcmV0"),
                    shown.contains("c2VjcmV0"),
                    debug.contains("REDACTED")
                ));
                out.push(format!("tls: {}", c.get_json("transport/link/tls").unwrap_or_default()));
                out.push(format!("serialized: {}", serde_json::to_string(&c).unwrap().contains("c2VjcmV0")));
                let mut c = $cfg::Config::default();
                let mut de = serde_json::Deserializer::from_str("168");
                out.push(format!("insert: {:?}", c.insert("transport/link/tx/lease", &mut de).map_err(|e| format!("{e:?}"))));
                out.push(format!("  lease {:?}", c.get_json("transport/link/tx/lease")));
                let mut de = serde_json::Deserializer::from_str("\"x\"");
                out.push(format!("insert bad: {:?}", c.insert("transport/link/tx/lease", &mut de).map_err(|e| format!("{e:?}"))));
                let mut de = serde_json::Deserializer::from_str("{\"enabled\": true}");
                out.push(format!("insert section: {:?}", c.insert("adminspace", &mut de).map_err(|e| format!("{e:?}"))));
                out.push(format!("  adminspace {:?}", c.get_json("adminspace")));
                out.push(format!("get typed: {:?}", c.get("adminspace/enabled").map(|a| a.downcast_ref::<bool>().copied()).map_err(|e| format!("{e:?}"))));
                out
            }

            /// The constructors, the expansion, the text of a configuration.
            pub fn builders() -> Vec<String> {
                let mut out = vec![];
                out.push(format!("empty: {}", $cfg::empty()));
                out.push(format!("default: {}", $cfg::default()));
                out.push(format!("peer: {}", $cfg::peer()));
                out.push(format!(
                    "client: {}",
                    $cfg::client(["tcp/a:1".parse::<$cfg::EndPoint>().unwrap(), "udp/b:2".parse().unwrap()])
                ));
                out.push(format!("client none: {}", $cfg::client(Vec::<$cfg::EndPoint>::new())));
                let e = $cfg::Config::default().expanded();
                // the identifier of an expanded configuration is drawn, so only its mode is read
                out.push(format!("expanded mode {:?}", e.mode()));
                let mut set = $cfg::Config::default();
                set.set_mode(Some($cfg::WhatAmI::Router)).unwrap();
                set.set_id(Some("abc".parse().unwrap())).unwrap();
                let e = set.expanded();
                out.push(format!("expanded set {:?} {}", e.mode(), e.id()));
                out.push(format!("keys: {:?}", keys()));
                out.push(format!(
                    "libloader off: {:?}",
                    $cfg::Config::default().libloader().search_paths()
                ));
                let mut c = $cfg::Config::default();
                c.insert_json5("plugins_loading", "{ enabled: true, search_dirs: ['/a', '/b'] }").unwrap();
                out.push(format!("libloader on: {:?}", c.libloader().search_paths()));
                out.push(format!("retry listen: {:?}", $cfg::Config::default().get_retry_config(None, true)));
                out.push(format!("retry connect: {:?}", $cfg::Config::default().get_retry_config(None, false)));
                out
            }

            struct Generic(Mutex<String>);
            impl $cfg::IConfig for Generic {
                fn get(&self, key: &str) -> Res<String> {
                    if key == "nothing" {
                        Err("no such key".into())
                    } else {
                        Ok(format!("{{\"key\":\"{key}\",\"n\":7,\"plugin\":{{\"a\":1}}}}"))
                    }
                }
                fn queries_default_timeout_ms(&self) -> u64 {
                    10_000
                }
                fn insert_json5(&self, key: &str, value: &str) -> Res<()> {
                    self.0.lock().unwrap().push_str(&format!("{key}={value};"));
                    Ok(())
                }
                fn to_json(&self) -> String {
                    format!("{{\"written\":\"{}\"}}", self.0.lock().unwrap())
                }
            }

            /// A `GenericConfig` over a type of the test's own.
            pub fn generic() -> Vec<String> {
                let g = $cfg::GenericConfig::new(Arc::new(Generic(Mutex::new(String::new()))));
                let mut out = vec![];
                out.push(format!("display {g}"));
                out.push(format!("debug {g:?}"));
                out.push(format!("typed {:?}", g.get_typed::<serde_json::Value>("x").map_err(|e| plain(&e.to_string()))));
                out.push(format!("typed bad {:?}", g.get_typed::<u64>("x").map_err(|e| plain(&e.to_string()))));
                out.push(format!("typed none {:?}", g.get_typed::<u64>("nothing").map_err(|e| plain(&e.to_string()))));
                out.push(format!("plugin {:?}", g.get_plugin_config("abc").map_err(|e| plain(&e.to_string()))));
                out.push(format!("timeout {}", g.queries_default_timeout_ms()));
                g.insert_json5("a", "1").unwrap();
                out.push(format!("written {g}"));
                out
            }
        }
    };
}

map_cases!(up, up_config);
map_cases!(wz, wz_config);

fn compare(group: &str, up: &[String], wz: &[String]) {
    assert!(!up.is_empty(), "{group} holds nothing");
    assert_eq!(up.len(), wz.len(), "{group}: the groups differ in length");
    if let Some((x, y)) = up.iter().zip(wz).find(|(x, y)| x != y) {
        // the lines of a whole configuration are long: show where they part
        let at = x.chars().zip(y.chars()).take_while(|(a, b)| a == b).count();
        let around = |s: &str| s.chars().skip(at.saturating_sub(80)).take(200).collect::<String>();
        panic!(
            "{group}\nupstream: {}\nwz:       {}\nparting at {at}:\nupstream: ...{}\nwz:       ...{}",
            x.chars().take(160).collect::<String>(),
            y.chars().take(160).collect::<String>(),
            around(x),
            around(y)
        );
    }
    if std::env::var_os("WZ_CONFIG_TRANSCRIPT").is_some() {
        for line in up {
            println!("{group}: {line}");
        }
    }
}

#[test]
fn the_keys_of_the_default_configuration_are_the_same() {
    let (u, w) = (up::keys(), wz::keys());
    assert!(u.len() > 100, "{}", u.len());
    assert_eq!(u, w);
}

#[test]
fn every_key_given_every_value() {
    let (u, w) = (up::grid(), wz::grid());
    // some are taken and some are refused
    assert!(u.iter().any(|l| l.contains(": Ok =>")), "no value taken");
    assert!(u.iter().any(|l| l.contains(": Err(")), "no value refused");
    compare("grid", &u, &w);
}

#[test]
fn every_key_read() {
    compare("reads", &up::reads(), &wz::reads());
}

#[test]
fn the_validators_and_the_values_of_each_type() {
    compare("validators", &up::validators(), &wz::validators());
}

#[test]
fn array_items_by_a_field() {
    compare("array items", &up::array_items(), &wz::array_items());
}

#[test]
fn the_plugin_section() {
    let (u, w) = (up::plugins(), wz::plugins());
    assert!(u.iter().any(|l| l.contains("PANIC")), "no panic seen");
    compare("plugins", &u, &w);
}

#[test]
fn secrets_and_the_insertion_through_a_deserializer() {
    let (u, w) = (up::secrets(), wz::secrets());
    assert!(u.iter().any(|l| l.contains("secret in debug false in text false")), "{u:#?}");
    compare("secrets", &u, &w);
}

#[test]
fn the_builders_and_the_text_of_a_configuration() {
    compare("builders", &up::builders(), &wz::builders());
}

#[test]
fn a_generic_configuration() {
    compare("generic", &up::generic(), &wz::generic());
}

#[test]
fn the_comparison_sees_a_key_that_differs() {
    let u = up::validators();
    let mut w = wz::validators();
    w[3] = format!("{} changed", w[3]);
    assert!(u.iter().zip(&w).any(|(x, y)| x != y));
    let mut g = up::grid();
    let other = g.pop().unwrap();
    g.push(format!("{other} changed"));
    assert_ne!(g, up::grid());
}
