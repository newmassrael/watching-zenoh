// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh`, the `config` module (the third part of the top crate): upstream's crate (`up_zenoh`)
//! and wz's (`wz_zenoh`) given the same inputs to `Config` and to its notifier, results equal as
//! text. (The crate `zenoh-config` under it has its own tests, `zenoh_config_*`; this file is about
//! what the top crate puts over it.)
//!
//! * `Config::from_json5` over inputs that are good, empty, cut, not an object, with a key that does
//!   not exist, and one that deserializes and is not valid (the nested `Err(Ok(_))` of the reader);
//! * `Config::from_file` over the kinds of file a user hands it, and `Config::from_env` with the
//!   variable unset, naming a file, naming a file that is not there, and holding bytes that are not
//!   text;
//! * the keys: `get_json` of keys that exist and ones that do not, `insert_json5` and `remove`;
//! * the items of an array by their `id=`: inserted, replaced, removed, refused;
//! * the serde, clone, display and default of a `Config`;
//! * the `unstable` arm: `from_deserializer`, the `Deref` and `DerefMut` to the crate under it and
//!   `From` of it;
//! * the notifier (`unstable`, with `plugins` for its subscription): the keys it lets be written,
//!   what a subscriber receives and in what order, a subscriber that is dropped, a clone that
//!   shares the state, and notifications sent from several threads;
//! * the example of the documentation of `Config` is upstream's file, byte for byte.
//!
//! No difference from upstream was seen.

use std::{
    cell::Cell,
    fs,
    panic::{catch_unwind, set_hook, take_hook, AssertUnwindSafe},
    path::{Path, PathBuf},
    sync::{Mutex, Once},
};

/// The variable `Config::from_env` reads is the process's, so the cases that set it do not overlap.
static ENV: Mutex<()> = Mutex::new(());

thread_local! {
    static QUIET: Cell<bool> = const { Cell::new(false) };
}

/// What a call that may panic made, as text, without the report of the panic. The hook is set once
/// and speaks for every thread but the one inside a call, so the tests that run side by side do not
/// lose the report of a panic that is theirs.
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

/// An error as text without the places of the crates that made it: each ` at <path>.rs:<line>` is
/// removed, wherever it stands in the text (a message that is the field of a debug print carries
/// its place in the middle).
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

/// A directory of files that both crates read. Its path is part of some error texts, so one
/// directory serves both and the texts that carry it are made relative.
struct Files {
    dir: PathBuf,
}

impl Files {
    fn new(tag: &str) -> Files {
        let dir = std::env::temp_dir().join(format!("wz-api-config-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Files { dir }
    }
    fn write(&self, name: &str, content: &str) -> PathBuf {
        let p = self.dir.join(name);
        fs::write(&p, content).unwrap();
        p
    }
    fn rel(&self, text: &str) -> String {
        text.replace(self.dir.to_str().unwrap(), "<dir>")
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

const GOOD: &str = r#"{ mode: "router", id: "1234abcd", listen: { endpoints: ["tcp/127.0.0.1:7447"] } }"#;
/// Deserializes and is not a valid configuration: a user without a password.
const NOT_VALID: &str = r#"{ transport: { auth: { usrpwd: { user: "u" } } } }"#;

macro_rules! config_cases {
    ($name:ident, $z:ident, $c:ident) => {
        mod $name {
            use super::*;
            use $z::config::{Config, Notifier, WhatAmI};

            type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

            /// A result as text: what the value of an `Ok` reads as, or the error without its place.
            fn show<T>(r: Res<T>, f: impl FnOnce(&T) -> String) -> String {
                match r {
                    Ok(v) => format!("Ok({})", f(&v)),
                    Err(e) => format!("Err({})", plain(&e.to_string())),
                }
            }

            fn key(c: &Config, k: &str) -> String {
                match c.get_json(k) {
                    Ok(s) => format!("Ok({s})"),
                    Err(e) => format!("Err({})", plain(&e.to_string())),
                }
            }

            /// What of a configuration is compared: three of its keys, its text and its size.
            fn summary(c: &Config) -> String {
                format!(
                    "mode={} id={} listen={} display={}",
                    key(c, "mode"),
                    key(c, "id"),
                    key(c, "listen/endpoints"),
                    c
                )
            }

            pub fn from_json5() -> Vec<String> {
                let inputs = [
                    "{}",
                    "",
                    "   ",
                    GOOD,
                    r#"{ mode: "client", connect: { endpoints: ["tcp/localhost:7447"] } }"#,
                    "// a comment\n{ /* inline */ mode: 'peer', metadata: { a: [1, 2, 3], }, }",
                    "{ mode: ",
                    "[1, 2]",
                    "42",
                    "null",
                    r#"{ nonsense: 1 }"#,
                    r#"{ mode: "weird" }"#,
                    r#"{ id: "not hex" }"#,
                    r#"{ transport: { link: { nonsense: true } } }"#,
                    NOT_VALID,
                ];
                inputs
                    .iter()
                    .map(|i| {
                        let r = caught(|| show(Config::from_json5(i), summary));
                        format!("from_json5 {i:?}: {r}")
                    })
                    .collect()
            }

            pub fn from_file(files: &Files) -> Vec<String> {
                let mut out = vec![];
                let names = [
                    ("ok.json5", GOOD),
                    ("ok.json", r#"{ "mode": "client", "connect": { "endpoints": ["tcp/localhost:7447"] } }"#),
                    ("ok.yaml", "mode: peer\nid: a1b2\nscouting:\n  multicast:\n    enabled: false\n"),
                    ("broken.json5", "{ mode: "),
                    ("not_valid.json5", NOT_VALID),
                    ("bad.txt", GOOD),
                    ("noext", GOOD),
                    ("empty.json5", ""),
                ];
                for (name, content) in names {
                    let p = files.write(name, content);
                    let r = caught(|| show(Config::from_file(&p), summary));
                    out.push(format!("from_file {name}: {}", files.rel(&r)));
                }
                let missing = files.dir.join("missing.json5");
                let r = caught(|| show(Config::from_file(&missing), summary));
                out.push(format!("from_file missing: {}", files.rel(&r)));
                let r = caught(|| show(Config::from_file(&files.dir), summary));
                out.push(format!("from_file a directory: {}", files.rel(&r)));
                let as_str = files.dir.join("ok.json5");
                let r = caught(|| show(Config::from_file(as_str.to_str().unwrap()), summary));
                out.push(format!("from_file a &str: {}", files.rel(&r)));
                out
            }

            pub fn from_env(files: &Files) -> Vec<String> {
                let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
                let mut out = vec![];
                out.push(format!("variable: {}", Config::DEFAULT_CONFIG_PATH_ENV));
                std::env::remove_var(Config::DEFAULT_CONFIG_PATH_ENV);
                out.push(format!("unset: {}", caught(|| show(Config::from_env(), summary))));
                let good = files.write("env.json5", GOOD);
                std::env::set_var(Config::DEFAULT_CONFIG_PATH_ENV, &good);
                let r = caught(|| show(Config::from_env(), summary));
                out.push(format!("a file: {}", files.rel(&r)));
                let missing = files.dir.join("not-there.json5");
                std::env::set_var(Config::DEFAULT_CONFIG_PATH_ENV, &missing);
                let r = caught(|| show(Config::from_env(), summary));
                out.push(format!("a file that is not there: {}", files.rel(&r)));
                std::env::set_var(Config::DEFAULT_CONFIG_PATH_ENV, "");
                let r = caught(|| show(Config::from_env(), summary));
                out.push(format!("an empty path: {}", files.rel(&r)));
                #[cfg(unix)]
                {
                    use std::os::unix::ffi::OsStrExt;
                    let bytes = std::ffi::OsStr::from_bytes(b"/tmp/\xff\xfe.json5");
                    std::env::set_var(Config::DEFAULT_CONFIG_PATH_ENV, bytes);
                    let r = caught(|| show(Config::from_env(), summary));
                    out.push(format!("bytes that are not text: {}", files.rel(&r)));
                }
                std::env::remove_var(Config::DEFAULT_CONFIG_PATH_ENV);
                out
            }

            pub fn keys() -> Vec<String> {
                let mut out = vec![];
                let mut c = Config::default();
                for k in [
                    "", "mode", "id", "connect", "connect/endpoints", "connect/timeout_ms",
                    "listen/endpoints", "scouting/multicast/enabled", "scouting/multicast/address",
                    "transport/link/tx/batch_size", "transport/shared_memory/enabled", "qos",
                    "qos/network", "plugins", "adminspace/enabled", "nonexistent", "mode/", "/mode",
                    "mode/extra", "scouting//enabled",
                ] {
                    out.push(format!("get {k:?}: {}", caught(|| key(&c, k))));
                }
                let steps: [(&str, &str); 12] = [
                    ("mode", "\"router\""),
                    ("mode", "42"),
                    ("mode", "\"nonsense\""),
                    ("mode", "{"),
                    ("nonsense", "1"),
                    ("listen/endpoints", r#"["tcp/127.0.0.1:7447"]"#),
                    ("listen/endpoints", r#"["no-such-protocol"]"#),
                    ("scouting/multicast/enabled", "false"),
                    ("scouting/multicast/ttl", "-1"),
                    ("metadata", r#"{ name: "a", list: [1, 2] }"#),
                    ("plugins/rest/http_port", "8000"),
                    ("transport/link/tx/batch_size", "65536"),
                ];
                for (k, v) in steps {
                    let r = caught(|| show(c.insert_json5(k, v).map(|_| ()), |_| String::new()));
                    out.push(format!("insert {k:?} {v:?}: {r}; now {}", caught(|| key(&c, k))));
                }
                for k in [
                    "mode", "mode", "nonexistent", "listen/endpoints", "metadata", "plugins/rest",
                    "plugins/rest/http_port", "scouting/multicast",
                ] {
                    let r = caught(|| show(c.remove(k), |_| String::new()));
                    out.push(format!("remove {k:?}: {r}; now {}", caught(|| key(&c, k))));
                }
                out.push(format!("after all: {}", caught(|| summary(&c))));
                out
            }

            pub fn array_items() -> Vec<String> {
                let mut out = vec![];
                let mut c = Config::default();
                let item = |id: &str, flow: &str| {
                    format!(
                        r#"{{ id: "{id}", messages: ["put"], key_exprs: ["**"], overwrite: {{ priority: "real_time" }}, flows: ["{flow}"] }}"#
                    )
                };
                let steps: Vec<(String, String)> = vec![
                    ("qos/network/id=item1".into(), item("item1", "egress")),
                    ("qos/network/id=item1".into(), item("item1", "ingress")),
                    ("qos/network/id=item2".into(), item("item2", "egress")),
                    ("qos/network/id=other".into(), item("item3", "egress")),
                    ("qos/network".into(), item("item4", "egress")),
                    ("qos/network/id=item5".into(), "{ not: valid".into()),
                    ("qos/network/id=item6".into(), r#"{ id: "item6", messages: [] }"#.into()),
                    ("mode/id=x".into(), item("x", "egress")),
                    ("nonexistent/id=x".into(), item("x", "egress")),
                    ("qos/network/id=".into(), item("", "egress")),
                ];
                for (k, v) in &steps {
                    let r = caught(|| show(c.try_insert_json5_array_item(k, v), |b| b.to_string()));
                    out.push(format!(
                        "try_insert {k:?}: {r}; qos/network {}",
                        caught(|| key(&c, "qos/network"))
                    ));
                }
                for k in [
                    "qos/network/id=item2", "qos/network/id=item2", "qos/network/id=nobody",
                    "qos/network/id=item1", "qos/network", "mode/id=x", "nonexistent/id=x",
                    "qos/network/id=item1",
                ] {
                    let r = caught(|| show(c.try_remove_json5_array_item(k), |b| b.to_string()));
                    out.push(format!(
                        "try_remove {k:?}: {r}; qos/network {}",
                        caught(|| key(&c, "qos/network"))
                    ));
                }
                out
            }

            pub fn serde_clone_display() -> Vec<String> {
                let mut out = vec![];
                let default = Config::default();
                out.push(format!("default display: {default}"));
                out.push(format!("default json: {}", serde_json::to_string(&default).unwrap()));
                let from = Config::from_json5("{}").unwrap();
                out.push(format!("from {{}} equals default: {}", from.to_string() == default.to_string()));
                let good = Config::from_json5(GOOD).unwrap();
                let json = serde_json::to_string(&good).unwrap();
                out.push(format!("good json: {json}"));
                let back: Res<Config> = serde_json::from_str(&json).map_err(|e| e.into());
                out.push(format!("back from json: {}", show(back, summary)));
                for text in ["{}", "[]", "null", r#"{"mode":"nope"}"#, r#"{"nonsense":1}"#, r#"{"mode":"peer","id":"ab"}"#] {
                    let r: Res<Config> = serde_json::from_str(text).map_err(|e| e.into());
                    out.push(format!("serde_json {text}: {}", caught(|| show(r, summary))));
                }
                let mut copy = good.clone();
                copy.insert_json5("mode", "\"client\"").unwrap();
                out.push(format!("clone changed: {} original: {}", key(&copy, "mode"), key(&good, "mode")));
                out.push(format!("debug of default: {}", format!("{default:?}").len() > 100));
                out.push(format!("debug equal to a clone's: {}", format!("{good:?}") == format!("{:?}", good.clone())));
                out
            }

            pub fn unstable_arm() -> Vec<String> {
                let mut out = vec![];
                for input in ["{}", GOOD, "{ mode: ", NOT_VALID, r#"{ nonsense: 1 }"#, r#"{ mode: "client" }"#] {
                    let r = caught(|| match json5::Deserializer::from_str(input) {
                        Err(e) => format!("no deserializer: {}", plain(&e.to_string())),
                        Ok(mut d) => match Config::from_deserializer(&mut d) {
                            Ok(c) => format!("Ok({})", key(&c, "mode")),
                            Err(Ok(c)) => format!("Err(Ok({}))", key(&c, "mode")),
                            Err(Err(e)) => format!("Err(Err({}))", plain(&e.to_string())),
                        },
                    });
                    out.push(format!("from_deserializer {input:?}: {r}"));
                }
                let mut c = Config::default();
                out.push(format!("deref mode: {:?}", c.mode()));
                out.push(format!("deref multicast: {:?}", c.scouting().multicast().enabled()));
                let r = c.insert("mode", &mut json5::Deserializer::from_str("\"router\"").unwrap());
                out.push(format!("deref_mut insert: {r:?} -> {:?}", c.mode()));
                let r = c.insert("mode", &mut json5::Deserializer::from_str("\"nope\"").unwrap());
                out.push(format!("deref_mut insert nope: {} -> {:?}", plain(&format!("{r:?}")), c.mode()));
                out.push(format!("through the wrapper: {}", key(&c, "mode")));
                let inner: $c::Config = {
                    let mut i = $c::Config::default();
                    i.insert("mode", &mut json5::Deserializer::from_str("\"client\"").unwrap()).unwrap();
                    i
                };
                let from = Config::from(inner);
                out.push(format!("from the crate under it: {}", key(&from, "mode")));
                out.push(format!("what the wrapper names: {:?}", WhatAmI::Router));
                out
            }

            pub fn notifier() -> Vec<String> {
                let mut out = vec![];
                let n = Notifier::new($c::Config::default().expanded());
                out.push(format!("debug: {n:?}"));
                let rx1 = n.subscribe();
                let rx2 = n.subscribe();
                let drain = |label: &str, out: &mut Vec<String>| {
                    for (i, rx) in [&rx1, &rx2].iter().enumerate() {
                        let mut got = vec![];
                        while let Ok(k) = rx.try_recv() {
                            got.push(k.to_string());
                        }
                        out.push(format!("{label}: subscriber {i} got {got:?}"));
                    }
                };
                let text = |n: &Notifier<$c::ExpandedConfig>, k: &str| match n.lock().get_json(k) {
                    Ok(s) => format!("Ok({s})"),
                    Err(e) => format!("Err({})", plain(&e.to_string())),
                };
                out.push(format!("lock: {}", text(&n, "mode")));
                let r = caught(|| show(n.insert_json5("plugins/p/x", "1"), |_| String::new()));
                out.push(format!("insert plugins/p/x: {r}; now {}", text(&n, "plugins")));
                drain("after insert", &mut out);
                for (k, v) in [("mode", "\"router\""), ("connect/endpoints", "[]"), ("plugins", "{}"), ("", "1")] {
                    let r = caught(|| show(n.insert_json5(k, v), |_| String::new()));
                    out.push(format!("insert {k:?}: {r}; mode now {}", text(&n, "mode")));
                }
                drain("after refused inserts", &mut out);
                let r = caught(|| show(n.try_insert_json5_array_item("qos/network/id=a", "{}"), |b| b.to_string()));
                out.push(format!("try_insert array at qos: {r}"));
                let item = r#"{ id: "a", messages: ["put"], key_exprs: ["**"], overwrite: { priority: "real_time" }, flows: ["egress"] }"#;
                let r = caught(|| show(n.try_insert_json5_array_item("plugins/p/id=a", item), |b| b.to_string()));
                out.push(format!("try_insert array at plugins: {r}; now {}", text(&n, "plugins")));
                drain("after array insert", &mut out);
                let r = caught(|| show(n.insert_json5("plugins/p/items", "[]"), |_| String::new()));
                out.push(format!("make an array at plugins: {r}"));
                for v in [r#"{ id: "a", v: 1 }"#, r#"{ id: "a", v: 2 }"#, r#"{ id: "b", v: 3 }"#, "{ no_id: 1 }"] {
                    let r = caught(|| show(n.try_insert_json5_array_item("plugins/p/items/id=a", v), |b| b.to_string()));
                    out.push(format!("try_insert {v}: {r}; now {}", text(&n, "plugins/p/items")));
                }
                // A key with no `field=value` is not an array operation: `false`, and nothing is told.
                let r = caught(|| show(n.try_insert_json5_array_item("plugins/p/items", r#"{ id: "c" }"#), |b| b.to_string()));
                out.push(format!("try_insert with no field filter: {r}; now {}", text(&n, "plugins/p/items")));
                drain("after array items", &mut out);
                let r = caught(|| show(n.remove("plugins/p/x"), |_| String::new()));
                out.push(format!("remove plugins/p/x: {r}; now {}", text(&n, "plugins")));
                let r = caught(|| show(n.remove("nonexistent"), |_| String::new()));
                out.push(format!("remove nonexistent: {r}"));
                let r = caught(|| show(n.remove("mode"), |_| String::new()));
                out.push(format!("remove mode: {r}; now {}", text(&n, "mode")));
                drain("after removes", &mut out);
                for k in [
                    "plugins/p/id=a", "plugins/p/id=nobody", "qos/network/id=a", "nonexistent/id=a",
                    "plugins/p/items/id=a", "plugins/p/items/id=a", "plugins/p/items/id=zzz",
                    "qos/network/id=nobody", "plugins/p/items", "mode",
                ] {
                    let r = caught(|| show(n.try_remove_json5_array_item(k), |b| b.to_string()));
                    out.push(format!("try_remove {k:?}: {r}; plugins now {}", text(&n, "plugins")));
                }
                drain("after array removes", &mut out);
                n.notify("one");
                n.notify(String::from("two"));
                n.notify("");
                drain("after notify", &mut out);
                let twin = n.clone();
                twin.notify("from the clone");
                let r = caught(|| show(twin.insert_json5("plugins/q/y", "true"), |_| String::new()));
                out.push(format!("through the clone: {r}; the original sees {}", text(&n, "plugins/q/y")));
                drain("after the clone", &mut out);
                drop(rx1);
                n.notify("after one is dropped");
                let mut got = vec![];
                while let Ok(k) = rx2.try_recv() {
                    got.push(k.to_string());
                }
                out.push(format!("after a drop: the other got {got:?}"));
                drop(rx2);
                n.notify("after both are dropped");
                out.push("no subscriber left: ok".to_string());
                let late = n.subscribe();
                n.notify("late");
                out.push(format!("late: {:?}", late.try_recv().map(|k| k.to_string())));
                out.push(format!("late again: {:?}", late.try_recv().map(|k| k.to_string())));
                // Two dead subscribers behind a live one: the list is pruned from its end, so the
                // indices it marked are still the ones that are dead.
                let (a, b, c) = (n.subscribe(), n.subscribe(), n.subscribe());
                drop(b);
                drop(c);
                n.notify("x1");
                n.notify("x2");
                let mut got = vec![];
                while let Ok(k) = a.try_recv() {
                    got.push(k.to_string());
                }
                out.push(format!("a live one before two dead ones: {got:?}"));
                out
            }

            pub fn across_threads() -> Vec<String> {
                let n = Notifier::new($c::Config::default().expanded());
                let rx = n.subscribe();
                let mut hs = vec![];
                for t in 0..4 {
                    let n = n.clone();
                    hs.push(std::thread::spawn(move || {
                        for i in 0..25 {
                            n.notify(format!("t{t}/{i}"));
                        }
                    }));
                }
                for h in hs {
                    h.join().unwrap();
                }
                let mut got: Vec<String> = vec![];
                while let Ok(k) = rx.try_recv() {
                    got.push(k.to_string());
                }
                // Each thread's own keys arrive in the order it sent them.
                let mut per_thread_in_order = true;
                for t in 0..4 {
                    let mine: Vec<usize> = got
                        .iter()
                        .filter_map(|k| k.strip_prefix(&format!("t{t}/")))
                        .map(|i| i.parse().unwrap())
                        .collect();
                    per_thread_in_order &= mine == (0..25).collect::<Vec<_>>();
                }
                got.sort();
                vec![
                    format!("received: {}", got.len()),
                    format!("per thread in order: {per_thread_in_order}"),
                    format!("first and last sorted: {:?} {:?}", got.first(), got.last()),
                ]
            }
        }
    };
}

config_cases!(up, up_zenoh, up_config);
config_cases!(wz, wz_zenoh, wz_config);

fn compare(group: &str, up: &[String], wz: &[String]) {
    assert!(up.len() > 2, "{group} holds {} line(s)", up.len());
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
fn from_json5_over_inputs_good_and_bad() {
    let (u, w) = (up::from_json5(), wz::from_json5());
    assert!(u.iter().any(|l| l.contains("Err(The config was correctly deserialized")), "{u:#?}");
    assert!(u.iter().any(|l| l.contains("Ok(mode=")), "{u:#?}");
    compare("from_json5", &u, &w);
}

#[test]
fn from_file_over_the_files_a_user_hands_it() {
    let files = Files::new("file");
    let (u, w) = (up::from_file(&files), wz::from_file(&files));
    assert!(u.iter().any(|l| l.starts_with("from_file ok.yaml: Ok(")), "{u:#?}");
    compare("from_file", &u, &w);
}

#[test]
fn from_env_with_the_variable_unset_and_set() {
    let files = Files::new("env");
    let (u, w) = (up::from_env(&files), wz::from_env(&files));
    assert!(u.iter().any(|l| l.starts_with("a file: Ok(")), "{u:#?}");
    compare("from_env", &u, &w);
}

#[test]
fn keys_read_inserted_and_removed() {
    let (u, w) = (up::keys(), wz::keys());
    assert!(u.iter().any(|l| l.starts_with("insert \"mode\" \"\\\"router\\\"\": Ok(")), "{u:#?}");
    compare("keys", &u, &w);
}

#[test]
fn the_items_of_an_array_by_their_id() {
    let (u, w) = (up::array_items(), wz::array_items());
    assert!(u.iter().any(|l| l.starts_with("try_insert \"qos/network/id=item2\": Ok(true)")), "{u:#?}");
    compare("array items", &u, &w);
}

#[test]
fn serde_clone_display_and_default() {
    compare("serde and display", &up::serde_clone_display(), &wz::serde_clone_display());
}

#[test]
fn the_unstable_arm_deserializer_deref_and_from() {
    let (u, w) = (up::unstable_arm(), wz::unstable_arm());
    assert!(u.iter().any(|l| l.starts_with("from_deserializer") && l.contains("Err(Ok(")), "{u:#?}");
    compare("unstable arm", &u, &w);
}

#[test]
fn the_notifier_tells_its_subscribers() {
    let (u, w) = (up::notifier(), wz::notifier());
    assert!(u.iter().any(|l| l.contains("subscriber 0 got [\"plugins/p/x\"]")), "{u:#?}");
    compare("notifier", &u, &w);
}

#[test]
fn notifications_sent_from_several_threads() {
    let (u, w) = (up::across_threads(), wz::across_threads());
    assert_eq!(u[0], "received: 100");
    assert_eq!(u[1], "per thread in order: true");
    compare("threads", &u, &w);
}

/// The example in the documentation of `Config` is a file of the pinned crate, which the crate
/// reads when its documentation is built; a copy that differs by a byte would show another example.
#[test]
fn the_example_of_the_documentation_is_upstreams_file() {
    let ours = fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/wz-zenoh/DEFAULT_CONFIG.json5"))
        .expect("the copy in the crate");
    let home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")))
        .expect("a cargo home");
    let mut found = None;
    for index in fs::read_dir(home.join("registry/src")).expect("the registry sources") {
        let p = index.unwrap().path().join("zenoh-1.10.1/DEFAULT_CONFIG.json5");
        if p.is_file() {
            found = Some(p);
            break;
        }
    }
    let theirs = fs::read(found.expect("zenoh-1.10.1 in the registry, which up_zenoh builds from"))
        .unwrap();
    assert_eq!(ours.len(), theirs.len(), "the copy differs in length");
    assert!(ours == theirs, "the copy differs in content");
}

#[test]
fn the_comparison_sees_a_config_that_differs() {
    let u = up::keys();
    let mut w = wz::keys();
    let i = w.iter().position(|l| l.starts_with("get \"mode\"")).unwrap();
    w[i] = format!("{} changed", w[i]);
    assert!(u.iter().zip(&w).any(|(x, y)| x != y));
    assert_ne!(up::keys(), up::array_items());
}
