// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A client whose configuration enables the admin space, asked for its own admin key by another
//! client through their router: upstream's crate (`up_zenoh`) and wz's (`wz_zenoh`) as that client,
//! given the same configuration, with an upstream router and an upstream client that asks. Results
//! equal as text.
//!
//! ## The question
//!
//! Upstream's runtime starts its admin space whatever the mode
//! (`zenoh/src/net/runtime/mod.rs` @ `let start_admin_space = *config.adminspace.enabled();`) and
//! declares `@/<zid>/<whatami>/**` through a face of its routing tables, so a client's admin space
//! is declared to its router and a query from another node reaches it over the client's own link.
//! A client of wz's crate is a registry of faces rather than a node, and the question is whether
//! it declares and answers the same.
//!
//! What is read is what the asker sees: whether it is answered under the client's root, the names
//! of the root document's fields, the client's id, metadata and locators in it, and the one session
//! it lists (its router). The version is the build's own and is not compared. Where the two crates
//! differ the difference is a line of `KNOWN_DIFFERENCES`, with the words of both.

use std::{
    net::TcpListener,
    sync::atomic::{AtomicU16, Ordering},
    time::{Duration, Instant},
};

/// A port nothing listens on, that the kernel never picks for a socket that binds port 0 (below
/// every platform's ephemeral range), and that no call of this function gives twice.
fn free_port() -> u16 {
    static NEXT: AtomicU16 = AtomicU16::new(0);
    loop {
        let offset = NEXT.fetch_add(1, Ordering::Relaxed);
        let port = 33_000 + ((std::process::id() % 8_000) as u16 + offset) % 16_000;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// How long the asker keeps asking before the line says it was not answered.
const PATIENCE: Duration = Duration::from_secs(10);

/// The id the client under test is opened with, so its admin key is the same in both runs.
const CLIENT_ID: &str = "c1a2";

/// The id of the upstream router, which the client lists as its one session.
const ROUTER_ID: &str = "a00031";

/// What one answer was: its key and its payload as text.
type Answer = (String, String);

/// The upstream nodes around the subject: the router it dials and the client that asks.
mod observer {
    use super::*;
    use up_zenoh::{Config, Session, Wait};

    /// An upstream node of `mode` with id `id`, that listens on `listen` and dials `connect` of the
    /// loopback, and scouts for nobody.
    pub fn open(id: &str, mode: &str, listen: Option<u16>, connect: Option<u16>) -> Session {
        let endpoints = |port: Option<u16>| match port {
            Some(port) => format!(r#"["tcp/127.0.0.1:{port}"]"#),
            None => "[]".to_owned(),
        };
        let config = Config::from_json5(&format!(
            r#"{{ id: "{id}", mode: "{mode}",
                  listen: {{ endpoints: {} }}, connect: {{ endpoints: {} }},
                  scouting: {{ multicast: {{ enabled: false }} }} }}"#,
            endpoints(listen),
            endpoints(connect)
        ))
        .expect("a configuration zenoh reads");
        up_zenoh::open(config).wait().expect("an upstream node opens")
    }

    /// The answers a GET of `selector` from `asker` gets, as `(key, payload)`.
    pub fn ask(asker: &Session, selector: &str) -> Vec<Answer> {
        let replies = asker
            .get(selector)
            .timeout(Duration::from_secs(2))
            .wait()
            .expect("asks");
        let mut found = Vec::new();
        while let Ok(reply) = replies.recv() {
            if let Ok(sample) = reply.result() {
                found.push((
                    sample.key_expr().to_string(),
                    sample
                        .payload()
                        .try_to_string()
                        .map(|text| text.into_owned())
                        .unwrap_or_default(),
                ));
            }
        }
        found
    }

    /// Ask `selector` until an answer comes or the patience runs out.
    pub fn ask_until_answered(asker: &Session, selector: &str) -> Vec<Answer> {
        let deadline = Instant::now() + PATIENCE;
        loop {
            let found = ask(asker, selector);
            if !found.is_empty() || Instant::now() >= deadline {
                return found;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

/// The lines one answer under the client's root says.
fn read_root(root: &str, answers: &[Answer]) -> Vec<String> {
    let mut out = vec![format!(
        "answers under the client's root: {}",
        answers.iter().filter(|(key, _)| key == root).count()
    )];
    let Some((_, body)) = answers.iter().find(|(key, _)| key == root) else {
        return out;
    };
    let document: serde_json::Value = match serde_json::from_str(body) {
        Ok(document) => document,
        Err(e) => {
            out.push(format!("the root document is not JSON: {e}"));
            return out;
        }
    };
    let names = |value: &serde_json::Value| -> String {
        let mut names: Vec<&str> = value
            .as_object()
            .map(|object| object.keys().map(String::as_str).collect())
            .unwrap_or_default();
        names.sort_unstable();
        names.join(",")
    };
    out.push(format!("the root document's fields: {}", names(&document)));
    out.push(format!("its zid: {}", document["zid"]));
    out.push(format!("its metadata: {}", document["metadata"]));
    out.push(format!("its locators: {}", document["locators"]));
    let sessions = document["sessions"].as_array().cloned().unwrap_or_default();
    out.push(format!("its sessions: {}", sessions.len()));
    for session in &sessions {
        out.push(format!("a session's fields: {}", names(session)));
        out.push(format!(
            "a session's peer and role: {} {}",
            session["peer"], session["whatami"]
        ));
    }
    out
}

macro_rules! client_cases {
    ($name:ident, $z:ident) => {
        mod $name {
            use super::*;
            use $z::{Config, Wait};

            /// The client under test: it says who it is, dials the router on `port` of the
            /// loopback, looks for nobody, and enables its admin space with a metadata of its own.
            fn client(port: u16) -> Config {
                Config::from_json5(&format!(
                    r#"{{ id: "{CLIENT_ID}", mode: "client",
                          connect: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                          scouting: {{ multicast: {{ enabled: false }} }},
                          metadata: {{ name: "client-a" }},
                          adminspace: {{ enabled: true }} }}"#
                ))
                .expect("a configuration zenoh reads")
            }

            /// What the asker behind the router sees of the client's admin space.
            pub fn seen() -> Vec<String> {
                let port = free_port();
                let router = observer::open(ROUTER_ID, "router", Some(port), None);
                let subject = $z::open(client(port)).wait().expect("the client opens");
                let asker = observer::open("b00031", "client", None, Some(port));
                let root = format!("@/{CLIENT_ID}/client");
                let mut out = read_root(&root, &observer::ask_until_answered(&asker, &root));
                out.push(format!(
                    "answers under the router role: {}",
                    observer::ask(&asker, &format!("@/{CLIENT_ID}/router/**")).len()
                ));
                drop(asker);
                drop(subject);
                drop(router);
                out
            }
        }
    };
}

client_cases!(up, up_zenoh);
client_cases!(wz, wz_zenoh);

/// The lines of the two crates must be equal, but for the ones listed here with the words of both:
/// a difference that is known is a difference that is named.
const KNOWN_DIFFERENCES: &[(&str, &str)] = &[];

fn compare(group: &str, up: &[String], wz: &[String]) {
    let unexpected: Vec<String> = up
        .iter()
        .zip(wz.iter())
        .filter(|(u, w)| u != w && !KNOWN_DIFFERENCES.iter().any(|(k, _)| u.starts_with(k)))
        .map(|(u, w)| format!("upstream: {u}\n        wz: {w}"))
        .collect();
    assert_eq!(
        up.len(),
        wz.len(),
        "{group}: upstream says {up:#?}, wz says {wz:#?}"
    );
    assert!(unexpected.is_empty(), "{group}\n{}", unexpected.join("\n"));
    if std::env::var_os("WZ_SESSION_TRANSCRIPT").is_some() {
        for line in up {
            println!("{group}: {line}");
        }
    }
}

#[test]
fn a_client_answers_its_admin_key_to_another_client_through_its_router() {
    // The log of upstream's nodes, for a run that is asked for it with `RUST_LOG`.
    up_zenoh::try_init_log_from_env();
    let (u, w) = (up::seen(), wz::seen());
    // The control: upstream's own client is answered, with its own id and its router listed, so a
    // comparison that passes is not a comparison of two nothings.
    for line in [
        "answers under the client's root: 1".to_owned(),
        format!("its zid: \"{CLIENT_ID}\""),
        format!("a session's peer and role: \"{ROUTER_ID}\" \"router\""),
    ] {
        assert!(u.contains(&line), "upstream does not say `{line}`: {u:#?}");
    }
    compare("client admin space", &u, &w);
}

#[test]
fn the_comparison_sees_a_client_that_answers_nothing() {
    let u = vec!["answers under the client's root: 1".to_owned()];
    let w = vec!["answers under the client's root: 0".to_owned()];
    let caught = std::panic::catch_unwind(|| compare("control", &u, &w));
    assert!(
        caught.is_err(),
        "a client that answers nothing must be a difference"
    );
}
