// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh`, the opening and closing of a session (slice Z1a of the top crate): upstream's crate
//! (`up_zenoh`) and wz's (`wz_zenoh`) given the same configurations, results equal as text.
//!
//! * the identity: a session says the id its configuration states, `id()` says it again with an
//!   entity of its own, a clone is equal to what it clones and two sessions are not equal;
//! * the lifecycle: a session is open until it is closed, a second close is not an error, a close
//!   from an asynchronous context completes, the last handle dropped closes the session while a
//!   clone of it keeps it open, and what a closed session still listens on (a port that no
//!   longer answers);
//! * the refusals: the configurations that cannot be opened are refused in the words upstream
//!   refuses them in, without the place in the source each crate reports them from.
//!
//! Where the two differ the difference is a line of `known_differences`, with the words of both.

use std::{
    fmt::Debug,
    net::{SocketAddr, TcpListener, TcpStream},
    time::Duration,
};

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

/// A result as text.
fn text<T: Debug, E: std::fmt::Display>(r: Result<T, E>) -> String {
    match r {
        Ok(v) => format!("Ok({v:?})"),
        Err(e) => format!("Err({})", plain(&e.to_string())),
    }
}

/// A port nothing listens on.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("a port")
        .local_addr()
        .expect("its address")
        .port()
}

/// Whether something answers on `port` of the loopback.
fn answers(port: u16) -> bool {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_ok()
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

macro_rules! session_cases {
    ($name:ident, $z:ident) => {
        mod $name {
            use super::*;
            use $z::{Config, Wait};

            /// A peer that says who it is, listens on `port` of the loopback and looks for nobody.
            fn peer(id: &str, port: u16) -> Config {
                Config::from_json5(&format!(
                    r#"{{ id: "{id}", mode: "peer",
                          listen: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                ))
                .expect("a configuration zenoh reads")
            }

            fn config(json5: &str) -> Config {
                Config::from_json5(json5).expect("a configuration zenoh reads")
            }

            pub fn identity() -> Vec<String> {
                let mut out = vec![];
                let (port_a, port_b) = (free_port(), free_port());
                let one = $z::open(peer("a1b2c3", port_a)).wait().expect("opens");
                let two = $z::open(peer("a1b2c4", port_b)).wait().expect("opens");
                out.push(format!("zid: {}", one.zid()));
                out.push(format!("zid of the other: {}", two.zid()));
                out.push(format!("id carries the zid: {}", one.id().zid()));
                out.push(format!("ids of two sessions differ: {}", one.id() != two.id()));
                out.push(format!("is_closed: {}", one.is_closed()));
                let clone = one.clone();
                out.push(format!("a clone equals: {}", clone == one));
                out.push(format!("two sessions equal: {}", one == two));
                out.push(format!("a clone has the same id: {}", clone.id() == one.id()));
                // Another session that states the same id is another session, equal to nothing
                // but its clones, and its own entity id is not the first one's.
                let same_id = $z::open(peer("a1b2c3", free_port())).wait().expect("opens");
                out.push(format!("same zid: {}", same_id.zid() == one.zid()));
                out.push(format!("same zid, equal sessions: {}", same_id == one));
                out.push(format!("same zid, equal ids: {}", same_id.id() == one.id()));
                out
            }

            pub fn lifecycle() -> Vec<String> {
                let mut out = vec![];
                let port = free_port();
                let session = $z::open(peer("a1b2c5", port)).wait().expect("opens");
                let clone = session.clone();
                out.push(format!("listening: {}", answers(port)));
                out.push(format!("close: {}", text(session.close().wait())));
                out.push(format!(
                    "closed: {} and its clone: {}",
                    session.is_closed(),
                    clone.is_closed()
                ));
                out.push(format!("second close: {}", text(session.close().wait())));
                out.push(format!("listening after close: {}", answers(port)));
                out
            }

            pub fn last_handle() -> Vec<String> {
                let mut out = vec![];
                let port = free_port();
                let session = $z::open(peer("a1b2c6", port)).wait().expect("opens");
                let clone = session.clone();
                drop(session);
                out.push(format!("listening with a handle left: {}", answers(port)));
                out.push(format!("clone closed: {}", clone.is_closed()));
                drop(clone);
                std::thread::sleep(Duration::from_millis(100));
                out.push(format!("listening with none left: {}", answers(port)));
                out
            }

            pub fn asynchronous() -> Vec<String> {
                let mut out = vec![];
                let port = free_port();
                let runtime = runtime();
                runtime.block_on(async {
                    let session = $z::open(peer("a1b2c7", port)).await.expect("opens");
                    out.push(format!("closed before: {}", session.is_closed()));
                    out.push(format!("close: {}", text(session.close().await)));
                    out.push(format!("closed after: {}", session.is_closed()));
                });
                out
            }

            /// What each configuration that cannot be opened is refused with. Every row stays on
            /// the loopback and in a role with no scouting, so none of them waits for a network.
            ///
            /// `closed_port` is a port nothing listens on and `taken_port` one that something does,
            /// the same two for both crates so that what they report names the same endpoints.
            pub fn refusals(closed_port: u16, taken_port: u16) -> Vec<String> {
                let group = r#"["udp/224.0.0.224:7446#iface=lo"]"#;
                let off = "scouting: { multicast: { enabled: false } }";
                let closed = format!(r#"["tcp/127.0.0.1:{closed_port}"]"#);
                let rows: Vec<(&str, String)> = vec![
                    (
                        "a client with nothing to dial",
                        format!(r#"{{ mode: "client", {off} }}"#),
                    ),
                    (
                        "a peer told to dial a multicast group",
                        format!(
                            r#"{{ mode: "peer", {off}, listen: {{ endpoints: [] }},
                                 connect: {{ endpoints: {group} }} }}"#
                        ),
                    ),
                    (
                        "a router told to dial a multicast group",
                        format!(
                            r#"{{ mode: "router", {off}, listen: {{ endpoints: [] }},
                                 connect: {{ endpoints: {group} }} }}"#
                        ),
                    ),
                    (
                        "qos together with lowlatency",
                        format!(
                            r#"{{ mode: "client", {off}, connect: {{ endpoints: {closed} }},
                                 transport: {{ unicast: {{ lowlatency: true }} }} }}"#
                        ),
                    ),
                    (
                        "a client whose only endpoint nobody listens on",
                        format!(r#"{{ mode: "client", {off}, connect: {{ endpoints: {closed} }} }}"#),
                    ),
                    (
                        "a peer whose only listener is on a port that is taken",
                        format!(
                            r#"{{ mode: "peer", {off}, listen: {{ endpoints: ["tcp/127.0.0.1:{taken_port}"] }} }}"#
                        ),
                    ),
                    (
                        "a peer that listens on a taken port and dials one nobody listens on",
                        format!(
                            r#"{{ mode: "peer", {off}, listen: {{ endpoints: ["tcp/127.0.0.1:{taken_port}"] }},
                                 connect: {{ endpoints: {closed} }} }}"#
                        ),
                    ),
                ];
                rows.into_iter()
                    .map(|(label, json5)| {
                        format!("{label}: {}", text($z::open(config(&json5)).wait().map(|_| ())))
                    })
                    .collect()
            }
        }
    };
}

mod up {
    use super::*;
    session_cases!(cases, up_zenoh);
    pub use cases::*;
}

mod wz {
    use super::*;
    session_cases!(cases, wz_zenoh);
    pub use cases::*;
}

/// The lines on which the two differ, with the words of both, held so that a change on either side
/// shows. Empty while no difference has been seen.
fn known_differences() -> Vec<(&'static str, &'static str, &'static str)> {
    // The engine reports that a link it was told to listen on did not open and not which one or
    // why, so a session that listens and dials says "LinkFailed" where upstream says what the
    // operating system answered. The slice that carries the cause of a failed open through the
    // engine closes these two.
    vec![
        (
            "refusals",
            "Can not create a new TCP listener bound to",
            "the session could not be opened: LinkFailed",
        ),
    ]
}

fn compare(group: &str, up: &[String], wz: &[String]) {
    assert_eq!(up.len(), wz.len(), "{group}: the transcripts differ in length\nupstream: {up:#?}\nwz: {wz:#?}");
    let known = known_differences();
    let mut unexpected = vec![];
    for (x, y) in up.iter().zip(wz) {
        if x == y {
            continue;
        }
        let expected = known
            .iter()
            .any(|(g, u, w)| *g == group && x.contains(u) && y.contains(w));
        if !expected {
            unexpected.push(format!("upstream: {x}\nwz:       {y}"));
        }
    }
    assert!(unexpected.is_empty(), "{group}\n{}", unexpected.join("\n"));
    if std::env::var_os("WZ_SESSION_TRANSCRIPT").is_some() {
        for line in up {
            println!("{group}: {line}");
        }
    }
}

#[test]
fn the_identity_of_a_session() {
    let (u, w) = (up::identity(), wz::identity());
    assert!(u.iter().any(|l| l == "zid: a1b2c3"), "{u:#?}");
    compare("identity", &u, &w);
}

#[test]
fn the_lifecycle_of_a_session() {
    let (u, w) = (up::lifecycle(), wz::lifecycle());
    assert!(u.iter().any(|l| l == "listening: true"), "{u:#?}");
    assert!(u.iter().any(|l| l == "listening after close: false"), "{u:#?}");
    compare("lifecycle", &u, &w);
}

#[test]
fn the_last_handle_dropped_closes_the_session() {
    let (u, w) = (up::last_handle(), wz::last_handle());
    assert!(u.iter().any(|l| l == "listening with a handle left: true"), "{u:#?}");
    assert!(u.iter().any(|l| l == "listening with none left: false"), "{u:#?}");
    compare("last handle", &u, &w);
}

#[test]
fn a_session_opens_and_closes_from_an_asynchronous_context() {
    let (u, w) = (up::asynchronous(), wz::asynchronous());
    assert!(u.iter().any(|l| l == "closed after: true"), "{u:#?}");
    compare("asynchronous", &u, &w);
}

#[test]
fn the_configurations_that_cannot_be_opened() {
    // A port that something listens on for as long as the rows run, and one nothing does.
    let taken = TcpListener::bind("127.0.0.1:0").expect("a port");
    let taken_port = taken.local_addr().expect("its address").port();
    let closed_port = free_port();
    let (u, w) = (
        up::refusals(closed_port, taken_port),
        wz::refusals(closed_port, taken_port),
    );
    drop(taken);
    assert!(u.iter().all(|l| l.contains(": Err(")), "{u:#?}");
    compare("refusals", &u, &w);
}

#[test]
fn the_comparison_sees_a_session_that_differs() {
    let u = up::identity();
    let mut w = wz::identity();
    w[0] = format!("{} changed", w[0]);
    assert!(u.iter().zip(&w).any(|(x, y)| x != y));
    assert_ne!(up::identity(), up::lifecycle());
}
