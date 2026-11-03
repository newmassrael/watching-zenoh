// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A peer that listens and declares a publisher BEFORE a router dials it: upstream's crate
//! (`up_zenoh`) and wz's (`wz_zenoh`) as that peer, given the same configurations, with an upstream
//! router that dials the peer afterwards and an upstream client behind the router that subscribes.
//! Results equal as text.
//!
//! ## The question
//!
//! `Session::declare_publisher` of the native engine sends the matching interest when the publisher
//! is declared, and the cache that sends a declaration again after a reconnect was not known to send
//! it to a link the peer accepts LATER. A peer of the C ABI (zenoh-pico's own limit) sends nothing
//! to a router that dials it afterwards, so the question was whether the native engine did the
//! same. The question had no measurement: the two orders below are it.
//!
//! * `publisher first`: the peer listens and declares its publisher, and only then does the router
//!   dial it. The client behind the router subscribes once the router holds the link.
//! * `router first`: the router holds the link before the publisher is declared. The control: what
//!   the first order is compared with, and what tells a comparison of two nothings from one of two
//!   nodes that deliver.
//!
//! What is read in each order is what the observers see: the router sees the peer, the client
//! receives a sample the publisher puts, and the publisher says whether it matches a subscriber.
//! Where the two crates differ the difference is a line of `known_differences`, with the words of both.

use std::{
    net::TcpListener,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

/// A port nothing listens on, that the kernel never picks for a socket that binds port 0 (below
/// every platform's ephemeral range), and that no call of this function gives twice.
fn free_port() -> u16 {
    use std::sync::atomic::AtomicU16;
    static NEXT: AtomicU16 = AtomicU16::new(0);
    loop {
        let offset = NEXT.fetch_add(1, Ordering::Relaxed);
        let port = 31_000 + ((std::process::id() % 8_000) as u16 + offset) % 18_000;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// How long a condition is waited for before the line says it did not hold.
const PATIENCE: Duration = Duration::from_secs(10);

fn wait_for(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    condition()
}

/// The upstream nodes around the subject: the router that dials it and the client behind that router.
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

    /// Whether the router has a link to a peer.
    pub fn holds_a_peer(router: &Session) -> bool {
        router.info().peers_zid().wait().next().is_some()
    }

    /// A client that subscribes to everything under `demo/pp` and counts what it receives.
    pub struct Client {
        _session: Session,
        _subscriber: up_zenoh::pubsub::Subscriber<()>,
        pub received: Arc<AtomicUsize>,
    }

    pub fn client(id: &str, router_port: u16) -> Client {
        let session = open(id, "client", None, Some(router_port));
        let received = Arc::new(AtomicUsize::new(0));
        let count = received.clone();
        let subscriber = session
            .declare_subscriber("demo/pp/**")
            .callback(move |_| {
                count.fetch_add(1, Ordering::SeqCst);
            })
            .wait()
            .expect("a subscriber");
        Client {
            _session: session,
            _subscriber: subscriber,
            received,
        }
    }
}

macro_rules! peer_cases {
    ($name:ident, $z:ident) => {
        mod $name {
            use super::*;
            use $z::{Config, Wait};

            /// The peer under test: it says who it is, listens on `port` of the loopback and looks
            /// for nobody.
            fn peer(port: u16) -> Config {
                Config::from_json5(&format!(
                    r#"{{ id: "5a0020", mode: "peer",
                          listen: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                ))
                .expect("a configuration zenoh reads")
            }

            /// One order: the publisher is declared before the router dials (`publisher_first`) or
            /// after it holds the link, and what the observers and the publisher say follows.
            fn order(publisher_first: bool) -> Vec<String> {
                let mut out = vec![];
                let (peer_port, router_port) = (free_port(), free_port());
                let subject = $z::open(peer(peer_port)).wait().expect("the peer opens");
                let mut publisher = None;
                if publisher_first {
                    publisher = Some(
                        subject
                            .declare_publisher("demo/pp/key")
                            .wait()
                            .expect("a publisher is declared"),
                    );
                }
                // The router dials the peer, and listens for the client.
                let router = observer::open("a00020", "router", Some(router_port), Some(peer_port));
                out.push(format!(
                    "the router holds a link to the peer: {}",
                    wait_for(|| observer::holds_a_peer(&router))
                ));
                if publisher.is_none() {
                    publisher = Some(
                        subject
                            .declare_publisher("demo/pp/key")
                            .wait()
                            .expect("a publisher is declared"),
                    );
                }
                let publisher = publisher.expect("a publisher");
                let client = observer::client("b00020", router_port);
                // The publisher puts until the client has one, which is when the subscription of the
                // client has reached the peer by way of the router.
                let delivered = wait_for(|| {
                    publisher.put("v").wait().expect("a put");
                    client.received.load(Ordering::SeqCst) > 0
                });
                out.push(format!("the client behind the router received a sample: {delivered}"));
                out.push(format!(
                    "the publisher matches a subscriber: {}",
                    wait_for(|| publisher.matching_status().wait().map(|s| s.matching()).unwrap_or(false))
                ));
                out
            }

            /// Both orders.
            pub fn orders() -> Vec<String> {
                let mut out = vec![];
                for (label, publisher_first) in [("publisher first", true), ("router first", false)] {
                    out.extend(order(publisher_first).into_iter().map(|l| format!("{label}: {l}")));
                }
                out
            }
        }
    };
}

peer_cases!(up, up_zenoh);
peer_cases!(wz, wz_zenoh);

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
    assert_eq!(up.len(), wz.len(), "{group}: upstream says {up:#?}, wz says {wz:#?}");
    assert!(unexpected.is_empty(), "{group}\n{}", unexpected.join("\n"));
    if std::env::var_os("WZ_SESSION_TRANSCRIPT").is_some() {
        for line in up {
            println!("{group}: {line}");
        }
    }
}

#[test]
fn a_peer_that_declared_a_publisher_before_a_router_dials_it_reaches_a_client_behind_the_router() {
    // The log of upstream's nodes, for a run that is asked for it with `RUST_LOG`.
    up_zenoh::try_init_log_from_env();
    let (u, w) = (up::orders(), wz::orders());
    // The control: upstream's own peer delivers in both orders, so a comparison that passes is not
    // a comparison of two nothings.
    for order in ["publisher first", "router first"] {
        assert!(
            u.iter().any(|l| l == &format!("{order}: the router holds a link to the peer: true")),
            "{u:#?}"
        );
        assert!(
            u.iter()
                .any(|l| l == &format!("{order}: the client behind the router received a sample: true")),
            "{u:#?}"
        );
    }
    compare("peer publisher before router", &u, &w);
}

#[test]
fn the_comparison_sees_a_peer_that_delivers_nothing() {
    let u = vec!["publisher first: the client behind the router received a sample: true".to_owned()];
    let w = vec!["publisher first: the client behind the router received a sample: false".to_owned()];
    let caught = std::panic::catch_unwind(|| compare("control", &u, &w));
    assert!(caught.is_err(), "a peer that delivers nothing must be a difference");
}
