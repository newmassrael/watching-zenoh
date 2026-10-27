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

/// A port nothing listens on, that the kernel never picks for a socket that binds port 0 (below
/// every platform's ephemeral range, so a session of this process that listens on `tcp/[::]:0`
/// cannot be handed it between the choice and the use), and that no call of this function gives
/// twice. The numbers are tried from one that depends on the process, not read back from a socket
/// that is dropped.
fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    loop {
        let offset = NEXT.fetch_add(1, Ordering::Relaxed);
        let port = 12_000 + ((std::process::id() % 8_000) as u16 + offset) % 18_000;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// Whether something answers on `port` of the loopback.
fn answers(port: u16) -> bool {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_ok()
}

/// What upstream's own sessions see of the node a test opens, which is how the role a node plays is
/// observed: the handshake carries it, and the other side reads it (`routers_zid`, `peers_zid`, and
/// the transports with the role and the qualities each announced).
mod observer {
    use std::time::{Duration, Instant};

    use up_zenoh::{Config, Session, Wait};

    /// An upstream node of `mode` with id `id`, that listens on `listen` and dials `connect` of the
    /// loopback, and scouts for nobody.
    pub fn open(
        id: &str,
        mode: &str,
        listen: Option<u16>,
        connect: Option<u16>,
    ) -> Result<Session, String> {
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
        up_zenoh::open(config).wait().map_err(|error| error.to_string())
    }

    /// The routers and peers this session sees, and its transports (id, role, qos, multicast), each
    /// sorted.
    pub fn seen(session: &Session) -> String {
        let sorted = |mut list: Vec<String>| {
            list.sort();
            list
        };
        let info = session.info();
        let routers = sorted(info.routers_zid().wait().map(|z| z.to_string()).collect());
        let peers = sorted(info.peers_zid().wait().map(|z| z.to_string()).collect());
        let transports = sorted(
            info.transports()
                .wait()
                .map(|t| {
                    format!(
                        "{} {:?} qos={} multicast={}",
                        t.zid(),
                        t.whatami(),
                        t.is_qos(),
                        t.is_multicast()
                    )
                })
                .collect(),
        );
        format!("routers {routers:?} peers {peers:?} transports {transports:?}")
    }

    /// An upstream node that dials `port` and subscribes to `demo/**`, keeping what it receives as
    /// text: every field of a sample that crosses a link.
    pub struct Watcher {
        _session: Session,
        _subscriber: up_zenoh::pubsub::Subscriber<()>,
        seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    /// What a received sample says, as one line. `with_time` includes the time of its timestamp,
    /// which a stamp made by a clock would not repeat from one run to the next.
    fn describe(sample: &up_zenoh::sample::Sample, with_time: bool) -> String {
        let timestamp = sample.timestamp().map(|t| {
            if with_time {
                format!("{t}")
            } else {
                format!("id {}", t.get_id())
            }
        });
        let payload = sample.payload().len();
        let text = sample
            .payload()
            .try_to_string()
            .map_or_else(|_| "(not text)".to_owned(), |s| s.to_string());
        let attachment = sample
            .attachment()
            .map(|a| a.try_to_string().map_or_else(|_| "(not text)".to_owned(), |s| s.to_string()));
        let source = sample
            .source_info()
            .map(|i| (format!("{:?}", i.source_id()), i.source_sn()));
        format!(
            "{} {:?} len={payload} {} encoding={} priority={:?} congestion={:?} express={} \
             reliability={:?} timestamp={timestamp:?} attachment={attachment:?} source={source:?}",
            sample.key_expr(),
            sample.kind(),
            if payload <= 16 { text } else { format!("{}...", &text[..8.min(text.len())]) },
            sample.encoding(),
            sample.priority(),
            sample.congestion_control(),
            sample.express(),
            sample.reliability(),
        )
    }

    /// An upstream node that dials the node of `port` and subscribes to everything under `demo`.
    pub fn watch(id: &str, port: u16, with_time: bool) -> Result<Watcher, String> {
        let session = open(id, "peer", None, Some(port))?;
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = seen.clone();
        let subscriber = session
            .declare_subscriber("demo/**")
            .callback(move |sample| sink.lock().unwrap().push(describe(&sample, with_time)))
            .wait()
            .map_err(|error| error.to_string())?;
        Ok(Watcher {
            _session: session,
            _subscriber: subscriber,
            seen,
        })
    }

    impl Watcher {
        /// The lines received so far that are not the probe of readiness.
        pub fn lines(&self) -> Vec<String> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .filter(|line| !line.starts_with("demo/ready "))
                .cloned()
                .collect()
        }

        /// Whether a probe of readiness was received.
        pub fn is_ready(&self) -> bool {
            self.seen.lock().unwrap().iter().any(|line| line.starts_with("demo/ready "))
        }
    }

    /// An upstream node that dials `port` and publishes to the node it dials.
    pub struct Source {
        session: Session,
    }

    pub fn source(id: &str, port: u16) -> Result<Source, String> {
        Ok(Source {
            session: open(id, "peer", None, Some(port))?,
        })
    }

    impl Source {
        /// A put on the key of readiness, repeated until the node dialled has the subscription.
        pub fn probe(&self) {
            self.session.put("demo/ready", "").wait().expect("a probe");
        }

        /// A put on `key` as one of the nodes that publish for the test of origins and callbacks.
        pub fn put(&self, key: &str, payload: &str) {
            self.session.put(key, payload).wait().expect("a put");
        }

        /// Every setting of a put and a delete, published as the other tests' subjects publish
        /// them: 13 publications that a subscriber of `demo/**` takes.
        pub fn publish_all(&self) -> usize {
            use up_zenoh::internal::traits::{
                EncodingBuilderTrait, QoSBuilderTrait, SampleBuilderTrait, TimestampBuilderTrait,
            };
            let session = &self.session;
            let mut sent = 0;
            let mut sent_one = |result: up_zenoh::Result<()>| {
                result.expect("a publication");
                sent += 1;
            };
            sent_one(session.put("demo/plain", "v1").wait());
            sent_one(
                session
                    .put("demo/settings", "v2")
                    .encoding(up_zenoh::bytes::Encoding::TEXT_PLAIN)
                    .priority(up_zenoh::qos::Priority::RealTime)
                    .congestion_control(up_zenoh::qos::CongestionControl::Block)
                    .express(true)
                    .attachment("attached")
                    .wait(),
            );
            sent_one(
                session
                    .put("demo/schema", "{}")
                    .encoding(up_zenoh::bytes::Encoding::APPLICATION_JSON.with_schema("v1"))
                    .wait(),
            );
            sent_one(
                session
                    .put("demo/low", "v3")
                    .priority(up_zenoh::qos::Priority::Background)
                    .congestion_control(up_zenoh::qos::CongestionControl::BlockFirst)
                    .wait(),
            );
            let id = up_zenoh::time::TimestampId::try_from(&[0xab_u8, 0xcd][..]).expect("an id");
            let at = up_zenoh::time::Timestamp::new(up_zenoh::time::NTP64(0x1234_5678_9abc_def0), id);
            sent_one(session.put("demo/stamped", "v4").timestamp(at).wait());
            sent_one(
                session
                    .put("demo/sourced", "v5")
                    .source_info(up_zenoh::sample::SourceInfo::new(
                        up_zenoh::session::EntityGlobalId::new("c0ffee".parse().expect("an id"), 7),
                        41,
                    ))
                    .wait(),
            );
            sent_one(session.delete("demo/plain").wait());
            sent_one(session.delete("demo/plain").attachment("gone").wait());
            // A key declared by the source goes on the wire as a declaration and its suffix, and is
            // kept until the end of the call, after which the samples have been seen by the test.
            let declared = session.declare_keyexpr("demo/declared").wait().expect("declares");
            sent_one(session.put(&declared, "v9").wait());
            let longer = declared.join("leaf").expect("a key");
            sent_one(session.put(&longer, "v10").wait());
            sent_one(session.put("demo/big", vec![7u8; 70_000]).wait());
            // Last, and after the fragments of the large one, which end a batch. Upstream puts a
            // message of the other reliability into the batch that is open, behind a frame header
            // of its own, and the engine reads a frame to the end of the batch it is in, so
            // whatever follows a best-effort message in a batch is lost to it (carried in
            // docs/zenoh-api-on-the-engine.md, Z2c). Sent here, no reliable message is behind it.
            sent_one(
                session
                    .put("demo/best", "v6")
                    .reliability(up_zenoh::qos::Reliability::BestEffort)
                    .wait(),
            );
            std::thread::sleep(Duration::from_millis(400));
            sent
        }
    }

    /// What a reply says, as one line: who answered, and every field of the answer that crosses a
    /// link.
    fn describe_reply(reply: &up_zenoh::query::Reply) -> String {
        let replier = reply.replier_id().map(|id| id.zid().to_string());
        match reply.result() {
            Ok(sample) => format!("ok replier={replier:?} {}", describe(sample, false)),
            Err(error) => format!(
                "err replier={replier:?} {} encoding={}",
                error
                    .payload()
                    .try_to_string()
                    .map_or_else(|_| "(not text)".to_owned(), |s| s.to_string()),
                error.encoding()
            ),
        }
    }

    /// The lines of the replies of a get, sorted, once the get is over.
    fn collect<E: std::fmt::Display>(
        label: &str,
        asked: Result<up_zenoh::handlers::FifoChannelHandler<up_zenoh::query::Reply>, E>,
    ) -> Vec<String> {
        let mut lines = match asked {
            Ok(replies) => replies.iter().map(|reply| describe_reply(&reply)).collect(),
            Err(error) => vec![format!("the get failed: {error}")],
        };
        lines.sort();
        let mut out = vec![format!("{label}: {} reply(ies)", lines.len())];
        out.extend(lines.into_iter().map(|line| format!("{label}: {line}")));
        out
    }

    /// An upstream node that dials the node of `port` and asks it queries of every shape, once the
    /// node answers a probe, keeping what comes back as text.
    pub fn asks(id: &str, port: u16) -> Result<Vec<String>, String> {
        use up_zenoh::{
            bytes::Encoding,
            query::{QueryTarget, ReplyKeyExpr},
            qos::{CongestionControl, Priority},
        };
        let session = open(id, "peer", None, Some(port))?;
        let wait = Duration::from_secs(5);
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut ready = false;
        while !ready && Instant::now() < deadline {
            ready = session
                .get("demo/q/ready")
                .timeout(Duration::from_secs(1))
                .wait()
                .map(|replies| replies.iter().count() > 0)
                .unwrap_or(false);
        }
        let mut out = vec![format!("queryable known: {ready}")];
        out.extend(collect("plain", session.get("demo/q/plain?a=1;b=2").timeout(wait).wait()));
        out.extend(collect(
            "with a body",
            session
                .get("demo/q/body")
                .payload("body")
                .encoding(Encoding::TEXT_PLAIN)
                .attachment("att")
                .timeout(wait)
                .wait(),
        ));
        out.extend(collect(
            "every form of reply",
            session.get("demo/q/forms/**").target(QueryTarget::All).timeout(wait).wait(),
        ));
        out.extend(collect(
            "disjoint reply refused",
            session.get("demo/q/far").timeout(Duration::from_secs(2)).wait(),
        ));
        out.extend(collect(
            "disjoint reply accepted",
            session
                .get("demo/q/far")
                .accept_replies(ReplyKeyExpr::Any)
                .timeout(wait)
                .wait(),
        ));
        out.extend(collect("answered late", session.get("demo/q/held").timeout(wait).wait()));
        out.extend(collect(
            "with options",
            session
                .get("demo/q/options")
                .priority(Priority::RealTime)
                .congestion_control(CongestionControl::Block)
                .express(true)
                .timeout(wait)
                .wait(),
        ));
        out.extend(collect(
            "nobody to answer",
            session.get("demo/elsewhere/none").timeout(Duration::from_secs(2)).wait(),
        ));
        Ok(out)
    }

    /// An upstream node that dials `port` and answers the queries of `demo/g/**` in every form a
    /// queryable has, keeping what each query said as text.
    pub struct Answerer {
        _session: Session,
        _queryable: up_zenoh::query::Queryable<()>,
        saw: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    /// An upstream node that dials the node of `port` and answers the queries it is asked.
    pub fn answerer(id: &str, port: u16) -> Result<Answerer, String> {
        use up_zenoh::internal::traits::{
            EncodingBuilderTrait, QoSBuilderTrait, SampleBuilderTrait, TimestampBuilderTrait,
        };
        let session = open(id, "peer", None, Some(port))?;
        let saw = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let record = saw.clone();
        // The queries that are never answered: held until the node ends.
        let held = std::sync::Arc::new(std::sync::Mutex::new(Vec::<up_zenoh::query::Query>::new()));
        let queryable = session
            .declare_queryable("demo/g/**")
            .complete(true)
            .callback(move |query| {
                let key = query.key_expr().as_str().to_owned();
                if key == "demo/g/ready" {
                    query.reply("demo/g/ready", "ready").wait().expect("replies");
                    return;
                }
                let body_of = |bytes: Option<&up_zenoh::bytes::ZBytes>| {
                    bytes.map(|b| b.try_to_string().map(|s| s.into_owned()).unwrap_or_default())
                };
                record.lock().unwrap().push(format!(
                    "saw {} | key {key} | parameters {} | payload {:?} | encoding {:?} | \
                     attachment {:?} | priority {:?} congestion {:?} express {} | source {:?} | \
                     accepts {:?}",
                    query.selector(),
                    query.parameters(),
                    body_of(query.payload()),
                    query.encoding().map(|e| e.to_string()),
                    body_of(query.attachment()),
                    query.priority(),
                    query.congestion_control(),
                    query.express(),
                    query.source_info().map(|i| (format!("{:?}", i.source_id()), i.source_sn())),
                    query.accepts_replies(),
                ));
                let at = |time: u64| {
                    let id = up_zenoh::time::TimestampId::try_from(&[0xab_u8, 0xcd][..]).expect("an id");
                    up_zenoh::time::Timestamp::new(up_zenoh::time::NTP64(time), id)
                };
                match key.as_str() {
                    "demo/g/plain" => {
                        query.reply("demo/g/plain", "r1").wait().expect("replies");
                    }
                    "demo/g/body" => {
                        let body = body_of(query.payload()).unwrap_or_default();
                        query
                            .reply("demo/g/body", body)
                            .encoding(up_zenoh::bytes::Encoding::APPLICATION_JSON)
                            .wait()
                            .expect("replies");
                    }
                    "demo/g/forms/**" => {
                        query
                            .reply("demo/g/forms/a", "pa")
                            .encoding(up_zenoh::bytes::Encoding::TEXT_PLAIN.with_schema("s"))
                            .attachment("with")
                            .timestamp(at(0x1234_5678_9abc_def0))
                            .express(true)
                            .priority(up_zenoh::qos::Priority::DataHigh)
                            .congestion_control(up_zenoh::qos::CongestionControl::Drop)
                            .source_info(up_zenoh::sample::SourceInfo::new(
                                up_zenoh::session::EntityGlobalId::new("c0ffee".parse().expect("an id"), 7),
                                41,
                            ))
                            .wait()
                            .expect("replies");
                        query
                            .reply_del("demo/g/forms/b")
                            .attachment("gone")
                            .timestamp(at(0x1234_5678_9abc_def0))
                            .wait()
                            .expect("replies");
                        query
                            .reply_err("broken")
                            .encoding(up_zenoh::bytes::Encoding::TEXT_PLAIN)
                            .wait()
                            .expect("replies");
                    }
                    "demo/g/far" => {
                        let _ = query.reply("demo/other/key", "far").wait();
                    }
                    "demo/g/held" => {
                        let late = query.clone();
                        std::thread::spawn(move || {
                            std::thread::sleep(Duration::from_millis(200));
                            let _ = late.reply("demo/g/held", "late").wait();
                        });
                    }
                    "demo/g/silent" => held.lock().unwrap().push(query),
                    // Two versions of one value, the newer first, and a third on another key.
                    "demo/g/dup" => {
                        query.reply("demo/g/dup", "new").timestamp(at(2_000_000_000)).wait().expect("replies");
                        query.reply("demo/g/dup", "old").timestamp(at(1_000_000_000)).wait().expect("replies");
                        query.reply("demo/g/dup", "bare").wait().expect("replies");
                    }
                    "demo/g/options" => {
                        query.reply("demo/g/options", "o").express(false).wait().expect("replies");
                    }
                    _ => {}
                }
            })
            .wait()
            .map_err(|error| error.to_string())?;
        Ok(Answerer {
            _session: session,
            _queryable: queryable,
            saw,
        })
    }

    impl Answerer {
        /// What each query said, in the order they came.
        pub fn lines(&self) -> Vec<String> {
            self.saw.lock().unwrap().clone()
        }
    }

    /// [`seen`] once the session sees `count` transports, or after five seconds.
    pub fn seen_with(session: &Session, count: usize) -> String {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let now = seen(session);
            if now.matches(" qos=").count() >= count || Instant::now() > deadline {
                return now;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
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

            /// A node of this crate of `mode` with id `id`, that listens on `listen` and dials
            /// `connect` of the loopback, and scouts for nobody.
            fn node(id: &str, mode: &str, listen: Option<u16>, connect: Option<u16>) -> Config {
                let endpoints = |port: Option<u16>| match port {
                    Some(port) => format!(r#"["tcp/127.0.0.1:{port}"]"#),
                    None => "[]".to_owned(),
                };
                config(&format!(
                    r#"{{ id: "{id}", mode: "{mode}",
                          listen: {{ endpoints: {} }}, connect: {{ endpoints: {} }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#,
                    endpoints(listen),
                    endpoints(connect)
                ))
            }

            /// What this crate's session sees of the nodes it is connected to (its own `info`), once
            /// it sees `expected` of them or after five seconds.
            fn sees(session: &$z::Session, expected: usize) -> String {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                loop {
                    let info = session.info();
                    let sorted = |mut list: Vec<String>| {
                        list.sort();
                        list
                    };
                    let routers = sorted(info.routers_zid().wait().map(|z| z.to_string()).collect());
                    let peers = sorted(info.peers_zid().wait().map(|z| z.to_string()).collect());
                    if routers.len() + peers.len() >= expected || std::time::Instant::now() > deadline {
                        return format!(
                            "the session is {} and sees routers {routers:?} peers {peers:?}",
                            info.zid().wait()
                        );
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }

            /// The role this crate's node plays, as upstream's nodes on the other side of a link
            /// read it: each line is what an upstream node sees of the one opened here, and what
            /// the node sees of that node in return.
            pub fn roles() -> Vec<String> {
                let mut out = vec![];
                // A node of this crate that listens, seen by an upstream node that dials it.
                for (id, mode, observer_id, observer_mode) in [
                    ("5a0001", "router", "b00001", "client"),
                    ("5a0002", "peer", "b00002", "peer"),
                ] {
                    let port = free_port();
                    let subject = $z::open(node(id, mode, Some(port), None)).wait();
                    let line = match &subject {
                        Err(error) => format!("the {mode} did not open: {}", plain(&error.to_string())),
                        Ok(session) => match observer::open(observer_id, observer_mode, None, Some(port)) {
                            Ok(observer) => {
                                // A node that listens sees a peer that dials it, and a client is
                                // neither a router nor a peer, so it sees one only of the first.
                                let expected = usize::from(observer_mode == "peer");
                                format!("{}; {}", observer::seen(&observer), sees(session, expected))
                            }
                            Err(error) => format!("the observer did not open: {}", plain(&error)),
                        },
                    };
                    out.push(format!("{mode} listening, {observer_mode} dials: {line}"));
                }
                // A client, a peer and a router of this crate that each dial an upstream router,
                // seen by it.
                for (id, mode) in [
                    ("5a0003", "client"),
                    ("5a0004", "peer"),
                    ("5a0005", "router"),
                ] {
                    let port = free_port();
                    let upstream = observer::open("a00001", "router", Some(port), None)
                        .expect("the upstream router opens");
                    let subject = $z::open(node(id, mode, None, Some(port))).wait();
                    let line = match &subject {
                        Err(error) => format!("the {mode} did not open: {}", plain(&error.to_string())),
                        Ok(session) => {
                            format!("{}; {}", observer::seen_with(&upstream, 1), sees(session, 1))
                        }
                    };
                    out.push(format!("{mode} dials an upstream router: {line}"));
                }
                out
            }

            /// What a node of this crate publishes, as an upstream node that subscribes on the other
            /// side of a link receives it: every setting of a put and a delete, a key declared on the
            /// session, a payload larger than a batch, and the destinations that deliver nothing.
            /// `timestamping` turns on the node's clock, so that the publications carry its stamps.
            pub fn publications(timestamping: bool) -> Vec<String> {
                use $z::internal::traits::{
                    EncodingBuilderTrait, QoSBuilderTrait, SampleBuilderTrait, TimestampBuilderTrait,
                };
                let mut out = vec![];
                let port = free_port();
                let subject = $z::open(config(&format!(
                    r#"{{ id: "5a0010", mode: "peer",
                          listen: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                          timestamping: {{ enabled: {timestamping} }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                )))
                .wait()
                .expect("opens");
                let watcher = observer::watch("b00010", port, !timestamping).expect("the observer opens");
                // The subject knows the observer's subscription once a probe on its key arrives.
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                while !watcher.is_ready() && std::time::Instant::now() < deadline {
                    subject.put("demo/ready", "").wait().expect("a probe");
                    std::thread::sleep(Duration::from_millis(50));
                }
                out.push(format!("subscription known: {}", watcher.is_ready()));
                let mut delivered = 0usize;
                let mut record = |label: &str, result: Result<(), _>, arrives: bool| {
                    out.push(format!("{label}: {}", text(result)));
                    delivered += usize::from(arrives);
                };
                record("plain put", subject.put("demo/plain", "v1").wait(), true);
                record(
                    "put with every setting",
                    subject
                        .put("demo/settings", "v2")
                        .encoding($z::bytes::Encoding::TEXT_PLAIN)
                        .priority($z::qos::Priority::RealTime)
                        .congestion_control($z::qos::CongestionControl::Block)
                        .express(true)
                        .attachment("attached")
                        .wait(),
                    true,
                );
                record(
                    "put with a schema",
                    subject
                        .put("demo/schema", "{}")
                        .encoding($z::bytes::Encoding::APPLICATION_JSON.with_schema("v1"))
                        .wait(),
                    true,
                );
                record(
                    "put with the lowest priority and blocking first",
                    subject
                        .put("demo/low", "v3")
                        .priority($z::qos::Priority::Background)
                        .congestion_control($z::qos::CongestionControl::BlockFirst)
                        .wait(),
                    true,
                );
                if !timestamping {
                    let id = $z::time::TimestampId::try_from(&[0xab_u8, 0xcd][..]).expect("an id");
                    let at = $z::time::Timestamp::new($z::time::NTP64(0x1234_5678_9abc_def0), id);
                    record(
                        "put with a timestamp",
                        subject.put("demo/stamped", "v4").timestamp(at).wait(),
                        true,
                    );
                }
                record(
                    "put with a source",
                    subject
                        .put("demo/sourced", "v5")
                        .source_info($z::sample::SourceInfo::new(
                            $z::session::EntityGlobalId::new(
                                "c0ffee".parse().expect("an id"),
                                7,
                            ),
                            41,
                        ))
                        .wait(),
                    true,
                );
                record(
                    "put best effort",
                    subject
                        .put("demo/best", "v6")
                        .reliability($z::qos::Reliability::BestEffort)
                        .wait(),
                    true,
                );
                record(
                    "put to remote only",
                    subject
                        .put("demo/remote", "v7")
                        .allowed_destination($z::sample::Locality::Remote)
                        .wait(),
                    true,
                );
                record(
                    "put to the session only",
                    subject
                        .put("demo/local", "v8")
                        .allowed_destination($z::sample::Locality::SessionLocal)
                        .wait(),
                    false,
                );
                record("delete", subject.delete("demo/plain").wait(), true);
                record(
                    "delete with an attachment",
                    subject.delete("demo/plain").attachment("gone").wait(),
                    true,
                );
                // A key declared on the session goes on the wire as a declaration and its suffix.
                // The declaration is kept until the samples have been seen: its retraction is
                // carried at the control priority, which a link serves before the data priority,
                // so a retraction sent right behind a put may reach the peer first (upstream's
                // pipeline pulls its queues in the same order).
                let mut declarations = vec![];
                if let Ok(declared) = subject.declare_keyexpr("demo/declared").wait() {
                    record("put on a declared key", subject.put(&declared, "v9").wait(), true);
                    let longer = declared.join("leaf").expect("a key");
                    record("put on a key under a declared one", subject.put(&longer, "v10").wait(), true);
                    declarations.push(declared);
                    declarations.push(longer);
                }
                // A payload larger than a batch is sent in fragments and arrives whole.
                record("put of 70000 bytes", subject.put("demo/big", vec![7u8; 70_000]).wait(), true);
                // Refusals made before anything is sent.
                record("put on an invalid key", subject.put("demo//bad", "x").wait(), false);
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                while watcher.lines().len() < delivered && std::time::Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(20));
                }
                // What may still be on its way, and should not be.
                std::thread::sleep(Duration::from_millis(300));
                drop(declarations);
                let mut received = watcher.lines();
                // Samples of different priorities are carried by different queues, so their order
                // is not the order they were sent in.
                received.sort();
                out.push(format!("received {} of {delivered}", received.len()));
                out.extend(received.into_iter().map(|line| format!("sample: {line}")));
                subject.close().wait().expect("closes");
                out.push(format!("put after close: {}", text(subject.put("demo/after", "x").wait())));
                out.push(format!("delete after close: {}", text(subject.delete("demo/after").wait())));
                out
            }

            /// A publisher declared on a session that an upstream observer is connected to: the
            /// settings it says, what it publishes with and without overriding them, the sink it
            /// is, what undeclaring it does, and what a closed session leaves of it. Everything a
            /// publisher writes is for the observer's subscription, which says what arrived.
            pub fn publishers() -> Vec<String> {
                use $z::internal::traits::{EncodingBuilderTrait, QoSBuilderTrait, SampleBuilderTrait};
                let mut out = vec![];
                let port = free_port();
                let subject = $z::open(config(&format!(
                    r#"{{ id: "5a0011", mode: "peer",
                          listen: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                )))
                .wait()
                .expect("opens");
                let watcher = observer::watch("b00011", port, true).expect("the observer opens");
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                while !watcher.is_ready() && std::time::Instant::now() < deadline {
                    subject.put("demo/ready", "").wait().expect("a probe");
                    std::thread::sleep(Duration::from_millis(50));
                }
                out.push(format!("subscription known: {}", watcher.is_ready()));
                let mut delivered = 0usize;
                let mut record = |label: &str, result: Result<(), _>, arrives: bool| {
                    out.push(format!("{label}: {}", text(result)));
                    delivered += usize::from(arrives);
                };
                let plain = subject.declare_publisher("demo/pub/plain").wait().expect("declares");
                let settings = subject
                    .declare_publisher("demo/pub/settings")
                    .encoding($z::bytes::Encoding::TEXT_PLAIN)
                    .priority($z::qos::Priority::RealTime)
                    .congestion_control($z::qos::CongestionControl::Block)
                    .express(true)
                    .reliability($z::qos::Reliability::BestEffort)
                    .wait()
                    .expect("declares");
                let says = format!(
                    "plain says: {} {} {:?} {:?} {:?}",
                    plain.key_expr(),
                    plain.encoding(),
                    plain.congestion_control(),
                    plain.priority(),
                    plain.reliability(),
                );
                let also = format!(
                    "settings says: {} {} {:?} {:?} {:?}",
                    settings.key_expr(),
                    settings.encoding(),
                    settings.congestion_control(),
                    settings.priority(),
                    settings.reliability(),
                );
                record("plain put", plain.put("p1").wait(), true);
                record("put of a publisher with settings", settings.put("p2").attachment("a").wait(), true);
                record(
                    "put overriding the encoding",
                    plain.put("p3").encoding($z::bytes::Encoding::APPLICATION_JSON).wait(),
                    true,
                );
                record("delete", plain.delete().wait(), true);
                record("delete with an attachment", plain.delete().attachment("gone").wait(), true);
                let remote = subject
                    .declare_publisher("demo/pub/remote")
                    .allowed_destination($z::sample::Locality::Remote)
                    .wait()
                    .expect("declares");
                record("put to remote only", remote.put("p4").wait(), true);
                let local = subject
                    .declare_publisher("demo/pub/local")
                    .allowed_destination($z::sample::Locality::SessionLocal)
                    .wait()
                    .expect("declares");
                record("put to the session only", local.put("p5").wait(), false);
                // A key declared on the session is held by the publisher declared for it.
                let mut kept = vec![];
                if let Ok(declared) = subject.declare_keyexpr("demo/pub/declared").wait() {
                    let on_declared = subject.declare_publisher(declared.clone()).wait().expect("declares");
                    drop(declared);
                    record("put of a publisher on a declared key", on_declared.put("p6").wait(), true);
                    kept.push(on_declared);
                }
                // The publisher is a sink of the samples of a subscriber.
                let source = subject.declare_subscriber("demo/pub/in").wait().expect("declares");
                record(
                    "put for the sink",
                    subject
                        .put("demo/pub/in", "p7")
                        .encoding($z::bytes::Encoding::TEXT_PLAIN)
                        .attachment("sunk")
                        .wait(),
                    true,
                );
                let mut sink = subject
                    .declare_publisher("demo/pub/out")
                    .priority($z::qos::Priority::DataLow)
                    .wait()
                    .expect("declares");
                match source.recv_timeout(Duration::from_secs(5)) {
                    Ok(Some(sample)) => record(
                        "sink",
                        futures::executor::block_on(futures::SinkExt::send(&mut sink, sample)),
                        true,
                    ),
                    other => record("sink", Err(format!("no sample ({other:?})").into()), false),
                }
                // What undeclaring a publisher says.
                let gone = subject.declare_publisher("demo/pub/gone").wait().expect("declares");
                record("undeclare", gone.undeclare().wait(), false);
                record(
                    "publisher on an invalid key",
                    subject.declare_publisher("demo//bad").wait().map(|_| ()),
                    false,
                );
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                while watcher.lines().len() < delivered && std::time::Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(20));
                }
                std::thread::sleep(Duration::from_millis(300));
                drop(kept);
                let mut received = watcher.lines();
                received.sort();
                out.push(says);
                out.push(also);
                out.push(format!("received {} of {delivered}", received.len()));
                out.extend(received.into_iter().map(|line| format!("sample: {line}")));
                subject.close().wait().expect("closes");
                out.push(format!("put after close: {}", text(plain.put("x").wait())));
                out.push(format!("delete after close: {}", text(plain.delete().wait())));
                out.push(format!("declare after close: {}", text(subject.declare_publisher("demo/after").wait().map(|_| ()))));
                out.push(format!("undeclare after close: {}", text(plain.undeclare().wait())));
                out
            }

            /// A queryable declared on a session that an upstream node asks over a link: what the
            /// queryable saw of each query, how each reply it made came out, and what the asker
            /// received of them.
            pub fn queryables() -> Vec<String> {
                use $z::internal::traits::{
                    EncodingBuilderTrait, QoSBuilderTrait, SampleBuilderTrait, TimestampBuilderTrait,
                };
                let port = free_port();
                let subject = $z::open(config(&format!(
                    r#"{{ id: "5a0012", mode: "peer",
                          listen: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                          scouting: {{ multicast: {{ enabled: false }} }} }}"#
                )))
                .wait()
                .expect("opens");
                let saw = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
                let record = saw.clone();
                let queryable = subject
                    .declare_queryable("demo/q/**")
                    .complete(true)
                    .callback(move |query| {
                        let key = query.key_expr().as_str().to_owned();
                        if key == "demo/q/ready" {
                            query.reply("demo/q/ready", "ready").wait().expect("replies");
                            return;
                        }
                        let body_of = |bytes: Option<&$z::bytes::ZBytes>| {
                            bytes.map(|b| b.try_to_string().map(|s| s.into_owned()).unwrap_or_default())
                        };
                        record.lock().unwrap().push(format!(
                            "saw {} | key {key} | parameters {} | payload {:?} | encoding {:?} | \
                             attachment {:?} | priority {:?} congestion {:?} express {} | source {:?} | \
                             accepts {:?}",
                            query.selector(),
                            query.parameters(),
                            body_of(query.payload()),
                            query.encoding().map(|e| e.to_string()),
                            body_of(query.attachment()),
                            query.priority(),
                            query.congestion_control(),
                            query.express(),
                            query.source_info().map(|i| (format!("{:?}", i.source_id()), i.source_sn())),
                            query.accepts_replies(),
                        ));
                        let outcome = |label: &str, result: Result<(), _>| {
                            record.lock().unwrap().push(format!("reply {label}: {}", text(result)));
                        };
                        match key.as_str() {
                            "demo/q/plain" => outcome("plain", query.reply("demo/q/plain", "r1").wait()),
                            "demo/q/body" => {
                                let body = body_of(query.payload()).unwrap_or_default();
                                outcome(
                                    "echo",
                                    query
                                        .reply("demo/q/body", body)
                                        .encoding($z::bytes::Encoding::APPLICATION_JSON)
                                        .wait(),
                                );
                            }
                            "demo/q/forms/**" => {
                                let id = $z::time::TimestampId::try_from(&[0xab_u8, 0xcd][..]).expect("an id");
                                let at = $z::time::Timestamp::new($z::time::NTP64(0x1234_5678_9abc_def0), id);
                                outcome(
                                    "put with every setting",
                                    query
                                        .reply("demo/q/forms/a", "pa")
                                        .encoding($z::bytes::Encoding::TEXT_PLAIN.with_schema("s"))
                                        .attachment("with")
                                        .timestamp(at)
                                        .express(true)
                                        .source_info($z::sample::SourceInfo::new(
                                            $z::session::EntityGlobalId::new("c0ffee".parse().expect("an id"), 7),
                                            41,
                                        ))
                                        .wait(),
                                );
                                outcome("delete", query.reply_del("demo/q/forms/b").attachment("gone").timestamp(at).wait());
                                outcome(
                                    "error",
                                    query
                                        .reply_err("broken")
                                        .encoding($z::bytes::Encoding::TEXT_PLAIN)
                                        .wait(),
                                );
                            }
                            "demo/q/far" => {
                                outcome("disjoint", query.reply("demo/other/key", "far").wait());
                            }
                            "demo/q/held" => {
                                let late = query.clone();
                                std::thread::spawn(move || {
                                    std::thread::sleep(Duration::from_millis(200));
                                    let _ = late.reply("demo/q/held", "late").wait();
                                });
                            }
                            "demo/q/options" => {
                                outcome("options", query.reply("demo/q/options", "o").express(false).wait())
                            }
                            _ => {}
                        }
                    })
                    .wait()
                    .expect("declares");
                let mut out = observer::asks("b00012", port).expect("the asker opens");
                out.extend(saw.lock().unwrap().iter().cloned());
                out.push(format!("queryable key: {}", queryable.key_expr()));
                subject.close().wait().expect("closes");
                out.push(format!(
                    "declare after close: {}",
                    text(subject.declare_queryable("demo/after").wait().map(|_| ()))
                ));
                out.push(format!("undeclare after close: {}", text(queryable.undeclare().wait())));
                out
            }

            /// What a reply says, as one line: who answered, and every field of the answer that
            /// crosses a link.
            fn describe_reply(reply: &$z::query::Reply) -> String {
                let replier = reply.replier_id().map(|id| id.zid().to_string());
                match reply.result() {
                    Ok(sample) => format!("ok replier={replier:?} {}", describe(sample)),
                    // Two nodes expire a query in the time given it: the session that asked, with
                    // an error of its own, and the node that was asked, which says so for the
                    // query it forwarded (upstream's routing, with an error that names its zid and
                    // has the default encoding). Whichever expires first is the one the asker is
                    // handed, and it is not the same from one run to the next, so the line says
                    // what is the same: that the get ended with a timeout.
                    Err(error) if error.payload().try_to_string().is_ok_and(|s| s == "Timeout") => {
                        "err Timeout".to_owned()
                    }
                    Err(error) => format!(
                        "err replier={replier:?} {} encoding={}",
                        error
                            .payload()
                            .try_to_string()
                            .map_or_else(|_| "(not text)".to_owned(), |s| s.to_string()),
                        error.encoding()
                    ),
                }
            }

            /// The lines of the replies of a get, sorted, once the get is over.
            fn replies_of<E: std::fmt::Display>(
                label: &str,
                asked: Result<$z::handlers::FifoChannelHandler<$z::query::Reply>, E>,
            ) -> Vec<String> {
                let mut lines = match asked {
                    Ok(replies) => replies.iter().map(|reply| describe_reply(&reply)).collect(),
                    Err(error) => vec![format!("the get failed: {}", plain(&error.to_string()))],
                };
                lines.sort();
                let mut out = vec![format!("{label}: {} reply(ies)", lines.len())];
                out.extend(lines.into_iter().map(|line| format!("{label}: {line}")));
                out
            }

            /// A node of this crate that asks an upstream queryable queries of every shape: what
            /// each get received, and what the queryable saw of each query.
            pub fn gets() -> Vec<String> {
                use $z::{
                    internal::traits::{EncodingBuilderTrait, QoSBuilderTrait, SampleBuilderTrait},
                    query::{ConsolidationMode, QueryTarget, ReplyKeyExpr},
                };
                let port = free_port();
                let subject = $z::open(peer("5a0030", port)).wait().expect("opens");
                let answerer = observer::answerer("b00030", port).expect("the answerer opens");
                let wait = Duration::from_secs(5);
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                let mut ready = false;
                while !ready && std::time::Instant::now() < deadline {
                    ready = subject
                        .get("demo/g/ready")
                        .timeout(Duration::from_secs(1))
                        .wait()
                        .map(|replies| replies.iter().count() > 0)
                        .unwrap_or(false);
                }
                let mut out = vec![format!("queryable known: {ready}")];
                out.extend(replies_of("plain", subject.get("demo/g/plain?a=1;b=2").timeout(wait).wait()));
                out.extend(replies_of(
                    "with a body",
                    subject
                        .get("demo/g/body")
                        .payload("body")
                        .encoding($z::bytes::Encoding::TEXT_PLAIN)
                        .attachment("att")
                        .source_info($z::sample::SourceInfo::new(
                            $z::session::EntityGlobalId::new("c0ffee".parse().expect("an id"), 3),
                            5,
                        ))
                        .timeout(wait)
                        .wait(),
                ));
                out.extend(replies_of(
                    "every form of reply",
                    subject.get("demo/g/forms/**").target(QueryTarget::All).timeout(wait).wait(),
                ));
                out.extend(replies_of(
                    "target all complete",
                    subject.get("demo/g/plain").target(QueryTarget::AllComplete).timeout(wait).wait(),
                ));
                out.extend(replies_of(
                    "disjoint reply refused",
                    subject.get("demo/g/far").timeout(Duration::from_secs(2)).wait(),
                ));
                out.extend(replies_of(
                    "disjoint reply accepted",
                    subject.get("demo/g/far").accept_replies(ReplyKeyExpr::Any).timeout(wait).wait(),
                ));
                out.extend(replies_of("answered late", subject.get("demo/g/held").timeout(wait).wait()));
                out.extend(replies_of(
                    "never answered",
                    subject.get("demo/g/silent").timeout(Duration::from_millis(500)).wait(),
                ));
                for (label, mode) in [
                    ("auto", None),
                    ("none", Some(ConsolidationMode::None)),
                    ("monotonic", Some(ConsolidationMode::Monotonic)),
                    ("latest", Some(ConsolidationMode::Latest)),
                ] {
                    let get = subject.get("demo/g/dup").timeout(wait);
                    out.extend(replies_of(
                        &format!("versions, consolidation {label}"),
                        match mode {
                            Some(mode) => get.consolidation(mode).wait(),
                            None => get.wait(),
                        },
                    ));
                }
                out.extend(replies_of(
                    "with options",
                    subject
                        .get("demo/g/options")
                        .priority($z::qos::Priority::RealTime)
                        .congestion_control($z::qos::CongestionControl::Block)
                        .express(true)
                        .timeout(wait)
                        .wait(),
                ));
                out.extend(replies_of(
                    "nobody to answer",
                    subject.get("demo/elsewhere/none").timeout(Duration::from_secs(2)).wait(),
                ));
                out.extend(replies_of("an invalid selector", subject.get("demo//bad").wait()));
                out.extend(
                    answerer
                        .lines()
                        .into_iter()
                        .map(|line| format!("the answerer {line}")),
                );
                subject.close().wait().expect("closes");
                out.extend(replies_of("a get after close", subject.get("demo/g/plain").wait()));
                out
            }

            /// A node of this crate that asks an upstream queryable through queriers of every
            /// shape: what each querier says of itself, what each get of one received, and what
            /// the queryable saw of each query.
            pub fn queriers() -> Vec<String> {
                use $z::{
                    internal::traits::{EncodingBuilderTrait, QoSBuilderTrait, SampleBuilderTrait},
                    query::{ConsolidationMode, QueryTarget, ReplyKeyExpr},
                };
                let port = free_port();
                let subject = $z::open(peer("5a0040", port)).wait().expect("opens");
                let answerer = observer::answerer("b00040", port).expect("the answerer opens");
                let wait = Duration::from_secs(5);
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                let mut ready = false;
                while !ready && std::time::Instant::now() < deadline {
                    ready = subject
                        .get("demo/g/ready")
                        .timeout(Duration::from_secs(1))
                        .wait()
                        .map(|replies| replies.iter().count() > 0)
                        .unwrap_or(false);
                }
                let mut out = vec![format!("queryable known: {ready}")];
                let says = |label: &str, querier: &$z::query::Querier<'_>| {
                    format!(
                        "{label} says: {} {:?} {:?} {:?}",
                        querier.key_expr(),
                        querier.priority(),
                        querier.congestion_control(),
                        querier.accept_replies(),
                    )
                };
                let plain = subject
                    .declare_querier("demo/g/plain")
                    .priority($z::qos::Priority::RealTime)
                    .congestion_control($z::qos::CongestionControl::Block)
                    .express(true)
                    .target(QueryTarget::AllComplete)
                    .timeout(wait)
                    .wait()
                    .expect("declares");
                out.push(says("plain", &plain));
                // A querier asks again as it was declared, and each get is a query of its own.
                for round in ["first", "second"] {
                    out.extend(replies_of(
                        &format!("plain, {round}"),
                        plain.get().parameters("a=1;b=2").wait(),
                    ));
                }
                let body = subject.declare_querier("demo/g/body").timeout(wait).wait().expect("declares");
                out.extend(replies_of(
                    "with a body",
                    body.get()
                        .payload("body")
                        .encoding($z::bytes::Encoding::TEXT_PLAIN)
                        .attachment("att")
                        .source_info($z::sample::SourceInfo::new(
                            $z::session::EntityGlobalId::new("c0ffee".parse().expect("an id"), 3),
                            5,
                        ))
                        .wait(),
                ));
                let forms = subject
                    .declare_querier("demo/g/forms/**")
                    .target(QueryTarget::All)
                    .timeout(wait)
                    .wait()
                    .expect("declares");
                out.extend(replies_of("every form of reply", forms.get().wait()));
                let far = subject
                    .declare_querier("demo/g/far")
                    .accept_replies(ReplyKeyExpr::Any)
                    .timeout(wait)
                    .wait()
                    .expect("declares");
                out.push(says("far", &far));
                out.extend(replies_of("disjoint reply accepted", far.get().wait()));
                let refusing = subject
                    .declare_querier("demo/g/far")
                    .timeout(Duration::from_secs(2))
                    .wait()
                    .expect("declares");
                out.push(says("refusing", &refusing));
                out.extend(replies_of("disjoint reply refused", refusing.get().wait()));
                let silent = subject
                    .declare_querier("demo/g/silent")
                    .timeout(Duration::from_millis(500))
                    .wait()
                    .expect("declares");
                out.extend(replies_of("never answered", silent.get().wait()));
                for (label, mode) in [
                    ("auto", None),
                    ("none", Some(ConsolidationMode::None)),
                    ("monotonic", Some(ConsolidationMode::Monotonic)),
                    ("latest", Some(ConsolidationMode::Latest)),
                ] {
                    let declared = subject.declare_querier("demo/g/dup").timeout(wait);
                    let dup = match mode {
                        Some(mode) => declared.consolidation(mode).wait(),
                        None => declared.wait(),
                    }
                    .expect("declares");
                    out.extend(replies_of(&format!("versions, consolidation {label}"), dup.get().wait()));
                }
                // A key the session declared goes on the wire as a declaration.
                let declared = subject.declare_keyexpr("demo/g/options").wait().expect("declares");
                let options = subject.declare_querier(declared).timeout(wait).wait().expect("declares");
                out.extend(replies_of("on a declared key", options.get().wait()));
                let nobody = subject
                    .declare_querier("demo/elsewhere/none")
                    .timeout(Duration::from_secs(2))
                    .wait()
                    .expect("declares");
                out.extend(replies_of("nobody to answer", nobody.get().wait()));
                out.push(format!(
                    "invalid key: {}",
                    text(subject.declare_querier("demo//bad").wait().map(|_| ()))
                ));
                out.extend(
                    answerer
                        .lines()
                        .into_iter()
                        .map(|line| format!("the answerer {line}")),
                );
                out.push(format!("undeclare: {}", text(plain.undeclare().wait())));
                subject.close().wait().expect("closes");
                out.extend(replies_of("a get after close", body.get().wait()));
                out.push(format!("undeclare after close: {}", text(body.undeclare().wait())));
                out.push(format!(
                    "declare after close: {}",
                    text(subject.declare_querier("demo/g/plain").wait().map(|_| ()))
                ));
                out
            }

            /// What a sample says, as one line: every field of it that crosses a link.
            fn describe(sample: &$z::sample::Sample) -> String {
                let timestamp = sample.timestamp().map(|t| format!("{t}"));
                let payload = sample.payload().len();
                let text = sample
                    .payload()
                    .try_to_string()
                    .map_or_else(|_| "(not text)".to_owned(), |s| s.to_string());
                let attachment = sample.attachment().map(|a| {
                    a.try_to_string().map_or_else(|_| "(not text)".to_owned(), |s| s.to_string())
                });
                let source = sample
                    .source_info()
                    .map(|i| (format!("{:?}", i.source_id()), i.source_sn()));
                format!(
                    "{} {:?} len={payload} {} encoding={} priority={:?} congestion={:?} \
                     express={} reliability={:?} timestamp={timestamp:?} attachment={attachment:?} \
                     source={source:?}",
                    sample.key_expr(),
                    sample.kind(),
                    if payload <= 16 { text } else { format!("{}...", &text[..8.min(text.len())]) },
                    sample.encoding(),
                    sample.priority(),
                    sample.congestion_control(),
                    sample.express(),
                    sample.reliability(),
                )
            }

            /// What a node of this crate receives, from an upstream node that dials it and from
            /// itself: every setting of a put and a delete, a key the publisher declared, a payload
            /// larger than a batch, the origins a subscriber can ask for, what a callback may do
            /// with the session that calls it, and the end of a subscriber with its session.
            pub fn subscriptions() -> Vec<String> {
                use std::sync::{
                    atomic::{AtomicUsize, Ordering},
                    Arc, Mutex,
                };

                let mut out = vec![];
                let port = free_port();
                let subject = $z::open(peer("5a0020", port)).wait().expect("opens");
                let seen = Arc::new(Mutex::new(Vec::<String>::new()));
                let sink = seen.clone();
                let _everything = subject
                    .declare_subscriber("demo/**")
                    .callback(move |sample| sink.lock().unwrap().push(describe(&sample)))
                    .wait()
                    .expect("declares");
                let count = |counter: &Arc<AtomicUsize>| {
                    let counter = counter.clone();
                    move |_sample: $z::sample::Sample| {
                        counter.fetch_add(1, Ordering::SeqCst);
                    }
                };
                let (local, remote, any) = (
                    Arc::new(AtomicUsize::new(0)),
                    Arc::new(AtomicUsize::new(0)),
                    Arc::new(AtomicUsize::new(0)),
                );
                let _local = subject
                    .declare_subscriber("demo/origin")
                    .allowed_origin($z::sample::Locality::SessionLocal)
                    .callback(count(&local))
                    .wait()
                    .expect("declares");
                let _remote = subject
                    .declare_subscriber("demo/origin")
                    .allowed_origin($z::sample::Locality::Remote)
                    .callback(count(&remote))
                    .wait()
                    .expect("declares");
                let _any = subject
                    .declare_subscriber("demo/origin")
                    .callback(count(&any))
                    .wait()
                    .expect("declares");
                // A callback that uses the session that calls it: declares a key and a subscriber,
                // publishes on both, undeclares, and asks who the session is, each of them blocking.
                let (done_tx, done) = std::sync::mpsc::channel::<String>();
                let done_tx = Mutex::new(done_tx);
                let inner_count = Arc::new(AtomicUsize::new(0));
                let in_callback = subject.clone();
                let counted = inner_count.clone();
                let _reentrant = subject
                    .declare_subscriber("demo/reenter/trigger")
                    .callback(move |sample| {
                        let mut steps = vec![];
                        let mut step = |label: &str, result: Result<(), String>| {
                            steps.push(format!("{label}: {}", text(result)));
                        };
                        let key = in_callback.declare_keyexpr("demo/reenter/key").wait();
                        step("declare a key", key.as_ref().map(|_| ()).map_err(|e| e.to_string()));
                        let inner = in_callback
                            .declare_subscriber("demo/reenter/inner/**")
                            .callback(count(&counted))
                            .wait();
                        step("declare a subscriber", inner.as_ref().map(|_| ()).map_err(|e| e.to_string()));
                        step(
                            "put on a key",
                            in_callback.put("demo/reenter/inner/a", "v").wait().map_err(|e| e.to_string()),
                        );
                        if let Ok(key) = &key {
                            step(
                                "put on the declared key",
                                in_callback.put(key, "v").wait().map_err(|e| e.to_string()),
                            );
                        }
                        if let Ok(inner) = inner {
                            step("undeclare it", inner.undeclare().wait().map_err(|e| e.to_string()));
                        }
                        step(
                            "ask who the session is",
                            Ok::<_, String>(in_callback.info().zid().wait().to_string()).map(|_| ()),
                        );
                        let line = format!(
                            "{}: {}",
                            sample.payload().try_to_string().unwrap(),
                            steps.join(", ")
                        );
                        let _ = done_tx.lock().unwrap().send(line);
                    })
                    .wait()
                    .expect("declares");
                let source = observer::source("b00020", port).expect("the source opens");
                // The source knows the subject's subscription once a probe of it arrives.
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                let ready = |seen: &Arc<Mutex<Vec<String>>>| {
                    seen.lock().unwrap().iter().any(|line| line.starts_with("demo/ready "))
                };
                while !ready(&seen) && std::time::Instant::now() < deadline {
                    source.probe();
                    std::thread::sleep(Duration::from_millis(50));
                }
                out.push(format!("subscription known: {}", ready(&seen)));
                let sent = source.publish_all();
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                let delivered = |seen: &Arc<Mutex<Vec<String>>>| {
                    seen.lock()
                        .unwrap()
                        .iter()
                        .filter(|line| !line.starts_with("demo/ready "))
                        .count()
                };
                while delivered(&seen) < sent && std::time::Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(20));
                }
                std::thread::sleep(Duration::from_millis(300));
                let mut received: Vec<String> = seen
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|line| !line.starts_with("demo/ready "))
                    .cloned()
                    .collect();
                // Samples of different priorities are carried by different queues, so their order
                // is not the order they were sent in.
                received.sort();
                out.push(format!("received {} of {sent}", received.len()));
                out.extend(received.into_iter().map(|line| format!("sample: {line}")));
                // The origins: the session's own put and the source's.
                subject.put("demo/origin", "own").wait().expect("puts");
                source.put("demo/origin", "other");
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                while remote.load(Ordering::SeqCst) < 1 && std::time::Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(20));
                }
                std::thread::sleep(Duration::from_millis(200));
                out.push(format!(
                    "origins: local={} remote={} any={}",
                    local.load(Ordering::SeqCst),
                    remote.load(Ordering::SeqCst),
                    any.load(Ordering::SeqCst)
                ));
                // The callback that uses the session, run from a link and from the session itself.
                source.put("demo/reenter/trigger", "remote");
                out.push(match done.recv_timeout(Duration::from_secs(10)) {
                    Ok(line) => format!("callback on the remote path: {line}"),
                    Err(_) => "callback on the remote path: it did not come back".to_owned(),
                });
                let own = subject.clone();
                std::thread::spawn(move || own.put("demo/reenter/trigger", "local").wait());
                out.push(match done.recv_timeout(Duration::from_secs(10)) {
                    Ok(line) => format!("callback on the local path: {line}"),
                    Err(_) => "callback on the local path: it did not come back".to_owned(),
                });
                out.push(format!("the callbacks' own subscribers took {}", inner_count.load(Ordering::SeqCst)));
                // The end of a subscriber with its session.
                let ending = subject.declare_subscriber("demo/ending").wait().expect("declares");
                subject.close().wait().expect("closes");
                out.push(format!(
                    "channel after close: {}",
                    text(ending.recv_timeout(Duration::from_secs(2)))
                ));
                out.push(format!(
                    "declare after close: {}",
                    text(subject.declare_subscriber("demo/after").wait().map(|_| ()))
                ));
                out.push(format!("undeclare after close: {}", text(ending.undeclare().wait())));
                out
            }

            /// What declaring a key expression on a session and undeclaring it come to, as text.
            pub fn declarations() -> Vec<String> {
                let mut out = vec![];
                let session = $z::open(peer("a1b2d0", free_port())).wait().expect("opens");
                let other = $z::open(peer("a1b2d1", free_port())).wait().expect("opens");
                // A key declared: what it says, wild or not, and what it says of an invalid one.
                let key = session.declare_keyexpr("demo/declared").wait();
                out.push(format!("declare: {}", text(key.as_ref().map(|k| k.to_string()))));
                let wild = session.declare_keyexpr("demo/*/wild").wait();
                out.push(format!("declare wild: {}", text(wild.as_ref().map(|k| k.to_string()))));
                out.push(format!(
                    "declare invalid: {}",
                    text(session.declare_keyexpr("demo//double").wait().map(|k| k.to_string()))
                ));
                out.push(format!(
                    "declare empty: {}",
                    text(session.declare_keyexpr("").wait().map(|k| k.to_string()))
                ));
                // The declared key is the key: it joins and concatenates as the plain one does.
                if let Ok(key) = &key {
                    out.push(format!("join: {}", text(key.join("leaf"))));
                    out.push(format!("concat: {}", text(key.concat("/leaf"))));
                    out.push(format!("intersects itself: {}", key.intersects(key)));
                }
                // Undeclared by its own session: the one reference, and a clone beside it.
                if let Ok(key) = key {
                    out.push(format!("undeclare: {}", text(session.undeclare(key).wait())));
                }
                if let Ok(wild) = wild {
                    let clone = wild.clone();
                    out.push(format!("undeclare with a clone: {}", text(session.undeclare(wild).wait())));
                    out.push(format!("the clone still reads: {}", clone));
                }
                // Declared twice, undeclared each.
                let first = session.declare_keyexpr("demo/twice").wait();
                let second = session.declare_keyexpr("demo/twice").wait();
                if let (Ok(first), Ok(second)) = (first, second) {
                    out.push(format!("twice, first: {}", text(session.undeclare(first).wait())));
                    out.push(format!("twice, second: {}", text(session.undeclare(second).wait())));
                }
                // A key that was never declared, and one declared by another session.
                let plain: $z::key_expr::KeyExpr = "demo/plain".try_into().expect("a key");
                out.push(format!("undeclare a plain key: {}", text(session.undeclare(plain).wait())));
                if let Ok(foreign) = other.declare_keyexpr("demo/foreign").wait() {
                    out.push(format!(
                        "undeclare another session's key: {}",
                        text(session.undeclare(foreign.clone()).wait())
                    ));
                    out.push(format!("then its own: {}", text(other.undeclare(foreign).wait())));
                }
                // A closed session declares nothing, and undeclares nothing.
                let kept = session.declare_keyexpr("demo/kept").wait();
                session.close().wait().expect("closes");
                out.push(format!(
                    "declare after close: {}",
                    text(session.declare_keyexpr("demo/after").wait().map(|k| k.to_string()))
                ));
                if let Ok(kept) = kept {
                    out.push(format!("undeclare after close: {}", text(session.undeclare(kept).wait())));
                }
                out
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
                out.push(format!(
                    "info: {} {:?} {:?}",
                    session.info().zid().wait(),
                    session.info().routers_zid().wait().count(),
                    session.info().peers_zid().wait().count()
                ));
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
    //
    // The role of a router is the other: this engine's session announces a peer's role to a node
    // that dials it whatever `mode` says, and a router is the router data plane, which a session
    // does not carry yet, so it is refused by its key and not opened as what it is not. The two
    // lines of the roles test that open one hold the words of both.
    vec![
        (
            "refusals",
            "Can not create a new TCP listener bound to",
            "the session could not be opened: LinkFailed",
        ),
        (
            "roles",
            "Router qos=true multicast=false",
            "the router did not open: `mode` = \"router\"",
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

/// The control of the roles test: upstream's own nodes as the subject, which must read as the
/// roles they play, so that a comparison that passes is not a comparison of two nothings.
#[test]
fn upstream_nodes_see_each_other_in_the_roles_they_play() {
    let u = up::roles();
    assert!(
        u.iter().any(|l| l.starts_with("router listening") && l.contains("routers [\"5a0001\"]")),
        "{u:#?}"
    );
    assert!(
        u.iter().any(|l| l.starts_with("peer listening") && l.contains("peers [\"5a0002\"]")),
        "{u:#?}"
    );
    assert!(
        u.iter().any(|l| l.starts_with("client dials") && l.contains("5a0003 Client")),
        "{u:#?}"
    );
    assert!(
        u.iter().any(|l| l.starts_with("peer dials") && l.contains("5a0004 Peer")),
        "{u:#?}"
    );
    assert!(
        u.iter().any(|l| l.starts_with("router dials") && l.contains("5a0005 Router")),
        "{u:#?}"
    );
    // And what each of them sees of the other through its own `info`.
    assert!(
        u.iter().any(|l| l.starts_with("peer listening") && l.contains("sees routers [] peers [\"b00002\"]")),
        "{u:#?}"
    );
    assert!(
        u.iter().any(|l| l.starts_with("client dials") && l.contains("sees routers [\"a00001\"] peers []")),
        "{u:#?}"
    );
    assert!(
        u.iter().any(|l| l.starts_with("peer dials") && l.contains("sees routers [\"a00001\"] peers []")),
        "{u:#?}"
    );
}

#[test]
fn the_role_a_node_plays_is_what_upstream_nodes_see_of_it() {
    // The log of upstream's nodes, for a run that is asked for it with `RUST_LOG`.
    up_zenoh::try_init_log_from_env();
    let (u, w) = (up::roles(), wz::roles());
    assert!(
        u.iter().any(|l| l.contains("Router") && l.starts_with("router listening")),
        "{u:#?}"
    );
    assert!(u.iter().any(|l| l.starts_with("client dials") && l.contains("Client")), "{u:#?}");
    assert!(u.iter().any(|l| l.starts_with("peer dials") && l.contains("Peer")), "{u:#?}");
    compare("roles", &u, &w);
}

#[test]
fn the_declaration_of_a_key_on_a_session() {
    let (u, w) = (up::declarations(), wz::declarations());
    assert!(u.iter().any(|l| l == "declare: Ok(\"demo/declared\")"), "{u:#?}");
    assert!(u.iter().any(|l| l.starts_with("declare invalid: Err(")), "{u:#?}");
    assert!(u.iter().any(|l| l == "undeclare: Ok(())"), "{u:#?}");
    assert!(u.iter().any(|l| l.starts_with("undeclare another session's key: Err(")), "{u:#?}");
    assert!(u.iter().any(|l| l.starts_with("undeclare a plain key: Err(")), "{u:#?}");
    compare("declarations", &u, &w);
}

#[test]
fn what_a_session_publishes_is_what_an_upstream_subscriber_receives() {
    // The log of upstream's nodes, for a run that is asked for it with `RUST_LOG`.
    up_zenoh::try_init_log_from_env();
    let (u, w) = (up::publications(false), wz::publications(false));
    assert!(u.iter().any(|l| l == "subscription known: true"), "{u:#?}");
    assert!(u.iter().any(|l| l.starts_with("received 13 of 13")), "{u:#?}");
    assert!(
        u.iter().any(|l| l.starts_with("sample: demo/settings Put len=2 v2 encoding=text/plain priority=RealTime congestion=Block express=true")),
        "{u:#?}"
    );
    compare("publications", &u, &w);
}

#[test]
fn what_a_session_with_a_clock_publishes_carries_its_stamps() {
    let (u, w) = (up::publications(true), wz::publications(true));
    assert!(
        u.iter().any(|l| l.starts_with("sample: demo/plain Put") && l.contains("timestamp=Some(\"id 5a0010\")")),
        "{u:#?}"
    );
    compare("publications with a clock", &u, &w);
}

#[test]
fn what_a_publisher_publishes_is_what_an_upstream_subscriber_receives() {
    // The log of upstream's nodes, for a run that is asked for it with `RUST_LOG`.
    up_zenoh::try_init_log_from_env();
    let (u, w) = (up::publishers(), wz::publishers());
    assert!(u.iter().any(|l| l == "subscription known: true"), "{u:#?}");
    assert!(u.iter().any(|l| l.starts_with("received 9 of 9")), "{u:#?}");
    assert!(
        u.iter().any(|l| l.starts_with("sample: demo/pub/settings Put len=2 p2 encoding=text/plain priority=RealTime congestion=Block express=true")),
        "{u:#?}"
    );
    compare("publishers", &u, &w);
}

#[test]
fn what_a_queryable_answers_is_what_an_upstream_node_receives() {
    // The log of upstream's nodes, for a run that is asked for it with `RUST_LOG`.
    up_zenoh::try_init_log_from_env();
    let (u, w) = (up::queryables(), wz::queryables());
    assert!(u.iter().any(|l| l == "queryable known: true"), "{u:#?}");
    assert!(u.iter().any(|l| l == "plain: 1 reply(ies)"), "{u:#?}");
    assert!(u.iter().any(|l| l == "every form of reply: 3 reply(ies)"), "{u:#?}");
    assert!(u.iter().any(|l| l == "disjoint reply accepted: 1 reply(ies)"), "{u:#?}");
    assert!(u.iter().any(|l| l == "disjoint reply refused: 0 reply(ies)"), "{u:#?}");
    assert!(u.iter().any(|l| l == "answered late: 1 reply(ies)"), "{u:#?}");
    compare("queryables", &u, &w);
}

#[test]
fn what_a_get_asks_is_what_an_upstream_queryable_receives_and_answers() {
    // The log of upstream's nodes, for a run that is asked for it with `RUST_LOG`.
    up_zenoh::try_init_log_from_env();
    let (u, w) = (up::gets(), wz::gets());
    assert!(u.iter().any(|l| l == "queryable known: true"), "{u:#?}");
    assert!(u.iter().any(|l| l == "plain: 1 reply(ies)"), "{u:#?}");
    assert!(u.iter().any(|l| l == "every form of reply: 3 reply(ies)"), "{u:#?}");
    assert!(u.iter().any(|l| l == "disjoint reply accepted: 1 reply(ies)"), "{u:#?}");
    assert!(u.iter().any(|l| l == "disjoint reply refused: 0 reply(ies)"), "{u:#?}");
    assert!(u.iter().any(|l| l == "answered late: 1 reply(ies)"), "{u:#?}");
    assert!(u.iter().any(|l| l == "never answered: 1 reply(ies)"), "{u:#?}");
    compare("gets", &u, &w);
}

#[test]
fn what_a_querier_asks_is_what_an_upstream_queryable_receives_and_answers() {
    // The log of upstream's nodes, for a run that is asked for it with `RUST_LOG`.
    up_zenoh::try_init_log_from_env();
    let (u, w) = (up::queriers(), wz::queriers());
    assert!(u.iter().any(|l| l == "queryable known: true"), "{u:#?}");
    assert!(u.iter().any(|l| l == "plain, second: 1 reply(ies)"), "{u:#?}");
    assert!(u.iter().any(|l| l == "every form of reply: 3 reply(ies)"), "{u:#?}");
    assert!(u.iter().any(|l| l == "disjoint reply accepted: 1 reply(ies)"), "{u:#?}");
    assert!(u.iter().any(|l| l == "disjoint reply refused: 0 reply(ies)"), "{u:#?}");
    assert!(u.iter().any(|l| l == "on a declared key: 1 reply(ies)"), "{u:#?}");
    assert!(u.iter().any(|l| l == "never answered: 1 reply(ies)"), "{u:#?}");
    compare("queriers", &u, &w);
}

#[test]
fn what_an_upstream_publisher_sends_is_what_a_subscriber_receives() {
    // The log of upstream's nodes, for a run that is asked for it with `RUST_LOG`.
    up_zenoh::try_init_log_from_env();
    let (u, w) = (up::subscriptions(), wz::subscriptions());
    assert!(u.iter().any(|l| l == "subscription known: true"), "{u:#?}");
    assert!(u.iter().any(|l| l.starts_with("received 12 of 12")), "{u:#?}");
    assert!(
        u.iter().any(|l| l.starts_with("sample: demo/settings Put len=2 v2 encoding=text/plain priority=RealTime congestion=Block express=true")),
        "{u:#?}"
    );
    assert!(u.iter().any(|l| l == "origins: local=1 remote=1 any=2"), "{u:#?}");
    assert!(
        u.iter().any(|l| l.starts_with("callback on the remote path: remote: declare a key: Ok(())")),
        "{u:#?}"
    );
    assert!(
        u.iter().any(|l| l.starts_with("callback on the local path: local: declare a key: Ok(())")),
        "{u:#?}"
    );
    compare("subscriptions", &u, &w);
}

#[test]
fn the_comparison_sees_a_session_that_differs() {
    let u = up::identity();
    let mut w = wz::identity();
    w[0] = format!("{} changed", w[0]);
    assert!(u.iter().zip(&w).any(|(x, y)| x != y));
    assert_ne!(up::identity(), up::lifecycle());
}
