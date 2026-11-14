// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh`, shared memory across a link (the shared-memory transport of the top crate): sessions
//! of upstream's crate (`up_zenoh`) and of wz's (`wz_zenoh`) in one process, linked over TCP on
//! the loopback, each pair of crates in both places, and what each session is handed compared
//! with what two upstream sessions hand each other.
//!
//! One session listens and the other dials it. A wz session that listens is a router node and one
//! that only dials is the registry of faces, so both of wz's engines meet upstream's, each way.
//! Each session sends the other, in shared memory it allocated from its provider:
//!
//! * a put, which the other's subscriber is handed;
//! * the value of a get, which the other's queryable is handed;
//! * a reply, which the other's get is handed.
//!
//! What is compared is, for each, the bytes and whether the receiver was handed shared memory.
//! With shared memory enabled on both sides every payload crosses as shared memory; with it
//! disabled on the dialler (the control) the link negotiates none and every payload crosses as its
//! bytes, which is also what shows that the comparison reads the difference.
//!
//! The crates share the machine's segments, so the tests of this binary take one lock.

#![cfg(target_os = "linux")]

use std::{
    net::TcpListener,
    sync::{mpsc::Receiver, Mutex, MutexGuard},
    time::{Duration, Instant},
};

static LOCK: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// How long one payload is waited for: the declarations of the other session cross the link
/// first, so a payload is sent again until it is handed over.
const WAIT: Duration = Duration::from_secs(10);

/// What a session is handed: the bytes, and whether they are shared memory.
type Seen = (Vec<u8>, bool);

/// A session of one of the two crates, as the scenario drives it.
trait Peer {
    /// The number of peers the session is linked to.
    fn linked(&self) -> usize;
    /// Subscribe to `key`, and what each sample is.
    fn subscribe(&mut self, key: &str) -> Receiver<Seen>;
    /// Put `body` on `key` from a buffer of the session's provider.
    fn put_shm(&self, key: &str, body: &[u8]);
    /// Answer the queries on `key` with nothing, and what the value of each is.
    fn record_values(&mut self, key: &str) -> Receiver<Seen>;
    /// Answer the queries on `key` with `body` in a buffer of the session's provider.
    fn answer_shm(&mut self, key: &str, body: &[u8]);
    /// Ask `key` with `body` in a buffer of the session's provider as the value.
    fn get_shm(&self, key: &str, body: &[u8]);
    /// Ask `key`, and the first reply, if one comes within half a second.
    fn first_reply(&self, key: &str) -> Option<Seen>;
}

macro_rules! peer {
    ($name:ident, $z:ident, $core:ident) => {
        mod $name {
            use std::sync::{mpsc, Arc, Mutex};
            use std::time::Duration;

            use $core::Wait;
            use $z::{bytes::ZBytes, shm::ShmProviderBuilder, Config, Session};

            use super::{Peer, Seen};

            fn seen(payload: &ZBytes) -> Seen {
                (payload.to_bytes().into_owned(), payload.as_shm().is_some())
            }

            /// What puts bytes into a buffer of shared memory of this crate's provider.
            type Alloc = Arc<dyn Fn(&[u8]) -> ZBytes + Send + Sync>;

            pub struct Node {
                session: Session,
                /// A provider of the node's own, not the session's: a session whose shared memory
                /// is disabled has none, and the control sends from it all the same.
                alloc: Alloc,
                /// The subscribers and queryables the scenario declared, held to its end.
                held: Vec<Box<dyn std::any::Any>>,
            }

            /// A peer with id `id` that listens on `listen` and dials `connect` of the loopback,
            /// scouts for nobody, and has shared memory as `shm` says.
            pub fn open(id: &str, listen: Option<u16>, connect: Option<u16>, shm: bool) -> Node {
                let endpoints = |port: Option<u16>| match port {
                    Some(port) => format!(r#"["tcp/127.0.0.1:{port}"]"#),
                    None => "[]".to_owned(),
                };
                let config = Config::from_json5(&format!(
                    r#"{{ id: "{id}", mode: "peer",
                          listen: {{ endpoints: {} }}, connect: {{ endpoints: {} }},
                          scouting: {{ multicast: {{ enabled: false }} }},
                          transport: {{ shared_memory: {{ enabled: {shm} }} }} }}"#,
                    endpoints(listen),
                    endpoints(connect)
                ))
                .expect("a configuration zenoh reads");
                let session = $z::open(config).wait().expect("opens");
                let provider = ShmProviderBuilder::default_backend(1usize << 20)
                    .wait()
                    .expect("a provider");
                let alloc: Alloc = Arc::new(move |body: &[u8]| {
                    let mut buffer = provider.alloc(body.len()).wait().expect("a buffer");
                    buffer.copy_from_slice(body);
                    ZBytes::from(buffer)
                });
                Node {
                    session,
                    alloc,
                    held: Vec::new(),
                }
            }

            impl Peer for Node {
                fn linked(&self) -> usize {
                    self.session.info().peers_zid().wait().count()
                }

                fn subscribe(&mut self, key: &str) -> mpsc::Receiver<Seen> {
                    let (sender, told) = mpsc::channel();
                    let sender = Mutex::new(sender);
                    let subscriber = self
                        .session
                        .declare_subscriber(key)
                        .callback(move |sample| {
                            let _ = sender.lock().unwrap().send(seen(sample.payload()));
                        })
                        .wait()
                        .expect("declares");
                    self.held.push(Box::new(subscriber));
                    told
                }

                fn put_shm(&self, key: &str, body: &[u8]) {
                    self.session
                        .put(key, (self.alloc)(body))
                        .wait()
                        .expect("puts");
                }

                fn record_values(&mut self, key: &str) -> mpsc::Receiver<Seen> {
                    let (sender, told) = mpsc::channel();
                    let sender = Mutex::new(sender);
                    let queryable = self
                        .session
                        .declare_queryable(key)
                        .callback(move |query| {
                            let value = query.payload().map_or((Vec::new(), false), seen);
                            let _ = sender.lock().unwrap().send(value);
                        })
                        .wait()
                        .expect("declares");
                    self.held.push(Box::new(queryable));
                    told
                }

                fn answer_shm(&mut self, key: &str, body: &[u8]) {
                    let (alloc, body, reply_key) =
                        (Arc::clone(&self.alloc), body.to_vec(), key.to_owned());
                    let queryable = self
                        .session
                        .declare_queryable(key)
                        .callback(move |query| {
                            // A reply that is refused is seen as a get that is never answered.
                            let _ = query
                                .reply(reply_key.as_str(), alloc(body.as_slice()))
                                .wait();
                        })
                        .wait()
                        .expect("declares");
                    self.held.push(Box::new(queryable));
                }

                fn get_shm(&self, key: &str, body: &[u8]) {
                    let _replies = self
                        .session
                        .get(key)
                        .payload((self.alloc)(body))
                        .wait()
                        .expect("asks");
                }

                fn first_reply(&self, key: &str) -> Option<Seen> {
                    let replies = self.session.get(key).wait().expect("asks");
                    let reply = replies
                        .recv_timeout(Duration::from_millis(500))
                        .ok()
                        .flatten()?;
                    Some(seen(
                        reply.result().expect("a sample, not an error").payload(),
                    ))
                }
            }
        }
    };
}

peer!(up, up_zenoh, up_core);
peer!(wz, wz_zenoh, wz_core);

/// The crate a session of the scenario is of.
#[derive(Clone, Copy, Debug)]
enum Crate {
    Up,
    Wz,
}

/// A port nothing listens on, that the kernel never picks for a socket that binds port 0, and that
/// no call of this function gives twice (see `../differential/tests/zenoh_api_session.rs`).
fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    loop {
        let offset = NEXT.fetch_add(1, Ordering::Relaxed);
        let port = 21_000 + ((std::process::id() % 4_000) as u16 + offset) % 9_000;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// A session id no other session of this process has.
fn next_id() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    format!("d5f{:03x}", NEXT.fetch_add(1, Ordering::Relaxed))
}

fn open(of: Crate, listen: Option<u16>, connect: Option<u16>, shm: bool) -> Box<dyn Peer> {
    let id = next_id();
    match of {
        Crate::Up => Box::new(up::open(&id, listen, connect, shm)) as Box<dyn Peer>,
        Crate::Wz => Box::new(wz::open(&id, listen, connect, shm)) as Box<dyn Peer>,
    }
}

/// `act` again every 100 ms until `told` is handed something, and what it was first handed.
fn until_told(mut act: impl FnMut(), told: &Receiver<Seen>) -> Option<Seen> {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        act();
        if let Ok(seen) = told.recv_timeout(Duration::from_millis(100)) {
            return Some(seen);
        }
    }
    None
}

/// The first reply `asker` is handed for `key`, asked again until one comes.
fn until_answered(asker: &dyn Peer, key: &str) -> Option<Seen> {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if let Some(seen) = asker.first_reply(key) {
            return Some(seen);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// One line of a transcript: what was handed, said in a way that does not depend on the crates.
fn line(what: &str, body: &[u8], seen: Option<Seen>) -> String {
    match seen {
        None => format!("{what}: never handed over"),
        Some((bytes, shared)) if bytes == body => format!(
            "{what}: the bytes, as {}",
            if shared {
                "shared memory"
            } else {
                "plain bytes"
            }
        ),
        Some((bytes, _)) => format!("{what}: {} other bytes", bytes.len()),
    }
}

/// A session of `listener` that listens and a session of `dialler` that dials it, the dialler
/// with shared memory as `dialler_shm` says, sending each other a put, the value of a get and a
/// reply in shared memory, each way; what each was handed, in order.
fn transcript(listener: Crate, dialler: Crate, dialler_shm: bool, tag: &str) -> Vec<String> {
    let body: Vec<u8> = (0..64u8).collect();
    let port = free_port();
    let mut listening = open(listener, Some(port), None, true);
    let mut dialling = open(dialler, None, Some(port), dialler_shm);
    let deadline = Instant::now() + Duration::from_secs(5);
    while listening.linked() < 1 || dialling.linked() < 1 {
        assert!(
            Instant::now() < deadline,
            "{listener:?} and {dialler:?} were never linked"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    let mut out = Vec::new();
    for (way, from_listener) in [
        ("listener to dialler", true),
        ("dialler to listener", false),
    ] {
        let (sender, receiver): (&mut Box<dyn Peer>, &mut Box<dyn Peer>) = if from_listener {
            (&mut listening, &mut dialling)
        } else {
            (&mut dialling, &mut listening)
        };
        let key = |what: &str| format!("diff/shm/{tag}/{}/{what}", u8::from(from_listener));

        let put = key("put");
        let told = receiver.subscribe(&put);
        let seen = until_told(|| sender.put_shm(&put, &body), &told);
        out.push(line(&format!("{way}, a put"), &body, seen));

        let value = key("value");
        let told = receiver.record_values(&value);
        let seen = until_told(|| sender.get_shm(&value, &body), &told);
        out.push(line(&format!("{way}, the value of a get"), &body, seen));

        let reply = key("reply");
        sender.answer_shm(&reply, &body);
        let seen = until_answered(&**receiver, &reply);
        out.push(line(&format!("{way}, a reply"), &body, seen));
    }
    out
}

/// Every pair of crates, the listener first.
const PAIRS: [(Crate, Crate); 4] = [
    (Crate::Up, Crate::Up),
    (Crate::Up, Crate::Wz),
    (Crate::Wz, Crate::Up),
    (Crate::Wz, Crate::Wz),
];

#[test]
fn shared_memory_crosses_a_link_to_and_from_upstream_as_between_two_upstream_sessions() {
    let _g = serial();
    let reference = transcript(Crate::Up, Crate::Up, true, "on-up-up");
    assert!(
        reference.iter().all(|l| l.ends_with("as shared memory")),
        "two upstream sessions did not hand each other shared memory: {reference:#?}"
    );
    for (listener, dialler) in &PAIRS[1..] {
        let tag = format!("on-{listener:?}-{dialler:?}").to_lowercase();
        assert_eq!(
            transcript(*listener, *dialler, true, &tag),
            reference,
            "{listener:?} listening, {dialler:?} dialling"
        );
    }
}

#[test]
fn with_shared_memory_off_on_one_side_every_payload_crosses_as_its_bytes() {
    let _g = serial();
    for (listener, dialler) in PAIRS {
        let tag = format!("off-{listener:?}-{dialler:?}").to_lowercase();
        let seen = transcript(listener, dialler, false, &tag);
        assert_eq!(seen.len(), 6, "{seen:#?}");
        assert!(
            seen.iter().all(|l| l.ends_with("as plain bytes")),
            "{listener:?} listening, {dialler:?} dialling without shared memory: {seen:#?}"
        );
    }
}
