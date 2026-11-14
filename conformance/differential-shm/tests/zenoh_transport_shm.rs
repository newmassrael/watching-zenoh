// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh`, shared memory across a link (the shared-memory transport of the top crate): sessions
//! of upstream's crate (`up_zenoh`) and of wz's (`wz_zenoh`) in one process, linked over TCP on
//! the loopback, each pair of crates in both places, and what each session is handed compared
//! with what two upstream sessions hand each other.
//!
//! One session listens and the other, a peer, dials it. The listener is a peer, and then a router,
//! which carries shared memory as its configuration says whatever its mode. A wz session that
//! listens is a router node at either role and one that only dials is the registry of faces, so
//! both of wz's engines meet upstream's, each way. Each session sends the other, in shared memory
//! it allocated from its provider:
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
//! The same is held of a put to a multicast group that two members join, two peers or a router
//! and a peer (a wz router there is a node, a wz peer the registry): a group negotiates nothing,
//! so each member's own configuration decides. The one difference held by name is a member whose
//! shared memory is disabled, which upstream hands the descriptor in the place of the data and
//! wz refuses; neither hands it the data.
//!
//! The crates share the machine's segments, so the tests of this binary take one lock.

#![cfg(target_os = "linux")]

use std::{
    net::{TcpListener, UdpSocket},
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
    /// The number of routers and peers the session is linked to.
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

            /// A session of `mode` with id `id` that listens on the endpoint `listen` (a TCP
            /// endpoint or a multicast group) and dials `connect`, scouts for nobody, and has
            /// shared memory as `shm` says.
            pub fn open(
                id: &str,
                mode: &str,
                listen: Option<&str>,
                connect: Option<&str>,
                shm: bool,
            ) -> Node {
                let endpoints = |endpoint: Option<&str>| match endpoint {
                    Some(endpoint) => format!(r#"["{endpoint}"]"#),
                    None => "[]".to_owned(),
                };
                let config = Config::from_json5(&format!(
                    r#"{{ id: "{id}", mode: "{mode}",
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
                    let info = self.session.info();
                    info.routers_zid().wait().count() + info.peers_zid().wait().count()
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

/// [`free_port`] for a multicast group: a UDP port nothing is bound to, given once.
fn free_group_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    loop {
        let offset = NEXT.fetch_add(1, Ordering::Relaxed);
        let port = 31_000 + ((std::process::id() % 4_000) as u16 + offset) % 9_000;
        if UdpSocket::bind(("0.0.0.0", port)).is_ok() {
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

fn open(
    of: Crate,
    mode: &str,
    listen: Option<&str>,
    connect: Option<&str>,
    shm: bool,
) -> Box<dyn Peer> {
    let id = next_id();
    match of {
        Crate::Up => Box::new(up::open(&id, mode, listen, connect, shm)) as Box<dyn Peer>,
        Crate::Wz => Box::new(wz::open(&id, mode, listen, connect, shm)) as Box<dyn Peer>,
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

/// The modes a listener is opened in. The dialler is a peer.
const LISTENER_MODES: [&str; 2] = ["peer", "router"];

/// A session of `listener` in `mode` that listens and a peer of `dialler` that dials it, the
/// dialler with shared memory as `dialler_shm` says, sending each other a put, the value of a get
/// and a reply in shared memory, each way; what each was handed, in order.
fn transcript(
    listener: Crate,
    mode: &str,
    dialler: Crate,
    dialler_shm: bool,
    tag: &str,
) -> Vec<String> {
    let body: Vec<u8> = (0..64u8).collect();
    let endpoint = format!("tcp/127.0.0.1:{}", free_port());
    let mut listening = open(listener, mode, Some(&endpoint), None, true);
    let mut dialling = open(dialler, "peer", None, Some(&endpoint), dialler_shm);
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
    for mode in LISTENER_MODES {
        let reference = transcript(
            Crate::Up,
            mode,
            Crate::Up,
            true,
            &format!("on-{mode}-up-up"),
        );
        assert!(
            reference.iter().all(|l| l.ends_with("as shared memory")),
            "two upstream sessions, the listener a {mode}, did not hand each other shared \
             memory: {reference:#?}"
        );
        for (listener, dialler) in &PAIRS[1..] {
            let tag = format!("on-{mode}-{listener:?}-{dialler:?}").to_lowercase();
            assert_eq!(
                transcript(*listener, mode, *dialler, true, &tag),
                reference,
                "{listener:?} listening as a {mode}, {dialler:?} dialling"
            );
        }
    }
}

#[test]
fn with_shared_memory_off_on_one_side_every_payload_crosses_as_its_bytes() {
    let _g = serial();
    for mode in LISTENER_MODES {
        for (listener, dialler) in PAIRS {
            let tag = format!("off-{mode}-{listener:?}-{dialler:?}").to_lowercase();
            let seen = transcript(listener, mode, dialler, false, &tag);
            assert_eq!(seen.len(), 6, "{seen:#?}");
            assert!(
                seen.iter().all(|l| l.ends_with("as plain bytes")),
                "{listener:?} listening as a {mode}, {dialler:?} dialling without shared \
                 memory: {seen:#?}"
            );
        }
    }
}

/// One member of a group: its crate, its mode and whether its shared memory is enabled.
#[derive(Clone, Copy, Debug)]
struct Member {
    of: Crate,
    mode: &'static str,
    shm: bool,
}

/// The modes of the two members of a group, the sender's first. A wz member in router mode is a
/// router node on the group, one in peer mode the registry of faces.
const GROUP_MODES: [(&str, &str); 3] = [("peer", "peer"), ("router", "peer"), ("peer", "router")];

/// A `receiver` and then a `sender` that join one multicast group, and what the receiver is
/// handed of a put of a buffer of shared memory the sender makes. A group negotiates nothing: a
/// member with shared memory sends a buffer as its descriptor to every member, and maps a
/// descriptor it receives.
fn group_line(sender: Member, receiver: Member) -> String {
    let group = format!("udp/224.0.0.1:{}", free_group_port());
    let mut receiving = open(receiver.of, receiver.mode, Some(&group), None, receiver.shm);
    let sending = open(sender.of, sender.mode, Some(&group), None, sender.shm);
    let key = format!("diff/shm/group/{}", next_id());
    let told = receiving.subscribe(&key);
    let body: Vec<u8> = (0..64u8).collect();
    let seen = until_told(|| sending.put_shm(&key, &body), &told);
    line("a put to the group", &body, seen)
}

#[test]
fn shared_memory_crosses_a_multicast_group_to_and_from_upstream_as_between_two_upstream_members() {
    let _g = serial();
    for (sender_mode, receiver_mode) in GROUP_MODES {
        for (sender_shm, expected) in [(true, "as shared memory"), (false, "as plain bytes")] {
            let members = |sender: Crate, receiver: Crate| {
                (
                    Member {
                        of: sender,
                        mode: sender_mode,
                        shm: sender_shm,
                    },
                    Member {
                        of: receiver,
                        mode: receiver_mode,
                        shm: true,
                    },
                )
            };
            let (sender, receiver) = members(Crate::Up, Crate::Up);
            let reference = group_line(sender, receiver);
            assert!(
                reference.ends_with(expected),
                "two upstream members, a {sender_mode} sending and a {receiver_mode} receiving, \
                 the sender's shared memory {sender_shm}: {reference}"
            );
            for (sender, receiver) in &PAIRS[1..] {
                let (sending, receiving) = members(*sender, *receiver);
                assert_eq!(
                    group_line(sending, receiving),
                    reference,
                    "{sending:?} sending, {receiving:?} receiving"
                );
            }
        }
    }
}

/// The group itself, with shared memory off on both members: a put crosses as its bytes between
/// every pair of crates and every pair of modes as between two upstream members. What this holds
/// is the group transport alone, the beacon a member of either crate must accept before it reads
/// anything the other sends, so a failure of the shared-memory cells above that this passes is
/// the shared memory's.
#[test]
fn a_put_crosses_a_multicast_group_between_the_crates_as_between_two_upstream_members() {
    let _g = serial();
    for (sender_mode, receiver_mode) in GROUP_MODES {
        let members = |sender: Crate, receiver: Crate| {
            (
                Member {
                    of: sender,
                    mode: sender_mode,
                    shm: false,
                },
                Member {
                    of: receiver,
                    mode: receiver_mode,
                    shm: false,
                },
            )
        };
        let (sender, receiver) = members(Crate::Up, Crate::Up);
        let reference = group_line(sender, receiver);
        assert!(
            reference.ends_with("as plain bytes"),
            "two upstream members, a {sender_mode} sending and a {receiver_mode} receiving: \
             {reference}"
        );
        for (sender, receiver) in &PAIRS[1..] {
            let (sending, receiving) = members(*sender, *receiver);
            assert_eq!(
                group_line(sending, receiving),
                reference,
                "{sending:?} sending, {receiving:?} receiving"
            );
        }
    }
}

/// The one place the two crates differ, by decision: a member whose shared memory is disabled
/// holds no reader, and is sent a descriptor all the same. Upstream's maps nothing and hands the
/// message up with the descriptor where the data was; wz's refuses the message, as it refuses a
/// descriptor on any link that did not negotiate shared memory, and counts it. Neither is handed
/// the data, which is what is held of upstream's.
#[test]
fn a_member_without_shared_memory_is_never_handed_a_descriptor_as_the_data() {
    let _g = serial();
    for (sender_mode, receiver_mode) in GROUP_MODES {
        for of in [Crate::Up, Crate::Wz] {
            let sender = Member {
                of,
                mode: sender_mode,
                shm: true,
            };
            let without = |of: Crate| Member {
                of,
                mode: receiver_mode,
                shm: false,
            };
            let upstream = group_line(sender, without(Crate::Up));
            assert!(
                !upstream.contains("the bytes"),
                "{sender:?} sending, upstream's {receiver_mode} without shared memory: {upstream}"
            );
            assert_eq!(
                group_line(sender, without(Crate::Wz)),
                "a put to the group: never handed over",
                "{sender:?} sending, wz's {receiver_mode} without shared memory"
            );
        }
    }
}
