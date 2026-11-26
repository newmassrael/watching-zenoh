// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The features that hold more than one link, face or session, in the form of one thread
//! (`row_callback::OneThread`): no read task starts, and each session is opened, called and read
//! on one thread of its own, as a program of one thread drives it ([`OwnThread`]). Each test is the
//! twin of a test of `threads` the module of its feature holds; the sessions are the engine against
//! itself over loopback, or over a group the program's transport carries.

use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
#[cfg(any(feature = "listen", all(feature = "group", feature = "app-transport")))]
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::EngineHold;
use wz_capi_port::SessionDrive;
#[cfg(any(feature = "listen", all(feature = "group", feature = "app-transport")))]
use wz_session_core::sink::SampleView;

/// A call the test hands a session's thread.
type Handed<E> = Box<dyn FnOnce(&E) + Send>;

/// A session of one thread on a thread of its own: opened there, read there between the calls the
/// test hands it, each run between two reads as a program's own calls are, and closed there once
/// it is let go of.
pub(super) struct OwnThread<E: SessionDrive> {
    calls: Option<Sender<Handed<E>>>,
    thread: Option<JoinHandle<()>>,
}

impl<E: SessionDrive> OwnThread<E> {
    /// The session `open` opens, on a thread of its own: back once it is open.
    pub(super) fn open(open: impl FnOnce() -> EngineHold<E> + Send + 'static) -> Self {
        let (calls, handed) = mpsc::channel::<Handed<E>>();
        let (opened, told) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let engine = open();
            let _ = opened.send(());
            loop {
                match handed.try_recv() {
                    Ok(call) => call(&engine),
                    Err(TryRecvError::Empty) => {
                        let _ = SessionDrive::read(&*engine, false);
                    }
                    Err(TryRecvError::Disconnected) => break,
                }
            }
            SessionDrive::close(&*engine);
        });
        told.recv().expect("the session opens on its thread");
        Self {
            calls: Some(calls),
            thread: Some(thread),
        }
    }

    /// `call` handed to the session's thread and run there between two of its reads: what it
    /// hands back arrives on the receiver once it returned.
    pub(super) fn hand<R: Send + 'static>(
        &self,
        call: impl FnOnce(&E) -> R + Send + 'static,
    ) -> Receiver<R> {
        let (answer, answered) = mpsc::channel();
        let handed: Handed<E> = Box::new(move |engine| {
            let _ = answer.send(call(engine));
        });
        self.calls
            .as_ref()
            .expect("a session's thread takes calls until it is let go of")
            .send(handed)
            .expect("the session's thread runs");
        answered
    }

    /// [`Self::hand`], waited for.
    pub(super) fn call<R: Send + 'static>(&self, call: impl FnOnce(&E) -> R + Send + 'static) -> R {
        self.hand(call)
            .recv()
            .expect("the session's thread ran the call")
    }
}

impl<E: SessionDrive> Drop for OwnThread<E> {
    fn drop(&mut self) {
        // Its calls let go of, the thread reads no more, closes the session and ends.
        drop(self.calls.take());
        if let Some(thread) = self.thread.take() {
            let ended = thread.join();
            if !std::thread::panicking() {
                ended.expect("the session's thread ends without a panic");
            }
        }
    }
}

/// Wait, for at most ten seconds, until `done`: each session reads on its own thread, so the test
/// only asks.
#[cfg(any(feature = "listen", all(feature = "group", feature = "app-transport")))]
fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !done() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// A subscriber of `session` on `pattern`, and what `read` takes of each sample it hears.
#[cfg(any(feature = "listen", all(feature = "group", feature = "app-transport")))]
fn hearing<E, T>(
    session: &OwnThread<E>,
    pattern: &'static str,
    read: fn(&dyn SampleView) -> T,
) -> Arc<std::sync::Mutex<Vec<T>>>
where
    E: SessionDrive + wz_capi_port::SessionEngine,
    T: Send + 'static,
{
    use wz_capi_port::{SubscriberSink, WireKey};
    use wz_session_core::locality::Locality;

    let heard = Arc::new(std::sync::Mutex::new(Vec::new()));
    let into = Arc::clone(&heard);
    session.call(move |engine| {
        engine
            .declare_subscriber_on_wire(
                pattern,
                WireKey::literal(),
                Locality::Any,
                None,
                SubscriberSink::shared(move |sample: &dyn SampleView| {
                    into.lock().unwrap().push(read(sample));
                }),
            )
            .expect("the session declares the subscriber");
    });
    heard
}

/// The payload of a sample.
#[cfg(any(feature = "listen", all(feature = "group", feature = "app-transport")))]
fn payload(sample: &dyn SampleView) -> Vec<u8> {
    sample.payload().to_vec()
}

/// `session` puts `payload` on `keyexpr`, named as the literal, for the peers alone.
#[cfg(any(feature = "listen", all(feature = "group", feature = "app-transport")))]
fn put<E>(session: &OwnThread<E>, keyexpr: &'static str, payload: &'static [u8])
where
    E: SessionDrive + wz_capi_port::SessionEngine,
{
    use wz_capi_port::WireKey;
    use wz_session_core::locality::Locality;
    use wz_session_core::publish_options::PublishOptions;

    session.call(move |engine| {
        engine
            .publish_on_wire_all(
                keyexpr,
                &WireKey::literal(),
                payload,
                &PublishOptions::put().with_locality(Locality::Remote),
            )
            .expect("a put the session carries");
    });
}

#[cfg(feature = "listen")]
mod listen {
    use std::io::Read;
    use std::net::TcpStream;
    use std::time::Duration;

    use super::super::{client_config, config_zid, open_with, Engine};
    use super::{eventually, hearing, payload, put, OwnThread};
    use crate::CoopConfig;
    use wz_session_core::WhatAmI;

    /// A session of one thread that listens on a loopback port the kernel picks and dials nothing,
    /// with the endpoint it is bound to. `tune` states what a test changes.
    fn listening(
        zid: u8,
        tune: impl FnOnce(&mut CoopConfig) + Send + 'static,
    ) -> (OwnThread<Engine>, String) {
        let session = OwnThread::open(move || {
            let mut config = CoopConfig {
                whatami: WhatAmI::Peer,
                zid: config_zid(zid),
                listen: vec!["tcp/127.0.0.1:0".to_owned()],
                ..client_config()
            };
            tune(&mut config);
            open_with(config)
        });
        let endpoint = session.call(|engine| engine.listening().pop().expect("one port is bound"));
        (session, endpoint)
    }

    /// A client session of one thread that dials `endpoint`.
    fn client(endpoint: &str, zid: u8) -> OwnThread<Engine> {
        let endpoint = endpoint.to_owned();
        OwnThread::open(move || {
            open_with(CoopConfig {
                endpoints: vec![endpoint],
                zid: config_zid(zid),
                ..client_config()
            })
        })
    }

    fn faces_up(session: &OwnThread<Engine>) -> usize {
        session.call(|engine| engine.faces_up())
    }

    /// A raw connection to the port `endpoint` names, which never speaks.
    fn connect(endpoint: &str) -> TcpStream {
        let port = endpoint
            .rsplit(':')
            .next()
            .expect("an endpoint with a port");
        TcpStream::connect(format!("127.0.0.1:{port}")).expect("the port accepts")
    }

    /// Whether the other end has closed `stream` within `within`: a read that returns end of
    /// stream. A stream still open is a read that times out.
    fn closed_by_peer(stream: &mut TcpStream, within: Duration) -> bool {
        stream
            .set_read_timeout(Some(within))
            .expect("a read timeout");
        let mut byte = [0u8; 1];
        matches!(stream.read(&mut byte), Ok(0))
    }

    /// A listener of one thread takes two clients of one thread, hears what each puts, and holds
    /// the other when one goes: its own reads accept the links, answer their handshakes and
    /// dispatch, with no read task. The CONTROL is the listener before any client, which holds no
    /// face. Twin of `listen::a_listener_hears_and_asks_every_client_it_has_taken`.
    #[test]
    fn a_listener_of_one_thread_takes_its_clients_and_hears_them() {
        let (listener, endpoint) = listening(0xa1, |_| {});
        assert_eq!(
            faces_up(&listener),
            0,
            "CONTROL: a listener holds no face until a peer comes"
        );
        let heard = hearing(&listener, "demo/l/**", payload);
        let first = client(&endpoint, 0xc1);
        let second = client(&endpoint, 0xc2);
        eventually("the listener to hold both faces", || {
            faces_up(&listener) == 2
        });
        put(&first, "demo/l/x", b"from-first");
        put(&second, "demo/l/x", b"from-second");
        eventually("the listener to hear both", || {
            heard.lock().unwrap().len() == 2
        });
        let mut payloads = heard.lock().unwrap().clone();
        payloads.sort();
        assert_eq!(payloads, [b"from-first".to_vec(), b"from-second".to_vec()]);

        drop(first);
        eventually("the lost client's face to go", || faces_up(&listener) == 1);
        put(&second, "demo/l/x", b"after-the-first");
        eventually("the listener to hear the client left", || {
            heard
                .lock()
                .unwrap()
                .iter()
                .any(|got| got == b"after-the-first")
        });
    }

    /// A node of one thread dialled twice by one peer of one thread holds the first link and
    /// refuses the second: each end holds one face, and keeps it, and the link carries a put. Twin
    /// of `one_face::a_second_dial_to_a_node_the_session_holds_is_refused`.
    #[test]
    fn a_second_dial_to_a_node_of_one_thread_is_refused() {
        let (listener, endpoint) = listening(0xa1, |_| {});
        let dialler = client(&endpoint, 0xc1);
        eventually("the first link", || {
            faces_up(&listener) == 1 && faces_up(&dialler) == 1
        });
        let again = endpoint.clone();
        assert!(
            dialler.call(move |engine| engine.attach_face(&again).is_ok()),
            "the second dial reaches the port"
        );
        eventually("the second link to be decided", || {
            faces_up(&listener) == 1 && faces_up(&dialler) == 1
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(
            (faces_up(&listener), faces_up(&dialler)),
            (1, 1),
            "each end holds one face and keeps it"
        );
        let heard = hearing(&listener, "demo/one/**", payload);
        put(&dialler, "demo/one/x", b"over-the-one");
        eventually("the listener to hear the dialler", || {
            heard
                .lock()
                .unwrap()
                .iter()
                .any(|got| got == b"over-the-one")
        });
    }

    /// A connection that arrives when a listener of one thread holds as many faces as it may is
    /// closed unread, and the face it holds stands: the face table gives the link no row. CONTROL:
    /// with room for another face the connection is kept, its handshake under way. Twin of
    /// `listen::a_connection_past_max_faces_is_closed_unread`. Turned red by a take of a face
    /// past `max_faces` (`Core::takes_a_face`), or an accept that makes a link's session where
    /// the table gave no row (`CoopEngine::accept_links`).
    #[test]
    fn a_connection_past_max_faces_is_closed_unread_by_a_listener_of_one_thread() {
        let (full, endpoint) = listening(0xa1, |config| config.max_faces = 1);
        let held = client(&endpoint, 0xc1);
        eventually("the one face to be up", || faces_up(&full) == 1);
        let mut over = connect(&endpoint);
        assert!(
            closed_by_peer(&mut over, Duration::from_secs(3)),
            "the listener is full, so it closes the connection"
        );
        assert_eq!(faces_up(&full), 1, "and the face it holds stands");
        drop(held);

        let (roomy, endpoint) = listening(0xa2, |config| config.max_faces = 2);
        let _held = client(&endpoint, 0xc2);
        eventually("the one face to be up", || faces_up(&roomy) == 1);
        let mut kept = connect(&endpoint);
        assert!(
            !closed_by_peer(&mut kept, Duration::from_millis(300)),
            "CONTROL: with room for another face the connection is kept"
        );
    }

    /// A connection that never speaks to a listener of one thread is let go of once the bound of
    /// its handshake passes, and the one row the face table has takes the next connection: the
    /// face's going lets go of what its row's place held, then its record. CONTROL: inside the
    /// bound the connection is kept. Twin of
    /// `listen::a_connection_that_never_speaks_is_let_go_when_the_bound_passes`. Turned red by a
    /// going the read's look at the life does not carry out (`Effects::removes` in
    /// `CoopEngine::drive_link`): the row stays taken and the client after it is closed unread.
    #[test]
    fn a_connection_that_never_speaks_to_a_listener_of_one_thread_is_let_go_at_the_bound() {
        let (listener, endpoint) = listening(0xa1, |config| {
            config.max_faces = 1;
            config.timeouts.accepting_inactivity_ms = 300;
        });
        let mut silent = connect(&endpoint);
        assert!(
            !closed_by_peer(&mut silent, Duration::from_millis(100)),
            "CONTROL: inside the bound the connection is kept"
        );
        assert!(
            closed_by_peer(&mut silent, Duration::from_secs(3)),
            "past the bound the listener closes it"
        );
        let _client = client(&endpoint, 0xc1);
        eventually("a client to be taken in the row it let go of", || {
            faces_up(&listener) == 1
        });
    }

    /// A listener of one thread with room for one face takes a second client in the place of the
    /// first once it went, and hears it: the row the first face's going let go of is made anew for
    /// the next link. CONTROL: the first client is heard. Turned red by a going that keeps the
    /// face's record (`Core::remove_face` in `CoopEngine::drive_link`), or a row whose place a
    /// link taken after it finds still holding the last one's (`DirectSlot::clear`).
    #[test]
    fn a_listener_of_one_thread_takes_a_client_in_the_place_of_one_that_went() {
        let (listener, endpoint) = listening(0xa1, |config| config.max_faces = 1);
        let heard = hearing(&listener, "demo/r/**", payload);
        let first = client(&endpoint, 0xc1);
        eventually("the first face", || faces_up(&listener) == 1);
        put(&first, "demo/r/x", b"from-first");
        eventually("CONTROL: the first client heard", || {
            heard.lock().unwrap().iter().any(|got| got == b"from-first")
        });
        drop(first);
        eventually("the first face to go", || faces_up(&listener) == 0);
        let second = client(&endpoint, 0xc2);
        eventually("the second face, in the first one's row", || {
            faces_up(&listener) == 1
        });
        put(&second, "demo/r/x", b"from-second");
        eventually("the second client heard", || {
            heard
                .lock()
                .unwrap()
                .iter()
                .any(|got| got == b"from-second")
        });
    }
}

#[cfg(all(feature = "shared-key-ids", feature = "listen"))]
mod shared_key_ids {
    use std::sync::Arc;

    use crate::tests::host_links;
    use wz_capi_port::{SessionEngine, WireKey};
    use wz_runtime_posix::stream::PosixTcpDial;
    use wz_runtime_posix::{PosixClock, PosixEntropy};
    use wz_session_core::locality::Locality;
    use wz_session_core::policy::{KeyWireForm, SessionPolicy};
    use wz_session_core::publish_options::PublishOptions;
    use wz_session_core::shared_key_ids::KeyIds;
    use wz_session_core::sink::SampleView;
    use wz_session_core::WhatAmI;

    use super::super::{client_config, config_zid, Engine, LOOPBACK};
    use super::{eventually, hearing, OwnThread};
    use crate::{CoopConfig, OpenKeyIds};

    /// A session of `config` holding a dictionary of a key and a key below it, which names keys
    /// by their ids on the wire.
    fn keyed(config: CoopConfig) -> EngineHold<Engine> {
        let ids = Arc::new(
            KeyIds::new([(40, "lab/rig"), (41, "lab/rig/alpha")]).expect("a valid dictionary"),
        );
        let mut policy = SessionPolicy::defaults();
        policy
            .select_key_wire_form(KeyWireForm::Shared)
            .expect("a host build allows every value of the key-wire form");
        Engine::open_with_key_ids(
            host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
            PosixClock,
            PosixEntropy,
            config,
            policy,
            OpenKeyIds::shared(ids),
        )
        .expect("the session opens")
    }

    /// The key of a sample.
    fn key(sample: &dyn SampleView) -> String {
        sample.keyexpr().to_owned()
    }

    /// A put by an id of the dictionary both ends hold, alone and with a suffix, reaches a
    /// listener of one thread from a client of one thread, the id read by the listener's own
    /// reads. Twin of `shared_key_ids::a_put_by_a_shared_id_reaches_a_session_that_holds_the_dictionary`.
    #[test]
    fn a_put_by_a_shared_id_reaches_a_listener_of_one_thread() {
        let listener = OwnThread::open(|| {
            keyed(CoopConfig {
                whatami: WhatAmI::Peer,
                zid: config_zid(0xa1),
                listen: vec!["tcp/127.0.0.1:0".to_owned()],
                ..client_config()
            })
        });
        let endpoint = listener.call(|engine| engine.listening().pop().expect("one port is bound"));
        let heard = hearing(&listener, "lab/**", key);
        let client = OwnThread::open(move || {
            keyed(CoopConfig {
                endpoints: vec![endpoint],
                zid: config_zid(0xc1),
                ..client_config()
            })
        });
        eventually("the listener to hold the client's face", || {
            listener.call(|engine| engine.faces_up()) == 1
        });
        client.call(|engine| {
            let remote = PublishOptions::put().with_locality(Locality::Remote);
            engine
                .publish_on_wire_all(
                    "lab/rig/alpha",
                    &WireKey::aliased(41, None),
                    b"one",
                    &remote,
                )
                .expect("a put the link carries");
            engine
                .publish_on_wire_all(
                    "lab/rig/gamma",
                    &WireKey::aliased(40, Some("/gamma".to_owned())),
                    b"two",
                    &remote,
                )
                .expect("a put the link carries");
        });
        eventually("the listener to hear both puts", || {
            heard.lock().unwrap().len() == 2
        });
        assert_eq!(*heard.lock().unwrap(), ["lab/rig/alpha", "lab/rig/gamma"]);
    }
}

#[cfg(all(feature = "group", feature = "app-transport"))]
mod group {
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use wz_capi_port::PeerLists;

    use super::super::group_stack::{member_config, open_member, Network, GROUP};
    use super::{eventually, hearing, payload, put, OwnThread};
    use crate::CoopConfig;

    /// Two members of one thread, each on a thread of its own, learn each other by their JOINs,
    /// which each one's reads beacon and take, and a put of the first crosses the group; the second,
    /// closed, tells the group it leaves, which the first hears. A put is heard once: its leg to
    /// the group is one, whatever the session's faces (turned red by a group leg sent with each
    /// face's). Twin of
    /// `group::two_members_learn_each_other_by_their_joins_and_a_put_crosses_the_group`.
    #[test]
    fn two_members_of_one_thread_learn_each_other_and_a_put_crosses_the_group() {
        let network = Arc::new(Network::default());
        let member = |id: u8| {
            let network = Arc::clone(&network);
            OwnThread::open(move || {
                open_member(&network, id, member_config(id, GROUP)).expect("the member joins")
            })
        };
        let first = member(1);
        let second = member(2);
        assert_eq!(
            (network.joins_of(1), network.joins_of(2)),
            (1, 1),
            "each session asked its stack to join the group once"
        );
        eventually("each member to list the other", || {
            first.call(|engine| engine.group_member_zids()) == [vec![2u8; 4]]
                && second.call(|engine| engine.group_member_zids()) == [vec![1u8; 4]]
        });
        assert!(
            network.beacons_of(1) > 0 && network.beacons_of(2) > 0,
            "each member's reads beaconed its JOIN"
        );

        let heard = hearing(&second, "demo/group/**", payload);
        put(&first, "demo/group/a", b"over-the-group");
        eventually("the second member to hear the put", || {
            heard
                .lock()
                .unwrap()
                .iter()
                .any(|got| got == b"over-the-group")
        });
        // A put reaches the group once, whatever faces it is sent on beside the group: a second put,
        // heard in the first member's order after every copy of the first, closes the count.
        put(&first, "demo/group/b", b"after-it");
        eventually("the second member to hear the second put", || {
            heard.lock().unwrap().iter().any(|got| got == b"after-it")
        });
        assert_eq!(
            heard
                .lock()
                .unwrap()
                .iter()
                .filter(|got| *got == b"over-the-group")
                .count(),
            1,
            "the first put is heard once"
        );

        drop(second);
        assert_eq!(
            network.leaves.load(Ordering::SeqCst),
            1,
            "the closed session's stack left the group"
        );
        eventually("the first member to lose the second", || {
            first.call(|engine| engine.group_member_zids()).is_empty()
        });
    }

    /// A member of one thread whose stack loses its group link joins the group again a redial
    /// period later, its new session built in the place of the read slot its first join was
    /// given: the members learn each other again and a put crosses the group joined again, and
    /// the member made one place for the group's session in all. Turned red by a join again that
    /// gives the group's session a place of its own (`Core::seat_group`). Twin of
    /// `group::a_member_whose_group_link_is_lost_joins_the_group_again`.
    #[test]
    fn a_member_of_one_thread_whose_group_link_is_lost_joins_again_in_the_same_place() {
        let network = Arc::new(Network::default());
        let member = |id: u8| {
            let network = Arc::clone(&network);
            OwnThread::open(move || {
                let config = CoopConfig {
                    redial_ms: Some(100),
                    ..member_config(id, GROUP)
                };
                open_member(&network, id, config).expect("the member joins")
            })
        };
        let first = member(1);
        let second = member(2);
        eventually("each member to list the other", || {
            first.call(|engine| engine.group_member_zids()) == [vec![2u8; 4]]
                && second.call(|engine| engine.group_member_zids()) == [vec![1u8; 4]]
        });
        assert_eq!(network.joins_of(2), 1);
        assert_eq!(
            second.call(|engine| engine.group_places_made()),
            1,
            "CONTROL: the first join made the group's place"
        );

        network.cut(2);
        eventually(
            "the second member's stack to be asked to join again",
            || network.joins_of(2) == 2,
        );
        eventually("each member to list the other again", || {
            first.call(|engine| engine.group_member_zids()) == [vec![2u8; 4]]
                && second.call(|engine| engine.group_member_zids()) == [vec![1u8; 4]]
        });
        let heard = hearing(&second, "demo/group/**", payload);
        eventually("a put to cross the group joined again", || {
            put(&first, "demo/group/b", b"after-the-loss");
            heard
                .lock()
                .unwrap()
                .iter()
                .any(|got| got == b"after-the-loss")
        });
        assert_eq!(network.joins_of(2), 2, "joined again once, and only once");
        assert_eq!(
            second.call(|engine| engine.group_places_made()),
            1,
            "the join again built its session in the place of the first"
        );
    }
}
