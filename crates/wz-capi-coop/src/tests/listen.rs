// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session that listens: it binds a `tcp/` port, takes the connections that arrive as faces of
//! its own, and is the same session on each. The peers here are the engine itself in its client
//! role, over loopback, so what is proved is the engine against the engine and not against a
//! stand-in; every session is stepped by its read task, as a C program's would be.

use std::io::Read;
use std::net::TcpStream;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_port::{
    BatchStep, QueryHolder, QueryableSink, ReplyCallback, SessionDrive, SessionEngine,
    SubscriberSink, WireKey,
};
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::qos::CongestionControl;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::reply_sink::ReplyView;
use wz_session_core::session_init_params::SessionZid;
use wz_session_core::sink::SampleView;
use wz_session_core::WhatAmI;

use super::get::remote_get;
use super::{client_config, config_zid, open_with, Engine};
use crate::CoopConfig;
use crate::EngineHold;

/// A session whose read task is running, closed when it is let go of: a test's session is stepped
/// by a thread of its own, and one never closed would keep its port and its task.
pub(super) struct Stepped(EngineHold<Engine>);

impl Stepped {
    pub(super) fn new(engine: EngineHold<Engine>) -> Self {
        SessionDrive::start_read_task(&*engine).expect("the read task starts");
        Self(engine)
    }
}

impl Deref for Stepped {
    type Target = Engine;

    fn deref(&self) -> &Engine {
        &self.0
    }
}

impl Drop for Stepped {
    fn drop(&mut self) {
        SessionDrive::close(&*self.0);
    }
}

/// Wait, for at most five seconds, until `done`: every session is stepped by its own thread, so
/// the test only looks.
pub(super) fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// A session that listens on a loopback port the kernel picks and dials nothing, stepped by its
/// read task, with the endpoint it is bound to. `tune` states what a test changes.
pub(super) fn listening(tune: impl FnOnce(&mut CoopConfig)) -> (Stepped, String) {
    let mut config = CoopConfig {
        whatami: WhatAmI::Peer,
        zid: config_zid(0xa1),
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        ..client_config()
    };
    tune(&mut config);
    let engine = open_with(config);
    let endpoint = engine.listening().pop().expect("one port is bound");
    (Stepped::new(engine), endpoint)
}

/// A client session that dials `endpoint`, stepped by its read task.
pub(super) fn client(endpoint: &str, id: u8) -> Stepped {
    Stepped::new(open_with(CoopConfig {
        endpoints: vec![endpoint.to_owned()],
        zid: config_zid(id),
        ..client_config()
    }))
}

/// Whether the other end has closed `stream` within `within`: a read that returns end of stream.
/// A stream still open is a read that times out, which is the answer of a peer that holds it.
fn closed_by_peer(stream: &mut TcpStream, within: Duration) -> bool {
    stream
        .set_read_timeout(Some(within))
        .expect("a read timeout");
    let mut byte = [0u8; 1];
    matches!(stream.read(&mut byte), Ok(0))
}

/// A listener hears what each of two clients publishes, asks both of them with one get, and goes
/// on over the other when one is lost. The control is the listener before any client: it is open,
/// bound to the port it states, and has no face.
#[test]
fn a_listener_hears_and_asks_every_client_it_has_taken() {
    let (listener, endpoint) = listening(|_| {});
    assert!(
        endpoint.starts_with("tcp/127.0.0.1:") && !endpoint.ends_with(":0"),
        "the endpoint states the port the kernel picked, not the 0 asked for: {endpoint}"
    );
    assert_eq!(
        listener.faces_up(),
        0,
        "CONTROL: a listener holds no face until a peer comes"
    );

    let heard = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let into = heard.clone();
    listener
        .declare_subscriber_on_wire("demo/l/**", WireKey::literal(), Locality::Any, None, {
            let into = into.clone();
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                into.lock().unwrap().push(sample.payload().to_vec());
            })
        })
        .expect("the session declares the subscriber");

    let first = client(&endpoint, 0xc1);
    let second = client(&endpoint, 0xc2);
    eventually("the listener to hold both faces", || {
        listener.faces_up() == 2
    });

    for (peer, text) in [(&first, &b"from-first"[..]), (&second, &b"from-second"[..])] {
        peer.publish_on_wire_all(
            "demo/l/x",
            &WireKey::literal(),
            text,
            &PublishOptions::put().with_locality(Locality::Remote),
        )
        .expect("a put the link carries");
    }
    eventually("the listener to hear both", || {
        heard.lock().unwrap().len() == 2
    });
    let mut payloads = heard.lock().unwrap().clone();
    payloads.sort();
    assert_eq!(payloads, [b"from-first".to_vec(), b"from-second".to_vec()]);

    // Each client answers a query with its own payload; the listener's one get is one leg for each
    // face, and ends when both Finals are in.
    for (peer, text) in [(&first, &b"a-first"[..]), (&second, &b"a-second"[..])] {
        peer.declare_queryable_on_wire(
            "demo/g/**",
            WireKey::literal(),
            false,
            Locality::Any,
            None,
            QueryableSink::shared(
                move |query: &dyn QueryView, out: &mut dyn ReplyOut, _holder: &dyn QueryHolder| {
                    out.reply_keyed(query.keyexpr(), text)
                        .expect("a reply on the query's own key");
                },
            ),
        )
        .expect("the engine has queryables in this build");
    }
    let replies = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let ended = Arc::new(Mutex::new(0usize));
    struct End(Arc<Mutex<usize>>);
    impl Drop for End {
        fn drop(&mut self) {
            *self.0.lock().unwrap() += 1;
        }
    }
    let issued = listener.get_on_wire(
        "demo/g/a",
        &WireKey::literal(),
        &remote_get(),
        None,
        &mut || {
            let end = End(ended.clone());
            let into = replies.clone();
            ReplyCallback::shared(move |view: &dyn ReplyView| {
                let _held = &end;
                into.lock().unwrap().push(view.payload().to_vec());
            })
        },
    );
    assert_eq!(issued, Ok(2), "one leg for each face the listener holds");
    eventually("both legs to end", || *ended.lock().unwrap() == 2);
    let mut answers = replies.lock().unwrap().clone();
    answers.sort();
    assert_eq!(answers, [b"a-first".to_vec(), b"a-second".to_vec()]);

    // A client that goes takes its face and nothing else with it.
    drop(first);
    eventually("the lost client's face to go", || listener.faces_up() == 1);
    second
        .publish_on_wire_all(
            "demo/l/y",
            &WireKey::literal(),
            b"still-here",
            &PublishOptions::put().with_locality(Locality::Remote),
        )
        .expect("a put the link carries");
    eventually("the listener to hear the client that is left", || {
        heard.lock().unwrap().len() == 3
    });
}

/// A listener with a face and a port to watch waits on both at once: a read that finds nothing
/// returns after the idle wait, where looking at each in turn a millisecond apart returns about a
/// thousand times a second. The reads are counted over half a second of an idle session; the idle
/// wait is 100 ms, so a handful is the answer and a few hundred is the look.
#[test]
fn an_idle_listener_waits_on_its_port_and_its_links_together() {
    let (listener, endpoint) = listening(|_| {});
    let _client = client(&endpoint, 0xc1);
    eventually("the face to be up", || listener.faces_up() == 1);
    // The listener's own read task is not what is counted: it is stopped, and this thread reads.
    SessionDrive::stop_read_task(&*listener).expect("the read task stops");
    let until = Instant::now() + Duration::from_millis(500);
    let mut reads = 0u32;
    while Instant::now() < until {
        let _ = SessionDrive::read(&*listener, false);
        reads += 1;
    }
    assert!(
        reads < 40,
        "an idle listener was woken {reads} times in half a second"
    );
}

/// A connection that arrives when the session holds as many faces as it may is closed unread, and
/// the faces it holds go on. The control is the same flow with room for one more, where the
/// connection is kept: it is the listener's bound and not its handling of a raw connection that
/// closes the first.
#[test]
fn a_connection_past_max_faces_is_closed_unread() {
    let (full, endpoint) = listening(|config| config.max_faces = 1);
    let held = client(&endpoint, 0xc1);
    eventually("the one face to be up", || full.faces_up() == 1);
    let port = endpoint.rsplit(':').next().unwrap().to_owned();
    let mut over = TcpStream::connect(format!("127.0.0.1:{port}")).expect("the port accepts");
    assert!(
        closed_by_peer(&mut over, Duration::from_secs(3)),
        "the listener is full, so it closes the connection"
    );
    assert_eq!(full.faces_up(), 1, "and the face it holds stands");
    drop(held);

    let (roomy, endpoint) = listening(|config| config.max_faces = 2);
    let _held = client(&endpoint, 0xc1);
    eventually("the one face to be up", || roomy.faces_up() == 1);
    let port = endpoint.rsplit(':').next().unwrap().to_owned();
    let mut kept = TcpStream::connect(format!("127.0.0.1:{port}")).expect("the port accepts");
    assert!(
        !closed_by_peer(&mut kept, Duration::from_millis(300)),
        "CONTROL: with room for another face the connection is kept"
    );
}

/// A full listener counts a face it has lost track of until the face's lease ends, as zenoh-pico
/// counts a peer in its list until then (`vendor/zenoh-pico/src/transport/unicast/accept.c` @
/// `if (_z_transport_peer_unicast_slist_len(ztu->_peers) >= Z_LISTEN_MAX_CONNECTION_NB) {`): a
/// connection that arrives while the silent face still holds its link and that link's buffers is
/// closed unread, and one that arrives after the lease took the face is taken. The link of the
/// face taken in its place, and the face that stood all along, carry every sample whole: no link
/// reads into buffers another still holds. The CONTROL is the full listener before the face goes
/// silent, whose two faces are heard.
#[test]
fn a_full_listener_takes_a_lost_faces_place_once_its_lease_ends_and_not_before() {
    let (full, endpoint) = listening(|config| {
        config.max_faces = 2;
        config.accept_pending = 1;
    });
    let heard = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let into = heard.clone();
    full.declare_subscriber_on_wire(
        "demo/full/**",
        WireKey::literal(),
        Locality::Any,
        None,
        SubscriberSink::shared(move |sample: &dyn SampleView| {
            into.lock().unwrap().push(sample.payload().to_vec());
        }),
    )
    .expect("the session declares the subscriber");
    let put = |peer: &Stepped, tag: u8, at: u8| {
        // Long enough that a batch holds a few, so a sample read into another link's buffer
        // would show in its bytes.
        let payload = vec![tag ^ at; 200 + usize::from(at)];
        // Blocking: under the clients' pico profile a droppable put that finds its link's send
        // held by the client's own read task (a keep-alive) is dropped and told, and every sample
        // is what the listener's links are read for here.
        peer.publish_on_wire_all(
            "demo/full/x",
            &WireKey::literal(),
            &payload,
            &PublishOptions::put()
                .with_locality(Locality::Remote)
                .with_congestion_control(CongestionControl::Block),
        )
        .expect("a put the link carries");
        payload
    };

    let silent = Stepped::new(open_with(CoopConfig {
        endpoints: vec![endpoint.clone()],
        zid: config_zid(0xc1),
        lease_ms: 600,
        ..client_config()
    }));
    let standing = client(&endpoint, 0xc2);
    eventually("the listener to be full", || full.faces_up() == 2);
    let mut expected = vec![put(&silent, 0x10, 0), put(&standing, 0x20, 0)];
    eventually("CONTROL: both faces heard", || {
        heard.lock().unwrap().len() == 2
    });

    // The face goes silent: its socket stays open and nothing of its session is stepped, so the
    // listener learns of it only when the lease it advertised ends.
    SessionDrive::stop_read_task(&*silent).expect("the read task stops");
    let port = endpoint.rsplit(':').next().unwrap().to_owned();
    let mut early = TcpStream::connect(format!("127.0.0.1:{port}")).expect("the port accepts");
    assert!(
        closed_by_peer(&mut early, Duration::from_secs(3)),
        "the silent face is still counted, so the listener is full and closes the connection"
    );
    eventually("the silent face's lease to end", || full.faces_up() == 1);

    let late = client(&endpoint, 0xc3);
    eventually("the face taken in its place", || full.faces_up() == 2);
    for at in 1..=12u8 {
        expected.push(put(&standing, 0x20, at));
        expected.push(put(&late, 0x30, at));
    }
    eventually("every sample of both links", || {
        heard.lock().unwrap().len() == expected.len()
    });
    let mut got = heard.lock().unwrap().clone();
    got.sort();
    expected.sort();
    assert_eq!(got, expected, "each sample whole, as it was sent");
    drop(silent);
}

/// A connection that arrives while as many handshakes are under way as the session allows is
/// closed unread; one inside the bound is kept.
#[test]
fn a_connection_past_accept_pending_is_closed_unread() {
    let (listener, endpoint) = listening(|config| config.accept_pending = 1);
    let port = endpoint.rsplit(':').next().unwrap().to_owned();
    let mut pending = TcpStream::connect(format!("127.0.0.1:{port}")).expect("the port accepts");
    assert!(
        !closed_by_peer(&mut pending, Duration::from_millis(300)),
        "CONTROL: the first connection is inside the bound and is kept"
    );
    let mut over = TcpStream::connect(format!("127.0.0.1:{port}")).expect("the port accepts");
    assert!(
        closed_by_peer(&mut over, Duration::from_secs(3)),
        "a second handshake is past the bound, so the listener closes the connection"
    );
    assert!(
        !closed_by_peer(&mut pending, Duration::from_millis(100)),
        "and the handshake under way is not disturbed"
    );
    assert_eq!(listener.faces_up(), 0);
}

/// A connection that never speaks is let go when the handshake's bound passes: the face it took is
/// removed with its link, and the port takes the next connection as before.
#[test]
fn a_connection_that_never_speaks_is_let_go_when_the_bound_passes() {
    let (listener, endpoint) = listening(|config| {
        config.timeouts.accepting_inactivity_ms = 300;
    });
    let port = endpoint.rsplit(':').next().unwrap().to_owned();
    let mut silent = TcpStream::connect(format!("127.0.0.1:{port}")).expect("the port accepts");
    assert!(
        !closed_by_peer(&mut silent, Duration::from_millis(100)),
        "CONTROL: inside the bound the connection is kept"
    );
    assert!(
        closed_by_peer(&mut silent, Duration::from_secs(3)),
        "past the bound the listener closes it"
    );
    // The port is not spent: a client that speaks is taken.
    let _client = client(&endpoint, 0xc1);
    eventually("a client to be taken after it", || listener.faces_up() == 1);
}

/// A session that listens on a `udp/` port takes each client that dials it as a face of its own,
/// over the port's one socket: it hears what each publishes, and when one goes it keeps the other's
/// face. The CONTROL is the listener before any client: bound to the port it states, holding no
/// face.
#[test]
fn a_udp_listener_takes_each_client_as_a_face_of_its_own() {
    let (listener, endpoint) =
        listening(|config| config.listen = vec!["udp/127.0.0.1:0".to_owned()]);
    assert!(
        endpoint.starts_with("udp/127.0.0.1:") && !endpoint.ends_with(":0"),
        "the endpoint states the port the kernel picked, not the 0 asked for: {endpoint}"
    );
    assert_eq!(
        listener.faces_up(),
        0,
        "CONTROL: a listener holds no face until a peer comes"
    );

    let heard = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let into = heard.clone();
    listener
        .declare_subscriber_on_wire("demo/u/**", WireKey::literal(), Locality::Any, None, {
            let into = into.clone();
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                into.lock().unwrap().push(sample.payload().to_vec());
            })
        })
        .expect("the session declares the subscriber");

    let first = client(&endpoint, 0xc1);
    let second = client(&endpoint, 0xc2);
    eventually("the listener to hold both faces", || {
        listener.faces_up() == 2
    });
    for (peer, text) in [(&first, &b"u-first"[..]), (&second, &b"u-second"[..])] {
        peer.publish_on_wire_all(
            "demo/u/x",
            &WireKey::literal(),
            text,
            &PublishOptions::put().with_locality(Locality::Remote),
        )
        .expect("a put the link carries");
    }
    eventually("the listener to hear both", || {
        heard.lock().unwrap().len() == 2
    });
    let mut payloads = heard.lock().unwrap().clone();
    payloads.sort();
    assert_eq!(payloads, [b"u-first".to_vec(), b"u-second".to_vec()]);

    // A client that goes takes its face and its source on the port with it, and nothing else.
    drop(first);
    eventually("the lost client's face to go", || listener.faces_up() == 1);
    second
        .publish_on_wire_all(
            "demo/u/y",
            &WireKey::literal(),
            b"u-still-here",
            &PublishOptions::put().with_locality(Locality::Remote),
        )
        .expect("a put the link carries");
    eventually("the listener to hear the client that is left", || {
        heard.lock().unwrap().len() == 3
    });
}

/// A datagram that opens no session, sent to a `udp/` port, takes no face, and the port takes a
/// client that dials after it. The CONTROL is that client.
#[test]
fn a_stray_datagram_on_a_udp_port_takes_no_face() {
    let (listener, endpoint) =
        listening(|config| config.listen = vec!["udp/127.0.0.1:0".to_owned()]);
    let port = endpoint.rsplit(':').next().unwrap().to_owned();
    let stray = std::net::UdpSocket::bind("127.0.0.1:0").expect("a socket of the test's");
    stray
        .send_to(&[0x05, 0x00], format!("127.0.0.1:{port}"))
        .expect("the datagram is sent");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(listener.faces_up(), 0, "a stray opens no face");
    let _client = client(&endpoint, 0xc1);
    eventually("CONTROL: a client to be taken after it", || {
        listener.faces_up() == 1
    });
}

/// Step `engine` on this thread until `done`, for at most five seconds: how many reads it took.
fn reads_until(engine: &Engine, what: &str, mut done: impl FnMut() -> bool) -> usize {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut reads = 0;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        let _ = SessionDrive::read(engine, false);
        reads += 1;
    }
    reads
}

/// The puts a client writes in one batch window reach a listener's subscriber over the stream
/// link where they lie in the link's receive buffer: each put is handed once where it lies, none
/// copied, and the listener hands them all out in a few reads
/// however many the batch holds (one or two when nothing else arrives; at most a quarter of the
/// puts is asserted), where a link that handed one sample where it lies a read took a read a put.
/// The listener is stepped by this thread, so each read is counted. The CONTROL is the
/// subscriber's count.
#[test]
fn the_puts_of_one_stream_batch_are_handed_where_they_lie_in_a_few_reads() {
    let engine = open_with(CoopConfig {
        whatami: WhatAmI::Peer,
        zid: config_zid(0xa1),
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        ..client_config()
    });
    let endpoint = engine.listening().pop().expect("one port is bound");
    let received = Arc::new(AtomicUsize::new(0));
    let count = received.clone();
    engine
        .declare_subscriber_on_wire("demo/s/**", WireKey::literal(), Locality::Any, None, {
            let count = count.clone();
            SubscriberSink::shared(move |_sample: &dyn SampleView| {
                count.fetch_add(1, Ordering::SeqCst);
            })
        })
        .expect("the session declares the subscriber");
    // The client's open waits for the listener's answer, and this thread is what steps the
    // listener: the client opens on a thread of its own meanwhile.
    let dialing = std::thread::spawn(move || client(&endpoint, 0xc1));
    reads_until(&engine, "the client's face", || engine.faces_up() == 1);
    let peer = dialing.join().expect("the client opens");
    // What the handshake and the declarations left on the link is read before the batch is sent.
    std::thread::sleep(Duration::from_millis(100));
    for _ in 0..4 {
        let _ = SessionDrive::read(&*engine, false);
    }

    const PUTS: usize = 32;
    assert_eq!(
        peer.batch_all(BatchStep::Start),
        1,
        "the client's link opens a window"
    );
    for _ in 0..PUTS {
        peer.publish_on_wire_all(
            "demo/s/x",
            &WireKey::literal(),
            b"x",
            &PublishOptions::put().with_locality(Locality::Remote),
        )
        .expect("a put the window holds");
    }
    assert_eq!(
        peer.batch_all(BatchStep::Stop),
        1,
        "the window is written as it closes"
    );
    std::thread::sleep(Duration::from_millis(100));
    let (handed, lent) = (engine.samples_handed(), engine.samples_lent());
    let reads = reads_until(&engine, "the puts", || {
        received.load(Ordering::SeqCst) == PUTS
    });
    assert_eq!(
        engine.samples_handed() - handed,
        PUTS,
        "each put of the batch handed once"
    );
    assert_eq!(
        engine.samples_lent() - lent,
        PUTS,
        "each put handed where it lies in the stream link's buffer, none copied"
    );
    assert!(
        reads <= PUTS / 4,
        "{reads} reads for {PUTS} puts of one batch: a few, not one a put"
    );
}

/// A read whose step left a link holding input goes on with it at once, with no wait worked out
/// for it: here a second batch lies whole in the stream link's buffer behind the first. Where the
/// session keeps a round, the one read hands both out, the session taken once for its wait and
/// once a batch, and moves the links once at most, after the second. Where the read steps the
/// link itself (`direct`), the one step of the face takes both, one take a batch, so the wait, the
/// look at the life and the pump's deadlines are paid once for the two. Turned red by a read that
/// ends after the first batch while the link holds the second, or one that moves the links after
/// each batch; with `direct`, by a step that takes one batch a read
/// (`CoopEngine::take_held_input`).
#[test]
fn a_read_goes_on_with_the_input_its_step_left_held() {
    let engine = open_with(CoopConfig {
        whatami: WhatAmI::Peer,
        zid: config_zid(0xa1),
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        ..client_config()
    });
    let endpoint = engine.listening().pop().expect("one port is bound");
    let received = Arc::new(AtomicUsize::new(0));
    let count = received.clone();
    engine
        .declare_subscriber_on_wire("demo/s/**", WireKey::literal(), Locality::Any, None, {
            let count = count.clone();
            SubscriberSink::shared(move |_sample: &dyn SampleView| {
                count.fetch_add(1, Ordering::SeqCst);
            })
        })
        .expect("the session declares the subscriber");
    let dialing = std::thread::spawn(move || client(&endpoint, 0xc1));
    reads_until(&engine, "the client's face", || engine.faces_up() == 1);
    let peer = dialing.join().expect("the client opens");
    std::thread::sleep(Duration::from_millis(100));
    for _ in 0..4 {
        let _ = SessionDrive::read(&*engine, false);
    }

    const PUTS: usize = 8;
    let put = || {
        peer.publish_on_wire_all(
            "demo/s/x",
            &WireKey::literal(),
            b"x",
            &PublishOptions::put().with_locality(Locality::Remote),
        )
        .expect("a put the window holds");
    };
    assert_eq!(
        peer.batch_all(BatchStep::Start),
        1,
        "the client's link opens a window"
    );
    for _ in 0..PUTS {
        put();
    }
    assert_eq!(
        peer.batch_all(BatchStep::Flush),
        1,
        "the first batch is written"
    );
    for _ in 0..PUTS {
        put();
    }
    assert_eq!(
        peer.batch_all(BatchStep::Stop),
        1,
        "the second batch is written"
    );
    std::thread::sleep(Duration::from_millis(100));
    #[cfg(wz_round)]
    {
        let takes = |engine: &Engine| engine.takes.core.load(Ordering::SeqCst);
        let (before, polls) = (takes(&engine), engine.link_polls());
        let _ = SessionDrive::read(&*engine, false);
        assert_eq!(
            (takes(&engine) - before, received.load(Ordering::SeqCst)),
            (3, 2 * PUTS),
            "the read works out its wait, steps once a batch and hands both batches out"
        );
        assert!(
            engine.link_polls() - polls <= 1,
            "one move of the links at most, after the second batch"
        );
    }
    #[cfg(not(wz_round))]
    {
        let takes = engine.takes.pump_reads.load(Ordering::SeqCst);
        let _ = SessionDrive::read(&*engine, false);
        assert_eq!(
            received.load(Ordering::SeqCst),
            2 * PUTS,
            "the one read hands out both batches, the one held behind the first too"
        );
        assert_eq!(
            engine.takes.pump_reads.load(Ordering::SeqCst) - takes,
            2,
            "one take a batch, in the one step"
        );
    }
}

/// A listener's read turns the face that holds its client's link and passes over the dial role's
/// face, which dials nothing and holds no link: a look at it would move nothing, and the client's
/// face's look serves the session's own bookkeeping. With no client, the dial role's face is the
/// one a read turns all the same. Turned red by a read that turns a face at rest beside another
/// (`DirectFace::rests` in `CoopEngine::read_faces`, or a dial role that dials nothing not
/// noted at rest by the open), or one that turns no face when every face rests.
#[cfg(not(wz_round))]
#[test]
fn a_listeners_read_passes_over_its_resting_dial_face() {
    let engine = open_with(CoopConfig {
        whatami: WhatAmI::Peer,
        zid: config_zid(0xa2),
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        ..client_config()
    });
    let endpoint = engine.listening().pop().expect("one port is bound");
    let turns = |engine: &Engine| engine.takes.face_turns.load(Ordering::SeqCst);
    let before = turns(&engine);
    let _ = SessionDrive::read(&*engine, false);
    assert_eq!(
        turns(&engine) - before,
        1,
        "with no client the dial role's face is turned all the same"
    );
    let dialing = std::thread::spawn(move || client(&endpoint, 0xc2));
    reads_until(&engine, "the client's face", || engine.faces_up() == 1);
    let _peer = dialing.join().expect("the client opens");
    std::thread::sleep(Duration::from_millis(100));
    for _ in 0..4 {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert_eq!(
        engine.direct_faces().1,
        2,
        "CONTROL: the dial role's face and the client's are both in the read's walk"
    );
    let before = turns(&engine);
    let _ = SessionDrive::read(&*engine, false);
    assert_eq!(
        turns(&engine) - before,
        1,
        "the client's face alone is turned"
    );
}

/// A listener's read walks its face table up to the last row that holds a face and no further:
/// with one client, the dial role's row and the client's, whatever rows the table keeps for faces
/// to come. A second client moves the bound to its row, and the bound comes back as each client's
/// face goes. Turned red by walks of every row of the table (`DirectFaces::walked`), or a bound
/// that a face's going leaves where it was (`DirectFaces::hold_face`).
#[cfg(not(wz_round))]
#[test]
fn a_listeners_walk_ends_at_its_last_held_row() {
    let (listener, endpoint) = listening(|config| config.max_faces = 3);
    assert_eq!(
        listener.walked_rows(),
        1,
        "with no client, the dial role's row alone"
    );
    let first = client(&endpoint, 0xc1);
    eventually("the first face", || listener.faces_up() == 1);
    assert!(
        listener.direct_faces().0 >= 3,
        "CONTROL: the table keeps a row for each face it admits beside the dial role's"
    );
    assert_eq!(
        listener.walked_rows(),
        2,
        "the dial role's row and the first client's"
    );
    let second = client(&endpoint, 0xc2);
    eventually("the second face", || listener.faces_up() == 2);
    assert_eq!(
        listener.walked_rows(),
        3,
        "the bound moves to the second client's row"
    );
    drop(second);
    eventually("the second client's face to go", || {
        listener.walked_rows() == 2
    });
    drop(first);
    eventually("the first client's face to go", || {
        listener.walked_rows() == 1
    });
}

/// A row a face left is noted at rest by that face's last look, and the face an attach gives it
/// next wakes it: the attached dial lies in the face's record until the face's own look takes it
/// into the slot, so a read that passed the row over would never dial. CONTROL: the row's first
/// face, taken off the port, comes up and goes. Turned red by a row given a face and left at rest
/// (`DirectFaces::hold_face` not ending `DirectFace::rests`).
#[cfg(not(wz_round))]
#[test]
fn a_row_a_face_left_wakes_for_the_face_an_attach_gives_it() {
    let (listener, endpoint) = listening(|config| config.max_faces = 1);
    let first = client(&endpoint, 0xc1);
    eventually("CONTROL: the taken face", || listener.faces_up() == 1);
    drop(first);
    eventually("the taken face to go", || {
        listener.faces_up() == 0 && listener.walked_rows() == 1
    });
    let (other, other_endpoint) = listening(|config| config.zid = config_zid(0xa3));
    listener
        .attach_face(&other_endpoint)
        .expect("the attach takes the row the taken face left");
    eventually("the attached face, in the row the taken face left", || {
        listener.faces_up() == 1 && other.faces_up() == 1
    });
    assert_eq!(
        listener.walked_rows(),
        2,
        "the attached face holds the one row past the dial role's"
    );
}

/// A session whose one link is a stream waits on that link's input with nothing of the session
/// held, and the step after the wait reads what came: each put a listener makes reaches it after
/// such a wait. CONTROL: the listener, whose port is waited on beside its link, waits the same way.
/// Turned red by a lone link whose read waits some other way, which these waits would not count.
#[test]
fn a_lone_stream_link_is_waited_on_with_its_port_as_a_listener_is() {
    let (listener, endpoint) = listening(|_| {});
    let peer = client(&endpoint, 0xc1);
    let heard = Arc::new(AtomicUsize::new(0));
    let count = heard.clone();
    peer.declare_subscriber_on_wire("demo/rt/**", WireKey::literal(), Locality::Any, None, {
        let count = count.clone();
        SubscriberSink::shared(move |_sample: &dyn SampleView| {
            count.fetch_add(1, Ordering::SeqCst);
        })
    })
    .expect("the session declares the subscriber");
    eventually("the listener to hold the client's face", || {
        listener.faces_up() == 1
    });
    let polls = peer.takes.polls.load(Ordering::SeqCst);
    const PUTS: usize = 4;
    for n in 1..=PUTS {
        listener
            .publish_on_wire_all(
                "demo/rt/x",
                &WireKey::literal(),
                b"rt",
                &PublishOptions::put().with_locality(Locality::Remote),
            )
            .expect("a put the link carries");
        eventually("the client to hear the put", || {
            heard.load(Ordering::SeqCst) == n
        });
    }
    assert!(
        peer.takes.polls.load(Ordering::SeqCst) - polls >= PUTS,
        "each put was read after a wait on the link's input"
    );
    assert!(
        listener.takes.polls.load(Ordering::SeqCst) > 0,
        "CONTROL: the listener waits on its port and its link together"
    );
}

/// The zid a config states is the one the open session announces, its trailing zero bytes left
/// off as zenoh writes an id.
#[test]
fn a_session_announces_the_zid_its_config_states_without_its_trailing_zeros() {
    let (node, _) = listening(|config| config.zid = Some(SessionZid::from([0x5a, 0x5b, 0, 0])));
    assert_eq!(SessionEngine::session_zid(&*node), [0x5a, 0x5b]);
}

/// A key a peer names by its declaration and a suffix one byte past the row the listener composes
/// keys in is refused where it lies and counted, and the session reads the count off its faces
/// (`CoopEngine::in_place_fallbacks`). The CONTROL is a key named the same way that fits the row:
/// it is composed there, heard, and counted nowhere. Turned red by a face whose counts the session
/// does not read (`Registry::in_place_fallbacks` folding no face).
#[test]
fn a_composed_key_past_the_row_is_counted_where_the_session_reads_it() {
    let (listener, endpoint) = listening(|_| {});
    let heard = Arc::new(Mutex::new(Vec::<String>::new()));
    let into = heard.clone();
    listener
        .declare_subscriber_on_wire(
            "**",
            WireKey::literal(),
            Locality::Any,
            None,
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                into.lock().unwrap().push(sample.keyexpr().to_owned());
            }),
        )
        .expect("the session declares the subscriber");
    let peer = client(&endpoint, 0xc1);
    eventually("the listener to hold the client's face", || {
        listener.faces_up() == 1
    });
    // One chunk one byte short of the bound: the declaration fits, and with `/x` after it the
    // key is one byte past the row.
    let long = "a".repeat(wz_session_core::caps::MAX_KEYEXPR_BYTES - 1);
    let fits = peer
        .acquire_keyexpr("demo/c")
        .expect("room for a declaration")
        .mapping_id();
    let past = peer
        .acquire_keyexpr(&long)
        .expect("room for a declaration")
        .mapping_id();
    let remote = PublishOptions::put().with_locality(Locality::Remote);
    let long_key = format!("{long}/x");
    for (id, key) in [(fits, "demo/c/x"), (past, long_key.as_str())] {
        peer.publish_on_wire_all(
            key,
            &WireKey::aliased(id, Some("/x".to_owned())),
            b"v",
            &remote,
        )
        .expect("a put the link carries");
    }
    // The literal put after them on the same reliable link is the mark that both have arrived.
    peer.publish_on_wire_all("demo/mark", &WireKey::literal(), b"m", &remote)
        .expect("a put the link carries");
    eventually("the listener to hear the mark", || {
        heard.lock().unwrap().iter().any(|key| key == "demo/mark")
    });
    assert!(
        heard.lock().unwrap().iter().any(|key| key == "demo/c/x"),
        "CONTROL: a composed key that fits the row is heard"
    );
    assert_eq!(listener.in_place_fallbacks().keyexpr_past_bound, 1);
}
