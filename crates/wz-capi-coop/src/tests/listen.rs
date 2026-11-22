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
    QueryCallback, QueryHolder, ReplyCallback, SessionDrive, SessionEngine, WireKey,
};
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::reply_sink::ReplyView;
use wz_session_core::sink::SampleView;
use wz_session_core::WhatAmI;

use super::get::remote_get;
use super::{client_config, open_with, Engine};
use crate::CoopConfig;

/// A session whose read task is running, closed when it is let go of: a test's session is stepped
/// by a thread of its own, and one never closed would keep its port and its task.
pub(super) struct Stepped(Arc<Engine>);

impl Stepped {
    pub(super) fn new(engine: Arc<Engine>) -> Self {
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
        zid: Some(vec![0xa1; 4]),
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
        zid: Some(vec![id; 4]),
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
    listener.declare_subscriber_on_wire(
        "demo/l/**".to_owned(),
        WireKey::literal(),
        Locality::Any,
        None,
        Arc::new(move || {
            let into = into.clone();
            Box::new(move |sample: &dyn SampleView| {
                into.lock().unwrap().push(sample.payload().to_vec());
            })
        }),
    );

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
            "demo/g/**".to_owned(),
            WireKey::literal(),
            false,
            Locality::Any,
            None,
            Arc::new(move |_: Arc<dyn QueryHolder>| {
                Box::new(move |query: &dyn QueryView, out: &mut dyn ReplyOut| {
                    out.reply_keyed(query.keyexpr(), text)
                        .expect("a reply on the query's own key");
                }) as QueryCallback
            }),
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
            Box::new(move |view: &dyn ReplyView| {
                let _held = &end;
                into.lock().unwrap().push(view.payload().to_vec());
            }) as ReplyCallback
        },
    );
    assert_eq!(issued, Some(2), "one leg for each face the listener holds");
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
    listener.declare_subscriber_on_wire(
        "demo/u/**".to_owned(),
        WireKey::literal(),
        Locality::Any,
        None,
        Arc::new(move || {
            let into = into.clone();
            Box::new(move |sample: &dyn SampleView| {
                into.lock().unwrap().push(sample.payload().to_vec());
            })
        }),
    );

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
/// link where they lie in the link's receive buffer: each is handed on lying there, none is copied
/// into the lane, and the listener hands them all out in a few reads however many the batch
/// holds, where a link that handed one sample where it lies a read took a read a put. The listener
/// is stepped by this thread, so each read is counted. The CONTROL is the subscriber's count.
#[test]
fn the_puts_of_one_stream_batch_are_handed_where_they_lie_in_a_few_reads() {
    let engine = open_with(CoopConfig {
        whatami: WhatAmI::Peer,
        zid: Some(vec![0xa1; 4]),
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        ..client_config()
    });
    let endpoint = engine.listening().pop().expect("one port is bound");
    let received = Arc::new(AtomicUsize::new(0));
    let count = received.clone();
    engine.declare_subscriber_on_wire(
        "demo/s/**".to_owned(),
        WireKey::literal(),
        Locality::Any,
        None,
        Arc::new(move || {
            let count = count.clone();
            Box::new(move |_sample: &dyn SampleView| {
                count.fetch_add(1, Ordering::SeqCst);
            })
        }),
    );
    let peer = client(&endpoint, 0xc1);
    reads_until(&engine, "the client's face", || engine.faces_up() == 1);
    // What the handshake and the declarations left on the link is read before the batch is sent.
    std::thread::sleep(Duration::from_millis(100));
    for _ in 0..4 {
        let _ = SessionDrive::read(&*engine, false);
    }

    const PUTS: usize = 32;
    assert_eq!(
        peer.batch_start_all(),
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
        peer.batch_stop_all(),
        1,
        "the window is written as it closes"
    );
    std::thread::sleep(Duration::from_millis(100));
    let (handed, lent) = (engine.lane_handed(), engine.lane_lent());
    let reads = reads_until(&engine, "the puts", || {
        received.load(Ordering::SeqCst) == PUTS
    });
    assert_eq!(
        engine.lane_lent() - lent,
        PUTS,
        "each put handed where it lies in the stream link's buffer"
    );
    assert_eq!(
        engine.lane_handed() - handed,
        PUTS,
        "and none copied into the lane"
    );
    assert!(
        reads <= 4,
        "{reads} reads for {PUTS} puts of one batch: a few, not one a put"
    );
}
