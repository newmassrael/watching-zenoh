// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The engine against a router stand-in over the host's UDP sockets: a plain acceptor session on
//! a thread of its own, stepped there, told by the test what to declare and send, and reporting
//! what reached it.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use wz_capi_port::{FilterPlane, FilteredPut, SessionDrive, SessionEngine, WireKey};
use wz_runtime_coop::session_drive::{
    spawn_session, OpenedLink, SessionDriveConfig, SessionLinks, SessionRole,
};
use wz_runtime_coop::session_runtime::new_session_actions;
use wz_runtime_coop::{CoopLocalSet, CoopRuntime, CoopTime};
use wz_runtime_posix::links::PosixLinks;
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::close_reason::CloseReason;
use wz_session_core::declare_form::InterestForm;
use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
use wz_session_core::locality::Locality;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::observer::ApplicationLayerObserver;
use wz_session_core::publish_options::PublishOptions;
use wz_session_core::session_init_params::{LinkRxConf, SessionInitParams, TxQueueConf};
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::sink::{BoxedSink, SampleView};
use wz_session_core::WhatAmI;
use wz_session_mcu::app_layer::dispatch_to;

use crate::{CoopConfig, CoopEngine};

const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

type Engine = CoopEngine<PosixLinks, PosixClock>;

fn params(whatami: WhatAmI, zid: u8) -> SessionInitParams {
    SessionInitParams {
        whatami,
        zid: vec![zid; 4],
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 1024,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: vec![],
        tx_queue: TxQueueConf::default(),
        link_rx: LinkRxConf::default(),
        cookie_signing_key: SigningKey::new(vec![7u8; 32]).expect("key"),
    }
}

/// What the test tells the router to do.
enum Command {
    DeclareSubscriber(u64, &'static str),
    Push(&'static str, &'static [u8]),
    /// Close the session and stop, as a router that goes away does.
    Close,
}

/// What reached the router.
#[derive(Default)]
struct Seen {
    declares: usize,
    interests: usize,
    pushes: usize,
    /// What the router's catch-all subscriber received, when it holds one.
    samples: Vec<(String, Vec<u8>)>,
}

/// Whether the router holds a catch-all subscriber. It is a subscriber like any other: the router
/// declares it in answer to an Interest, so a test of what a session learns from declarations
/// starts without it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CatchAll {
    Held,
    None,
}

struct Router {
    port: u16,
    commands: std::sync::mpsc::Sender<Command>,
    seen: Arc<Mutex<Seen>>,
    thread: Option<JoinHandle<()>>,
}

impl Router {
    fn start(catch_all: CatchAll) -> Self {
        let port = UdpSocket::bind("127.0.0.1:0")
            .and_then(|s| s.local_addr())
            .expect("a free port")
            .port();
        Self::start_on(port, catch_all)
    }

    /// A router on `port`, which a router before it may have held.
    fn start_on(port: u16, catch_all: CatchAll) -> Self {
        let (commands, inbox) = channel();
        let (ready, bound) = channel();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let reported = seen.clone();
        let thread =
            std::thread::spawn(move || run_router(port, catch_all, inbox, reported, ready));
        bound.recv().expect("the router bound its port");
        Self {
            port,
            commands,
            seen,
            thread: Some(thread),
        }
    }

    fn endpoint(&self) -> String {
        format!("udp/127.0.0.1:{}", self.port)
    }

    fn send(&self, command: Command) {
        self.commands.send(command).expect("the router runs");
    }

    fn seen<T>(&self, read: impl FnOnce(&Seen) -> T) -> T {
        read(&self.seen.lock().unwrap())
    }
}

impl Drop for Router {
    fn drop(&mut self) {
        let (closed, _) = channel();
        self.commands = closed;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run_router(
    port: u16,
    catch_all: CatchAll,
    inbox: Receiver<Command>,
    seen: Arc<Mutex<Seen>>,
    ready: std::sync::mpsc::Sender<()>,
) {
    let links = PosixLinks::new(LOOPBACK, PosixTcpDial);
    let OpenedLink { sink, pump } = links.open_acceptor(port).expect("bind the router's end");
    let _ = ready.send(());
    let runtime = CoopRuntime::new(PosixClock);
    let local = CoopLocalSet::new(&runtime);
    // An acceptor mints a cookie per InitAck, from the entropy it is handed.
    let actions = new_session_actions(
        sink,
        params(WhatAmI::Router, 0xc3),
        CoopTime::new(&runtime),
        PosixEntropy,
    );
    let observer = std::rc::Rc::new(std::cell::RefCell::new(ApplicationLayerObserver::new()));
    if catch_all == CatchAll::Held {
        let samples = seen.clone();
        observer
            .borrow_mut()
            .subscribers
            .register_sink(
                "**",
                Locality::Any,
                BoxedSink::new(move |sample: &dyn SampleView| {
                    samples
                        .lock()
                        .unwrap()
                        .samples
                        .push((sample.keyexpr().to_owned(), sample.payload().to_vec()));
                }),
            )
            .expect("the router's catch-all");
    }
    let mut dispatch = dispatch_to(observer, actions.clone());
    let counted = seen;
    let _task = spawn_session(
        &local,
        pump,
        actions.clone(),
        CoopTime::new(&runtime),
        SessionDriveConfig {
            timeouts: SessionTimeouts::spec_defaults(),
            role: SessionRole::Acceptor,
            max_iters: None,
        },
        move |event| {
            if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event {
                let mut seen = counted.lock().unwrap();
                for m in messages {
                    match m {
                        NetworkMessage::Declare(_) => seen.declares += 1,
                        NetworkMessage::Interest(_) => seen.interests += 1,
                        NetworkMessage::Push(_) => seen.pushes += 1,
                        _ => {}
                    }
                }
            }
            dispatch(event);
        },
    );
    loop {
        local.run_until_idle();
        match inbox.try_recv() {
            Ok(Command::DeclareSubscriber(id, key)) => {
                let _ = actions.send_declare_subscriber(id, 0, Some(key));
            }
            Ok(Command::Push(key, value)) => {
                let _ = actions.send_push_literal(key, value, true);
            }
            Ok(Command::Close) => {
                actions.send_close_with_reason(CloseReason::Generic);
                local.run_until_idle();
                return;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => return,
        }
    }
}

/// A client's config for `router`, which redials none.
fn config(router: &Router) -> CoopConfig {
    CoopConfig {
        endpoints: vec![router.endpoint()],
        whatami: WhatAmI::Client,
        zid: Some(vec![0xb1; 4]),
        batch_size: 1024,
        lease_ms: 10_000,
        tx_queue: TxQueueConf::pico(),
        timeouts: SessionTimeouts::spec_defaults(),
        open_timeout_ms: 5_000,
        redial_ms: None,
        idle_wait_ms: 100,
    }
}

fn open(router: &Router) -> Arc<Engine> {
    open_with(config(router))
}

fn open_with(config: CoopConfig) -> Arc<Engine> {
    Engine::open(
        PosixLinks::new(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        PosixEntropy,
        config,
    )
    .expect("the session opens")
}

/// Step `engine` until `done`, for at most five seconds.
fn until(engine: &Engine, what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        let _ = SessionDrive::read(engine, false);
    }
}

/// A session opens to the router, knows it as a router, declares a subscriber the router sees,
/// receives what the router pushes on the key only when the program steps it, and publishes what
/// the router receives. The CONTROL is the push before any step: nothing is delivered between
/// two calls.
#[test]
fn a_stepped_client_session_declares_receives_and_publishes() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);
    assert!(
        engine.has_router_peer(),
        "the peer announced itself a router"
    );
    assert_eq!(
        engine.peer_identities(),
        vec![(vec![0xc3; 4], 0)],
        "and its zid"
    );

    let received = Arc::new(AtomicUsize::new(0));
    let count = received.clone();
    let declares_before = router.seen(|s| s.declares);
    engine.declare_subscriber_on_wire(
        "demo/**".to_owned(),
        WireKey::literal(),
        Locality::Any,
        None,
        Arc::new(move || {
            let count = count.clone();
            Box::new(move |sample: &dyn SampleView| {
                assert_eq!(sample.payload(), b"hello");
                count.fetch_add(1, Ordering::SeqCst);
            })
        }),
    );
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });

    router.send(Command::Push("demo/a", b"hello"));
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        received.load(Ordering::SeqCst),
        0,
        "CONTROL: nothing is delivered while the program does not step the session"
    );
    until(&engine, "the push", || received.load(Ordering::SeqCst) == 1);

    engine
        .publish_on_wire_all(
            "demo/b",
            &WireKey::literal(),
            b"world",
            &PublishOptions::put(),
        )
        .expect("a put the link carries");
    until(&engine, "the router to receive the put", || {
        router.seen(|s| {
            s.samples
                .iter()
                .any(|(k, v)| k == "demo/b" && v == b"world")
        })
    });
}

/// A write filter asks the router who subscribes and suppresses until a subscriber is declared,
/// then lets a put through; a session that is closed answers every step as closed. The router
/// holds no subscriber of its own until the test declares one, so what opens the filter is that
/// declaration alone.
#[test]
fn a_write_filter_suppresses_until_a_subscriber_is_declared() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let filter = engine.declare_write_filter(
        FilterPlane::Subscribers,
        "demo/x".to_owned(),
        &WireKey::literal(),
        Some(InterestForm {
            mapping_id: 0,
            suffix: Some("demo/x".to_owned()),
            aggregate: false,
        }),
        false,
    );
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) > 0
    });
    let params = PublishOptions::put()
        .plain_put_params()
        .expect("a plain put");
    assert_eq!(
        engine.put_plain_filtered(filter, "demo/x", 0, b"v", &params),
        FilteredPut::Suppressed,
        "no subscriber yet: the put is held back"
    );
    for _ in 0..20 {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert_eq!(
        router.seen(|s| s.pushes),
        0,
        "CONTROL: a held-back put never reaches the wire"
    );

    router.send(Command::DeclareSubscriber(1, "demo/**"));
    until(&engine, "the filter to open", || {
        !engine.write_filter_active(filter)
    });
    assert_eq!(
        engine.put_plain_filtered(filter, "demo/x", 0, b"v", &params),
        FilteredPut::Sent(Ok(0)),
    );
    until(&engine, "the router to receive the put", || {
        router.seen(|s| s.pushes) == 1
    });

    SessionDrive::close(&*engine);
    assert!(SessionDrive::is_closed(&*engine));
    assert!(SessionDrive::read(&*engine, false).is_err());
}

/// A session whose router goes away outlives the link: what that router declared goes with it,
/// the session dials again, declares over the new link what it holds, and its subscriber receives
/// as before. The CONTROL is the write filter, which the first router's subscriber opened and
/// which is shut again once that router is gone.
#[test]
fn a_lost_link_is_dialled_again_and_the_session_declares_again() {
    let router = Router::start(CatchAll::None);
    let port = router.port;
    // A short handshake deadline, so an attempt made while no router is there gives way soon.
    let engine = open_with(CoopConfig {
        redial_ms: Some(50),
        open_timeout_ms: 300,
        ..config(&router)
    });
    let received = Arc::new(AtomicUsize::new(0));
    let count = received.clone();
    engine.declare_subscriber_on_wire(
        "demo/**".to_owned(),
        WireKey::literal(),
        Locality::Any,
        None,
        Arc::new(move || {
            let count = count.clone();
            Box::new(move |_: &dyn SampleView| {
                count.fetch_add(1, Ordering::SeqCst);
            })
        }),
    );
    let filter = engine.declare_write_filter(
        FilterPlane::Subscribers,
        "demo/x".to_owned(),
        &WireKey::literal(),
        Some(InterestForm {
            mapping_id: 0,
            suffix: Some("demo/x".to_owned()),
            aggregate: false,
        }),
        false,
    );
    until(
        &engine,
        "the router to see the subscriber and the Interest",
        || router.seen(|s| s.declares >= 1 && s.interests >= 1),
    );
    router.send(Command::DeclareSubscriber(1, "demo/**"));
    until(&engine, "the filter to open", || {
        !engine.write_filter_active(filter)
    });

    router.send(Command::Close);
    drop(router);
    until(&engine, "the link to be lost", || {
        engine.peer_identities().is_empty()
    });
    assert!(
        !SessionDrive::is_closed(&*engine),
        "the session outlives its link"
    );
    assert!(
        engine.write_filter_active(filter),
        "CONTROL: the lost router's subscriber went with its link"
    );

    let router = Router::start_on(port, CatchAll::None);
    until(&engine, "the session to declare again", || {
        router.seen(|s| s.declares >= 1 && s.interests >= 1)
    });
    assert_eq!(engine.peer_identities(), vec![(vec![0xc3; 4], 0)]);
    router.send(Command::Push("demo/a", b"again"));
    until(&engine, "the push over the new link", || {
        received.load(Ordering::SeqCst) == 1
    });
}

/// A session keeps its lease while the program steps it: over three of its own leases with
/// nothing published, the router keeps it and still reaches its subscriber. A session that sent
/// no keep-alive would be expired by the router after one lease.
#[test]
fn a_stepped_session_keeps_its_lease() {
    let router = Router::start(CatchAll::None);
    let lease_ms = 600;
    let engine = open_with(CoopConfig {
        lease_ms,
        ..config(&router)
    });
    let received = Arc::new(AtomicUsize::new(0));
    let count = received.clone();
    engine.declare_subscriber_on_wire(
        "demo/**".to_owned(),
        WireKey::literal(),
        Locality::Any,
        None,
        Arc::new(move || {
            let count = count.clone();
            Box::new(move |_: &dyn SampleView| {
                count.fetch_add(1, Ordering::SeqCst);
            })
        }),
    );
    let quiet = Instant::now() + Duration::from_millis(3 * lease_ms);
    while Instant::now() < quiet {
        SessionDrive::read(&*engine, false).expect("the session stays open");
    }
    assert_eq!(engine.peer_identities(), vec![(vec![0xc3; 4], 0)]);
    router.send(Command::Push("demo/a", b"still"));
    until(&engine, "the push after three leases", || {
        received.load(Ordering::SeqCst) == 1
    });
}

/// How many reads a session makes in `span` with nothing arriving.
fn reads_in(engine: &Engine, span: Duration) -> u32 {
    let end = Instant::now() + span;
    let mut reads = 0;
    while Instant::now() < end {
        let _ = SessionDrive::read(engine, false);
        reads += 1;
    }
    reads
}

/// A read of a quiet session waits on its link, with nothing of the session held, for as long as
/// the config says, and the read task wakes the moment a push arrives. The CONTROL is the count:
/// a read that waited in the link's own loop took one millisecond, so the same span held hundreds
/// of reads, and a read task woke a thousand times a second.
#[test]
fn a_quiet_session_waits_on_its_link_and_wakes_for_a_push() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let reads = reads_in(&engine, Duration::from_millis(600));
    assert!(
        reads <= 8,
        "a quiet read waits up to 100 ms; 600 ms took {reads} reads"
    );

    let arrived = Arc::new(Mutex::new(None));
    let stamp = arrived.clone();
    engine.declare_subscriber_on_wire(
        "demo/**".to_owned(),
        WireKey::literal(),
        Locality::Any,
        None,
        Arc::new(move || {
            let stamp = stamp.clone();
            Box::new(move |_: &dyn SampleView| {
                stamp.lock().unwrap().get_or_insert(Instant::now());
            })
        }),
    );
    SessionDrive::start_read_task(&*engine).expect("a read task");
    // The read task's first wait is under way before the push is sent.
    std::thread::sleep(Duration::from_millis(250));
    let sent = Instant::now();
    router.send(Command::Push("demo/a", b"now"));
    let deadline = sent + Duration::from_secs(5);
    let at = loop {
        if let Some(at) = *arrived.lock().unwrap() {
            break at;
        }
        assert!(Instant::now() < deadline, "the push never arrived");
        std::thread::sleep(Duration::from_millis(1));
    };
    let took = at.duration_since(sent);
    assert!(
        took < Duration::from_millis(60),
        "a waiting read task wakes for the push, not at the end of its wait: {took:?}"
    );
    SessionDrive::close(&*engine);
}

/// A session waiting to dial again sleeps until the dial is due, at most the idle wait at a
/// time, instead of stepping a session that has no link.
#[test]
fn a_session_waiting_to_dial_again_sleeps() {
    let router = Router::start(CatchAll::None);
    let engine = open_with(CoopConfig {
        redial_ms: Some(10_000),
        open_timeout_ms: 100,
        ..config(&router)
    });
    router.send(Command::Close);
    drop(router);
    until(&engine, "the link to be lost", || {
        engine.peer_identities().is_empty()
    });
    // The dial made at the loss fails within its handshake deadline; the next is ten seconds
    // away.
    let _ = reads_in(&engine, Duration::from_millis(300));
    let reads = reads_in(&engine, Duration::from_millis(600));
    assert!(
        reads <= 8,
        "a session waiting to dial sleeps up to 100 ms at a time; 600 ms took {reads} reads"
    );
    assert!(!SessionDrive::is_closed(&*engine));
}

/// A session that redials none ends with its link, and reads as closed from then on.
#[test]
fn a_session_that_redials_none_ends_with_its_link() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    router.send(Command::Close);
    drop(router);
    until(&engine, "the session to end", || {
        SessionDrive::is_closed(&*engine)
    });
    assert!(SessionDrive::read(&*engine, false).is_err());
}
