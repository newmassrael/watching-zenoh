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
#[cfg(feature = "query")]
use wz_session_core::query_sink::{BoxedQuerySink, QueryView, ReplyOut};
use wz_session_core::session_init_params::{
    KeepAliveConf, LinkRxConf, SessionInitParams, TxQueueConf,
};
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::sink::{BoxedSink, SampleView};
use wz_session_core::WhatAmI;
use wz_session_mcu::app_layer::dispatch_to;

use crate::{CoopConfig, CoopEngine};

const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

/// The identity of the advanced publisher the router stands in for, and the key its cache and its
/// liveliness token share (`<base>/@adv/pub/<zid in hex>/<eid>/_`).
#[cfg(feature = "query")]
const ADVANCED_PUBLISHER_ZID: [u8; 1] = [0x02];
#[cfg(feature = "query")]
const ADVANCED_PUBLISHER_EID: u32 = 7;
#[cfg(feature = "query")]
const ADVANCED_PUBLISHER_KEY: &str = "demo/data/@adv/pub/2/7/_";

type Engine = CoopEngine<PosixLinks, PosixClock>;

fn params(whatami: WhatAmI, zid: u8) -> SessionInitParams {
    SessionInitParams {
        whatami,
        zid: vec![zid; 4],
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 1024,
        lease_ms: 10_000,
        keep_alive: KeepAliveConf::PICO,
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
    /// Declare queryable `.0` on the key, complete as `.2` says. Declared only: it answers
    /// nothing, which is all a test of what matches needs.
    DeclareQueryable(u64, &'static str, bool),
    UndeclareQueryable(u64),
    Push(&'static str, &'static [u8]),
    /// Close the session and stop, as a router that goes away does.
    Close,
    /// Ask a query of request id `.0` on the key.
    #[cfg(feature = "queryable")]
    Query(u64, &'static str),
    /// Hold a queryable on the key that answers each query with the payload, on the query's key.
    #[cfg(feature = "query")]
    Answer(&'static str, &'static [u8]),
    /// Answer no query from now on, as a peer gone quiet: a frame that carries one is dropped.
    #[cfg(feature = "query")]
    Silence,
    /// Answer no Interest from now on, as a peer gone quiet: a frame that carries one is dropped
    /// (after it is counted).
    #[cfg(feature = "liveliness-get")]
    MuteInterests,
    /// Hold token `.0` on the key and announce it.
    #[cfg(feature = "liveliness")]
    DeclareToken(u64, &'static str),
    /// Retract token `.0`.
    #[cfg(feature = "liveliness")]
    UndeclareToken(u64),
    /// Hold token `.0` on the key without announcing it: a peer learns it only by asking for the
    /// tokens alive.
    #[cfg(feature = "liveliness")]
    HoldToken(u64, &'static str),
    /// Push `.1` on the key as the advanced publisher of identity `(zid 2, eid 7)` would, with
    /// sequence number `.2`.
    #[cfg(feature = "query")]
    PushSequenced(&'static str, &'static [u8], u32),
    /// Hold the cache of that advanced publisher: a queryable on its `@adv` key that answers as
    /// the publisher's own cache does, out of the samples with the sequence numbers `.0`, each
    /// carrying its number as its payload. The selectors it is asked are recorded.
    #[cfg(feature = "query")]
    HoldCache(&'static [u8]),
}

/// What reached the router.
#[derive(Default)]
struct Seen {
    declares: usize,
    interests: usize,
    pushes: usize,
    /// What the router's catch-all subscriber received, when it holds one.
    samples: Vec<(String, Vec<u8>)>,
    /// The answers to the router's queries, in the order they arrived: `reply` for a Response,
    /// `final` for a ResponseFinal.
    #[cfg(feature = "queryable")]
    answers: Vec<&'static str>,
    /// The queries the session asked.
    #[cfg(feature = "query")]
    queries: usize,
    /// The parameters of each query the held cache was asked, in the order they arrived.
    #[cfg(feature = "query")]
    selectors: Vec<String>,
    /// Whether the router has done what the test told it about queries: holds the queryable it
    /// was told to, or has gone quiet.
    #[cfg(feature = "query")]
    settled: bool,
    /// The tokens the session holds, by the id it announced them under.
    #[cfg(feature = "liveliness")]
    tokens: Vec<(u64, String)>,
    /// How many tokens the router has been told to hold, once each is registered, so a test that
    /// asks right after is not answered before the router holds what it asked about.
    #[cfg(feature = "liveliness")]
    held: usize,
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
    #[cfg(feature = "liveliness")]
    let holding = observer.clone();
    #[cfg(feature = "liveliness")]
    let holds = seen.clone();
    #[cfg(feature = "liveliness-get")]
    let muted = std::rc::Rc::new(std::cell::Cell::new(false));
    #[cfg(feature = "liveliness-get")]
    let muting = muted.clone();
    #[cfg(feature = "liveliness")]
    {
        let declared = seen.clone();
        let undeclared = seen.clone();
        let mut observer = observer.borrow_mut();
        observer.liveliness.on_token_declared(move |token| {
            declared
                .lock()
                .unwrap()
                .tokens
                .push((token.id(), token.keyexpr().to_owned()));
        });
        observer.liveliness.on_token_undeclared(move |id| {
            undeclared.lock().unwrap().tokens.retain(|(t, _)| *t != id);
        });
    }
    #[cfg(feature = "query")]
    let answering = observer.clone();
    #[cfg(feature = "query")]
    let silent = std::rc::Rc::new(std::cell::Cell::new(false));
    #[cfg(feature = "query")]
    let silenced = silent.clone();
    #[cfg(feature = "query")]
    let counted_queries = seen.clone();
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
                        #[cfg(feature = "queryable")]
                        NetworkMessage::Response(_) => seen.answers.push("reply"),
                        #[cfg(feature = "queryable")]
                        NetworkMessage::ResponseFinal(_) => seen.answers.push("final"),
                        #[cfg(feature = "query")]
                        NetworkMessage::Request(_) => seen.queries += 1,
                        _ => {}
                    }
                }
                #[cfg(feature = "query")]
                if silenced.get()
                    && messages
                        .iter()
                        .any(|m| matches!(m, NetworkMessage::Request(_)))
                {
                    return;
                }
                #[cfg(feature = "liveliness-get")]
                if muted.get()
                    && messages
                        .iter()
                        .any(|m| matches!(m, NetworkMessage::Interest(_)))
                {
                    return;
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
            Ok(Command::DeclareQueryable(id, key, complete)) => {
                let _ = actions.send_declare_queryable(id, 0, Some(key), complete);
            }
            Ok(Command::UndeclareQueryable(id)) => {
                actions.send_undeclare_queryable(id);
            }
            #[cfg(feature = "liveliness-get")]
            Ok(Command::MuteInterests) => {
                muting.set(true);
                counted_queries.lock().unwrap().settled = true;
            }
            #[cfg(feature = "liveliness")]
            Ok(Command::DeclareToken(id, key)) => {
                let _ = holding.borrow_mut().local_tokens.register(id, key);
                let _ = actions.send_declare_token(id, 0, Some(key));
            }
            #[cfg(feature = "liveliness")]
            Ok(Command::UndeclareToken(id)) => {
                holding.borrow_mut().local_tokens.unregister(id);
                actions.send_undeclare_token(id);
            }
            #[cfg(feature = "liveliness")]
            Ok(Command::HoldToken(id, key)) => {
                let _ = holding.borrow_mut().local_tokens.register(id, key);
                holds.lock().unwrap().held += 1;
            }
            Ok(Command::Push(key, value)) => {
                let _ = actions.send_push_literal(key, value, true);
            }
            Ok(Command::Close) => {
                actions.send_close_with_reason(CloseReason::Generic);
                local.run_until_idle();
                return;
            }
            #[cfg(feature = "queryable")]
            Ok(Command::Query(rid, key)) => {
                let _ = actions.send_request_query(rid, 0, Some(key));
            }
            #[cfg(feature = "query")]
            Ok(Command::Answer(key, value)) => {
                answering
                    .borrow_mut()
                    .queryables
                    .register_sink(
                        key,
                        Locality::Any,
                        false,
                        BoxedQuerySink::new(
                            move |query: &dyn QueryView, out: &mut dyn ReplyOut| {
                                let _ = out.reply_keyed(query.keyexpr(), value);
                            },
                        ),
                    )
                    .expect("the router's queryable");
                counted_queries.lock().unwrap().settled = true;
            }
            #[cfg(feature = "query")]
            Ok(Command::Silence) => {
                silent.set(true);
                counted_queries.lock().unwrap().settled = true;
            }
            #[cfg(feature = "query")]
            Ok(Command::PushSequenced(key, value, sn)) => {
                let meta = wz_session_core::metadata::PushMetadata {
                    source_info: Some(wz_session_core::sample::SourceInfo::new(
                        &ADVANCED_PUBLISHER_ZID,
                        ADVANCED_PUBLISHER_EID,
                        sn,
                    )),
                    ..Default::default()
                };
                let _ = actions.send_push_with_meta_literal(key, value, true, &meta);
            }
            #[cfg(feature = "query")]
            Ok(Command::HoldCache(sns)) => {
                use wz_ext_pubsub::advanced_cache::{CacheConfig, CacheStore, CachedSample};
                use wz_session_core::sample::{SampleKind, SourceInfo, TimestampHint};
                // The ring holds every sample it is given: the default depth is one, and a cache
                // of one answers a range with its last sample alone.
                let store = CacheStore::new(CacheConfig {
                    max_samples: sns.len().max(1),
                    ..CacheConfig::default()
                });
                for &sn in sns {
                    store.cache_sample(CachedSample::new(
                        "demo/data",
                        vec![sn],
                        Some(SourceInfo::new(
                            &ADVANCED_PUBLISHER_ZID,
                            ADVANCED_PUBLISHER_EID,
                            u32::from(sn),
                        )),
                        TimestampHint {
                            time: 100 + u64::from(sn),
                            zid: ADVANCED_PUBLISHER_ZID.to_vec(),
                        },
                        SampleKind::Put,
                    ));
                }
                let mut cache = store.query_handler(|| 0);
                let asked = counted_queries.clone();
                answering
                    .borrow_mut()
                    .queryables
                    .register_sink(
                        ADVANCED_PUBLISHER_KEY,
                        Locality::Any,
                        false,
                        BoxedQuerySink::new(
                            move |query: &dyn QueryView, out: &mut dyn ReplyOut| {
                                asked.lock().unwrap().selectors.push(
                                    String::from_utf8_lossy(query.parameters().unwrap_or(&[]))
                                        .into_owned(),
                                );
                                cache(query, out);
                            },
                        ),
                    )
                    .expect("the router's cache");
                counted_queries.lock().unwrap().settled = true;
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
        keep_alive: KeepAliveConf::PICO,
        sn_resolution: wz_session_core::policy::SnResolution::default(),
        link_rx: LinkRxConf::default(),
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
            // For peers only: with `local-subscriber` the session's own subscriber (the one above,
            // which expects what the router pushed) would be handed it too.
            &PublishOptions::put().with_locality(Locality::Remote),
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

/// A matching listener records each verdict it is told.
fn heard() -> (wz_capi_port::MatchingSink, Arc<Mutex<Vec<bool>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let into = log.clone();
    (
        Arc::new(move |matching| into.lock().unwrap().push(matching)),
        log,
    )
}

/// A matching listener on the queryables counts what a querier's write filter on the same plane
/// counts: any queryable on the key, or only a complete one when the plane requires it, as
/// zenoh-pico's listener is that filter's callback. The CONTROL is a subscriber on the key, which
/// the router declares first and which opens a subscriber filter while neither listener hears it.
#[test]
fn a_queryable_matching_listener_counts_what_its_filter_counts() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let ask = || {
        Some(InterestForm {
            mapping_id: 0,
            suffix: Some("demo/q".to_owned()),
            aggregate: false,
        })
    };
    let any_plane = FilterPlane::Queryables {
        complete_required: false,
    };
    let complete_plane = FilterPlane::Queryables {
        complete_required: true,
    };
    let (sink, any) = heard();
    let any_id = engine.declare_matching_listener(any_plane, "demo/q".to_owned(), sink, false);
    let (sink, complete) = heard();
    engine.declare_matching_listener(complete_plane, "demo/q".to_owned(), sink, false);
    let complete_filter = engine.declare_write_filter(
        complete_plane,
        "demo/q".to_owned(),
        &WireKey::literal(),
        ask(),
        false,
    );
    let subscriber_filter = engine.declare_write_filter(
        FilterPlane::Subscribers,
        "demo/q".to_owned(),
        &WireKey::literal(),
        ask(),
        false,
    );
    until(&engine, "the router to see the Interests", || {
        router.seen(|s| s.interests) >= 2
    });

    router.send(Command::DeclareSubscriber(1, "demo/**"));
    until(&engine, "the subscriber filter to open", || {
        !engine.write_filter_active(subscriber_filter)
    });
    assert!(
        any.lock().unwrap().is_empty() && complete.lock().unwrap().is_empty(),
        "CONTROL: a subscriber is no queryable"
    );

    router.send(Command::DeclareQueryable(2, "demo/**", false));
    until(&engine, "the listener on any queryable to match", || {
        *any.lock().unwrap() == [true]
    });
    assert!(
        complete.lock().unwrap().is_empty(),
        "a queryable that is not complete matches no complete listener"
    );
    assert!(
        engine.write_filter_active(complete_filter),
        "nor the filter the listener counts with"
    );

    router.send(Command::DeclareQueryable(3, "demo/q", true));
    until(&engine, "the complete listener to match", || {
        *complete.lock().unwrap() == [true]
    });
    assert!(!engine.write_filter_active(complete_filter));

    router.send(Command::UndeclareQueryable(3));
    until(&engine, "the complete listener to match no more", || {
        *complete.lock().unwrap() == [true, false]
    });
    assert!(engine.write_filter_active(complete_filter));
    assert_eq!(
        *any.lock().unwrap(),
        [true],
        "the queryable that is not complete still matches"
    );

    // A retracted listener hears nothing more, while the other is told.
    engine.undeclare_matching_listener(any_id);
    router.send(Command::DeclareQueryable(4, "demo/q", true));
    until(&engine, "the complete listener to match again", || {
        *complete.lock().unwrap() == [true, false, true]
    });
    router.send(Command::UndeclareQueryable(2));
    router.send(Command::UndeclareQueryable(4));
    until(&engine, "the complete listener to match no more", || {
        complete.lock().unwrap().len() == 4
    });
    assert_eq!(*any.lock().unwrap(), [true]);
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

#[cfg(all(feature = "ticker", feature = "query", feature = "liveliness"))]
mod advanced;
#[cfg(feature = "connectivity")]
mod faces;
#[cfg(feature = "query")]
mod get;
#[cfg(feature = "liveliness")]
mod liveliness;
#[cfg(feature = "local-subscriber")]
mod local;
#[cfg(feature = "local-queryable")]
mod local_query;
#[cfg(feature = "queryable")]
mod queryable;
mod replay;
#[cfg(feature = "liveliness-get")]
mod snapshot;
#[cfg(feature = "ticker")]
mod ticker;
