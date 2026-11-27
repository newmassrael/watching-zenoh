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

use crate::EngineHold;
use wz_capi_port::{
    FilterPlane, FilteredPut, PeerLists, SessionDrive, SessionEngine, SubscriberSink, WireKey,
};
#[cfg(feature = "listen")]
use wz_runtime_coop::session_drive::Locator;
use wz_runtime_coop::session_drive::{
    spawn_session, OpenedLink, SessionDriveConfig, SessionLinks, SessionRole,
};
use wz_runtime_coop::session_runtime::new_session_actions;
use wz_runtime_coop::{CoopLocalSet, CoopRuntime, CoopTime};
use wz_runtime_posix::stream::PosixTcpDial;
use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::close_reason::CloseReason;
use wz_session_core::declare_form::InterestAsk;
use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
use wz_session_core::locality::Locality;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::observer::ApplicationLayerObserver;
use wz_session_core::publish_options::PublishOptions;
#[cfg(feature = "query")]
use wz_session_core::query_sink::{BoxedQuerySink, QueryView, ReplyOut};
use wz_session_core::session_init_params::{
    KeepAliveConf, LinkRxConf, SessionInitParams, SessionZid, TxQueueConf,
};
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::sink::{BoxedSink, SampleView};
use wz_session_core::WhatAmI;
use wz_session_mcu::app_layer::dispatch_to;

use crate::{CoopConfig, CoopEngine};

/// The host's links an engine opens over: counted as its sessions count the parts of a link
/// ([`crate::LinkCount`]), and waited for by their owner, as [`host_links`] made
/// `waited_by_owner` are.
pub(crate) type PosixLinks =
    <wz_runtime_posix::links::PosixLinks<crate::LinkCount> as crate::ComposedLinks>::WaitedByOwner;

/// The host's links bound on `local`, whose `tcp/` dial is `dial`, counted as the engine's
/// sessions count a link's parts.
pub(crate) fn host_links(
    local: impl Into<std::net::IpAddr>,
    dial: PosixTcpDial,
) -> wz_runtime_posix::links::PosixLinks<crate::LinkCount> {
    wz_runtime_posix::links::PosixLinks::new(local, dial).counted_by::<crate::LinkCount>()
}

/// The program's transport as the engine's links, counted as its sessions count a link's parts.
#[cfg(feature = "app-transport")]
pub(crate) type AppLinks = crate::app_link::AppLinks<crate::LinkCount>;

/// The links over `transport`, counted as the engine's sessions count a link's parts.
#[cfg(feature = "app-transport")]
pub(crate) fn app_links(transport: wz_session_core::app_transport::SessionTransport) -> AppLinks {
    crate::app_link::AppLinks::new(transport).counted_by::<crate::LinkCount>()
}

const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

/// The identity of the advanced publisher the router stands in for, and the key its cache and its
/// liveliness token share (`<base>/@adv/pub/<zid in hex>/<eid>/_`).
#[cfg(all(feature = "ticker", feature = "query", feature = "liveliness"))]
const ADVANCED_PUBLISHER_ZID: [u8; 1] = [0x02];
#[cfg(all(feature = "ticker", feature = "query", feature = "liveliness"))]
const ADVANCED_PUBLISHER_EID: u32 = 7;
#[cfg(all(feature = "ticker", feature = "query", feature = "liveliness"))]
const ADVANCED_PUBLISHER_KEY: &str = "demo/data/@adv/pub/2/7/_";

type Engine = CoopEngine<PosixLinks, PosixClock>;

pub(crate) fn params(whatami: WhatAmI, zid: u8) -> SessionInitParams {
    SessionInitParams {
        whatami,
        zid: [zid; 4].into(),
        seq_num_res: wz_session_core::policy::SnResolution::Bits32,
        req_id_res: 2,
        batch_size: 1024,
        lease_ms: 10_000,
        keep_alive: KeepAliveConf::PICO,
        initial_sn: 0,
        cookie: vec![],
        tx_queue: TxQueueConf::of_snapshot(
            &wz_session_core::policy::SessionPolicy::defaults(),
            &wz_session_core::limits::SessionLimits::BUILD,
        ),
        link_rx: LinkRxConf::default(),
        policy: wz_session_core::policy::SessionPolicy::defaults(),
        limits: wz_session_core::limits::SessionLimits::BUILD,
        cookie_signing_key: SigningKey::new(vec![7u8; 32]).expect("key").into(),
        region: None,
    }
}

/// What the test tells the router to do.
enum Command {
    DeclareSubscriber(wz_session_core::wire_id::EntityId, &'static str),
    /// Declare queryable `.0` on the key, complete as `.2` says. Declared only: it answers
    /// nothing, which is all a test of what matches needs. Only the builds whose tests watch or
    /// match a peer's queryables send it: a key's matching listener, the faces' table of a listener
    /// with local queryables, a declaration watch of the queryables.
    #[cfg(any(
        feature = "key-matching-listener",
        all(
            feature = "listen",
            feature = "query",
            feature = "queryable",
            feature = "local-queryable"
        ),
        all(
            any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ),
            any(feature = "query", feature = "queryable")
        )
    ))]
    DeclareQueryable(wz_session_core::wire_id::EntityId, &'static str, bool),
    #[cfg(any(
        feature = "key-matching-listener",
        all(
            feature = "listen",
            feature = "query",
            feature = "queryable",
            feature = "local-queryable"
        ),
        all(
            any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ),
            any(feature = "query", feature = "queryable")
        )
    ))]
    UndeclareQueryable(u64),
    Push(&'static str, &'static [u8]),
    /// Push `.1` samples on the key in one batch window, so that one frame carries them all; the
    /// payload of each is its index.
    PushBatch(&'static str, u8),
    /// [`Command::Push`] stamped with a time by the router.
    PushStamped(&'static str, &'static [u8]),
    /// Push `.1` naming id `.0` in the RECEIVER's space, as a zenoh router does for a subscriber it
    /// routes to once the subscriber has declared a key expression to it: the id is one the
    /// session under test declared, and the key is what that declaration says.
    PushReceiverAlias(wz_session_core::wire_id::ExprId, &'static [u8]),
    /// Declare the key `.1` under id `.0` in the router's own space, as a peer that names its
    /// keys by alias does.
    DeclareKeyexpr(wz_session_core::wire_id::ExprId, &'static str),
    /// In one batch window, so that one frame carries all three: push `.1` naming id `.0` of the
    /// router's space with no suffix, undeclare the id, and push `.1` on it again, which the
    /// receiver can no longer resolve.
    PushAliasThenUndeclare(wz_session_core::wire_id::ExprId, &'static [u8]),
    /// In one batch window, so that one frame carries both: push `.2` on the key `.1`, then
    /// retract subscriber `.0` of the router's.
    PushThenUndeclareSubscriber(u64, &'static str, &'static [u8]),
    /// In one batch window: declare the key `.1` under id `.0` of the router's space, push `.2`
    /// naming the id, send a KeepAlive and push `.3` naming the id again. The KeepAlive drains the
    /// open batch before it, so the declaration and the first Push share a frame and the second
    /// Push follows the KeepAlive.
    DeclarePushKeepAlivePush(
        wz_session_core::wire_id::ExprId,
        &'static str,
        &'static [u8],
        &'static [u8],
    ),
    /// Declare each subscriber `.0` names, id and key, in one batch window, so that one frame
    /// carries them all.
    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    DeclareSubscriberBatch(&'static [(wz_session_core::wire_id::EntityId, &'static str)]),
    /// Send the final of the initial declarations, as a peer does once it has declared what it
    /// held when the link came up.
    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    FinishInitial,
    /// Close the session and stop, as a router that goes away does.
    Close,
    /// Ask a query of request id `.0` on the key.
    #[cfg(feature = "queryable")]
    Query(wz_session_core::wire_id::RequestId, &'static str),
    /// In one batch window, so that one frame carries all three: push on the key `.0`, ask a
    /// query of request id `.1` on the key `.2`, and push on `.0` again.
    #[cfg(feature = "queryable")]
    QueryBetweenPushes(
        &'static str,
        wz_session_core::wire_id::RequestId,
        &'static str,
    ),
    /// Ask a query of request id `.0` naming its key by id `.1` in the sender's space and the
    /// rest `.2`, which no declaration precedes: an id of the key ids both ends share. Sent only
    /// by the shared key ids' tests (`tests::shared_key_ids`), and compiled where they are.
    #[cfg(all(
        feature = "queryable",
        feature = "shared-key-ids",
        feature = "listen",
        feature = "query",
        feature = "threads"
    ))]
    QueryById(
        wz_session_core::wire_id::RequestId,
        wz_session_core::wire_id::ExprId,
        &'static str,
    ),
    /// Hold a queryable on the key that answers each query with the payload, on the query's key.
    #[cfg(feature = "query")]
    Answer(&'static str, &'static [u8]),
    /// [`Command::Answer`] with each reply stamped by the router's clock.
    #[cfg(feature = "query")]
    AnswerStamped(&'static str, &'static [u8]),
    /// Hold a queryable on the key `.0` that answers each query once on each of the keys `.1`,
    /// each with the payload `.2`, as a get on a wildcard is answered by a key of each.
    #[cfg(feature = "query")]
    AnswerOnKeys(&'static str, &'static [&'static str], &'static [u8]),
    /// Answer no query from now on, as a peer gone quiet: a frame that carries one is dropped.
    #[cfg(feature = "query")]
    Silence,
    /// Answer no Interest from now on, as a peer gone quiet: a frame that carries one is dropped
    /// (after it is counted).
    #[cfg(feature = "liveliness-get")]
    MuteInterests,
    /// Hold token `.0` on the key and announce it.
    #[cfg(feature = "liveliness")]
    DeclareToken(wz_session_core::wire_id::EntityId, &'static str),
    /// Retract token `.0`.
    #[cfg(feature = "liveliness")]
    UndeclareToken(u64),
    /// Hold token `.0` on the key without announcing it: a peer learns it only by asking for the
    /// tokens alive.
    #[cfg(feature = "liveliness")]
    HoldToken(u64, &'static str),
    /// Push `.1` on the key as the advanced publisher of identity `(zid 2, eid 7)` would, with
    /// sequence number `.2`.
    #[cfg(all(feature = "ticker", feature = "query", feature = "liveliness"))]
    PushSequenced(&'static str, &'static [u8], u32),
    /// Ask the session, as Interest `.0`, for its subscribers on the key, those it holds now and
    /// those it declares later.
    #[cfg(any(feature = "interest-answer", feature = "listen"))]
    AskSubscribers(u64, &'static str),
    /// Hold the cache of that advanced publisher: a queryable on its `@adv` key that answers as
    /// the publisher's own cache does, out of the samples with the sequence numbers `.0`, each
    /// carrying its number as its payload. The selectors it is asked are recorded.
    #[cfg(all(feature = "ticker", feature = "query", feature = "liveliness"))]
    HoldCache(&'static [u8]),
}

/// What reached the router.
#[derive(Default)]
struct Seen {
    declares: usize,
    /// The id of each subscriber the router was declared, in the order the declarations arrived.
    subscribers: Vec<u64>,
    /// The place among the declarations of each `DeclareFinal` of the initial interest the router
    /// was told: the count of declarations that had arrived with it, itself included.
    initial_finals: Vec<usize>,
    /// The id of each subscriber the router was told went, in the order the retractions arrived
    /// (the direct read's tests read it).
    #[cfg(not(wz_round))]
    undeclared_subscribers: Vec<u64>,
    interests: usize,
    /// The Interest each subscriber declaration that answers one names, in the order they arrived.
    #[cfg(any(feature = "interest-answer", feature = "listen"))]
    subscriber_answers: Vec<u64>,
    /// The Interest each declaration Final names, in the order they arrived.
    #[cfg(any(feature = "interest-answer", feature = "listen"))]
    interest_finals: Vec<u64>,
    pushes: usize,
    /// What the router's catch-all subscriber received, when it holds one.
    samples: Vec<(String, Vec<u8>)>,
    /// The answers to the router's queries, in the order they arrived: `reply` for a Response,
    /// `final` for a ResponseFinal.
    #[cfg(feature = "queryable")]
    answers: Vec<&'static str>,
    /// How each Response named its key on the wire: its id, the rest after it and the mapping bit
    /// (`true` is the sender's space).
    #[cfg(all(feature = "queryable", feature = "shared-key-ids"))]
    reply_keys: Vec<(wz_session_core::wire_id::ExprId, Option<String>, bool)>,
    /// How each Interest that names a key named it on the wire: its id and the rest after it, in
    /// the order the Interests arrived (the key tests' module reads it).
    #[cfg(all(
        feature = "shared-key-ids",
        feature = "listen",
        feature = "query",
        feature = "queryable"
    ))]
    interest_keys: Vec<(wz_session_core::wire_id::ExprId, Option<String>)>,
    /// The queries the session asked.
    #[cfg(feature = "query")]
    queries: usize,
    /// The parameters of each query the held cache was asked, in the order they arrived.
    #[cfg(all(feature = "ticker", feature = "query", feature = "liveliness"))]
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

/// The zid every router stand-in has unless a test gives it another: a session holds one face for
/// each zid, so a test that holds two routers at once gives them two (`Router::start_as`).
const ROUTER_ZID: u8 = 0xc3;

struct Router {
    port: u16,
    commands: std::sync::mpsc::Sender<Command>,
    seen: Arc<Mutex<Seen>>,
    thread: Option<JoinHandle<()>>,
}

impl Router {
    /// A stand-in that accepts on a free port. Its acceptor arms its accept window
    /// (`SessionTimeouts::accepting_inactivity_ms`, one second) when it starts and closes silently
    /// once the window passes with no handshake, so a test dials it as soon as it starts it.
    fn start(catch_all: CatchAll) -> Self {
        Self::start_as(ROUTER_ZID, catch_all)
    }

    /// A router that is the node `zid` (four bytes of it).
    fn start_as(zid: u8, catch_all: CatchAll) -> Self {
        Self::start_on_as(router_port(), zid, catch_all)
    }

    /// A router on `port`, which a router before it may have held.
    fn start_on(port: u16, catch_all: CatchAll) -> Self {
        Self::start_on_as(port, ROUTER_ZID, catch_all)
    }

    fn start_on_as(port: u16, zid: u8, catch_all: CatchAll) -> Self {
        Self::start_announcing(port, zid, WhatAmI::Router, catch_all)
    }

    /// A stand-in that announces itself a peer, on a free port: a session holding the shared
    /// key ids names its keys to a peer by them, and to a router by its declarations. Compiled where
    /// its readers, the shared key ids' tests (`tests::shared_key_ids`), are.
    #[cfg(all(
        feature = "queryable",
        feature = "shared-key-ids",
        feature = "listen",
        feature = "query",
        feature = "threads"
    ))]
    fn start_peer() -> Self {
        Self::start_announcing(router_port(), ROUTER_ZID, WhatAmI::Peer, CatchAll::None)
    }

    /// A stand-in that announces itself as `whatami`: a peer is told what a router is not (the
    /// key form of the shared key ids, whose rule sends a router the declared form).
    fn start_announcing(port: u16, zid: u8, whatami: WhatAmI, catch_all: CatchAll) -> Self {
        Self::start_at(StandInEnd::Accepts(port), port, (zid, whatami), catch_all)
    }

    /// A stand-in that announces itself as `whatami` and dials, over TCP, the session that
    /// listens at `to`: what that session tells a face it took off its port is what it reports.
    #[cfg(feature = "listen")]
    fn dial_announcing(to: std::net::SocketAddr, whatami: WhatAmI) -> Self {
        Self::start_at(
            StandInEnd::Dials(to),
            to.port(),
            (ROUTER_ZID, whatami),
            CatchAll::None,
        )
    }

    /// A stand-in at `end` of its link, the node `zid` announcing itself as `whatami`, whose
    /// port, the one it accepts on or the one it dials, is `port`.
    fn start_at(
        end: StandInEnd,
        port: u16,
        (zid, whatami): (u8, WhatAmI),
        catch_all: CatchAll,
    ) -> Self {
        let (commands, inbox) = channel();
        let (ready, bound) = channel();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let reported = seen.clone();
        let thread = std::thread::spawn(move || {
            run_router(end, (zid, whatami), catch_all, inbox, reported, ready)
        });
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

/// The lowest port the host gives a bind of port 0: Linux states its range
/// (`ip_local_port_range`), and the other hosts these tests run on start theirs at the dynamic
/// range.
fn ephemeral_floor() -> u16 {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|range| range.split_whitespace().next()?.parse().ok())
        .unwrap_or(49_152)
}

/// A free port for a router stand-in, below the ports the host gives a bind of port 0: a test
/// lets the stand-in go and starts one again on its port, and in between no socket another test
/// binds on port 0 can be given it, as it could a port the host handed out. Within the process
/// each port is handed once (a counter from an offset of the process's own, so another process
/// starts elsewhere), and a port some socket holds is passed over.
fn router_port() -> u16 {
    use std::sync::atomic::{AtomicU32, Ordering};
    const FLOOR: u32 = 10_000;
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let span = u32::from(ephemeral_floor()).saturating_sub(FLOOR).max(1);
    let offset = std::process::id().wrapping_mul(7_919) % span;
    for _ in 0..span {
        let at = FLOOR + (offset + NEXT.fetch_add(1, Ordering::Relaxed)) % span;
        let port = u16::try_from(at).expect("below the host's ephemeral ports");
        if UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("no free port below the host's ephemeral ports");
}

/// A stand-in's port lies below the ports the host gives a bind of port 0 and is handed once in
/// the process. Turned red by a port the host could give another socket, or one handed twice.
#[test]
fn a_router_port_is_below_the_ephemeral_ports_and_handed_once() {
    let (first, second) = (router_port(), router_port());
    assert!(first < ephemeral_floor() && second < ephemeral_floor());
    assert_ne!(first, second, "each port is handed once");
}

/// How `response` named its key on the wire: its id, the rest and the mapping bit (`true` is the
/// sender's space).
#[cfg(all(feature = "queryable", feature = "shared-key-ids"))]
fn reply_key_of(
    response: &wz_session_core::wire::ResponseOwned,
) -> (wz_session_core::wire_id::ExprId, Option<String>, bool) {
    let body = &response.keyexpr.body;
    let (id, rest) = wz_session_core::wireexpr_resolve::id_and_suffix(body);
    let sender = matches!(
        body,
        wz_session_core::wire::parts::WireexprOwnedVariant::WireexprLocal(_)
    );
    (id, rest.map(str::to_owned), sender)
}

/// The slots the router stand-in's link lends its session. The stand-in is built with the session
/// core the engine under test is built with, so a lend-only build (`tx-lend-only`) gives it the
/// send that has no heap frame to fall back on: a frame with no slot free is not sent, the InitAck
/// included. Two, because the stand-in's session batches and holds one slot open while it encodes
/// into another; a link holds at least the slots its session needs whatever it is given
/// (`SESSION_TX_SLOTS`).
const ROUTER_TX_SLOTS: usize = 2;

/// The host's links of the router stand-in, counted for one task: the stand-in's session runs on
/// a runtime of its own on its own thread, whichever form the engine under test takes, so its
/// link's parts are counted as that runtime's are and not as the engine's.
type RouterLinks = wz_runtime_posix::links::PosixLinks<wz_runtime_coop::link_cells::OneTask>;

/// The host's links the router stand-in accepts on: each lends its session [`ROUTER_TX_SLOTS`]
/// slots of the stand-in's batch, `batch_size` bytes, in every build of the crate.
fn router_links(batch_size: u16) -> RouterLinks {
    RouterLinks::new(LOOPBACK, PosixTcpDial)
        .with_tx_buffers(ROUTER_TX_SLOTS, usize::from(batch_size))
}

/// Which end of its link the stand-in's session is.
#[derive(Clone, Copy)]
enum StandInEnd {
    /// It accepts on this port, which the session under test dials.
    Accepts(u16),
    /// It dials the session under test, which listens at this address, over TCP.
    #[cfg(feature = "listen")]
    Dials(std::net::SocketAddr),
}

fn run_router(
    end: StandInEnd,
    (zid, whatami): (u8, WhatAmI),
    catch_all: CatchAll,
    inbox: Receiver<Command>,
    seen: Arc<Mutex<Seen>>,
    ready: std::sync::mpsc::Sender<()>,
) {
    let init = params(whatami, zid);
    let links = router_links(init.batch_size);
    let (OpenedLink { sink, pump }, role) = match end {
        StandInEnd::Accepts(port) => (
            links.open_acceptor(port).expect("bind the router's end"),
            SessionRole::Acceptor,
        ),
        #[cfg(feature = "listen")]
        StandInEnd::Dials(to) => (
            links
                .open_initiator(Locator::tcp(to))
                .expect("dial the session that listens"),
            SessionRole::Initiator,
        ),
    };
    let _ = ready.send(());
    let runtime = CoopRuntime::try_new(PosixClock).expect("the heap has room");
    let local = CoopLocalSet::try_new(&runtime).expect("the heap has room");
    // An acceptor mints a cookie per InitAck, from the entropy it is handed.
    let actions =
        new_session_actions(sink, init, CoopTime::new(&runtime)).expect("the heap has room");
    let observer = std::rc::Rc::new(std::cell::RefCell::new(ApplicationLayerObserver::new()));
    if catch_all == CatchAll::Held {
        let samples = seen.clone();
        observer
            .borrow_mut()
            .register_subscriber(
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
        observer
            .with_app(|app| {
                app.liveliness.on_token_declared(move |token| {
                    declared
                        .lock()
                        .unwrap()
                        .tokens
                        .push((token.id(), token.keyexpr().to_owned()));
                })
            })
            .expect("no quota is stated on this table");
        observer
            .with_app(|app| {
                app.liveliness.on_token_undeclared(move |id| {
                    undeclared.lock().unwrap().tokens.retain(|(t, _)| *t != id);
                })
            })
            .expect("no quota is stated on this table");
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
        wz_runtime_coop::session_runtime::SessionEntropy::try_new(PosixEntropy)
            .expect("the heap has room"),
        CoopTime::new(&runtime),
        SessionDriveConfig {
            timeouts: SessionTimeouts::spec_defaults(),
            role,
            max_iters: None,
        },
        move |event| {
            if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event {
                let mut seen = counted.lock().unwrap();
                for m in messages {
                    match m {
                        NetworkMessage::Declare(declare) => {
                            seen.declares += 1;
                            match &declare.body {
                                wz_codecs::declare::DeclareOwnedVariant::CodecZenohDeclSubscriber(
                                    subscriber,
                                ) => seen.subscribers.push(subscriber.id),
                                #[cfg(not(wz_round))]
                                wz_codecs::declare::DeclareOwnedVariant::CodecZenohUndeclSubscriber(
                                    gone,
                                ) => seen.undeclared_subscribers.push(gone.id),
                                _ => {}
                            }
                            if declare.interest_id
                                == Some(wz_session_core::extbound::INITIAL_INTEREST_ID)
                                && matches!(
                                    &declare.body,
                                    wz_codecs::declare::DeclareOwnedVariant::CodecZenohDeclFinal(_)
                                )
                            {
                                let at = seen.declares;
                                seen.initial_finals.push(at);
                            }
                            #[cfg(any(feature = "interest-answer", feature = "listen"))]
                            if let Some(interest) = declare.interest_id {
                                use wz_codecs::declare::DeclareOwnedVariant as Body;
                                match &declare.body {
                                    Body::CodecZenohDeclSubscriber(_) => {
                                        seen.subscriber_answers.push(interest);
                                    }
                                    Body::CodecZenohDeclFinal(_) => {
                                        seen.interest_finals.push(interest);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        NetworkMessage::Interest(_interest) => {
                            seen.interests += 1;
                            #[cfg(all(
                                feature = "shared-key-ids",
                                feature = "listen",
                                feature = "query",
                                feature = "queryable"
                            ))]
                            if let Some(keyexpr) = wz_session_core::interest_build::interest_body(
                                &_interest.header_c_or_f,
                            )
                            .and_then(|body| body.keyexpr.as_ref())
                            {
                                let (id, rest) =
                                    wz_session_core::wireexpr_resolve::id_and_suffix(&keyexpr.body);
                                seen.interest_keys.push((id, rest.map(str::to_owned)));
                            }
                        }
                        NetworkMessage::Push(_) => seen.pushes += 1,
                        #[cfg(feature = "queryable")]
                        NetworkMessage::Response(_response) => {
                            seen.answers.push("reply");
                            #[cfg(feature = "shared-key-ids")]
                            seen.reply_keys.push(reply_key_of(_response));
                        }
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
            // The records the router's session reads where their frame lies: a Push, a Request and a
            // Response on every in-place receive, and the control records where the build lends them.
            // Counted as their owned forms are, and dropped on the same rules.
            if let IterationEvent::InPlace(record) = event {
                let mut seen = counted.lock().unwrap();
                if let Some(declare) = record.declare() {
                    seen.declares += 1;
                    match &declare.body {
                        wz_codecs::lent::DeclareVariant::CodecZenohDeclSubscriber(subscriber) => {
                            seen.subscribers.push(subscriber.id);
                        }
                        #[cfg(not(wz_round))]
                        wz_codecs::lent::DeclareVariant::CodecZenohUndeclSubscriber(gone) => {
                            seen.undeclared_subscribers.push(gone.id);
                        }
                        _ => {}
                    }
                    if declare.interest_id == Some(wz_session_core::extbound::INITIAL_INTEREST_ID)
                        && matches!(
                            &declare.body,
                            wz_codecs::lent::DeclareVariant::CodecZenohDeclFinal(_)
                        )
                    {
                        let at = seen.declares;
                        seen.initial_finals.push(at);
                    }
                    #[cfg(any(feature = "interest-answer", feature = "listen"))]
                    if let Some(interest) = declare.interest_id {
                        match &declare.body {
                            wz_codecs::lent::DeclareVariant::CodecZenohDeclSubscriber(_) => {
                                seen.subscriber_answers.push(interest);
                            }
                            wz_codecs::lent::DeclareVariant::CodecZenohDeclFinal(_) => {
                                seen.interest_finals.push(interest);
                            }
                            _ => {}
                        }
                    }
                }
                if let Some(_interest) = record.interest() {
                    seen.interests += 1;
                    #[cfg(all(
                        feature = "shared-key-ids",
                        feature = "listen",
                        feature = "query",
                        feature = "queryable"
                    ))]
                    if let Some(keyexpr) =
                        wz_session_core::interest_build::interest_body(&_interest.header_c_or_f)
                            .and_then(|body| body.keyexpr.as_ref())
                    {
                        let (id, rest) =
                            wz_session_core::wireexpr_resolve::id_and_suffix_view(&keyexpr.body);
                        seen.interest_keys.push((id, rest.map(str::to_owned)));
                    }
                }
                if record.push().is_some() {
                    seen.pushes += 1;
                }
                #[cfg(feature = "queryable")]
                if let Some(_response) = record.response() {
                    seen.answers.push("reply");
                    #[cfg(feature = "shared-key-ids")]
                    {
                        let (id, rest, sender) =
                            wz_session_core::wireexpr_resolve::id_suffix_and_space_viewed(
                                &_response.keyexpr.body,
                            );
                        seen.reply_keys.push((id, rest.map(str::to_owned), sender));
                    }
                }
                #[cfg(feature = "queryable")]
                if record.response_final().is_some() {
                    seen.answers.push("final");
                }
                #[cfg(feature = "query")]
                if record.request().is_some() {
                    seen.queries += 1;
                }
                drop(seen);
                #[cfg(feature = "query")]
                if silenced.get() && record.request().is_some() {
                    return;
                }
                #[cfg(feature = "liveliness-get")]
                if muted.get() && record.interest().is_some() {
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
                let _ = actions.send_declare_subscriber(
                    id,
                    wz_session_core::named_key::NamedKey::literal(key).expect("a key"),
                );
            }
            #[cfg(any(
                feature = "key-matching-listener",
                all(
                    feature = "listen",
                    feature = "query",
                    feature = "queryable",
                    feature = "local-queryable"
                ),
                all(
                    any(
                        feature = "remote-declaration-watch",
                        feature = "declarations-synced-event"
                    ),
                    any(feature = "query", feature = "queryable")
                )
            ))]
            Ok(Command::DeclareQueryable(id, key, complete)) => {
                let _ = actions.send_declare_queryable(
                    id,
                    wz_session_core::named_key::NamedKey::literal(key).expect("a key"),
                    complete,
                );
            }
            #[cfg(any(
                feature = "key-matching-listener",
                all(
                    feature = "listen",
                    feature = "query",
                    feature = "queryable",
                    feature = "local-queryable"
                ),
                all(
                    any(
                        feature = "remote-declaration-watch",
                        feature = "declarations-synced-event"
                    ),
                    any(feature = "query", feature = "queryable")
                )
            ))]
            Ok(Command::UndeclareQueryable(id)) => {
                actions.send_undeclare_queryable(id);
            }
            #[cfg(any(feature = "interest-answer", feature = "listen"))]
            Ok(Command::AskSubscribers(id, key)) => {
                let _ = actions.send_interest_subscribers(id, true, true, 0, Some(key));
            }
            #[cfg(feature = "liveliness-get")]
            Ok(Command::MuteInterests) => {
                muting.set(true);
                counted_queries.lock().unwrap().settled = true;
            }
            #[cfg(feature = "liveliness")]
            Ok(Command::DeclareToken(id, key)) => {
                let _ = holding
                    .borrow_mut()
                    .with_app(|app| app.local_tokens.register(u64::from(id), key));
                let _ = actions.send_declare_token(
                    id,
                    wz_session_core::named_key::NamedKey::literal(key).expect("a key"),
                );
            }
            #[cfg(feature = "liveliness")]
            Ok(Command::UndeclareToken(id)) => {
                holding
                    .borrow_mut()
                    .with_app(|app| app.local_tokens.unregister(id));
                actions.send_undeclare_token(id);
            }
            #[cfg(feature = "liveliness")]
            Ok(Command::HoldToken(id, key)) => {
                let _ = holding
                    .borrow_mut()
                    .with_app(|app| app.local_tokens.register(id, key));
                holds.lock().unwrap().held += 1;
            }
            Ok(Command::Push(key, value)) => {
                let _ = actions.send_push_literal(key, value, true);
            }
            #[cfg(any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ))]
            Ok(Command::DeclareSubscriberBatch(declared)) => {
                let _ = actions.batch_start();
                for &(id, key) in declared {
                    let _ = actions.send_declare_subscriber(
                        id,
                        wz_session_core::named_key::NamedKey::literal(key).expect("a key"),
                    );
                }
                let _ = actions.batch_stop();
            }
            Ok(Command::PushBatch(key, count)) => {
                let _ = actions.batch_start();
                for index in 0..count {
                    let _ = actions.send_push_literal(key, &[index], true);
                }
                let _ = actions.batch_stop();
            }
            Ok(Command::PushStamped(key, value)) => {
                let stamp = router_stamp(zid);
                let meta = wz_session_core::metadata::PushMetadata {
                    timestamp: Some(&stamp),
                    ..Default::default()
                };
                let _ = actions.send_push_with_meta_literal(key, value, true, &meta);
            }
            Ok(Command::PushReceiverAlias(id, value)) => {
                // The aliased builder names the SENDER's space; this Push names the receiver's.
                let mut push = wz_session_core::push_build::build_push_aliased(id, None, value)
                    .expect("a Push naming an id");
                push.keyexpr.body =
                    wz_session_core::wire::parts::WireexprOwnedVariant::WireexprNonlocal(
                        wz_session_core::wire::parts::WireexprNonlocalOwned {
                            id,
                            suffix_len: None,
                            suffix: None,
                        },
                    );
                let _ =
                    actions.send_network_message(NetworkMessage::Push(Box::new(push)), true, false);
            }
            Ok(Command::DeclareKeyexpr(id, key)) => {
                let declare = wz_session_core::declare_build::build_declare_kexpr(id, key)
                    .expect("a declaration");
                let _ = actions.send_network_message(
                    NetworkMessage::Declare(Box::new(declare)),
                    true,
                    false,
                );
            }
            Ok(Command::PushThenUndeclareSubscriber(id, key, value)) => {
                let _ = actions.batch_start();
                let _ = actions.send_push_literal(key, value, true);
                actions.send_undeclare_subscriber(id);
                let _ = actions.batch_stop();
            }
            Ok(Command::DeclarePushKeepAlivePush(id, key, first, second)) => {
                let aliased = |value: &[u8]| {
                    NetworkMessage::Push(Box::new(
                        wz_session_core::push_build::build_push_aliased(id, None, value)
                            .expect("a Push naming an id"),
                    ))
                };
                let declare = wz_session_core::declare_build::build_declare_kexpr(id, key)
                    .expect("a declaration");
                let _ = actions.batch_start();
                let _ = actions.send_network_message(
                    NetworkMessage::Declare(Box::new(declare)),
                    true,
                    false,
                );
                let _ = actions.send_network_message(aliased(first), true, false);
                actions.send_keep_alive();
                let _ = actions.send_network_message(aliased(second), true, false);
                let _ = actions.batch_stop();
            }
            Ok(Command::PushAliasThenUndeclare(id, value)) => {
                let aliased = || {
                    NetworkMessage::Push(Box::new(
                        wz_session_core::push_build::build_push_aliased(id, None, value)
                            .expect("a Push naming an id"),
                    ))
                };
                let undeclare = wz_session_core::declare_build::build_undeclare_kexpr(id);
                let _ = actions.batch_start();
                let _ = actions.send_network_message(aliased(), true, false);
                let _ = actions.send_network_message(
                    NetworkMessage::Declare(Box::new(undeclare)),
                    true,
                    false,
                );
                let _ = actions.send_network_message(aliased(), true, false);
                let _ = actions.batch_stop();
            }
            #[cfg(any(
                feature = "remote-declaration-watch",
                feature = "declarations-synced-event"
            ))]
            Ok(Command::FinishInitial) => {
                use wz_session_core::response_sink::DeclareReplySink;
                actions.send_declare_final_reply(wz_session_core::extbound::INITIAL_INTEREST_ID);
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
            #[cfg(feature = "queryable")]
            Ok(Command::QueryBetweenPushes(pushed, rid, asked)) => {
                let _ = actions.batch_start();
                let _ = actions.send_push_literal(pushed, b"before", true);
                let _ = actions.send_request_query(rid, 0, Some(asked));
                let _ = actions.send_push_literal(pushed, b"after", true);
                let _ = actions.batch_stop();
            }
            #[cfg(all(
                feature = "queryable",
                feature = "shared-key-ids",
                feature = "listen",
                feature = "query",
                feature = "threads"
            ))]
            Ok(Command::QueryById(rid, id, rest)) => {
                let _ = actions.send_request_query(rid, id, Some(rest));
            }
            #[cfg(feature = "query")]
            Ok(Command::Answer(key, value)) => {
                answering
                    .borrow_mut()
                    .with_app(|app| {
                        app.queryables.register_sink(
                            key,
                            Locality::Any,
                            false,
                            BoxedQuerySink::new(
                                move |query: &dyn QueryView, out: &mut dyn ReplyOut| {
                                    let _ = out.reply_keyed(query.keyexpr(), value);
                                },
                            ),
                        )
                    })
                    .expect("the router's queryable");
                counted_queries.lock().unwrap().settled = true;
            }
            #[cfg(feature = "query")]
            Ok(Command::AnswerStamped(key, value)) => {
                let stamp = router_stamp(zid);
                answering
                    .borrow_mut()
                    .with_app(|app| {
                        app.queryables.register_sink(
                            key,
                            Locality::Any,
                            false,
                            BoxedQuerySink::new(
                                move |query: &dyn QueryView, out: &mut dyn ReplyOut| {
                                    let _ = out.reply_keyed_stamped(
                                        query.keyexpr(),
                                        value,
                                        None,
                                        &stamp,
                                    );
                                },
                            ),
                        )
                    })
                    .expect("the router's queryable");
                counted_queries.lock().unwrap().settled = true;
            }
            #[cfg(feature = "query")]
            Ok(Command::AnswerOnKeys(key, keys, value)) => {
                answering
                    .borrow_mut()
                    .with_app(|app| {
                        app.queryables.register_sink(
                            key,
                            Locality::Any,
                            false,
                            BoxedQuerySink::new(
                                move |_query: &dyn QueryView, out: &mut dyn ReplyOut| {
                                    for answered in keys {
                                        let _ = out.reply_keyed(answered, value);
                                    }
                                },
                            ),
                        )
                    })
                    .expect("the router's queryable");
                counted_queries.lock().unwrap().settled = true;
            }
            #[cfg(feature = "query")]
            Ok(Command::Silence) => {
                silent.set(true);
                counted_queries.lock().unwrap().settled = true;
            }
            #[cfg(all(feature = "ticker", feature = "query", feature = "liveliness"))]
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
            #[cfg(all(feature = "ticker", feature = "query", feature = "liveliness"))]
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
                        TimestampHint::new(100 + u64::from(sn), &ADVANCED_PUBLISHER_ZID).unwrap(),
                        SampleKind::Put,
                    ));
                }
                let cache = store.query_handler(|| 0);
                let asked = counted_queries.clone();
                answering
                    .borrow_mut()
                    .with_app(|app| {
                        app.queryables.register_sink(
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
                    })
                    .expect("the router's cache");
                counted_queries.lock().unwrap().settled = true;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => return,
        }
    }
}

/// The time the router stamps what it is told to stamp, under its own zid.
fn router_stamp(zid: u8) -> wz_session_core::sample::TimestampHint {
    wz_session_core::sample::TimestampHint::new(0x6000_0000_0000_0001, &[zid; 4]).unwrap()
}

/// A client's config for `router`, which redials none.
fn config(router: &Router) -> CoopConfig {
    CoopConfig {
        endpoints: vec![router.endpoint()],
        ..client_config()
    }
}

/// The four-byte zid of `byte` a test's config states.
fn config_zid(byte: u8) -> Option<SessionZid> {
    Some(SessionZid::from([byte; 4]))
}

/// A client's config that dials nothing and listens on nothing: what a test states the endpoints
/// of itself.
fn client_config() -> CoopConfig {
    CoopConfig {
        endpoints: Vec::new(),
        whatami: WhatAmI::Client,
        zid: config_zid(0xb1),
        owned_address: None,
        batch_size: 1024,
        lease_ms: 10_000,
        keep_alive: KeepAliveConf::PICO,
        sn_resolution: wz_session_core::policy::SnResolution::default(),
        link_rx: LinkRxConf::default(),
        tx_queue: TxQueueConf::pico_of_snapshot(
            &wz_session_core::policy::SessionPolicy::defaults(),
            &wz_session_core::limits::SessionLimits::defaults(),
        ),
        timeouts: SessionTimeouts::spec_defaults(),
        open_timeout_ms: 5_000,
        redial_ms: None,
        idle_wait_ms: 100,
        listen: Vec::new(),
        accept_pending: crate::arena::admitted_handshakes(
            &wz_session_core::limits::SessionLimits::defaults(),
        )
        .expect("the build admits its own value"),
        max_faces:
            crate::arena::admitted_faces(&wz_session_core::limits::SessionLimits::defaults())
                .expect("the build admits its own value"),
        groups: Vec::new(),
        clock_moves: None,
        limits: wz_session_core::limits::SessionLimits::defaults(),
        initial_interest: false,
    }
}

fn open(router: &Router) -> EngineHold<Engine> {
    open_with(config(router))
}

fn open_with(config: CoopConfig) -> EngineHold<Engine> {
    Engine::open(
        host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
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

/// Sessions open at once past the rows the build states, on the heap storage policy: with the
/// build's `ENGINE_ROWS` rows held, eleven sessions open, each to a router of its own, and each is
/// reached through its handle; once each closes, its handle is not open and reaches nothing, as
/// zenoh-pico's upgrade of a closed session's weak handle answers none. A build on the fixed policy
/// holds its sessions to that count, which `tests/engine_rows.rs` reads, so it opens none here.
/// Turned red by a heap table that refuses an open past the count, or a close that leaves a handle
/// reaching its engine.
#[test]
fn sessions_open_past_the_builds_rows_on_the_heap_policy_and_closed_ones_are_reached_no_more() {
    if wz_session_core::bounded::ENFORCES_CAPACITY {
        return;
    }
    let held: Vec<crate::RowClaim> = (0..wz_session_core::caps::ENGINE_ROWS)
        .map(|_| crate::RowClaim::take().expect("the heap gives a row"))
        .collect();
    // Each stand-in is dialled right after it starts: one started ahead of the opens before its
    // own would be past its accept window (`Router::start`) by the time it is dialled.
    let (routers, engines): (Vec<Router>, Vec<EngineHold<Engine>>) = (0..11)
        .map(|_| {
            let router = Router::start(CatchAll::None);
            let engine = open(&router);
            (router, engine)
        })
        .unzip();
    let handles: Vec<_> = engines.iter().map(EngineHold::downgrade).collect();
    assert!(
        handles
            .iter()
            .all(|handle| handle.is_open() && handle.upgrade().is_some()),
        "every open session is reached"
    );
    for engine in &engines {
        SessionDrive::close(&**engine);
    }
    assert!(
        handles
            .iter()
            .all(|handle| !handle.is_open() && handle.upgrade().is_none()),
        "a closed session's handle reaches nothing"
    );
    drop((engines, routers));
    drop(held);
}

/// The router stand-in's link lends its session two slots of the stand-in's whole batch, which a
/// lend-only session that batches needs. The CONTROL is the host's links as they come, which lend
/// the slots their session needs (`SESSION_TX_SLOTS`), each as long as their receive buffer, and
/// none past them while those are out.
#[test]
fn the_router_stand_ins_link_lends_its_session_a_slot_of_its_batch() {
    use wz_session_core::qos::Priority;
    let batch = params(WhatAmI::Router, ROUTER_ZID).batch_size;
    let OpenedLink { sink, .. } = router_links(batch)
        .open_acceptor(0)
        .expect("bind the router's end");
    let grant = sink
        .tx_slot_acquire(usize::from(batch), Priority::DEFAULT)
        .expect("the stand-in's link lends its session a slot");
    let (base, len) = sink.tx_slot_storage(grant.slot);
    assert!(!base.is_null(), "the slot is memory");
    assert!(
        len >= grant.headroom + usize::from(batch),
        "a slot of {len} bytes holds a batch of {batch} after its headroom"
    );
    let second = sink
        .tx_slot_acquire(usize::from(batch), Priority::DEFAULT)
        .expect("a second slot while the first is out");
    sink.tx_slot_abort(grant.slot);
    sink.tx_slot_abort(second.slot);

    let OpenedLink { sink: plain, .. } = host_links(LOOPBACK, PosixTcpDial)
        .open_acceptor(0)
        .expect("bind a plain end");
    let held = [(); wz_session_core::link::SESSION_TX_SLOTS].map(|()| {
        plain
            .tx_slot_acquire(usize::from(batch), Priority::DEFAULT)
            .expect("CONTROL: a link given no storage lends its session's slots")
    });
    for grant in &held {
        assert_eq!(
            plain.tx_slot_storage(grant.slot).1,
            plain.link_rx_capacity(),
            "CONTROL: each as long as its receive buffer"
        );
    }
    assert!(
        plain
            .tx_slot_acquire(usize::from(batch), Priority::DEFAULT)
            .is_none(),
        "CONTROL: and none past them while they are out"
    );
    for grant in held {
        plain.tx_slot_abort(grant.slot);
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
    engine
        .declare_subscriber_on_wire("demo/**", WireKey::literal(), Locality::Any, None, {
            let count = count.clone();
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                assert_eq!(sample.payload(), b"hello");
                count.fetch_add(1, Ordering::SeqCst);
            })
        })
        .expect("the session declares the subscriber");
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

/// A subscriber the program declares after a peer asked for the session's subscribers, current and
/// future, is told to that peer in answer to its Interest by the declaration itself: the session is
/// not stepped after it, so no record, keep-alive or lease check of the link's can stage the
/// answer. The CONTROL is the declaration itself, which reaches the peer unstepped too, so what
/// the session sends outside a step is seen. Turned red by an answer staged only by the next event
/// of the link's session.
#[cfg(feature = "interest-answer")]
#[test]
fn a_subscriber_declared_after_a_peers_interest_is_answered_by_the_declaration() {
    const INTEREST: u64 = 41;
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    router.send(Command::AskSubscribers(INTEREST, "demo/**"));
    until(&engine, "the session to answer the Interest", || {
        router.seen(|s| s.interest_finals.contains(&INTEREST))
    });
    assert!(
        !router.seen(|s| s.subscriber_answers.contains(&INTEREST)),
        "CONTROL: no subscriber answered the Interest before one is declared"
    );
    let declared_before = router.seen(|s| s.subscribers.len());
    engine
        .declare_subscriber_on_wire(
            "demo/a",
            WireKey::literal(),
            Locality::Any,
            None,
            SubscriberSink::shared(|_: &dyn SampleView| {}),
        )
        .expect("the session declares the subscriber");
    // Waited for with the session unstepped.
    let unstepped = |what: &str, done: &dyn Fn(&Seen) -> bool| {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !router.seen(done) {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what} with the session unstepped"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    };
    unstepped("CONTROL: the declaration", &|s| {
        s.subscribers.len() > declared_before
    });
    unstepped("the answer to the Interest", &|s| {
        s.subscriber_answers.contains(&INTEREST)
    });
}

/// A session that listens without the answering end of an Interest (`listen` without
/// `interest-answer`, as the zenoh-pico preset builds a peer) answers no Interest a peer asks on a
/// unicast face, as zenoh-pico's unicast session answers none: no `DeclareFinal` names it, and a
/// subscriber declared after it reaches the peer as a declaration and not as an answer. The CONTROL
/// is that declaration. Turned red by an answer staged, or a Final sent, in such a build.
#[cfg(all(feature = "listen", not(feature = "interest-answer")))]
#[test]
fn a_listening_build_without_the_answer_answers_no_interest() {
    const INTEREST: u64 = 41;
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    router.send(Command::AskSubscribers(INTEREST, "demo/**"));
    let declared_before = router.seen(|s| s.subscribers.len());
    engine
        .declare_subscriber_on_wire(
            "demo/a",
            WireKey::literal(),
            Locality::Any,
            None,
            SubscriberSink::shared(|_: &dyn SampleView| {}),
        )
        .expect("the session declares the subscriber");
    until(&engine, "CONTROL: the declaration", || {
        router.seen(|s| s.subscribers.len() > declared_before)
    });
    // Stepped long enough for the Interest, sent before the declaration, to have been read.
    let settled = Instant::now() + Duration::from_millis(200);
    until(&engine, "the Interest to be read", || {
        Instant::now() >= settled
    });
    assert!(
        !router.seen(|s| s.interest_finals.contains(&INTEREST)),
        "no DeclareFinal answers the Interest"
    );
    assert!(
        !router.seen(|s| s.subscriber_answers.contains(&INTEREST)),
        "no subscriber answers it"
    );
}

/// A publish that finds nothing handed to the session takes the session's lock once and the queue
/// of handed legs not at all, so a stream of puts pays no lock for what no other publish left
/// behind. The CONTROL is a read step, which looks at the queue under its lock every time. A
/// build of the dial face alone keeps no queue, nor does one that sends each face its own leg.
#[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
#[test]
fn a_publish_with_nothing_handed_takes_the_session_once_and_not_the_handed_queue() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let takes = |engine: &Engine| {
        (
            engine.takes.core.load(Ordering::SeqCst),
            engine.takes.handed.load(Ordering::SeqCst),
        )
    };
    let (core_before, handed_before) = takes(&engine);
    for _ in 0..10 {
        engine
            .publish_on_wire_all(
                "demo/b",
                &WireKey::literal(),
                b"x",
                &PublishOptions::put().with_locality(Locality::Remote),
            )
            .expect("a put the link carries");
    }
    let (core_after, handed_after) = takes(&engine);
    assert_eq!(
        core_after - core_before,
        10,
        "one take of the session a put"
    );
    assert_eq!(handed_after, handed_before, "no take of the handed queue");
    let _ = SessionDrive::read(&*engine, false);
    assert_eq!(
        takes(&engine).1,
        handed_after + 1,
        "CONTROL: a read step looks under the queue's lock"
    );
}

/// A subscriber's undeclaration holds the session once: the one hold looks for its row in the
/// liveliness subscribers' table, which the port's one id space numbers it in too, and then in the
/// subscribers'. The CONTROL is its declaration, which holds the session once as well. Turned red
/// by an undeclaration that looks for a liveliness subscriber under a hold of its own (a build
/// with `liveliness`).
#[test]
fn a_subscriber_is_undeclared_in_one_hold_of_the_session() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let takes = || engine.takes.core.load(Ordering::SeqCst);
    let before = takes();
    let id = engine
        .declare_subscriber_on_wire(
            "demo/a",
            WireKey::literal(),
            Locality::Any,
            None,
            SubscriberSink::shared(|_: &dyn SampleView| {}),
        )
        .expect("the session declares the subscriber")
        .id;
    let declared = takes();
    assert_eq!(
        declared - before,
        1,
        "CONTROL: one hold for the declaration"
    );
    engine.undeclare_subscriber(id);
    assert_eq!(takes() - declared, 1, "one hold for the undeclaration");
}

/// Each operation lets the session go as it ends, its round sealed and its lock let go in the one
/// drop of its hold: the same operation on another thread right after takes the session at once.
/// Turned red by a hold whose drop seals the round and leaves the lock held, where the other
/// thread waits past the bound.
#[test]
fn an_operation_lets_the_session_go_for_the_next_one_on_another_thread() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let _ = engine.declarations_synced();
    let other = engine.clone();
    let (done, finished) = channel();
    std::thread::spawn(move || {
        let _ = other.declarations_synced();
        let _ = done.send(());
    });
    assert!(
        finished.recv_timeout(Duration::from_secs(10)).is_ok(),
        "the hold before let the session go"
    );
    let _ = engine.declarations_synced();
}

/// A read step on a session with nothing due reads the session's clock once, before its tasks ran,
/// and wakes their timers, moves every face, sweeps the gets and looks for a due job by that one
/// reading, none for its tasks apart from it; its wait, with no deadline to work out, reads it not
/// at all. A read that steps its one link itself keeps that link's deadlines (its keep-alive, its
/// lease) with the session's, which a build whose links are tasks leaves to the tasks' timers: its
/// wait has that deadline to work out, and reads the clock once for it. The session's lock is
/// taken twice: for the wait and for the step. The counts are otherwise the same in every build,
/// one with groups among them, the session having joined none: the sweep of the gets, each face
/// and the look for a due job share the step's reading and its take. Turned red by a step that
/// reads the clock again for its link, a wait that reads it with nothing to bound, or a read that
/// takes the session to step and poll the groups of a session that joined none
/// (`CoopEngine::read_groups`).
#[test]
fn a_read_step_reads_the_clock_once_and_takes_the_session_for_its_wait_and_its_step() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    until(&engine, "the declarations to be told", || {
        engine.declarations_synced()
    });
    let (reads, task_reads, takes) = (
        engine.clock_reads(),
        engine.task_clock_reads(),
        engine.takes.core.load(Ordering::SeqCst),
    );
    let _ = SessionDrive::read(&*engine, false);
    let wait_reads = usize::from(cfg!(not(wz_round)));
    assert_eq!(
        engine.clock_reads() - reads,
        1 + wait_reads,
        "one reading for the step, and one for a wait bounded by the link's own deadlines"
    );
    assert_eq!(
        engine.task_clock_reads() - task_reads,
        0,
        "the step's tasks ran on its one reading, with none of their own"
    );
    assert_eq!(
        engine.takes.core.load(Ordering::SeqCst) - takes,
        2,
        "one take for the wait and one for the step"
    );
}

/// The session's step ends a chain of its one reassembly Router once the chain is past its
/// deadline, though no link's receive sweeps it, and not before: a step at once leaves a chain
/// staged now on the Router's epoch open, as one measured on another epoch would not be. The
/// CONTROL is the chain, open when it is begun.
#[test]
fn the_sessions_step_ends_a_chain_past_its_deadline() {
    use wz_session_core::extfragment::FragmentMarkers;
    use wz_session_core::qos::Priority;
    use wz_session_core::reassembly_dispatch::{Fragment, IngestOutcome};

    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let begun = engine.with_chain_router(|reassembly, now_ms| {
        reassembly.ingest(
            Fragment {
                peer_key: &[0x5a; 16],
                reliable: true,
                sn: 1,
                more: 1,
                payload: b"part",
                priority: Priority::DEFAULT,
                markers: FragmentMarkers::NONE,
            },
            wz_session_core::sn::mask_from_res(0x02),
            now_ms,
            |_| {},
        )
    });
    assert_eq!(begun, IngestOutcome::Begun);
    let open_chains = || engine.with_chain_router(|reassembly, _| reassembly.active_chains());
    assert_eq!(open_chains(), 1, "CONTROL: the chain is open");
    let _ = SessionDrive::read(&*engine, false);
    assert_eq!(
        open_chains(),
        1,
        "a step before the deadline leaves the chain open"
    );
    until(&engine, "the step to end the chain", || open_chains() == 0);
}

/// The samples a read takes from a link that leaves its datagram where it lies are handed to the
/// subscriber's callback where they lie, each once, with the session free: their payloads are
/// read in the datagram, which is held back only until the last callback returns. A read that
/// finds nothing hands nothing out. One thread delivers, so the list of the threads delivering
/// beside it is never taken. The CONTROL is the count of the samples handed to the subscriber.
#[test]
fn a_received_sample_is_handed_where_it_lies_and_an_empty_read_hands_nothing() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let received = Arc::new(AtomicUsize::new(0));
    let count = received.clone();
    let free: Arc<Mutex<Vec<bool>>> = Arc::default();
    let session = EngineHold::downgrade(&engine);
    let declares_before = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire("demo/**", WireKey::literal(), Locality::Any, None, {
            let count = count.clone();
            let free = free.clone();
            SubscriberSink::shared(move |_sample: &dyn SampleView| {
                if let Some(engine) = session.upgrade() {
                    free.lock().unwrap().push(engine.session_is_free());
                }
                count.fetch_add(1, Ordering::SeqCst);
            })
        })
        .expect("the session declares the subscriber");
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    until(&engine, "the declarations to be told", || {
        engine.declarations_synced()
    });
    let (handed, lent, list) = (
        engine.samples_handed(),
        engine.samples_lent(),
        engine.delivery_list_takes(),
    );
    for _ in 0..4 {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert_eq!(
        (engine.samples_handed(), engine.samples_lent()),
        (handed, lent),
        "a read with nothing to read handed something out"
    );
    const SAMPLES: usize = 8;
    for _ in 0..SAMPLES {
        router.send(Command::Push("demo/a", b"x"));
    }
    std::thread::sleep(Duration::from_millis(200));
    until(&engine, "the pushes", || {
        received.load(Ordering::SeqCst) == SAMPLES
    });
    assert_eq!(
        engine.samples_handed() - handed,
        SAMPLES,
        "each sample handed once"
    );
    assert_eq!(
        engine.samples_lent() - lent,
        SAMPLES,
        "each sample handed where its datagram lies, none copied"
    );
    assert_eq!(
        *free.lock().unwrap(),
        [true; SAMPLES],
        "a callback found the session held"
    );
    assert_eq!(
        engine.delivery_list_takes(),
        list,
        "one thread delivered, and took the list of the others"
    );
}

/// A Push the link lends is handed to the subscribers' plane alone, and what follows it (the
/// subscribers' tables reconciled, the drains, the Finals owed) is done under the one lookup of
/// its face its dispatch made: the fan over every plane is handed none of them. The CONTROL is
/// the subscriber's count of the samples it was handed.
#[test]
fn a_received_push_is_handed_to_the_subscribers_alone_under_one_lookup() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let received = Arc::new(AtomicUsize::new(0));
    let count = received.clone();
    let declares_before = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire("demo/**", WireKey::literal(), Locality::Any, None, {
            let count = count.clone();
            SubscriberSink::shared(move |_sample: &dyn SampleView| {
                count.fetch_add(1, Ordering::SeqCst);
            })
        })
        .expect("the session declares the subscriber");
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    let (alone, lookups, fanned) = engine.push_dispatches();
    const SAMPLES: usize = 8;
    for _ in 0..SAMPLES {
        router.send(Command::Push("demo/a", b"x"));
    }
    until(&engine, "the pushes", || {
        received.load(Ordering::SeqCst) == SAMPLES
    });
    let (alone_after, lookups_after, fanned_after) = engine.push_dispatches();
    assert_eq!(
        alone_after - alone,
        SAMPLES,
        "each Push to the subscribers' plane alone"
    );
    assert_eq!(
        lookups_after - lookups,
        SAMPLES,
        "one lookup of the face a Push, its drains included"
    );
    assert_eq!(
        fanned_after, fanned,
        "the fan over every plane was handed a Push"
    );
}

/// A subscriber that undeclares itself from inside its callback is handed nothing more, though the
/// delivery kept its callback and the lane still holds samples for it: the removal from the table
/// ends what the delivery kept, as a look in the table for each sample would have found nothing.
#[test]
fn a_subscriber_undeclared_inside_its_callback_is_handed_nothing_more() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let received = Arc::new(AtomicUsize::new(0));
    let count = received.clone();
    let own: Arc<Mutex<Option<wz_capi_port::SubId>>> = Arc::new(Mutex::new(None));
    let own_id = own.clone();
    let session = EngineHold::downgrade(&engine);
    let declares_before = router.seen(|s| s.declares);
    let id = engine
        .declare_subscriber_on_wire("demo/**", WireKey::literal(), Locality::Any, None, {
            let count = count.clone();
            let own_id = own_id.clone();
            SubscriberSink::shared(move |_sample: &dyn SampleView| {
                if count.fetch_add(1, Ordering::SeqCst) + 1 == 3 {
                    let id = own_id.lock().unwrap().take();
                    if let (Some(id), Some(engine)) = (id, session.upgrade()) {
                        engine.undeclare_subscriber(id);
                    }
                }
            })
        })
        .expect("declared")
        .id;
    *own.lock().unwrap() = Some(id);
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    for _ in 0..8 {
        router.send(Command::Push("demo/a", b"x"));
    }
    std::thread::sleep(Duration::from_millis(200));
    until(&engine, "the third push", || {
        received.load(Ordering::SeqCst) >= 3
    });
    // What is left of the pushes is read and passed over.
    for _ in 0..10 {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert_eq!(
        received.load(Ordering::SeqCst),
        3,
        "nothing is handed to a subscriber after its undeclaration"
    );
}

/// A Push and, after it in the same batch, the retraction of the router's subscriber that opened a
/// write filter. A read that hands each record out where it lies, a read task's among them, and a
/// round of one thread apply the retraction after the Push's callback returned, so the callback
/// sees the filter still open, as zenoh-pico calls each callback while it reads the batch
/// (`vendor/zenoh-pico/src/transport/unicast/rx.c` @ `_z_handle_network_message`); only a round
/// beside other threads (`wz_round` with a read task) reads the batch whole before its callbacks,
/// which see the filter shut. Turned red by a round of one thread that takes the next record while
/// it has room (`Round::has_room`), or a direct read that applies a record before the callbacks
/// of the one before it returned.
#[test]
fn a_retraction_after_a_push_in_one_batch_is_applied_after_the_pushs_callback() {
    use wz_session_core::row_callback::ThreadForm;

    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let ask = Some(InterestAsk {
        mapping_id: 0,
        suffix: Some("demo/o"),
        aggregate: false,
    });
    let filter = engine
        .declare_write_filter(
            FilterPlane::Subscribers,
            "demo/o",
            &WireKey::literal(),
            ask,
            false,
        )
        .expect("a session with ids left declares")
        .id;
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) >= 1
    });
    router.send(Command::DeclareSubscriber(1, "demo/**"));
    until(&engine, "the filter to open", || {
        !engine.write_filter_active(filter)
    });
    let seen: Arc<Mutex<Vec<bool>>> = Arc::default();
    let session = EngineHold::downgrade(&engine);
    let declares_before = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire("demo/o", WireKey::literal(), Locality::Any, None, {
            let seen = seen.clone();
            SubscriberSink::shared(move |_: &dyn SampleView| {
                if let Some(engine) = session.upgrade() {
                    seen.lock()
                        .unwrap()
                        .push(engine.write_filter_active(filter));
                }
            })
        })
        .expect("declared");
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    router.send(Command::PushThenUndeclareSubscriber(1, "demo/o", b"v"));
    until(&engine, "the push and the retraction after it", || {
        !seen.lock().unwrap().is_empty() && engine.write_filter_active(filter)
    });
    let read_whole_first = cfg!(wz_round) && <crate::form::CoopForm as ThreadForm>::OTHER_THREADS;
    assert_eq!(
        *seen.lock().unwrap(),
        [read_whole_first],
        "the callback saw the filter shut only where the batch is read whole before it"
    );
}

/// The samples of one batch are handed in the read that hands the first of them, in a build of one
/// thread as in one of threads: a round of one thread takes one record at a time, and the read
/// steps on while the link still holds the rest of the batch it read, which the round's gate tells
/// the read (`holds_input`). Turned red by a read that ends after the first record while the link
/// holds the rest.
#[test]
fn the_samples_of_one_batch_are_handed_in_the_read_that_hands_the_first() {
    const SAMPLES: u8 = 3;
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let got = Arc::new(Mutex::new(Vec::new()));
    let into = got.clone();
    let declares_before = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire(
            "demo/**",
            WireKey::literal(),
            Locality::Any,
            None,
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                into.lock().unwrap().push(sample.payload().to_vec());
            }),
        )
        .expect("the session declares the subscriber");
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    router.send(Command::PushBatch("demo/batch", SAMPLES));
    let deadline = Instant::now() + Duration::from_secs(5);
    while got.lock().unwrap().is_empty() {
        assert!(Instant::now() < deadline, "timed out waiting for the batch");
        let _ = SessionDrive::read(&*engine, false);
    }
    let sent: Vec<Vec<u8>> = (0..SAMPLES).map(|index| vec![index]).collect();
    assert_eq!(
        *got.lock().unwrap(),
        sent,
        "the whole batch, in order, by the read that handed its first sample"
    );
}

/// A session whose links are all up and settled moves them on no more while nothing that moves
/// them comes: the reads that hand samples look at no face's value. Once the link's session ends,
/// a step moves them and finds the link lost, which ends a session that redials none. Turned red
/// by a step that moves settled links at each receive (`Core::move_links` calling `poll_links`
/// whatever it finds, or a read that steps its one link itself and looks at the link's life with
/// nothing come and nothing due), or a settled session that misses its link's end.
#[test]
fn settled_links_are_moved_only_once_a_link_ends() {
    const SAMPLES: u8 = 4;
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let got = Arc::new(Mutex::new(Vec::new()));
    let into = got.clone();
    let declares_before = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire(
            "demo/**",
            WireKey::literal(),
            Locality::Any,
            None,
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                into.lock().unwrap().push(sample.payload().to_vec());
            }),
        )
        .expect("the session declares the subscriber");
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    // A read more moves what the declaration changed, and leaves the links settled.
    let _ = SessionDrive::read(&*engine, false);
    let polls = engine.link_polls();
    router.send(Command::PushBatch("demo/settled", SAMPLES));
    until(&engine, "the samples", || {
        got.lock().unwrap().len() == usize::from(SAMPLES)
    });
    assert_eq!(
        engine.link_polls() - polls,
        0,
        "no move of settled links for the samples"
    );
    router.send(Command::Close);
    drop(router);
    until(&engine, "the link's end to end the session", || {
        SessionDrive::is_closed(&*engine)
    });
    assert!(
        engine.link_polls() > polls,
        "CONTROL: the link's end moves the links"
    );
}

/// The read that hands what the session's link took from its stack in one receive, eight samples
/// of one datagram, hands every one of them and moves the session's links once at most, after
/// the last (none while they are settled, `settled_links_are_moved_only_once_a_link_ends`), and
/// looks at the queue of handed publishes once, in a build of one thread as in one of threads.
/// A datagram link takes one datagram a receive, so the session's round is lowered below the
/// datagram's samples: a step reads one record (one thread) or as many as the round has room for
/// (threads) while the link keeps the rest, and leaves the links where they stood. Datagrams the
/// stack still queues are not the link's input and each is a receive of its own. Its tasks read
/// no clock of their own: the step that received the datagram wakes their timers by its one
/// reading, and the steps that go on with it wake none until the last, by that step's own
/// reading, so a timer is late by one receive's reading at most. Turned red by a step that moves the links each time it reads (the
/// `Stepped::Read` return taken out of `CoopEngine::step`), which moves them once a step, a read
/// that ends with that step while the link keeps the rest, or a step that goes on with the
/// receive's input and reads the clock for its timers (`run_tasks` in place of
/// `run_tasks_at(None)` there), once a step.
#[test]
fn the_read_that_hands_what_one_receive_took_moves_the_links_once() {
    use entity_tables::{lowered, open_under};
    use wz_session_core::limit_binding::Quota;
    const SAMPLES: u8 = 8;
    const RECORDS: usize = 4;
    // The premise: the datagram holds more samples than a step of either build reads.
    const _: () = assert!(SAMPLES as usize > RECORDS);
    let router = Router::start(CatchAll::None);
    let engine = open_under(
        &router,
        lowered(|l| l.select_delivery_lane_events(Quota::at_most(RECORDS))),
    );
    let got = Arc::new(Mutex::new(Vec::new()));
    let into = got.clone();
    let declares_before = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire(
            "demo/**",
            WireKey::literal(),
            Locality::Any,
            None,
            SubscriberSink::shared(move |sample: &dyn SampleView| {
                into.lock().unwrap().push(sample.payload().to_vec());
            }),
        )
        .expect("the session declares the subscriber");
    until(&engine, "the router to see the subscriber", || {
        router.seen(|s| s.declares) > declares_before
    });
    router.send(Command::PushBatch("demo/batch", SAMPLES));
    // Nothing steps the session meanwhile, so the datagram lies in its socket before the read.
    std::thread::sleep(Duration::from_millis(300));
    let samples = engine.samples_handed();
    let polls = engine.link_polls();
    let task_clock_reads = engine.task_clock_reads();
    #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
    let handed = engine.takes.handed.load(Ordering::SeqCst);
    let _ = SessionDrive::read(&*engine, false);
    let sent: Vec<Vec<u8>> = (0..SAMPLES).map(|index| vec![index]).collect();
    assert_eq!(
        *got.lock().unwrap(),
        sent,
        "every sample, in order, by the one read"
    );
    assert_eq!(
        engine.samples_handed() - samples,
        usize::from(SAMPLES),
        "each sample of the datagram handed once"
    );
    assert!(
        engine.link_polls() - polls <= 1,
        "one move of the links at most for what the receive took"
    );
    assert_eq!(
        engine.task_clock_reads() - task_clock_reads,
        0,
        "the tasks' timers are woken by the steps' own readings, with none of their own"
    );
    #[cfg(all(wz_round, any(feature = "listen", feature = "group")))]
    assert_eq!(
        engine.takes.handed.load(Ordering::SeqCst) - handed,
        1,
        "one look at the handed publishes for what the receive took"
    );
}

/// A peer's sample that reaches three subscribers is handed to each of them once, in the same order
/// for every sample, each sample after the one before it, with the session's lock let go: one
/// callback steps the session and publishes from inside itself, and the router receives what it
/// published. Turned red by a delivery made under the session's lock (the step and the put from
/// inside the call would wait on it for good), a row handed a sample twice or not at all, or the
/// rows of one sample handed in another order than those of the next.
#[test]
fn a_sample_for_three_subscribers_is_handed_to_each_in_order_with_the_session_free() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);
    // What each subscriber was handed: its tag and the payload.
    type Handed = Arc<Mutex<Vec<(u8, Vec<u8>)>>>;
    let handed: Handed = Arc::default();
    let published: Arc<Mutex<Vec<bool>>> = Arc::default();
    let session = EngineHold::downgrade(&engine);
    let declares_before = router.seen(|s| s.declares);
    for tag in 1..=3u8 {
        let handed = handed.clone();
        let published = published.clone();
        engine
            .declare_subscriber_on_wire(
                "demo/**",
                WireKey::literal(),
                Locality::Any,
                None,
                SubscriberSink::shared(move |sample: &dyn SampleView| {
                    handed
                        .lock()
                        .unwrap()
                        .push((tag, sample.payload().to_vec()));
                    if tag != 2 {
                        return;
                    }
                    // From inside the call: a step and a put, each of which takes the session's
                    // lock.
                    if let Some(engine) = session.upgrade() {
                        let _ = SessionDrive::read(&*engine, false);
                        let put = engine.publish_on_wire_all(
                            "echo/two",
                            &WireKey::literal(),
                            sample.payload(),
                            &PublishOptions::put().with_locality(Locality::Remote),
                        );
                        published.lock().unwrap().push(put.is_ok());
                    }
                }),
            )
            .expect("the session declares the subscriber");
    }
    until(&engine, "the router to see the subscribers", || {
        router.seen(|s| s.declares) > declares_before
    });
    router.send(Command::Push("demo/a", b"one"));
    router.send(Command::Push("demo/a", b"two"));
    until(&engine, "both samples, to every subscriber", || {
        handed.lock().unwrap().len() >= 6
    });
    let handed = handed.lock().unwrap().clone();
    assert_eq!(
        handed.len(),
        6,
        "each sample handed to each subscriber once"
    );
    let (one, two) = handed.split_at(3);
    assert!(
        one.iter().all(|(_, payload)| payload == b"one")
            && two.iter().all(|(_, payload)| payload == b"two"),
        "each sample handed to every subscriber before the next: {handed:?}"
    );
    let order = |of: &[(u8, Vec<u8>)]| of.iter().map(|(tag, _)| *tag).collect::<Vec<u8>>();
    let mut tags = order(one);
    assert_eq!(order(two), tags, "the same order for each sample");
    tags.sort_unstable();
    assert_eq!(tags, [1, 2, 3], "each subscriber once a sample");
    assert_eq!(
        *published.lock().unwrap(),
        [true, true],
        "the put from inside the call was taken"
    );
    until(
        &engine,
        "the router to receive the puts made in the calls",
        || {
            router.seen(|s| {
                s.samples
                    .iter()
                    .filter(|(key, _)| key == "echo/two")
                    .count()
                    == 2
            })
        },
    );
}

/// Under the pico profile a droppable publish that finds the session held by a read step waits for
/// the step, blocked, and is sent once the step lets go: the holder holds no send, so the publish
/// is no congestion drop, and it does not spin on the session while it waits. The CONTROL is the
/// time it took: no less than the step held the session.
// Two threads on one session at once, which a build of one thread does not have.
#[cfg(feature = "threads")]
#[test]
fn a_droppable_publish_behind_a_read_step_waits_without_spinning_and_is_sent() {
    use wz_session_core::qos::CongestionControl;
    use wz_session_core::session_init_params::HeldDrop;
    let router = Router::start(CatchAll::Held);
    assert_eq!(
        config(&router).tx_queue.held_drop,
        HeldDrop::DropAtOnce,
        "the pico profile"
    );
    let engine = open(&router);
    let spins = engine.takes.spins.load(Ordering::SeqCst);
    let (holds, held) = channel();
    let step = {
        let engine = engine.clone();
        std::thread::spawn(move || {
            engine.holding_as_a_step(|| {
                holds.send(()).expect("the test waits for the hold");
                std::thread::sleep(Duration::from_millis(200));
            });
        })
    };
    held.recv().expect("the step holds the session");
    let started = Instant::now();
    let sent = engine.publish_on_wire_all(
        "demo/behind",
        &WireKey::literal(),
        b"behind",
        &PublishOptions::put()
            .with_locality(Locality::Remote)
            .with_congestion_control(CongestionControl::Drop),
    );
    let took = started.elapsed();
    step.join().expect("the step");
    assert!(sent.is_ok(), "the publish was sent: {sent:?}");
    assert_eq!(
        engine.takes.spins.load(Ordering::SeqCst),
        spins,
        "no turn spun on the held session"
    );
    assert!(
        took >= Duration::from_millis(150),
        "CONTROL: it waited for the step, {took:?}"
    );
    until(&engine, "the router to receive the put", || {
        router.seen(|s| s.samples.iter().any(|(k, _)| k == "demo/behind"))
    });
}

/// Under the pico profile a droppable publish that finds the session held by a read working out
/// its wait tries the session again, spinning, rather than blocking on its lock, and is sent once
/// the read lets go: the read holds no send and lets go within its take. The CONTROL is the read
/// step's hold above, which the same publish waits for blocked, with no spin.
// Two threads on one session at once, which a build of one thread does not have.
#[cfg(feature = "threads")]
#[test]
fn a_droppable_publish_behind_a_read_working_out_its_wait_spins_and_is_sent() {
    use wz_session_core::qos::CongestionControl;
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);
    let spins = engine.takes.spins.load(Ordering::SeqCst);
    let (holds, held) = channel();
    let wait = {
        let engine = engine.clone();
        std::thread::spawn(move || {
            engine.holding_as_a_read_wait(|| {
                holds.send(()).expect("the test waits for the hold");
                std::thread::sleep(Duration::from_millis(100));
            });
        })
    };
    held.recv().expect("the read holds the session");
    let sent = engine.publish_on_wire_all(
        "demo/behind-wait",
        &WireKey::literal(),
        b"behind",
        &PublishOptions::put()
            .with_locality(Locality::Remote)
            .with_congestion_control(CongestionControl::Drop),
    );
    wait.join().expect("the read");
    assert!(sent.is_ok(), "the publish was sent: {sent:?}");
    assert!(
        engine.takes.spins.load(Ordering::SeqCst) > spins,
        "it tried the held session again rather than wait on its lock"
    );
    until(&engine, "the router to receive the put", || {
        router.seen(|s| s.samples.iter().any(|(k, _)| k == "demo/behind-wait"))
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
    let filter = engine
        .declare_write_filter(
            FilterPlane::Subscribers,
            "demo/x",
            &WireKey::literal(),
            Some(InterestAsk {
                mapping_id: 0,
                suffix: Some("demo/x"),
                aggregate: false,
            }),
            false,
        )
        .expect("a session with ids left declares")
        .id;
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) > 0
    });
    let params = PublishOptions::put()
        .plain_put_params()
        .expect("a plain put");
    assert_eq!(
        engine.put_plain_filtered(
            filter,
            "demo/x",
            wz_session_core::session_tables::KeyexprRef::by_id(0),
            b"v",
            &params
        ),
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
        engine.put_plain_filtered(
            filter,
            "demo/x",
            wz_session_core::session_tables::KeyexprRef::by_id(0),
            b"v",
            &params
        ),
        FilteredPut::Sent(Ok(0)),
    );
    until(&engine, "the router to receive the put", || {
        router.seen(|s| s.pushes) == 1
    });

    SessionDrive::close(&*engine);
    assert!(SessionDrive::is_closed(&*engine));
    assert!(SessionDrive::read(&*engine, false).is_err());
}

/// The one entry a declared entity's write goes through (`publish_filtered`) holds a write back
/// while its filter says nothing matches, and once a subscriber opens the filter sends one with
/// options the general way and one with none the plain way its row keeps, or answers `NotPlain`
/// with nothing sent when the row keeps none.
#[test]
fn a_filtered_publish_is_held_back_then_sent() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let filter = engine
        .declare_write_filter(
            FilterPlane::Subscribers,
            "demo/x",
            &WireKey::literal(),
            Some(InterestAsk {
                mapping_id: 0,
                suffix: Some("demo/x"),
                aggregate: false,
            }),
            false,
        )
        .expect("a session with ids left declares")
        .id;
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) > 0
    });
    let opts = PublishOptions::put();
    let literal = WireKey::literal();
    assert_eq!(
        engine.publish_filtered(filter, "demo/x", &literal, b"v", Some(&opts)),
        FilteredPut::Suppressed,
        "no subscriber yet: the put is held back"
    );
    assert_eq!(
        engine.publish_filtered(filter, "demo/x", &literal, b"v", None),
        FilteredPut::Suppressed,
        "a bare put is held back the same"
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
    assert!(matches!(
        engine.publish_filtered(filter, "demo/x", &literal, b"v", Some(&opts)),
        FilteredPut::Sent(Ok(_))
    ));
    until(&engine, "the router to receive the put", || {
        router.seen(|s| s.pushes) == 1
    });
    assert_eq!(
        engine.publish_filtered(filter, "demo/x", &literal, b"v", None),
        FilteredPut::NotPlain,
        "a row that keeps no plain form sends nothing itself"
    );
    let params = opts.plain_put_params().expect("a plain put");
    engine.keep_write_filter_plain(
        filter,
        Some((
            params,
            wz_session_core::session_tables::KeyexprRef::by_id(0),
        )),
    );
    assert!(matches!(
        engine.publish_filtered(filter, "demo/x", &literal, b"v", None),
        FilteredPut::Sent(Ok(_))
    ));
    until(&engine, "the router to receive the plain put", || {
        router.seen(|s| s.pushes) == 2
    });
    SessionDrive::close(&*engine);
}

/// A matching listener records each verdict it is told.
fn heard() -> (wz_capi_port::MatchingSink, Arc<Mutex<Vec<bool>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let into = log.clone();
    (
        wz_capi_port::MatchingSink::shared(move |matching| into.lock().unwrap().push(matching)),
        log,
    )
}

/// A matching listener declared from a write filter counts what the filter was declared to count,
/// on its key: it matches once a peer declares a subscriber on that key and not on another, and one
/// from an id that names no filter is refused as of a closed session, its sink let go. The CONTROL
/// is the filter itself, which opens on the same declaration.
#[test]
fn a_listener_from_a_filter_counts_what_the_filter_counts() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let filter = engine
        .declare_write_filter(
            FilterPlane::Subscribers,
            "demo/f",
            &WireKey::literal(),
            Some(InterestAsk {
                mapping_id: 0,
                suffix: Some("demo/f"),
                aggregate: false,
            }),
            false,
        )
        .expect("a session with ids left declares")
        .id;
    let (sink, told) = heard();
    engine
        .declare_filter_matching_listener(filter, sink)
        .expect("the filter is declared");
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) >= 1
    });
    router.send(Command::DeclareSubscriber(1, "demo/other"));
    router.send(Command::DeclareSubscriber(2, "demo/f"));
    until(&engine, "the listener to match", || {
        *told.lock().unwrap() == [true]
    });
    assert!(
        !engine.write_filter_active(filter),
        "CONTROL: the filter opened on the same subscriber"
    );
    let (sink, refused) = heard();
    assert_eq!(
        engine.declare_filter_matching_listener(0, sink),
        Err(wz_capi_port::Refusal::Closed)
    );
    assert_eq!(
        Arc::strong_count(&refused),
        1,
        "the refused sink is not kept: the log is held by nothing else"
    );
}

/// A build without a querier or a queryable holds no table of the queryables a peer declares, so a
/// matching listener and a write filter on that plane are refused (a listener with
/// `Refusal::NotBuilt`, a filter with none) and the listener's sink goes with the refusal. The CONTROL is a listener on the
/// subscribers' plane, which every build that keeps listeners on a key holds.
#[cfg(all(
    not(any(feature = "query", feature = "queryable")),
    feature = "key-matching-listener"
))]
#[test]
fn a_build_without_the_queryables_plane_refuses_their_listener_and_filter() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let plane = FilterPlane::Queryables {
        complete_required: false,
    };
    let (sink, told) = heard();
    assert_eq!(
        engine.declare_matching_listener(plane, "demo/q", sink, false),
        Err(wz_capi_port::Refusal::NotBuilt)
    );
    assert_eq!(
        Arc::strong_count(&told),
        1,
        "the refused sink is not kept: the log is held by nothing else"
    );
    assert_eq!(
        engine.declare_write_filter(
            plane,
            "demo/q",
            &WireKey::literal(),
            Some(InterestAsk {
                mapping_id: 0,
                suffix: Some("demo/q"),
                aggregate: false,
            }),
            false,
        ),
        Err(wz_capi_port::Refusal::NotBuilt)
    );
    let (sink, subscribers) = heard();
    assert!(
        engine
            .declare_matching_listener(FilterPlane::Subscribers, "demo/q", sink, false)
            .is_ok(),
        "CONTROL: the subscribers' plane is held"
    );
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) >= 1
    });
    // A peer's queryable is read past and kept nowhere: the declaration after it is heard.
    router.send(Command::DeclareQueryable(2, "demo/**", false));
    router.send(Command::UndeclareQueryable(2));
    router.send(Command::DeclareSubscriber(1, "demo/**"));
    until(&engine, "the subscriber listener to match", || {
        *subscribers.lock().unwrap() == [true]
    });
    assert!(told.lock().unwrap().is_empty());
}

/// A matching listener on the queryables counts what a querier's write filter on the same plane
/// counts: any queryable on the key, or only a complete one when the plane requires it, as
/// zenoh-pico's listener is that filter's callback. The CONTROL is a subscriber on the key, which
/// the router declares first and which opens a subscriber filter while neither listener hears it.
#[cfg(all(
    any(feature = "query", feature = "queryable"),
    feature = "key-matching-listener"
))]
#[test]
fn a_queryable_matching_listener_counts_what_its_filter_counts() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let ask = || {
        Some(InterestAsk {
            mapping_id: 0,
            suffix: Some("demo/q"),
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
    let any_id = engine
        .declare_matching_listener(any_plane, "demo/q", sink, false)
        .expect("a session with rows left declares");
    let (sink, complete) = heard();
    engine
        .declare_matching_listener(complete_plane, "demo/q", sink, false)
        .expect("a session with rows left declares");
    let complete_filter = engine
        .declare_write_filter(complete_plane, "demo/q", &WireKey::literal(), ask(), false)
        .expect("a session with ids left declares")
        .id;
    let subscriber_filter = engine
        .declare_write_filter(
            FilterPlane::Subscribers,
            "demo/q",
            &WireKey::literal(),
            ask(),
            false,
        )
        .expect("a session with ids left declares")
        .id;
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

/// A matching listener declared once a peer's subscriber already matches is told so once, as it
/// is declared, as zenoh-pico tells a listener added to a filter that is open. The watch reports
/// the match as it registers; a second report of it would take the first back, and the listener
/// would never hear that it matches. The CONTROL is the write filter, open before the listener.
#[cfg(feature = "key-matching-listener")]
#[test]
fn a_listener_declared_on_a_match_is_told_once() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let filter = engine
        .declare_write_filter(
            FilterPlane::Subscribers,
            "demo/x",
            &WireKey::literal(),
            Some(InterestAsk {
                mapping_id: 0,
                suffix: Some("demo/x"),
                aggregate: false,
            }),
            false,
        )
        .expect("a session with ids left declares")
        .id;
    until(&engine, "the router to see the Interest", || {
        router.seen(|s| s.interests) >= 1
    });
    router.send(Command::DeclareSubscriber(1, "demo/**"));
    until(&engine, "the filter to open", || {
        !engine.write_filter_active(filter)
    });

    let (sink, told) = heard();
    assert!(engine
        .declare_matching_listener(FilterPlane::Subscribers, "demo/x", sink, false)
        .is_ok());
    assert_eq!(
        *told.lock().unwrap(),
        [true],
        "the listener is told it matches as it is declared"
    );
    for _ in 0..20 {
        let _ = SessionDrive::read(&*engine, false);
    }
    assert_eq!(*told.lock().unwrap(), [true], "and told it once");
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
    engine
        .declare_subscriber_on_wire("demo/**", WireKey::literal(), Locality::Any, None, {
            let count = count.clone();
            SubscriberSink::shared(move |_: &dyn SampleView| {
                count.fetch_add(1, Ordering::SeqCst);
            })
        })
        .expect("the session declares the subscriber");
    let filter = engine
        .declare_write_filter(
            FilterPlane::Subscribers,
            "demo/x",
            &WireKey::literal(),
            Some(InterestAsk {
                mapping_id: 0,
                suffix: Some("demo/x"),
                aggregate: false,
            }),
            false,
        )
        .expect("a session with ids left declares")
        .id;
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

/// A session holds a transport while its link is up, and none once its router went away and no
/// dial of it has succeeded since, as zenoh-pico's session holds none until it reconnects: the
/// batch doors answer then that it has no transport. Once it dials the router again it holds one.
#[test]
fn a_session_whose_link_is_lost_holds_no_transport_until_it_dials_again() {
    let router = Router::start(CatchAll::None);
    let port = router.port;
    let engine = open_with(CoopConfig {
        redial_ms: Some(50),
        open_timeout_ms: 300,
        ..config(&router)
    });
    assert!(
        engine.has_transport(),
        "CONTROL: the link to the router is up"
    );

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
        !engine.has_transport(),
        "no link is up and the session listens on no port"
    );

    let _router = Router::start_on(port, CatchAll::None);
    until(&engine, "the session to dial the router again", || {
        !engine.peer_identities().is_empty()
    });
    assert!(engine.has_transport());
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
    engine
        .declare_subscriber_on_wire("demo/**", WireKey::literal(), Locality::Any, None, {
            let count = count.clone();
            SubscriberSink::shared(move |_: &dyn SampleView| {
                count.fetch_add(1, Ordering::SeqCst);
            })
        })
        .expect("the session declares the subscriber");
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
// The read task's wait, which a build of one thread does not start.
#[cfg(feature = "threads")]
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
    engine
        .declare_subscriber_on_wire("demo/**", WireKey::literal(), Locality::Any, None, {
            let stamp = stamp.clone();
            SubscriberSink::shared(move |_: &dyn SampleView| {
                stamp.lock().unwrap().get_or_insert(Instant::now());
            })
        })
        .expect("the session declares the subscriber");
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

/// A record the read task hands out reaches its callback with nothing of the session held but the
/// face's read slot: a put another thread makes while the callback runs, and that the callback
/// waits for, is sent and returns, and the callback returns after it. Turned red by a read that
/// holds the session's lock or the face's send place across a record's callbacks (the put would
/// wait for the callback, which waits for the put), and, as it does not build, by `threads` kept
/// among the features that keep the round where each value has a lock of its own (`build.rs`):
/// the face count read below is the direct read's.
#[cfg(all(feature = "threads", wz_value_locks, not(feature = "group")))]
#[test]
fn a_put_another_thread_makes_inside_a_read_tasks_callback_is_sent_and_both_return() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);
    let (_, turned) = engine.direct_faces();
    assert!(turned >= 1, "the read steps the faces itself");
    let (entered, inside) = channel::<()>();
    let (put_done, put_seen) = channel::<bool>();
    let put_seen = Mutex::new(put_seen);
    let returned = Arc::new(AtomicUsize::new(0));
    let after = returned.clone();
    engine
        .declare_subscriber_on_wire(
            "demo/in/**",
            WireKey::literal(),
            Locality::Any,
            None,
            SubscriberSink::shared(move |_: &dyn SampleView| {
                let _ = entered.send(());
                let sent = put_seen
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5));
                if sent == Ok(true) {
                    after.fetch_add(1, Ordering::SeqCst);
                }
            }),
        )
        .expect("the session declares the subscriber");
    SessionDrive::start_read_task(&*engine).expect("a read task");
    router.send(Command::Push("demo/in/a", b"in"));
    inside
        .recv_timeout(Duration::from_secs(5))
        .expect("the read task calls the callback");
    let sent = engine.publish_on_wire_all(
        "demo/out",
        &WireKey::literal(),
        b"out",
        &PublishOptions::put().with_locality(Locality::Remote),
    );
    put_done
        .send(sent.is_ok())
        .expect("the callback waits for the put");
    until(&engine, "the callback to return after the put", || {
        returned.load(Ordering::SeqCst) == 1
    });
    until(&engine, "the router to receive the put", || {
        router.seen(|s| s.samples.iter().any(|(k, _)| k == "demo/out"))
    });
    SessionDrive::close(&*engine);
}

/// A system that gives no thread for the read task is answered, not panicked on: the start answers
/// `NoThread`, the task is not running, the session is still open, and a start once the system
/// gives a thread starts it. zenoh-pico answers its task creation's error the same way.
#[cfg(feature = "threads")]
#[test]
fn a_start_given_no_thread_is_refused_and_a_later_start_runs_the_task() {
    use wz_capi_port::ReadTaskStartRefused;

    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    assert_eq!(
        engine.start_reader(|_| None),
        Err(ReadTaskStartRefused::NoThread)
    );
    assert!(!SessionDrive::read_task_is_running(&*engine));
    assert!(
        !SessionDrive::is_closed(&*engine),
        "a refused start leaves the session open"
    );

    SessionDrive::start_read_task(&*engine).expect("a read task once a thread is given");
    assert!(SessionDrive::read_task_is_running(&*engine));
    SessionDrive::close(&*engine);
}

/// Starting the read task makes nothing of the heap of its own: what the thread runs is a value
/// handed to the system's spawn, and the stop moves the engine's run of tasks, so no box and no
/// word is made for either. A system that gives no thread is the start's every step but the
/// thread. Turned red by a body boxed for the spawn or a stop word shared with the task.
#[cfg(feature = "threads")]
#[test]
fn starting_the_read_task_makes_nothing_of_the_heap_of_its_own() {
    use wz_capi_port::ReadTaskStartRefused;

    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let mut refused = None;
    let allocations = redial_heap::counted(|| {
        refused = Some(engine.start_reader(|_| None));
    });
    assert_eq!(refused, Some(Err(ReadTaskStartRefused::NoThread)));
    assert_eq!(
        allocations, 0,
        "the start boxes nothing and makes no stop word"
    );
    SessionDrive::start_read_task(&*engine).expect("a read task once a thread is given");
    SessionDrive::stop_read_task(&*engine).expect("stopped from the test's thread");
    assert!(
        !SessionDrive::read_task_is_running(&*engine),
        "CONTROL: the stop ends the task the start ran"
    );
    SessionDrive::close(&*engine);
}

/// The session's peers are read one at a time, by key: the dial role's face is the one peer, a
/// read past its key finds none, and the walk a C ABI makes hands each identity on with the
/// session free, so what it is handed to may read the session again (a C callback may call into
/// its session).
#[test]
fn the_peers_are_read_one_at_a_time_and_handed_on_with_the_session_free() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let (key, peer) = engine.next_peer(0).expect("the router is a peer");
    assert_eq!(peer.zid.to_vec(), vec![ROUTER_ZID; 4]);
    assert_eq!(peer.whatami, 0, "a router, in its wire form");
    assert_eq!(engine.next_peer(key + 1), None, "no peer past the one");
    let mut handed = Vec::new();
    wz_capi_port::each_peer(&*engine, |peer| {
        assert!(
            engine.next_peer(0).is_some(),
            "the session is free while an identity is handed on"
        );
        handed.push(peer);
    });
    assert_eq!(handed, [peer]);
    assert!(
        engine.group_member_zids().is_empty(),
        "a session that joined no group has no member"
    );
}

/// An open asked for a place for the ABI's handle lends it from the session's arena, its last row:
/// the place is aligned as a span starts, holds the layout, takes the arena two spans more than the
/// same open without it, and is the program's to write; a handle aligned past a span is refused.
#[test]
fn an_open_asked_for_a_handle_lends_its_place_from_the_sessions_arena() {
    use crate::arena::{AllocatorMemory, ArenaPlan, ArenaRefused};
    use crate::OpenKeyIds;
    use core::alloc::Layout;
    use wz_session_core::bounded::{Arena, ARENA_ALIGN};
    use wz_session_core::byte_cells::LentByteCells;
    use wz_session_core::policy::SessionPolicy;

    #[repr(C, align(8))]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Handle([u8; 40]);
    let layout = Layout::new::<Handle>();
    let router = Router::start(CatchAll::None);
    let holding = Engine::open_made_in(
        host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        PosixEntropy,
        || config(&router),
        SessionPolicy::defaults(),
        OpenKeyIds::none(),
        crate::arena::OpenStorage {
            memory: &AllocatorMemory,
            plan: crate::arena::PlanFrom::Config(Box::leak(Box::new(
                crate::arena::HeldPlaces::handle(layout),
            ))),
        },
    )
    .expect("the session opens");
    let other = Router::start(CatchAll::None);
    let without = open(&other);
    let place_rows = Arena::span(LentByteCells::FLAG_BYTES)
        .and_then(|flag| Arena::span(layout.size()).map(|bytes| flag + bytes));
    assert_eq!(
        Some(holding.arena_bytes()),
        place_rows.map(|rows| without.arena_bytes() + rows),
        "the place is two spans of the arena"
    );

    let drive = Engine::into_drive(holding.clone());
    let place = drive
        .handle_place()
        .expect("the open was asked for a place");
    assert!(place.bytes() >= layout.size());
    assert_eq!(place.as_ptr().as_ptr() as usize % ARENA_ALIGN, 0);
    // SAFETY: the place holds a `Handle`'s layout, nothing else uses it, and the engine stands.
    unsafe {
        place
            .as_ptr()
            .cast::<Handle>()
            .as_ptr()
            .write(Handle([7; 40]));
        assert_eq!(
            place.as_ptr().cast::<Handle>().as_ptr().read(),
            Handle([7; 40])
        );
    }
    drop(drive);
    assert!(
        Engine::into_drive(without.clone()).handle_place().is_none(),
        "an open asked for none lends none"
    );

    let mut plan = ArenaPlan::of(&config(&router), &config(&router).limits).expect("a plan");
    assert_eq!(
        plan.holding(&crate::arena::HeldPlaces::handle(
            Layout::from_size_align(32, 2 * ARENA_ALIGN).expect("a layout")
        )),
        Err(ArenaRefused::TooLarge),
        "a handle aligned past a span has no place"
    );
}

/// An open asked for places of an entity kind lends one for each row the session keeps of the kind,
/// from its own arena: every one is lent once and the one past them is refused, a place given back
/// is lent again, and another session's places are its own, so one session at its limit refuses
/// nothing to the other. Turned red by places shared between sessions, or counted by anything but
/// the session's own limit.
#[test]
fn an_open_lends_a_place_for_each_row_of_an_entity_kind_from_its_own_arena() {
    use crate::arena::{AllocatorMemory, ArenaPlan, EntityKind, HeldPlaces};
    use crate::OpenKeyIds;
    use core::alloc::Layout;
    use wz_capi_port::PlaceLender;
    use wz_session_core::bounded::ARENA_ALIGN;
    use wz_session_core::policy::SessionPolicy;

    let layout = Layout::from_size_align(48, 8).expect("a layout");
    let held = HeldPlaces::NONE.with_entity(EntityKind::Subscriber, layout);
    let open = |router: &Router| {
        Engine::open_made_in(
            host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
            PosixClock,
            PosixEntropy,
            || config(router),
            SessionPolicy::defaults(),
            OpenKeyIds::none(),
            crate::arena::OpenStorage {
                memory: &AllocatorMemory,
                plan: crate::arena::PlanFrom::Config(Box::leak(Box::new(held))),
            },
        )
        .expect("the session opens")
    };
    let (router, other_router) = (Router::start(CatchAll::None), Router::start(CatchAll::None));
    let (one, other) = (open(&router), open(&other_router));
    let rows = ArenaPlan::of(&config(&router), &config(&router).limits)
        .expect("a plan")
        .entities()
        .of_kind(EntityKind::Subscriber);
    assert!(rows > 0, "the session keeps subscribers");
    assert_eq!(one.place_counts(EntityKind::Subscriber), (0, rows));
    assert_eq!(
        one.place_counts(EntityKind::Publisher),
        (0, 0),
        "a kind the open was asked for no place of has none"
    );
    assert_eq!(one.claim_place(EntityKind::Publisher), None);

    let mut lent: Vec<_> = (0..rows)
        .map(|_| {
            one.claim_place(EntityKind::Subscriber)
                .expect("a place for each row")
        })
        .collect();
    assert!(lent.iter().all(|place| {
        place.kind() == EntityKind::Subscriber
            && place.as_ptr().as_ptr() as usize % ARENA_ALIGN == 0
    }));
    assert_eq!(
        one.claim_place(EntityKind::Subscriber),
        None,
        "none past them"
    );
    let theirs = other
        .claim_place(EntityKind::Subscriber)
        .expect("the other session's places are its own");
    assert_eq!(other.place_counts(EntityKind::Subscriber), (1, rows));
    let theirs = one
        .give_back_place(theirs)
        .expect_err("a session takes back no place another lent");
    assert_eq!(other.place_counts(EntityKind::Subscriber), (1, rows));

    let first = lent.pop().expect("a lent place");
    let at = first.as_ptr();
    assert_eq!(one.give_back_place(first), Ok(()));
    let again = one
        .claim_place(EntityKind::Subscriber)
        .expect("a place given back is lent again");
    assert_eq!(again.as_ptr(), at);
    lent.push(again);
    for place in lent {
        assert_eq!(one.give_back_place(place), Ok(()));
    }
    assert_eq!(other.give_back_place(theirs), Ok(()));
    assert_eq!(one.place_counts(EntityKind::Subscriber), (0, rows));
    assert_eq!(other.place_counts(EntityKind::Subscriber), (0, rows));
}

/// A place the ABI gives back on the thread that holds its session's lock (the last count of a
/// get let go of by a drop made under the lock) would wait on itself: a debug build fails there at
/// once, so no such path survives a test. Turned red by a hold of the lock the thread does not
/// mark.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "taken again on the thread that holds it")]
fn a_place_given_back_under_its_sessions_lock_fails_instead_of_waiting() {
    use crate::arena::{AllocatorMemory, EntityKind, HeldPlaces, OpenStorage};
    use crate::OpenKeyIds;
    use core::alloc::Layout;
    use wz_capi_port::PlaceLender;
    use wz_session_core::policy::SessionPolicy;

    let layout = Layout::from_size_align(48, 8).expect("a layout");
    let held = HeldPlaces::NONE.with_entity(EntityKind::Subscriber, layout);
    let router = Router::start(CatchAll::None);
    let engine = Engine::open_made_in(
        host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        PosixEntropy,
        || config(&router),
        SessionPolicy::defaults(),
        OpenKeyIds::none(),
        OpenStorage {
            memory: &AllocatorMemory,
            plan: crate::arena::PlanFrom::Config(Box::leak(Box::new(held))),
        },
    )
    .expect("the session opens");
    let place = engine
        .claim_place(EntityKind::Subscriber)
        .expect("a place for a subscriber");
    let _ = engine.under_the_lock(|| engine.give_back_place(place));
}

/// A session of the `advanced-cache` build keeps a ring of `ADVANCED_CACHE_BYTES` for its caches,
/// zeroed at its open and its own: what one call writes the next reads, and another session's
/// ring is another span.
#[cfg(feature = "advanced-cache")]
#[test]
fn an_open_keeps_a_zeroed_ring_of_its_own_for_its_caches() {
    use wz_session_core::caps::ADVANCED_CACHE_BYTES;

    let (router, other_router) = (Router::start(CatchAll::None), Router::start(CatchAll::None));
    let (one, other) = (open(&router), open(&other_router));
    let ring = one.cache_bytes().expect("the session keeps a ring");
    let mut seen = (0, false);
    ring.with_cache_bytes(&mut |bytes| {
        seen = (bytes.len(), bytes.iter().all(|byte| *byte == 0));
        if let Some(first) = bytes.first_mut() {
            *first = 7;
        }
    });
    assert_eq!(
        seen,
        (ADVANCED_CACHE_BYTES, true),
        "the ring is the limit's, zeroed"
    );
    other
        .cache_bytes()
        .expect("the other session keeps a ring")
        .with_cache_bytes(&mut |bytes| {
            if let Some(first) = bytes.first_mut() {
                *first = 9;
            }
        });
    let mut first = None;
    ring.with_cache_bytes(&mut |bytes| first = bytes.first().copied());
    assert_eq!(
        first,
        Some(7),
        "a session's ring is its own and keeps what was written"
    );
}

/// The C handle's drive is the engine's own allocation, held by value: the engine it hands out is
/// the one it holds, and letting go of it closes the session while the engine itself lives on in
/// the other holders, as an entity declared on a session that is dropped finds it closed.
#[test]
fn a_drive_is_the_engines_own_allocation_and_its_drop_closes_the_session() {
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    let drive: crate::CoopDrive<PosixLinks, PosixClock> = Engine::into_drive(engine.clone());
    assert!(
        core::ptr::addr_eq(
            EngineHold::as_ptr(&drive.engine()),
            EngineHold::as_ptr(&engine)
        ),
        "the drive hands out the engine it holds, no copy of it"
    );
    assert!(!drive.is_closed());
    drop(drive);
    assert!(
        SessionDrive::is_closed(&*engine),
        "the handle's drop closes the session"
    );
}

/// A peer that was told an id names it. A zenoh router sends a subscriber the samples it routes
/// to it by the key expression the subscriber declared to it (the receiver's id space, `M=0`),
/// not by the literal, and a session that cannot resolve the id drops the sample: the engine
/// heard nothing through a router for want of this, while a peer that names its own aliases (the
/// sender's space) was heard all along. The id is one the session declared, and the key it
/// resolves to is what that declaration says.
///
/// The CONTROL is the literal key, which the same subscriber hears: a drop is then the id's, and
/// not the subscription's.
#[test]
fn a_sample_naming_an_id_the_session_declared_is_resolved_and_delivered() {
    let router = Router::start(CatchAll::Held);
    let engine = open(&router);

    let id = engine
        .acquire_keyexpr("demo/named")
        .expect("a key expression the link takes")
        .mapping_id();
    let seen = Arc::new(Mutex::new(Vec::<(String, Vec<u8>)>::new()));
    let record = seen.clone();
    let declares_before = router.seen(|s| s.declares);
    engine
        .declare_subscriber_on_wire(
            "demo/named",
            WireKey::aliased(id, None),
            Locality::Any,
            None,
            {
                let record = record.clone();
                SubscriberSink::shared(move |sample: &dyn SampleView| {
                    record
                        .lock()
                        .unwrap()
                        .push((sample.keyexpr().to_string(), sample.payload().to_vec()));
                })
            },
        )
        .expect("the session declares the subscriber");
    until(&engine, "the router to see the declarations", || {
        router.seen(|s| s.declares) > declares_before
    });

    router.send(Command::Push("demo/named", b"by the literal"));
    until(&engine, "the literal push", || {
        seen.lock().unwrap().len() == 1
    });

    router.send(Command::PushReceiverAlias(id, b"by the id"));
    until(&engine, "the push naming the declared id", || {
        seen.lock().unwrap().len() == 2
    });
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            ("demo/named".to_owned(), b"by the literal".to_vec()),
            ("demo/named".to_owned(), b"by the id".to_vec()),
        ],
        "the id resolves to the key the session declared for it"
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

/// The redeclare door: an open session tells the peer of its one link everything it holds again
/// and answers the count of links, and a closed one answers that it is closed.
#[test]
fn a_session_redeclares_over_each_link_that_is_up_and_a_closed_one_refuses() {
    use wz_capi_port::RedeclareRefusal;
    let router = Router::start(CatchAll::None);
    let engine = open(&router);
    assert_eq!(SessionEngine::redeclare(&*engine), Ok(1), "the dial link");
    router.send(Command::Close);
    drop(router);
    until(&engine, "the session to end", || {
        SessionDrive::is_closed(&*engine)
    });
    assert_eq!(
        SessionEngine::redeclare(&*engine),
        Err(RedeclareRefusal::Closed)
    );
}

/// `zid-derivation = address-ports`: the zid is the first listen endpoint's own address, the
/// lowest tcp and udp ports and the eight bytes the source gives, in the wire form; a session
/// whose listeners name no address of the node is refused with the reason, and a source that
/// fails is the entropy refusal a random zid gets.
#[test]
fn a_derived_zid_is_the_listeners_address_and_ports_then_the_sources_bytes() {
    use crate::engine::derived_zid;
    use crate::OpenError;
    use wz_session_core::entropy::{EntropySource, EntropyUnavailable};
    use wz_session_core::zid_derivation::ZidDerivationError;

    struct Seeded(u8);
    impl EntropySource for Seeded {
        fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
            for byte in buf.iter_mut() {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }
    struct Failing;
    impl EntropySource for Failing {
        fn try_fill_bytes(&mut self, _buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
            Err(EntropyUnavailable)
        }
    }

    let listen = std::vec![
        "udp/10.77.0.5:28001".to_string(),
        "tcp/10.77.0.5:28000".to_string(),
    ];
    let zid = derived_zid(&listen, None, &mut Seeded(0x31)).expect("a listener names the node");
    let expected: [u8; 16] = [
        10, 77, 0, 5, 0x60, 0x6D, 0x61, 0x6D, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    ];
    assert_eq!(zid.to_vec(), expected.to_vec());
    assert_eq!(
        derived_zid(&["tcp/0.0.0.0:28000".to_string()], None, &mut Seeded(1)),
        Err(OpenError::ZidDerivation(ZidDerivationError::NoAddress))
    );
    assert_eq!(
        derived_zid(&listen, None, &mut Failing),
        Err(OpenError::EntropyUnavailable)
    );

    // A node that only dials has no listener: the address its config states heads the zid, both
    // port fields are 0, as the address-ports rule writes them for a node with no listener of
    // either protocol, and the source's bytes follow.
    let zid = derived_zid(
        std::iter::empty::<&str>(),
        Some([127, 0, 0, 1]),
        &mut Seeded(0x31),
    )
    .expect("the stated address names the node");
    let expected: [u8; 16] = [
        127, 0, 0, 1, 0, 0, 0, 0, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    ];
    assert_eq!(zid.to_vec(), expected.to_vec());
    // The stated address heads the zid over a listener's, whose ports follow it.
    let zid = derived_zid(&listen, Some([192, 0, 2, 7]), &mut Seeded(0x31))
        .expect("the stated address names the node");
    let expected: [u8; 16] = [
        192, 0, 2, 7, 0x60, 0x6D, 0x61, 0x6D, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    ];
    assert_eq!(zid.to_vec(), expected.to_vec());
    assert_eq!(
        derived_zid(std::iter::empty::<&str>(), None, &mut Seeded(1)),
        Err(OpenError::ZidDerivation(ZidDerivationError::NoAddress)),
        "a node that only dials and states no address"
    );
}

/// A session that only dials, under `zid-derivation = address-ports`, opens on the zid its
/// config's own address heads, its port fields 0; the same config without the address is refused
/// with the reason before anything is dialled.
#[test]
fn a_session_that_only_dials_opens_on_the_zid_its_stated_address_heads() {
    use crate::arena::AllocatorMemory;
    use crate::{OpenError, OpenKeyIds};
    use wz_session_core::policy::{SessionPolicy, ZidDerivation};
    use wz_session_core::zid_derivation::ZidDerivationError;

    let mut policy = SessionPolicy::defaults();
    if policy
        .select_zid_derivation(ZidDerivation::AddressPorts)
        .is_err()
    {
        // A build whose domain of the policy leaves the value out derives no zid at all.
        return;
    }
    let open = |config: CoopConfig| {
        Engine::open_made_in(
            host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
            PosixClock,
            PosixEntropy,
            move || config,
            policy,
            OpenKeyIds::none(),
            crate::arena::OpenStorage {
                memory: &AllocatorMemory,
                plan: crate::arena::PlanFrom::Config(&crate::arena::HeldPlaces::NONE),
            },
        )
    };
    let router = Router::start(CatchAll::None);
    let engine = open(CoopConfig {
        zid: None,
        owned_address: Some([127, 0, 0, 1]),
        ..config(&router)
    })
    .expect("the session opens");
    assert_eq!(
        &SessionEngine::zid(&*engine)[..8],
        &[127, 0, 0, 1, 0, 0, 0, 0],
        "the stated address, then no listener's ports"
    );
    SessionDrive::close(&*engine);
    let refused = open(CoopConfig {
        zid: None,
        ..config(&router)
    })
    .err();
    assert_eq!(
        refused,
        Some(OpenError::ZidDerivation(ZidDerivationError::NoAddress))
    );
}

/// A session whose source gives nothing opens no link: its config states its zid, so the first
/// draw is the cookie key of the dial's handshake, and the open is refused with the entropy
/// refusal. Turned red by a start of a link that dials on without a key, or that names the
/// refusal otherwise.
#[test]
fn an_open_whose_source_gives_no_cookie_key_is_refused_with_the_entropy_refusal() {
    use crate::OpenError;
    use wz_session_core::entropy::{EntropySource, EntropyUnavailable};

    struct Dry;
    impl EntropySource for Dry {
        fn try_fill_bytes(&mut self, _buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
            Err(EntropyUnavailable)
        }
    }

    let router = Router::start(CatchAll::None);
    let refused = Engine::open(
        host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        Dry,
        config(&router),
    )
    .err();
    assert_eq!(refused, Some(OpenError::EntropyUnavailable));
}

/// Bytes the open makes a zid of (drawn or derived) are refused when they are no zid: all zero
/// bytes, none, and seventeen are refused, and one and sixteen, trailing zeros trimmed, are the
/// zid the session announces.
#[test]
fn made_bytes_of_zero_or_seventeen_are_refused_as_a_zid() {
    use crate::engine::wire_zid;
    use crate::OpenError;
    use wz_session_core::session_init_params::ZidError;

    assert_eq!(
        wire_zid(&[0, 0, 0, 0]),
        Err(OpenError::InvalidZid(ZidError::AllZero { len: 4 }))
    );
    assert_eq!(
        wire_zid(&[]),
        Err(OpenError::InvalidZid(ZidError::LengthOutOfRange { len: 0 }))
    );
    assert_eq!(
        wire_zid(&[0x11; 17]),
        Err(OpenError::InvalidZid(ZidError::LengthOutOfRange {
            len: 17
        }))
    );
    assert_eq!(
        wire_zid(&[0x11, 0, 0]).map(|zid| zid.to_vec()),
        Ok(std::vec![0x11])
    );
    assert_eq!(
        wire_zid(&[0x22; 16]).map(|zid| zid.to_vec()),
        Ok(std::vec![0x22; 16])
    );
}

/// The limits an open holds its tables to are read where the config holds them: every reader
/// of them is handed the config's own, and no copy is made to read them. Turned red by a
/// resolver that hands back limits of its own.
#[test]
fn the_open_reads_its_limits_where_the_config_holds_them() {
    use crate::engine::resolve_limits;

    let config = client_config();
    assert!(core::ptr::eq(resolve_limits(&config), &config.limits));
}

/// A zid's wire form ends at its last non-zero byte, whatever comes before it, and a zid whose
/// last byte is not zero is its own wire form.
#[test]
fn the_wire_form_of_a_zid_ends_at_its_last_non_zero_byte() {
    use crate::engine::wire_form;

    assert_eq!(wire_form(SessionZid::from([0x11, 0, 0, 0])), [0x11]);
    assert_eq!(
        wire_form(SessionZid::from([0, 0x22, 0, 0x33, 0])),
        [0, 0x22, 0, 0x33]
    );
    assert_eq!(wire_form(SessionZid::from([0x44; 16])), [0x44; 16]);
}

/// A drawn zid is the source's sixteen bytes up to the last non-zero one, and sixteen zero bytes
/// are the refusal of a source that gave none; bytes past sixteen are refused by their length as
/// given, trailing zeros and all. Turned red by a wire form taken before the length is judged, or
/// by a draw of zero bytes refused as anything but the entropy refusal.
#[test]
fn a_drawn_zid_is_trimmed_and_a_draw_of_zero_bytes_is_the_entropy_refusal() {
    use crate::engine::{fresh_zid, wire_zid};
    use crate::OpenError;
    use wz_session_core::entropy::{EntropySource, EntropyUnavailable};
    use wz_session_core::session_init_params::ZidError;

    struct Gives([u8; 16]);
    impl EntropySource for Gives {
        fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
            for (byte, given) in buf.iter_mut().zip(self.0) {
                *byte = given;
            }
            Ok(())
        }
    }

    let mut inner_zero = [0u8; 16];
    inner_zero[0] = 0x11;
    inner_zero[2] = 0x22;
    assert_eq!(
        fresh_zid(&mut Gives(inner_zero)).map(|zid| zid.to_vec()),
        Ok(std::vec![0x11, 0, 0x22])
    );
    assert_eq!(
        fresh_zid(&mut Gives([0x33; 16])).map(|zid| zid.to_vec()),
        Ok(std::vec![0x33; 16])
    );
    assert_eq!(
        fresh_zid(&mut Gives([0; 16])),
        Err(OpenError::EntropyUnavailable)
    );
    let mut long = [0u8; 17];
    long[0] = 0x44;
    assert_eq!(
        wire_zid(&long),
        Err(OpenError::InvalidZid(ZidError::LengthOutOfRange {
            len: 17
        }))
    );
}

/// A build without the shared key ids names a key as upstream does and no other way: a session
/// opened under any other key-wire form is refused before it dials, and `declared` opens on as
/// before (and fails here for the endpoint the config does not name).
#[cfg(not(feature = "shared-key-ids"))]
#[test]
fn a_key_wire_form_but_declared_is_refused_in_a_build_without_shared_key_ids() {
    use crate::{KeyWireFormRefused, OpenError};
    use wz_session_core::policy::{KeyWireForm, SessionPolicy};

    let open = |form: KeyWireForm| {
        let mut policy = SessionPolicy::defaults();
        policy
            .select_key_wire_form(form)
            .expect("a host build allows every value of the key-wire form");
        Engine::open_with_policy(
            host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
            PosixClock,
            PosixEntropy,
            client_config(),
            policy,
        )
        .err()
    };
    for form in [KeyWireForm::Shared, KeyWireForm::Literal] {
        assert_eq!(
            open(form),
            Some(OpenError::KeyWireForm(KeyWireFormRefused::NotInBuild))
        );
    }
    assert_eq!(open(KeyWireForm::Declared), Some(OpenError::NoEndpoint));
}

/// A width of sequence numbers the build's `sn-resolution` domain leaves out is refused at the
/// open, before anything is reserved or dialled, and a width it holds goes on to the endpoints.
#[test]
fn a_width_outside_the_sn_resolution_domain_is_refused_at_the_open() {
    use crate::OpenError;
    use wz_session_core::policy::SnResolution;
    use wz_session_core::policy_binding::{OutsideDomain, PolicyValue};

    for width in SnResolution::WIDTHS {
        let mut config = client_config();
        config.sn_resolution = width;
        let refused = Engine::open(
            host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
            PosixClock,
            PosixEntropy,
            config,
        )
        .err();
        let want = if <SnResolution as PolicyValue>::DOMAIN.contains(width) {
            OpenError::NoEndpoint
        } else {
            OpenError::SnResolution(OutsideDomain { value: width })
        };
        assert_eq!(refused, Some(want), "{}", width.id());
    }
}

/// A group whose width of sequence numbers the build's `sn-resolution` domain leaves out is
/// refused at the open with that width, before the group is looked at, whether or not the build
/// has groups; a width the domain holds is not refused for its width.
#[test]
fn a_group_of_a_width_outside_the_sn_resolution_domain_is_refused_at_the_open() {
    use crate::OpenError;
    use wz_capi_port::group::{GroupDeclarations, GroupJoin, GroupProfile};
    use wz_session_core::policy::SnResolution;
    use wz_session_core::policy_binding::{OutsideDomain, PolicyValue};

    for width in SnResolution::WIDTHS {
        let refused = Engine::open(
            host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
            PosixClock,
            PosixEntropy,
            CoopConfig {
                groups: vec![GroupJoin {
                    endpoint: "udp/239.7.7.7:7447#iface=lan7".to_owned(),
                    profile: GroupProfile {
                        lease_ms: 10_000,
                        join_interval_ms: 2_500,
                        max_sessions: None,
                        seq_num_res: width,
                        req_id_res: 0x02,
                        batch_size: 2_048,
                        is_qos: false,
                        compression: false,
                        join_rule: wz_session_core::multicast_params::GroupJoinRule::Pico,
                    },
                    is_shm: false,
                    declarations: GroupDeclarations::Entities,
                }],
                ..client_config()
            },
        )
        .err();
        if <SnResolution as PolicyValue>::DOMAIN.contains(width) {
            assert!(
                !matches!(refused, Some(OpenError::SnResolution(_))),
                "{}: a held width is not refused for its width",
                width.id()
            );
        } else {
            assert_eq!(
                refused,
                Some(OpenError::SnResolution(OutsideDomain { value: width })),
                "{}",
                width.id()
            );
        }
    }
}

/// A build without groups refuses a session that names one by name, before it dials anything,
/// and opens no group instead of it: the session would be missing the group it was told to join.
#[cfg(not(feature = "group"))]
#[test]
fn a_build_without_groups_refuses_a_session_that_joins_one() {
    use crate::{EndpointRefusal, OpenError, Refusal};
    use wz_capi_port::group::{GroupDeclarations, GroupJoin, GroupProfile};

    let refused = Engine::open(
        host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        PosixEntropy,
        CoopConfig {
            groups: vec![GroupJoin {
                endpoint: "udp/239.7.7.7:7447#iface=lan7".to_owned(),
                profile: GroupProfile {
                    lease_ms: 10_000,
                    join_interval_ms: 2_500,
                    max_sessions: None,
                    seq_num_res: wz_session_core::policy::SnResolution::Bits32,
                    req_id_res: 0x02,
                    batch_size: 2_048,
                    is_qos: false,
                    compression: false,
                    join_rule: wz_session_core::multicast_params::GroupJoinRule::Pico,
                },
                is_shm: false,
                declarations: GroupDeclarations::Entities,
            }],
            ..client_config()
        },
    )
    .err();
    assert_eq!(
        refused,
        Some(OpenError::Group(EndpointRefusal::new(
            "udp/239.7.7.7:7447#iface=lan7",
            Refusal::GroupsNotBuilt,
        )))
    );
}

/// A refusal is a value, and reads as the endpoint and the reason only when a program prints it:
/// one that names no endpoint reads as the reason alone, and the reasons that carry another's
/// refusal read as it.
#[test]
fn an_endpoint_refusal_reads_as_its_endpoint_and_its_reason() {
    use crate::{EndpointRefusal, Refusal};
    use wz_runtime_coop::locator_text::DialRefused;
    use wz_runtime_coop::session_drive::LinkOpenError;

    let refusal = |endpoint: &str, why| EndpointRefusal::new(endpoint, why).to_string();
    assert_eq!(
        refusal("udp/239.7.7.7:7447", Refusal::GroupsNotBuilt),
        "udp/239.7.7.7:7447: joining a group is not built"
    );
    assert_eq!(
        refusal("tcp/127.0.0.1:7447", Refusal::ListeningNotBuilt),
        "tcp/127.0.0.1:7447: listening is not built"
    );
    assert_eq!(
        refusal("tcp/127.0.0.1:7447", Refusal::NoAnswerInTime),
        "tcp/127.0.0.1:7447: no answer in time"
    );
    assert_eq!(
        refusal("tcp/127.0.0.1:7447", Refusal::Link(LinkOpenError::Refused)),
        "tcp/127.0.0.1:7447: Refused"
    );
    assert_eq!(
        refusal("foo/bar", Refusal::Locator(DialRefused::Unsupported)),
        "foo/bar: Unsupported"
    );
    assert_eq!(
        refusal(
            "tcp/127.0.0.1:7447",
            Refusal::HandshakeClosed(CloseReason::Generic)
        ),
        "tcp/127.0.0.1:7447: the handshake ended: Generic"
    );
    assert_eq!(refusal("", Refusal::LinkLost), "the link was lost");
    assert_eq!(
        refusal("tcp/127.0.0.1:7447", Refusal::TextTooLong),
        "tcp/127.0.0.1:7447: the endpoint is longer than MAX_LOCATOR_LEN"
    );
    // A text longer than a row keeps the whole characters that fit in one, and no more.
    let long = format!(
        "tcp/{}",
        "\u{e9}".repeat(wz_session_core::caps::MAX_LOCATOR_LEN)
    );
    let kept = EndpointRefusal::new(&long, Refusal::TextTooLong).endpoint;
    assert!(
        long.starts_with(kept.as_str()),
        "a cut at a character's end"
    );
    assert!(kept.len() <= wz_session_core::caps::MAX_LOCATOR_LEN);
    assert!(
        kept.len() + 2 > wz_session_core::caps::MAX_LOCATOR_LEN,
        "every whole character that fits is kept"
    );
}

/// A dial refused before any link is made names its endpoint and its cause: a text that names no
/// address the build reads, and no host either, is refused by the locator, a protocol the links do
/// not carry by the links. Turned red by a refusal that names the other cause or loses the
/// endpoint.
#[test]
fn a_dial_refused_at_once_names_its_endpoint_and_its_cause() {
    use crate::{EndpointRefusal, OpenError, Refusal};
    use wz_runtime_coop::locator_text::DialRefused;
    use wz_runtime_coop::session_drive::LinkOpenError;

    for (endpoint, why) in [
        (
            "tcp/127.0.0.256:7447",
            Refusal::Locator(DialRefused::BadAddress),
        ),
        (
            "tls/127.0.0.1:7447",
            Refusal::Link(LinkOpenError::Unsupported),
        ),
    ] {
        let refused = open_with_result(CoopConfig {
            endpoints: vec![endpoint.into()],
            ..client_config()
        });
        assert_eq!(
            refused,
            Some(OpenError::Unreachable(EndpointRefusal::new(endpoint, why))),
            "{endpoint}"
        );
    }
}

/// A build that listens without the udp listener (`listen` without `udp-listen`, as the zenoh-pico
/// preset builds a peer) refuses a `udp/` endpoint to listen on by name, as a scheme its links do
/// not carry: zenoh-pico's POSIX link has no such listener either. The CONTROL is a `tcp/` endpoint
/// in the same build, which opens. Turned red by a udp port bound in such a build, or by a refusal
/// that loses the endpoint or its cause.
#[cfg(all(feature = "listen", not(feature = "udp-listen")))]
#[test]
fn a_build_without_the_udp_listener_refuses_a_udp_endpoint_to_listen_on() {
    use crate::{EndpointRefusal, OpenError, Refusal};
    use wz_runtime_coop::session_drive::LinkOpenError;

    let listening_on = |endpoint: &str| CoopConfig {
        whatami: WhatAmI::Peer,
        listen: vec![endpoint.to_owned()],
        ..client_config()
    };
    let udp = "udp/127.0.0.1:0";
    assert_eq!(
        open_with_result(listening_on(udp)),
        Some(OpenError::Listen(EndpointRefusal::new(
            udp,
            Refusal::Link(LinkOpenError::Unsupported)
        )))
    );
    assert_eq!(
        open_with_result(listening_on("tcp/127.0.0.1:0")),
        None,
        "CONTROL: a tcp/ endpoint opens"
    );
}

/// The open writes each endpoint's text into a row of the session's arena: one longer than a row
/// is refused by name, an endpoint to dial as unreachable and one to listen on as a port not
/// listened on, and more endpoints than the build's rows refuse the arena. A face attached after
/// the open keeps its endpoint's text in a row's length too, and one longer is refused before any
/// dial. The CONTROL is the open of the same config with a text that fits.
#[test]
fn an_endpoint_text_longer_than_a_row_is_refused_by_name() {
    use crate::arena::ArenaRefused;
    use crate::{EndpointRefusal, OpenError, Refusal};
    use wz_session_core::caps::{MAX_LOCATOR_LEN, MAX_STATIC_CONNECT};

    let router = Router::start(CatchAll::None);
    let long = format!("tcp/127.0.0.1:{}", "7".repeat(MAX_LOCATOR_LEN));
    let refused = open_with_result(CoopConfig {
        endpoints: vec![long.clone()],
        ..config(&router)
    });
    assert_eq!(
        refused,
        Some(OpenError::Unreachable(EndpointRefusal::new(
            &long,
            Refusal::TextTooLong
        )))
    );
    let refused = open_with_result(CoopConfig {
        listen: vec![long.clone()],
        max_faces: 0,
        accept_pending: 1,
        ..config(&router)
    });
    assert_eq!(
        refused,
        Some(OpenError::Listen(EndpointRefusal::new(
            &long,
            Refusal::TextTooLong
        )))
    );
    let refused = open_with_result(CoopConfig {
        endpoints: vec![router.endpoint(); MAX_STATIC_CONNECT + 1],
        ..config(&router)
    });
    assert!(
        matches!(
            refused,
            Some(OpenError::Arena(ArenaRefused::Limit {
                limit: crate::arena::ArenaLimit::MaxStaticConnect,
                ..
            }))
        ),
        "{refused:?}"
    );
    // A face is attached beside the dial role's only in a build that adds faces (`listen`).
    #[cfg(feature = "listen")]
    {
        let engine = open(&router);
        assert_eq!(
            engine.attach_face(&long).err(),
            Some(OpenError::Unreachable(EndpointRefusal::new(
                &long,
                Refusal::TextTooLong
            )))
        );
    }
}

/// What the open of `config` was refused with, `None` when it opened.
fn open_with_result(config: CoopConfig) -> Option<crate::OpenError> {
    Engine::open(
        host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        PosixEntropy,
        config,
    )
    .err()
}

/// The open with the config's maker answers what the open with the config answers, the maker run
/// once whether the open succeeds or is refused: a config that names nothing to dial or listen on
/// is refused with `NoEndpoint` both ways, after the maker ran once. Turned red by an open that
/// makes the config twice, or reads it otherwise than `open_in`.
#[test]
fn a_config_made_inside_the_open_is_refused_as_the_config_handed_in() {
    use crate::arena::AllocatorMemory;
    use crate::{OpenError, OpenKeyIds};
    use std::cell::Cell;
    use wz_session_core::policy::SessionPolicy;

    let made = Cell::new(0u32);
    let refused = Engine::open_made_in(
        host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        PosixEntropy,
        || {
            made.set(made.get() + 1);
            client_config()
        },
        SessionPolicy::defaults(),
        OpenKeyIds::none(),
        crate::arena::OpenStorage {
            memory: &AllocatorMemory,
            plan: crate::arena::PlanFrom::Config(&crate::arena::HeldPlaces::NONE),
        },
    )
    .err();
    assert_eq!(refused, Some(OpenError::NoEndpoint));
    assert_eq!(made.get(), 1, "the maker runs once, inside the open");
    let handed_in = Engine::open(
        host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        PosixEntropy,
        client_config(),
    )
    .err();
    assert_eq!(
        handed_in, refused,
        "CONTROL: the config handed in is refused the same way"
    );
}

/// A session opened from a config its maker builds is the session the same config opens handed
/// in: a listener on a loopback port the kernel picks announces the zid the config states and
/// reserved an arena of the same bytes either way.
#[cfg(feature = "listen")]
#[test]
fn a_config_made_inside_the_open_opens_the_session_the_config_opens() {
    use crate::arena::AllocatorMemory;
    use crate::OpenKeyIds;
    use wz_session_core::policy::SessionPolicy;

    let listener = || CoopConfig {
        whatami: WhatAmI::Peer,
        zid: config_zid(0xa7),
        listen: vec!["tcp/127.0.0.1:0".to_owned()],
        ..client_config()
    };
    let made = Engine::open_made_in(
        host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        PosixEntropy,
        listener,
        SessionPolicy::defaults(),
        OpenKeyIds::none(),
        crate::arena::OpenStorage {
            memory: &AllocatorMemory,
            plan: crate::arena::PlanFrom::Config(&crate::arena::HeldPlaces::NONE),
        },
    )
    .expect("a listener opens once it is bound");
    let handed_in = open_with(listener());
    assert_eq!(
        SessionDrive::zid(&*made),
        SessionDrive::zid(&*handed_in),
        "the zid the config states"
    );
    assert_eq!(made.arena_bytes(), handed_in.arena_bytes());
    assert_eq!(made.listening().len(), 1, "one port is bound");
}

/// A dial of a host name reaches an address the host's resolver answers for it: a client that
/// dials `localhost` at the port a TCP listener holds on the loopback address connects to that
/// listener, where a dial that read the name as no address would be refused before any
/// connection. No zenoh node answers on the port, so the open itself ends without a session.
/// Turned red by a name refused at once or dialled at an address its resolver did not answer.
#[test]
fn a_dial_of_a_host_name_connects_to_the_address_it_resolves_to() {
    let listener = std::net::TcpListener::bind(std::net::SocketAddr::from((LOOPBACK, 0)))
        .expect("a free loopback port");
    let port = listener.local_addr().expect("the port it holds").port();
    listener
        .set_nonblocking(true)
        .expect("a listener asked without waiting");
    let refused = open_with_result(CoopConfig {
        endpoints: vec![format!("tcp/localhost:{port}")],
        open_timeout_ms: 500,
        ..client_config()
    });
    assert!(refused.is_some(), "no node answers the handshake");
    assert!(
        listener.accept().is_ok(),
        "the dial of the name connected to the listener: {refused:?}"
    );
}

/// An open that fails once its engine is built ends what it began: the port it bound before its
/// dial was refused is let go of, so a listener can bind it again at once.
#[cfg(feature = "listen")]
#[test]
fn an_open_whose_dial_is_refused_lets_go_of_the_port_it_bound() {
    let free_port = || {
        std::net::TcpListener::bind(std::net::SocketAddr::from((LOOPBACK, 0)))
            .and_then(|taken| taken.local_addr())
            .expect("a free loopback port")
            .port()
    };
    let (bound, dead) = (free_port(), free_port());
    let refused = Engine::open(
        host_links(LOOPBACK, PosixTcpDial).waited_by_owner(),
        PosixClock,
        PosixEntropy,
        CoopConfig {
            whatami: WhatAmI::Peer,
            listen: vec![format!("tcp/127.0.0.1:{bound}")],
            endpoints: vec![format!("tcp/127.0.0.1:{dead}")],
            ..client_config()
        },
    );
    assert!(
        refused.is_err(),
        "no node listens on the endpoint it dials, and it redials none"
    );
    std::net::TcpListener::bind(std::net::SocketAddr::from((LOOPBACK, bound)))
        .expect("the failed open let go of its port");
}

#[cfg(feature = "listen")]
mod admission_heap;
#[cfg(all(feature = "ticker", feature = "query", feature = "liveliness"))]
mod advanced;
#[cfg(all(feature = "app-transport", feature = "listen"))]
mod app_listen;
mod arena;
mod closure_drops;
mod congestion;
mod decl_watch;
mod dial_in_flight;
mod direct_receive;
// The runtime of a build whose read steps its one link itself, which runs no task.
#[cfg(not(any(feature = "threads", feature = "listen", feature = "group")))]
mod direct_runtime;
mod entity_tables;
// The mark the session's lock makes against a wait on a face is kept only in a debug build, and
// there not with the host's own locks (`host-sys`), which the module's tests read.
#[cfg(all(feature = "std", debug_assertions))]
mod face_order;
#[cfg(all(
    feature = "listen",
    feature = "query",
    feature = "queryable",
    feature = "local-queryable"
))]
mod face_table;
#[cfg(feature = "connectivity")]
mod faces;
#[cfg(feature = "query")]
mod get;
// Each member is stepped by its read task.
#[cfg(all(feature = "group", feature = "app-transport", feature = "threads"))]
mod group;
// A full group's stage, in both forms of the engine's calls.
#[cfg(all(feature = "group", feature = "app-transport"))]
mod group_congested;
#[cfg(all(feature = "group", feature = "app-transport"))]
mod group_stack;
mod held_keys;
#[cfg(feature = "group-host")]
mod host_group;
mod in_place;
mod link_sets;
// Every session of these is stepped by its read task (`listen::Stepped`).
#[cfg(all(
    feature = "listen",
    feature = "query",
    feature = "queryable",
    feature = "threads"
))]
mod listen;
#[cfg(feature = "liveliness")]
mod liveliness;
#[cfg(feature = "local-subscriber")]
mod local;
#[cfg(feature = "local-queryable")]
mod local_query;
#[cfg(all(
    feature = "listen",
    feature = "query",
    feature = "queryable",
    feature = "threads"
))]
mod one_face;
// Every session of these is opened, called and read on a thread of its own (`OwnThread`).
#[cfg(all(
    not(feature = "threads"),
    any(
        feature = "listen",
        feature = "group-host",
        all(feature = "group", feature = "app-transport")
    )
))]
mod one_thread;
mod plain_put;
mod program_clock;
#[cfg(feature = "queryable")]
mod queryable;
pub(crate) mod redial_heap;
mod redial_wait;
// The state of a session whose shape the build fixes: a build that plans at the open has none.
#[cfg(not(feature = "runtime-plan"))]
mod region;
mod replay;
#[cfg(wz_round)]
mod round;
// The cells a link's task takes: a build whose read steps its one link itself runs none.
#[cfg(wz_round)]
mod runtime_tables;
#[cfg(all(
    feature = "shared-key-ids",
    feature = "listen",
    feature = "query",
    feature = "queryable",
    feature = "threads"
))]
mod shared_key_ids;
// The simulated world the unit tests of a session step through: an in-memory network, a clock
// the test moves and a router stand-in on the test's own thread.
mod sim;
#[cfg(feature = "liveliness-get")]
mod snapshot;
mod step;
// Two threads of the host step one session at once.
#[cfg(feature = "threads")]
mod step_host;
#[cfg(feature = "ticker")]
mod ticker;
mod timestamps;
// A short pool's blocking publish waits for its slot with nothing of the session held only where
// it probes the faces first.
#[cfg(all(feature = "listen", feature = "tx-probe"))]
mod tx_pool;

/// The round is kept by exactly the builds that queue a record into it (`wz_round`, the crate's
/// build script): a build whose read task runs beside the program's calls with no lock of each
/// value's own (`wz_value_locks`: a host lock on a target with 8- and 64-bit atomics). A group's
/// read is no reason to keep it: the read task steps a group's session under the session's lock
/// and hands its records out with that lock let go of. The read that hands each record out as it
/// is read queues none, a get's reply included. A build that keeps none compiles no
/// `crate::round`, so this is read here, where every build reads it. The environment withholds
/// the value locks (`WZ_COOP_VALUE_LOCKS=off`), read here as the compiler was handed it, so a
/// host builds the form of a `threads` image with no host lock. Turned red by `group` put back
/// in the script's predicate: the shipped host preset (`threads` and `group`) would read
/// through the round again; and by a script that gives the locks the environment withholds.
#[test]
fn the_round_is_kept_by_exactly_the_builds_that_queue_into_it() {
    let withheld = option_env!("WZ_COOP_VALUE_LOCKS") == Some("off");
    let value_locks = !withheld
        && cfg!(all(
            any(feature = "std", feature = "host-sys"),
            target_has_atomic = "8",
            target_has_atomic = "64"
        ));
    assert_eq!(cfg!(wz_value_locks), value_locks);
    assert_eq!(cfg!(wz_round), cfg!(feature = "threads") && !value_locks);
}
