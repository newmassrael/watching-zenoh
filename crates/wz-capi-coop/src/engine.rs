// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! [`CoopEngine`]: one session the program steps, behind the C ABI's engine port.
//!
//! ## One lock, and callbacks outside it (decision D8)
//!
//! The session's state is the session shell's: a cooperative task set, `Rc` handles, `RefCell`
//! cells, none of it `Send`. It lives in [`Core`], and every access to it is made under ONE lock,
//! so the engine can be shared between the C session handle and every entity declared on it and
//! called from any thread, as zenoh-pico's multi-threaded arm allows.
//!
//! A C callback never runs under that lock. What the session delivers while it is stepped (a
//! sample for a subscriber, a change of a matching status) is queued as an owned value, and the
//! queue is handed out after the lock is released, so a callback may call back into its session:
//! publish, declare, undeclare itself. zenoh-pico does the same, copying what it delivers out of
//! its session mutex before it calls (`vendor/zenoh-pico/src/session/subscription.c` @
//! `_z_trigger_subscriptions_impl`). The C program's `drop(context)` is reached the same way: an
//! undeclaration takes the callback out under the lock and drops it after.
//!
//! ## A session outlives its link
//!
//! The session is the C program's; a link is one connection of it to a router. When the link is
//! lost, whatever ended it, the session dials its endpoints again, at once and then every
//! [`CoopConfig::redial_ms`] while none answers, and declares over the new link what it holds
//! under the ids it holds it by, as zenoh-pico's client reopens its session
//! (`Z_FEATURE_AUTO_RECONNECT`). What the lost peer declared goes with the link. The dial is
//! stepped like everything else: a step moves the handshake on and returns, so a program that
//! steps its session, or its read task, is what brings the link back.

use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::sync::{Arc, Weak};
use core::any::Any;
use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, Ordering};
// A 64-bit atomic where the target has one, and a critical section where it does not (a
// Cortex-M7 has 32-bit atomics only).
use portable_atomic::AtomicU64;

#[allow(unused_imports)]
use crate::prelude::*;

// The operating system the engine runs on: its mutex, its threads and its sleep are `std`'s on a
// host and the kernel's on an MCU (`docs/upstream-parity.md` section 5a, E1).
use wz_capi_port::os::{self, JoinHandle, Mutex, MutexGuard, ThreadId};
use wz_capi_port::sync::Lock;
use wz_capi_port::{
    CalledFromReadTask, FanoutError, FilterId, FilterPlane, FilteredPut, MatchId, MatchingSink,
    SessionClosed, SessionDrive, SessionEngine, SubId, SubscriberSink, WireKey,
};
#[cfg(feature = "ticker")]
use wz_capi_port::{Tick, TickerId};
use wz_runtime_coop::session_drive::{
    spawn_session, wait_any, LinkReadiness, OpenedLink, SessionDatagramLink, SessionDriveConfig,
    SessionLinks, SessionRole,
};
#[cfg(feature = "listen")]
use wz_runtime_coop::session_drive::{LinkListener, LinkOpenError};
use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopRuntime, CoopTime};
use wz_session_core::close_reason::CloseReason;
use wz_session_core::declare::matching::BoxedMatchingSink;
use wz_session_core::declare::queryable::QuerierCriterion;
use wz_session_core::declare::subscriber::PublisherCriterion;
use wz_session_core::declare_form::{InterestForm, RetractionKey};
use wz_session_core::driver_loop::DriverOutcome;
use wz_session_core::entropy::{EntropySource, EntropyUnavailable};
use wz_session_core::interest_build::InterestKinds;
use wz_session_core::locality::Locality;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::policy::SnResolution;
use wz_session_core::publish_options::{PlainPutParams, PublishError, PublishOptions};
use wz_session_core::pubsub::SubscriptionId;
use wz_session_core::push_build;
use wz_session_core::sample::{Sample, SampleKind};
use wz_session_core::send_wire_error::SendWireError;
use wz_session_core::session_init_params::{
    KeepAliveConf, LinkRxConf, SessionInitParams, TxQueueConf,
};
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::sink::{BoxedSink, SampleView};
use wz_session_core::WhatAmI;
#[cfg(feature = "listen")]
use wz_session_mcu::dial::parse_listen_locator;
use wz_session_mcu::dial::{parse_locator, McuActions};
#[cfg(feature = "queryable")]
use {
    query::{CoopHolder, QueryPlane},
    wz_capi_port::{QblId, QueryCallback, QueryableSink},
    wz_session_core::query::QueryableId,
    wz_session_core::query_sink::BoxedQuerySink,
    wz_session_core::reply_stage::ReplyStage,
};

#[cfg(feature = "queryable")]
mod query;

mod registry;
#[cfg(feature = "local-queryable")]
use registry::LOCAL_FACE;
use registry::{FaceId, Registry, DIAL_FACE};

mod replay;
use replay::{Kind, Replay};

#[cfg(feature = "ticker")]
mod ticker;
#[cfg(feature = "ticker")]
use ticker::Tickers;
use wz_session_core::replay_pacing::ReplayPacing;

#[cfg(feature = "connectivity")]
mod faces;
#[cfg(feature = "connectivity")]
use faces::FacePlane;
#[cfg(feature = "connectivity")]
use wz_session_core::face::FaceEventSink;
use wz_session_core::face::{FaceEventKind, FaceSnapshot};
#[cfg(feature = "local-queryable")]
use wz_session_core::{query::QueryEnvelope, sample::QosLevel};

#[cfg(feature = "liveliness-get")]
use wz_session_core::query_options::DEFAULT_QUERY_TIMEOUT_MS;

#[cfg(feature = "liveliness")]
mod liveliness;
#[cfg(feature = "liveliness")]
use {
    liveliness::{LiveSubEntry, LivelinessCallback, LivelinessQueue, TokenEntry},
    wz_capi_port::{LivelinessSink, TokenId},
};

#[cfg(feature = "query")]
mod get;
#[cfg(feature = "query")]
use {
    get::{GetEvent, GetKind, GetPlane, PendingGet},
    wz_capi_port::{cancellation::CancellableFan, ReplyCallback},
    wz_session_core::query_options::QueryOptions,
    wz_session_core::reply_acceptance::ReplyAcceptance,
    wz_session_core::reply_sink::ConsolidatingSink,
};

/// How a session is opened: what the ABI's config says, which the engine turns into the
/// session's parameters.
pub struct CoopConfig {
    /// The endpoints to dial (`tcp/a.b.c.d:port` or `udp/a.b.c.d:port`), in order: the session
    /// is opened to the first that answers, as zenoh-pico's client opens to the first of its
    /// `connect` locators that does.
    pub endpoints: Vec<String>,
    /// The role the session announces.
    pub whatami: WhatAmI,
    /// The session's zid as the config states it, up to sixteen bytes; `None` mints sixteen
    /// random ones.
    pub zid: Option<Vec<u8>>,
    /// The batch size the session advertises.
    pub batch_size: u16,
    /// The lease the session advertises, in milliseconds.
    pub lease_ms: u64,
    /// How often the session's keepalive speaks on an idle link.
    pub keep_alive: KeepAliveConf,
    /// The width of the sequence numbers the session advertises at its handshake.
    pub sn_resolution: SnResolution,
    /// What the session rejoins from fragments: a chain a fragment would take past its
    /// `max_message_size` is dropped.
    pub link_rx: LinkRxConf,
    /// The transmit model of the ABI the session stands for.
    pub tx_queue: TxQueueConf,
    /// The handshake's deadlines.
    pub timeouts: SessionTimeouts,
    /// How long one endpoint is given to complete the handshake, in milliseconds.
    pub open_timeout_ms: u64,
    /// How long a session whose link was lost waits to dial its endpoints again after a round of
    /// them failed, in milliseconds; the first round is dialled as soon as the loss is seen.
    /// `None` for a session that ends with its link.
    pub redial_ms: Option<u64>,
    /// The longest a read waits for its link to have something to read before it steps the
    /// session, in milliseconds; a read returns as soon as something is there. The wait is made
    /// with nothing of the session held, on a link whose network stack lets its owner wait
    /// (`SessionDatagramLink::readiness`); a link whose stack does not waits in its own loop.
    pub idle_wait_ms: u32,
    /// The endpoints to listen on (`tcp/a.b.c.d:port`; port 0 has the stack choose one, read back
    /// with [`CoopEngine::listening`]), which the session takes inbound links from for as long as
    /// it lives, each as a face of its own. A session that lists none and dials at least one is
    /// the dial role alone; one that lists some and dials none is only a listener, and is open as
    /// soon as it is bound (`listen`).
    pub listen: Vec<String>,
    /// How many inbound links may be in their handshake at once; one that arrives past it is
    /// closed unread. `transport/unicast/accept_pending` of zenoh, [`DEFAULT_ACCEPT_PENDING`]
    /// by default (`listen`). How long a handshake may take is `timeouts.accepting_inactivity_ms`.
    pub accept_pending: usize,
    /// How many faces the session holds besides the dial role's; an inbound link that arrives
    /// past it is closed unread. `transport/unicast/max_sessions` of zenoh,
    /// [`DEFAULT_MAX_FACES`] by default (`listen`).
    pub max_faces: usize,
}

/// Inbound links in their handshake at once, when the config states none: zenoh's
/// `transport/unicast/accept_pending`.
pub const DEFAULT_ACCEPT_PENDING: usize = 100;

/// Faces the session holds besides the dial role's, when the config states none: zenoh's
/// `transport/unicast/max_sessions`.
pub const DEFAULT_MAX_FACES: usize = 1000;

/// Why no session was opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// The configuration names no endpoint.
    NoEndpoint,
    /// An endpoint to listen on could not be listened on: it does not parse, the network opens no
    /// listener for its protocol, or the port is taken. The endpoint and the reason; a build
    /// without `listen` answers every listen endpoint this way.
    Listen(String),
    /// No endpoint could be dialled: each was refused, unreachable or did not complete the
    /// handshake in time. The last endpoint's reason.
    Unreachable(String),
    /// The platform gave no entropy for the session's zid or its cookie key.
    EntropyUnavailable,
}

/// The zid's wire form: the bytes up to the last non-zero one, as zenoh writes an id.
fn wire_zid(zid: &[u8]) -> Vec<u8> {
    let len = zid.iter().rposition(|b| *b != 0).map_or(0, |at| at + 1);
    zid[..len].to_vec()
}

/// The session's entropy source, which every draw of the session goes through: its zid, the
/// cookie key of each dial and, in a listening session, the cookie nonce of each handshake it
/// accepts. A board has one source and it is not copied, so the users of it hold the one source
/// behind a lock and draw from it in turn; each accepted session owns a handle of its own, as
/// the session-core's accept path requires of a source (`install_cookie_entropy`).
#[derive(Clone)]
struct SharedEntropy(Arc<Lock<Box<dyn EntropySource + Send>>>);

impl SharedEntropy {
    fn new(source: impl EntropySource + Send + 'static) -> Self {
        Self(Arc::new(Lock::new(Box::new(source))))
    }
}

impl EntropySource for SharedEntropy {
    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
        self.0.with(|source| source.try_fill_bytes(buf))
    }
}

/// Sixteen random bytes, not all zero (an id of zero bytes names nothing).
fn fresh_zid(entropy: &mut dyn EntropySource) -> Result<Vec<u8>, OpenError> {
    let mut zid = [0u8; 16];
    entropy
        .try_fill_bytes(&mut zid)
        .map_err(|_| OpenError::EntropyUnavailable)?;
    if zid.iter().all(|b| *b == 0) {
        return Err(OpenError::EntropyUnavailable);
    }
    Ok(wire_zid(&zid))
}

/// One session the program steps; see the module doc.
pub struct CoopEngine<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> {
    core: Mutex<Confined<Core<L, C>>>,
    /// What the session delivered under the lock, handed out after it: the samples for its
    /// subscribers, in the order they arrived, and the changes of its matching statuses. Two
    /// queues and not one of an enum, so a sample is queued as it was built and a matching flip
    /// does not take a sample's room.
    samples: Arc<Mutex<VecDeque<(SubId, Sample)>>>,
    matching: Arc<Mutex<VecDeque<(MatchId, bool)>>>,
    /// The callbacks deliveries go to, by the id of the entity that owns them. Kept outside
    /// [`Core`] so a delivery takes no session state, and a callback that undeclares another
    /// entity finds its target gone rather than the lock held.
    targets: Mutex<Vec<(u64, Target)>>,
    /// The queries waiting for their callbacks and the Finals held for them (`query`).
    #[cfg(feature = "queryable")]
    plane: Arc<QueryPlane>,
    /// What the session's gets queued for their callbacks (`get`).
    #[cfg(feature = "query")]
    gets: Arc<GetPlane>,
    /// What the session's watchers of its faces are owed, and who they are (`connectivity`).
    #[cfg(feature = "connectivity")]
    faces: Arc<FacePlane>,
    /// What the liveliness subscribers' sinks queued for their callbacks (`liveliness`).
    #[cfg(feature = "liveliness")]
    live_samples: LivelinessQueue,
    zid: [u8; 16],
    closed: AtomicBool,
    next_entity: AtomicU64,
    reader: Mutex<Option<ReadTask>>,
    /// The threads handing deliveries out for this engine now ([`Delivering`]): a callback that
    /// steps its session again from one of them queues what it delivers for the outer delivery.
    delivering: Lock<Vec<ThreadId>>,
    this: Weak<Self>,
}

/// The session state no other thread may touch while one does; see the module doc.
struct Confined<T>(T);

// SAFETY: a `Confined` is reached only through the `Mutex` that holds it in `CoopEngine`, so one
// thread at a time uses it. Its `Rc` handles and `RefCell` cells are all owned by the `Core`
// inside it: no clone of any of them is ever handed out of the lock (deliveries leave as owned
// `Sample`s and `bool`s, see `CoopEngine::samples`), so every handle of each `Rc` moves with the
// `Core` when another thread takes the lock, and none is used by two threads at once.
unsafe impl<T> Send for Confined<T> {}

/// One thread's delivery for one engine, from `enter` to drop. The engine keeps the threads
/// delivering for it ([`CoopEngine::delivering`]); a set held per engine and keyed by thread is
/// what a thread-local set keyed by engine was, without a thread-local, which an MCU kernel does
/// not give a Rust image.
struct Delivering<'a> {
    set: &'a Lock<Vec<ThreadId>>,
    thread: ThreadId,
}

impl<'a> Delivering<'a> {
    /// `None` when this thread is already delivering for the engine whose set this is.
    fn enter(set: &'a Lock<Vec<ThreadId>>) -> Option<Self> {
        let thread = os::current();
        set.with(|threads| {
            if threads.contains(&thread) {
                return None;
            }
            threads.push(thread);
            Some(Self { set, thread })
        })
    }
}

impl Drop for Delivering<'_> {
    fn drop(&mut self) {
        let thread = self.thread;
        self.set.with(|threads| threads.retain(|t| *t != thread));
    }
}

/// A subscriber's callback, as the ABI's sink minted it. Locked while it runs, so a delivery
/// from the read task and one from the program's own `zp_read` never overlap.
type SubscriberCallback = Arc<Mutex<Box<dyn FnMut(&dyn SampleView) + Send + 'static>>>;

/// A queryable's callback, locked while it runs as a subscriber's is.
#[cfg(feature = "queryable")]
type QueryableCallback = Arc<Mutex<QueryCallback>>;

/// Where a delivery goes.
enum Target {
    Subscriber(SubscriberCallback),
    Matching(MatchingSink),
    #[cfg(feature = "queryable")]
    Queryable(QueryableCallback),
    /// One leg of a get, locked while it runs.
    #[cfg(feature = "query")]
    Reply(Arc<Mutex<ReplyCallback>>),
    #[cfg(feature = "liveliness")]
    Liveliness(LivelinessCallback),
}

/// The read task: a thread that steps the session until it is told to stop.
struct ReadTask {
    stop: Arc<AtomicBool>,
    thread: JoinHandle,
    id: ThreadId,
}

struct Core<L: SessionLinks + 'static, C: ClockSource + 'static> {
    local: CoopLocalSet<C>,
    runtime: CoopRuntime<C>,
    clock: C,
    /// What the application holds and what the peer declared. It is the session's, so it
    /// outlives each link: a new link is dispatched to the same registry.
    registry: Rc<RefCell<Registry>>,
    /// The session's faces: the dial role's first, which is never removed, then the others in the
    /// order they came. What is declared is declared over each of them, and a get is asked of
    /// each.
    faces: Vec<Face<C>>,
    /// The face an accepted or attached link takes next, beneath the dial role's.
    next_face: FaceId,
    /// Where a face coming up or going down is reported (`connectivity`).
    #[cfg(feature = "connectivity")]
    watchers: Arc<FacePlane>,
    /// The network the session's links are opened on; it outlives them.
    links: L,
    /// The ports the session takes inbound links from (`listen`).
    #[cfg(feature = "listen")]
    listeners: Vec<Listening<L::Pump>>,
    /// Each handshake's cookie key and nonce come from here.
    entropy: SharedEntropy,
    config: CoopConfig,
    /// The zid in its wire form, which every handshake of the session announces.
    wire_zid: Vec<u8>,
    subscribers: Vec<SubEntry>,
    keyexprs: Vec<KexprEntry>,
    next_mapping: u64,
    filters: Vec<FilterEntry>,
    next_filter: FilterId,
    interests: Vec<InterestHold>,
    matches: Vec<MatchEntry>,
    next_match: MatchId,
    #[cfg(feature = "queryable")]
    queryables: Vec<QblEntry>,
    #[cfg(feature = "queryable")]
    plane: Arc<QueryPlane>,
    /// The legs of the session's gets still pending on its link.
    #[cfg(feature = "query")]
    pending_gets: Vec<PendingGet>,
    #[cfg(feature = "query")]
    gets: Arc<GetPlane>,
    /// The tokens the session holds, and its liveliness subscribers (`liveliness`).
    #[cfg(feature = "liveliness")]
    tokens: Vec<TokenEntry>,
    #[cfg(feature = "liveliness")]
    live_subs: Vec<LiveSubEntry>,
    /// The periodic jobs the program started on the session ([`SessionEngine::start_ticker`]).
    #[cfg(feature = "ticker")]
    tickers: Tickers,
}

/// A port the session listens on, and the wait for a connection on it.
#[cfg(feature = "listen")]
struct Listening<P> {
    listener: Box<dyn LinkListener<P>>,
    readiness: Option<Arc<dyn LinkReadiness>>,
}

/// One face of the session: the link it holds, and where the telling of the session's
/// declarations to that link's peer stands (`replay`).
struct Face<C: ClockSource + 'static> {
    id: FaceId,
    link: Link<C>,
    replay: Replay,
}

/// A face's link: up, in its handshake, or waiting to be dialled.
enum Link<C: ClockSource + 'static> {
    /// Established: the session's sends go through it.
    Up(Wire<C>),
    /// A handshake under way, given up at `deadline_us`. The dial role's face has dialled the
    /// endpoint before `next` and goes on to the one after; another face holds a link it
    /// dialled once or took off a port, and is removed when the handshake fails.
    Opening {
        wire: Wire<C>,
        next: usize,
        deadline_us: u64,
    },
    /// Lost, or no endpoint answered: the endpoints are dialled again at `at_us`.
    Waiting { at_us: u64 },
}

/// One link's half of the session: the actions that send over it, the task that runs it, the
/// link the task reads, and the wait its owner makes for that link's input.
struct Wire<C: ClockSource + 'static> {
    actions: Rc<McuActions<C>>,
    task: CoopLocalJoinHandle<DriverOutcome>,
    link: Rc<dyn SessionDatagramLink>,
    readiness: Option<Arc<dyn LinkReadiness>>,
    /// The link's generation, which the queries it carries are answered under (`query`).
    #[cfg(feature = "queryable")]
    generation: u64,
}

/// What a read waits for before it steps the session, with nothing of the session held.
enum IdleWait {
    /// Nothing: the link holds input already, or its own loop waits for it.
    None,
    /// The next input of any of these links, or the next connection on any of these ports, for
    /// at most this many milliseconds. Each wait is held for as long as the wait is, so the
    /// descriptor it names stays the link's.
    Input(Vec<Arc<dyn LinkReadiness>>, u32),
    /// Nothing to wait on: the next dial, or the next look at a port that gives no wait, for at
    /// most this many milliseconds.
    Sleep(u32),
}

impl IdleWait {
    fn wait(self) {
        match self {
            IdleWait::None => {}
            IdleWait::Input(waits, ms) => wait_any(&waits, ms),
            IdleWait::Sleep(ms) => os::sleep_ms(ms.into()),
        }
    }
}

struct SubEntry {
    id: SubId,
    registration: SubscriptionId,
    retraction: Option<RetractionKey>,
    keyexpr: String,
    /// The key the declaration names, kept to declare it again over a new link; holding it also
    /// keeps alive what it holds.
    wire: WireKey,
}

impl SubEntry {
    /// Declare this subscriber over `actions`: whether the link took it.
    fn declare<C: ClockSource + 'static>(&self, actions: &McuActions<C>) -> bool {
        if self.wire.is_literal() {
            actions.send_declare_subscriber(self.id, 0, Some(&self.keyexpr))
        } else {
            actions.send_declare_subscriber(
                self.id,
                self.wire.mapping_id,
                self.wire.suffix.as_deref(),
            )
        }
        .is_ok()
    }
}

/// One queryable: its registration with the observer and what its declaration says on the wire.
#[cfg(feature = "queryable")]
struct QblEntry {
    id: QblId,
    registration: QueryableId,
    retraction: Option<RetractionKey>,
    keyexpr: String,
    wire: WireKey,
    complete: bool,
}

#[cfg(feature = "queryable")]
impl QblEntry {
    /// Declare this queryable over `actions`: whether the link took it.
    fn declare<C: ClockSource + 'static>(&self, actions: &McuActions<C>) -> bool {
        if self.wire.is_literal() {
            actions.send_declare_queryable(self.id, 0, Some(&self.keyexpr), self.complete)
        } else {
            actions.send_declare_queryable(
                self.id,
                self.wire.mapping_id,
                self.wire.suffix.as_deref(),
                self.complete,
            )
        }
        .is_ok()
    }

    /// Retract this queryable over `actions`, naming its key when its declaration asked to.
    fn retract<C: ClockSource + 'static>(&self, actions: &McuActions<C>) {
        match &self.retraction {
            Some(key) => {
                actions.send_undeclare_queryable_naming(self.id, key.mapping_id, &key.suffix)
            }
            None => actions.send_undeclare_queryable(self.id),
        }
    }
}

struct KexprEntry {
    id: u64,
    keyexpr: String,
    holds: usize,
}

struct FilterEntry {
    id: FilterId,
    plane: FilterPlane,
    keyexpr: String,
    asked: bool,
    /// Whether the session's own entities count toward the filter (`local-subscriber`).
    count_local: bool,
}

/// One Interest the session holds open, and how many hold it.
struct InterestHold {
    plane: FilterPlane,
    keyexpr: String,
    interest_id: u64,
    form: InterestForm,
    holds: usize,
}

impl InterestHold {
    /// Send this Interest over `actions`, for what is declared now and what is declared later:
    /// whether the link took it.
    fn send<C: ClockSource + 'static>(&self, actions: &McuActions<C>) -> bool {
        actions
            .send_interest_kinds(
                self.interest_id,
                kinds(self.plane),
                /* current */ true,
                /* future */ true,
                self.form.aggregate,
                self.form.mapping_id,
                self.form.suffix.as_deref(),
            )
            .is_ok()
    }
}

struct MatchEntry {
    id: MatchId,
    /// What the listener counts, as a write filter names it: which registry `watch` is in.
    plane: FilterPlane,
    watch: u64,
    keyexpr: String,
}

/// The high bit of a request id taken by the leg of a get that the session's own queryables
/// answer (`local-queryable`): the ids the links' actions hand out are the wire's, which carries
/// far fewer bits, so none of them has it.
#[cfg(feature = "local-queryable")]
const LOCAL_REQUEST: u64 = 1 << 63;

/// The locality a matching criterion carries: what the entity counts. The session's own
/// entities of `plane`'s kind count (`Any`) only for one that asked them to and in a build that
/// delivers to them locally.
fn counted(plane: FilterPlane, count_local: bool) -> Locality {
    let delivers_locally = match plane {
        FilterPlane::Subscribers => cfg!(feature = "local-subscriber"),
        FilterPlane::Queryables { .. } => cfg!(feature = "local-queryable"),
    };
    if delivers_locally && count_local {
        Locality::Any
    } else {
        Locality::Remote
    }
}

/// The engine's mutex, held until the guard drops; one poisoned by a panic is recovered, since
/// every critical section here leaves its value consistent ([`os::Mutex::lock`]).
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock()
}

/// The two planes' Interest kinds, an Interest held per plane and key.
fn kinds(plane: FilterPlane) -> InterestKinds {
    match plane {
        FilterPlane::Subscribers => InterestKinds::SUBSCRIBERS,
        FilterPlane::Queryables { .. } => InterestKinds::QUERYABLES,
    }
}

/// What one send's failure means for a publish: a link that is down skips it, anything else is
/// a message no link could have carried.
fn leg(result: Result<(), SendWireError>) -> Result<usize, FanoutError> {
    match result.map_err(PublishError::from) {
        Ok(()) => Ok(0),
        Err(PublishError::TransportUnavailable | PublishError::RequiresUnicast) => Ok(0),
        Err(_) => Err(FanoutError::ExceedsCapacity),
    }
}

/// The `on_event` of a link whose session answers queries outside its lock: the registry's
/// dispatch, with the `ResponseFinal`s it owes held back for the queries a callback is still to
/// answer (`query`). Everything else the dispatch staged (the replies of a queryable that answers
/// in place, declare replies, get prunes) goes out at once, as [`dispatch_all`] sends it.
#[cfg(feature = "queryable")]
fn dispatch_holding_finals<C: ClockSource + 'static>(
    registry: Rc<RefCell<Registry>>,
    face: FaceId,
    actions: Rc<McuActions<C>>,
    plane: Arc<QueryPlane>,
    generation: u64,
) -> impl FnMut(wz_session_core::driver_loop::IterationEvent<'_>) + 'static {
    move |event| {
        let mut registry = registry.borrow_mut();
        // The queries this frame carries arrive on this face's link, whichever was dialled last.
        plane.arriving.store(generation, Ordering::Release);
        registry.dispatch_event(face, event);
        registry.flush_pending_replies(face, &*actions);
        for (rid, qos) in registry.take_pending_final_rids(face) {
            if lock(&plane.holds).owe(generation, rid, qos) {
                actions.send_response_final(rid, qos);
            }
        }
    }
}

/// The `on_event` of a link whose session has no queryable: the registry's dispatch, with
/// everything it staged sent at once.
#[cfg(not(feature = "queryable"))]
fn dispatch_all<C: ClockSource + 'static>(
    registry: Rc<RefCell<Registry>>,
    face: FaceId,
    actions: Rc<McuActions<C>>,
) -> impl FnMut(wz_session_core::driver_loop::IterationEvent<'_>) + 'static {
    move |event| registry.borrow_mut().dispatch(face, event, &*actions)
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> Core<L, C> {
    /// The dial role's face, which the session holds for its whole life.
    fn dial(&self) -> &Face<C> {
        &self.faces[0]
    }

    /// The actions of every face whose link is up, which is what the session sends through. A
    /// face whose link is dialled or waits to be is not among them: what is declared then is
    /// declared when it comes up.
    fn ups(&self) -> impl Iterator<Item = &Rc<McuActions<C>>> {
        self.faces.iter().filter_map(|face| match &face.link {
            Link::Up(wire) => Some(&wire.actions),
            _ => None,
        })
    }

    /// The faces whose links are up, which is what a get is asked of.
    #[cfg(feature = "query")]
    fn up_faces(&self) -> Vec<FaceId> {
        self.faces
            .iter()
            .filter(|face| matches!(face.link, Link::Up(_)))
            .map(|face| face.id)
            .collect()
    }

    /// The actions of face `id` while its link is up.
    #[cfg(feature = "query")]
    fn up_actions(&self, id: FaceId) -> Option<&Rc<McuActions<C>>> {
        self.faces.iter().find_map(|face| match &face.link {
            Link::Up(wire) if face.id == id => Some(&wire.actions),
            _ => None,
        })
    }

    /// The actions of the face whose link is up and is the link of `generation`: where an answer
    /// to a query that came in on that link goes.
    #[cfg(feature = "queryable")]
    fn up_as(&self, generation: u64) -> Option<&Rc<McuActions<C>>> {
        self.faces.iter().find_map(|face| match &face.link {
            Link::Up(wire) if wire.generation == generation => Some(&wire.actions),
            _ => None,
        })
    }

    /// Dial `endpoint` as face `face`: a link opened to it and run as the initiator
    /// ([`Self::open_wire`]). [`OpenError::Unreachable`] when the endpoint does not parse or the
    /// network opens no link to it, [`OpenError::EntropyUnavailable`] when the platform gives no
    /// cookie key for the attempt.
    fn dial_endpoint(&mut self, face: FaceId, endpoint: &str) -> Result<Wire<C>, OpenError> {
        let to = parse_locator(endpoint)
            .map_err(|refused| OpenError::Unreachable(format!("{endpoint}: {refused:?}")))?;
        let opened = self
            .links
            .open_initiator(to)
            .map_err(|refused| OpenError::Unreachable(format!("{endpoint}: {refused:?}")))?;
        self.open_wire(face, opened, SessionRole::Initiator)
    }

    /// Run a session over `opened` as face `face`, in `role`: the handshake begun, its task
    /// spawned on the session's local set and stepped once so that an initiator's InitSyn is sent
    /// now and not after the wait of the next read. The link is the same whichever end opened
    /// it; the role is the handshake's alone. [`OpenError::EntropyUnavailable`] when the platform
    /// gives no cookie key for the attempt.
    fn open_wire(
        &mut self,
        face: FaceId,
        opened: OpenedLink<L::Pump>,
        role: SessionRole,
    ) -> Result<Wire<C>, OpenError> {
        let OpenedLink { sink, pump } = opened;
        // The parameters the tokio engine gives a session (`wz-capi-core`'s `init_params`), with a
        // cookie key of its own per attempt.
        let params = SessionInitParams {
            whatami: self.config.whatami,
            zid: self.wire_zid.clone(),
            seq_num_res: self.config.sn_resolution.wire_code(),
            req_id_res: 2,
            batch_size: self.config.batch_size,
            lease_ms: self.config.lease_ms,
            keep_alive: self.config.keep_alive,
            initial_sn: 0,
            cookie: Vec::new(),
            tx_queue: self.config.tx_queue,
            link_rx: self.config.link_rx,
            cookie_signing_key: SigningKey::from_entropy(&mut self.entropy)
                .map_err(|_| OpenError::EntropyUnavailable)?,
        };
        let actions = McuActions::<C>::new_generic(sink, params, CoopTime::new(&self.runtime));
        // An acceptor mints a cookie at each InitAck from a nonce it draws, and one with no source
        // to draw from refuses every handshake (fail closed): it is given the session's, and a
        // source that is dry now is not a link to accept.
        #[cfg(feature = "listen")]
        if matches!(role, SessionRole::Acceptor) {
            actions.install_cookie_entropy(Box::new(self.entropy.clone()));
            if !actions.draw_cookie_nonce() {
                return Err(OpenError::EntropyUnavailable);
            }
        }
        let readiness = pump.readiness().map(Arc::from);
        let link = Rc::new(pump);
        #[cfg(feature = "queryable")]
        let generation = self.plane.generation.fetch_add(1, Ordering::AcqRel) + 1;
        #[cfg(feature = "queryable")]
        let dispatch = dispatch_holding_finals(
            self.registry.clone(),
            face,
            actions.clone(),
            self.plane.clone(),
            generation,
        );
        #[cfg(not(feature = "queryable"))]
        let dispatch = dispatch_all(self.registry.clone(), face, actions.clone());
        let task = spawn_session(
            &self.local,
            link.clone(),
            actions.clone(),
            CoopTime::new(&self.runtime),
            SessionDriveConfig {
                timeouts: self.config.timeouts,
                role,
                max_iters: None,
            },
            dispatch,
        );
        self.local.run_until_idle();
        Ok(Wire {
            actions,
            task,
            link,
            readiness,
            #[cfg(feature = "queryable")]
            generation,
        })
    }

    /// When a handshake begun now is given up, in microseconds on the session's clock.
    fn open_deadline_us(&self) -> u64 {
        self.clock
            .now_us()
            .saturating_add(self.config.open_timeout_ms.saturating_mul(1000))
    }

    /// Start a handshake with the first endpoint, from index `from` on, that a link opens to, as
    /// the dial role's face. `Err` with the reason the last endpoint tried gave (`last` when none
    /// is), or with [`OpenError::EntropyUnavailable`] when the platform gives no cookie key for
    /// the attempt.
    fn dial_from(&mut self, from: usize, mut last: OpenError) -> Result<Link<C>, OpenError> {
        for at in from..self.config.endpoints.len() {
            let endpoint = self.config.endpoints[at].clone();
            match self.dial_endpoint(DIAL_FACE, &endpoint) {
                Ok(wire) => {
                    return Ok(Link::Opening {
                        wire,
                        next: at + 1,
                        deadline_us: self.open_deadline_us(),
                    });
                }
                Err(OpenError::EntropyUnavailable) => return Err(OpenError::EntropyUnavailable),
                Err(refused) => last = refused,
            }
        }
        Err(last)
    }

    /// Dial from endpoint `from` on; when none answers, wait `redial_ms` to dial them all again,
    /// or end with the last endpoint's reason when the session redials none.
    fn dial_or_wait(
        &mut self,
        from: usize,
        last: OpenError,
        now_us: u64,
        redial_ms: Option<u64>,
    ) -> Result<Link<C>, OpenError> {
        match (self.dial_from(from, last), redial_ms) {
            (Ok(link), _) => Ok(link),
            (Err(OpenError::EntropyUnavailable), _) => Err(OpenError::EntropyUnavailable),
            (Err(last), None) => Err(last),
            (Err(_), Some(ms)) => Ok(Link::Waiting {
                at_us: now_us.saturating_add(ms.saturating_mul(1000)),
            }),
        }
    }

    /// Move every face's link on, after the session was stepped; see [`Self::poll_face`]. `Err`
    /// when the session ends, which only the dial role's face can bring about.
    fn poll_links(&mut self, redial_ms: Option<u64>) -> Result<(), OpenError> {
        // The connections that arrived come first, so their handshakes are moved on in this pass.
        #[cfg(feature = "listen")]
        self.accept_links();
        // From the last face to the first: a face that is gone is removed, which moves none of the
        // ones before it.
        for at in (0..self.faces.len()).rev() {
            self.poll_face(at, redial_ms)?;
        }
        Ok(())
    }

    /// Move the link of the face at `at` on. A handshake that completed brings the link up and
    /// begins to declare over it what the session holds, and a link that is up goes on with the
    /// telling when a turn of it is due (`replay`). The dial role's face is kept: a link that
    /// ended or ran out of time gives way to the next endpoint, and a lost link takes what its
    /// peer declared with it and is dialled again. Any other face is not dialled again: its lost
    /// or failed link takes the face with it. `Err` when the session ends: the dial role's link
    /// was lost, or no endpoint answered, and `redial_ms` is `None`; or the platform gave no
    /// entropy.
    fn poll_face(&mut self, at: usize, redial_ms: Option<u64>) -> Result<(), OpenError> {
        let now_us = self.clock.now_us();
        let now_ms = now_us / 1000;
        let id = self.faces[at].id;
        let link = core::mem::replace(&mut self.faces[at].link, Link::Waiting { at_us: now_us });
        let polled = match link {
            // zenoh-pico's client reopens whatever ended its link: a lease that ran out, a read
            // that failed, a Close from the router (`vendor/zenoh-pico/src/transport/unicast/read.c` @
            // `return _zp_unicast_failed_result(ztu, executor);`).
            Link::Up(wire) if wire.task.is_finished() => {
                // The face is read before the wire goes: what it was is what a watcher is told.
                let snapshot = self.face_of(&wire.actions);
                drop(wire);
                self.lose_link(id);
                self.report_face(FaceEventKind::Down, snapshot);
                if id != DIAL_FACE {
                    self.remove_face(at);
                    return Ok(());
                }
                if redial_ms.is_none() {
                    return Err(OpenError::Unreachable(String::from("the link was lost")));
                }
                self.dial_or_wait(0, OpenError::NoEndpoint, now_us, redial_ms)?
            }
            // A link that is up goes on telling its peer what the session holds, when a turn is
            // due.
            Link::Up(wire) if !self.faces[at].replay.finished() => {
                self.replay_turn(at, &wire.actions, now_ms);
                Link::Up(wire)
            }
            Link::Opening {
                wire,
                next,
                deadline_us,
            } => {
                if wire.actions.is_established() {
                    self.begin_replay(at, &wire.actions, now_ms);
                    let snapshot = self.face_of(&wire.actions);
                    self.report_face(FaceEventKind::Up, snapshot);
                    Link::Up(wire)
                } else if wire.task.is_finished() || now_us >= deadline_us {
                    let why = match (wire.actions.close_reason(), wire.task.is_finished()) {
                        (Some(reason), _) => format!("the handshake ended: {reason:?}"),
                        (None, true) => String::from("the handshake ended"),
                        (None, false) => String::from("no answer in time"),
                    };
                    wire.task.abort();
                    self.local.run_until_idle();
                    drop(wire);
                    if id != DIAL_FACE {
                        self.remove_face(at);
                        return Ok(());
                    }
                    let last = OpenError::Unreachable(format!(
                        "{}: {why}",
                        self.config.endpoints[next - 1]
                    ));
                    self.dial_or_wait(next, last, now_us, redial_ms)?
                } else {
                    Link::Opening {
                        wire,
                        next,
                        deadline_us,
                    }
                }
            }
            Link::Waiting { at_us } if now_us >= at_us => {
                self.dial_or_wait(0, OpenError::NoEndpoint, now_us, redial_ms)?
            }
            link => link,
        };
        self.faces[at].link = polled;
        Ok(())
    }

    /// Whether the session listens on any port.
    fn listens(&self) -> bool {
        #[cfg(feature = "listen")]
        {
            !self.listeners.is_empty()
        }
        #[cfg(not(feature = "listen"))]
        {
            false
        }
    }

    /// Listen on every endpoint the config lists. [`OpenError::Listen`] for the first that does
    /// not parse, that the network opens no listener for, or whose port is taken; a build without
    /// `listen` answers every endpoint so.
    fn listen_on_config(&mut self) -> Result<(), OpenError> {
        #[cfg(feature = "listen")]
        for endpoint in self.config.listen.clone() {
            let refused =
                |why: &dyn core::fmt::Debug| OpenError::Listen(format!("{endpoint}: {why:?}"));
            let at = parse_listen_locator(&endpoint).map_err(|why| refused(&why))?;
            let listener = self.links.open_listener(at).map_err(|why| refused(&why))?;
            let readiness = listener.readiness().map(Arc::from);
            self.listeners.push(Listening {
                listener,
                readiness,
            });
        }
        #[cfg(not(feature = "listen"))]
        if let Some(endpoint) = self.config.listen.first() {
            return Err(OpenError::Listen(format!(
                "{endpoint}: listening is not built"
            )));
        }
        Ok(())
    }

    /// Take the connections waiting on every port the session listens on, each as a face of its
    /// own whose handshake is run as the acceptor's. A port the platform has no descriptor or
    /// buffer for just now is looked at again on the next step, and one that is broken for good
    /// is let go of.
    #[cfg(feature = "listen")]
    fn accept_links(&mut self) {
        let mut at = 0;
        while at < self.listeners.len() {
            let broken = loop {
                match self.listeners[at].listener.accept() {
                    Ok(Some(opened)) => self.accept_face(opened),
                    Ok(None) | Err(LinkOpenError::Exhausted) => break false,
                    Err(_) => break true,
                }
            };
            if broken {
                self.listeners.remove(at);
            } else {
                at += 1;
            }
        }
    }

    /// Give a link taken off a port a face, and run its session as the acceptor. A link that
    /// arrives when the session holds as many faces as `max_faces`, or has as many handshakes
    /// under way as `accept_pending`, is closed unread: its peer learns the node is full from the
    /// close, where one left queued would wait for a handshake that never starts.
    #[cfg(feature = "listen")]
    fn accept_face(&mut self, opened: OpenedLink<L::Pump>) {
        let pending = self
            .faces
            .iter()
            .filter(|face| face.id != DIAL_FACE && matches!(face.link, Link::Opening { .. }))
            .count();
        if self.faces.len() > self.config.max_faces || pending >= self.config.accept_pending {
            return;
        }
        let id = self.next_face;
        // The tables first: the link's task dispatches to them from its first step.
        self.registry.borrow_mut().add_face(id);
        let Ok(wire) = self.open_wire(id, opened, SessionRole::Acceptor) else {
            self.registry.borrow_mut().remove_face(id);
            return;
        };
        self.next_face += 1;
        // The handshake is the acceptor's whole-handshake bound; the session's own timer in the
        // state machine is the same bound and ends the task, so whichever is first removes the face.
        let deadline_us = self.clock.now_us().saturating_add(
            self.config
                .timeouts
                .accepting_inactivity_ms
                .saturating_mul(1000),
        );
        self.push_opening(id, wire, deadline_us);
    }

    /// Add a face that holds `wire`, whose handshake is given up at `deadline_us`. It is told the
    /// session's declarations at the pace the dial role's face is.
    fn push_opening(&mut self, id: FaceId, wire: Wire<C>, deadline_us: u64) {
        let pacing = self.dial().replay.pacing();
        self.faces.push(Face {
            id,
            link: Link::Opening {
                wire,
                next: 0,
                deadline_us,
            },
            replay: Replay::with_pacing(pacing),
        });
    }

    /// Take the face at `at` out of the session, with its tables. The dial role's face is never
    /// taken out.
    fn remove_face(&mut self, at: usize) {
        if self.faces[at].id == DIAL_FACE {
            return;
        }
        let face = self.faces.remove(at);
        self.registry.borrow_mut().remove_face(face.id);
    }

    /// The face a link's `actions` are the end of, when something watches the faces (an event is
    /// the snapshot it carries) and the handshake has told who the peer is. A build without the
    /// connectivity plane watches nothing, and its snapshot is not linked.
    fn face_of(&self, actions: &McuActions<C>) -> Option<FaceSnapshot> {
        #[cfg(feature = "connectivity")]
        {
            if !self.watchers.watched() {
                return None;
            }
            FaceSnapshot::of_actions(actions)
        }
        #[cfg(not(feature = "connectivity"))]
        {
            let _ = actions;
            None
        }
    }

    /// Tell the watchers of the faces that `face` came up or went, with the session's other
    /// deliveries (`face_of` says whether there is anything to tell).
    fn report_face(&self, kind: FaceEventKind, face: Option<FaceSnapshot>) {
        #[cfg(feature = "connectivity")]
        if let Some(face) = face {
            self.watchers.happened(kind, face);
        }
        #[cfg(not(feature = "connectivity"))]
        let _ = (kind, face);
    }

    /// The faces that stand: those whose links have completed their handshakes.
    #[cfg(feature = "connectivity")]
    fn standing_faces(&self) -> Vec<FaceSnapshot> {
        self.faces
            .iter()
            .filter_map(|face| match &face.link {
                Link::Up(wire) if wire.actions.is_established() => {
                    FaceSnapshot::of_actions(&*wire.actions)
                }
                _ => None,
            })
            .collect()
    }

    /// What a lost link takes with it: every subscriber and queryable its peer declared, so a
    /// matching status or a write filter that counted on one reads the session as it now is.
    /// zenoh-pico drops a peer's targets from every write filter when its connection drops
    /// (`vendor/zenoh-pico/src/net/filtering.c` @ `case _Z_INTEREST_MSG_TYPE_CONNECTION_DROPPED: {`).
    fn lose_link(&mut self, id: FaceId) {
        // What the lost link's peer was told went with it: the next link's peer holds nothing.
        if let Some(face) = self.faces.iter_mut().find(|face| face.id == id) {
            face.replay.discard();
        }
        let mut registry = self.registry.borrow_mut();
        registry.flush_declarations_on_link_loss(id);
        registry.flush_liveliness_on_link_loss(id);
        // The gets asked of the face went with its link: the peer that owed their Finals is gone,
        // so each pending entry is dropped, which ends its leg (`get`).
        #[cfg(feature = "query")]
        {
            let mut at = 0;
            while at < self.pending_gets.len() {
                if self.pending_gets[at].face == id {
                    self.pending_gets.remove(at).unregister(&mut registry);
                } else {
                    at += 1;
                }
            }
        }
    }

    /// When the earliest pending get is due: a query's or a liveliness snapshot's, on any face.
    #[cfg(feature = "query")]
    fn next_get_deadline_ms(&self) -> Option<u64> {
        let registry = self.registry.borrow();
        registry
            .all_gets()
            .flat_map(|gets| {
                let due = gets.replies.next_deadline_ms();
                #[cfg(feature = "liveliness-get")]
                let due = [due, gets.liveliness_gets.next_deadline_ms()]
                    .into_iter()
                    .flatten()
                    .min();
                due
            })
            .min()
    }

    /// `most` milliseconds, or the whole milliseconds left until `due_ms` (rounded up, so a wait
    /// never ends a clock reading before the time it waits for), whichever is less.
    fn wait_until(&self, most: u32, due_ms: u64) -> u32 {
        let left_us = due_ms
            .saturating_mul(1000)
            .saturating_sub(self.clock.now_us());
        u32::try_from(left_us.div_ceil(1000)).map_or(most, |left| left.min(most))
    }

    /// What a read waits for before it steps the session: the link's next input, for at most
    /// [`CoopConfig::idle_wait_ms`], unless the link already holds some or waits in its own loop;
    /// and while no link is open, the next dial, for no longer either. zenoh-pico's read waits
    /// the same way, on a socket whose receive timeout is that long (`Z_CONFIG_SOCKET_TIMEOUT`).
    fn idle_wait(&self) -> IdleWait {
        let most = self.config.idle_wait_ms;
        // A get whose deadline comes first is swept when it is due, not up to a whole wait late.
        #[cfg(feature = "query")]
        let most = match self.next_get_deadline_ms() {
            Some(due_ms) => self.wait_until(most, due_ms),
            None => most,
        };
        // And so is the next turn of a replay a link owes its peer, which is not due by input.
        let most = match self
            .faces
            .iter()
            .filter_map(|face| face.replay.next_turn_ms())
            .min()
        {
            Some(due_ms) => self.wait_until(most, due_ms),
            None => most,
        };
        // And so is a periodic job the program started, which no input brings about either.
        #[cfg(feature = "ticker")]
        let most = match self.tickers.next_due_ms() {
            Some(due_ms) => self.wait_until(most, due_ms),
            None => most,
        };
        if most == 0 {
            return IdleWait::None;
        }
        // What the read waits on: the readiness of every link that holds no input already, and of
        // every port that gives one. A link that holds input is stepped at once, and one that
        // waits in its own loop has nothing to wait on here.
        let mut holds = false;
        let mut waits: Vec<Arc<dyn LinkReadiness>> = Vec::new();
        // Something the read cannot wait on that must still be looked at: a link that waits in its
        // own loop, beside links that do not, and a port that gives no wait.
        let mut own_loop = false;
        let mut dial_left_ms = None;
        for face in &self.faces {
            match &face.link {
                Link::Up(wire) | Link::Opening { wire, .. } => {
                    if wire.link.holds_input() {
                        holds = true;
                    } else if let Some(ready) = &wire.readiness {
                        waits.push(ready.clone());
                    } else {
                        own_loop = true;
                    }
                }
                Link::Waiting { at_us } => {
                    dial_left_ms = Some(at_us.saturating_sub(self.clock.now_us()) / 1000);
                }
            }
        }
        if holds {
            return IdleWait::None;
        }
        #[cfg(feature = "listen")]
        let mut unwaited_port = false;
        #[cfg(feature = "listen")]
        for listening in &self.listeners {
            match &listening.readiness {
                Some(ready) => waits.push(ready.clone()),
                None => unwaited_port = true,
            }
        }
        let most = match dial_left_ms {
            Some(left) => u32::try_from(left).map_or(most, |left| left.min(most)),
            None => most,
        };
        #[cfg(feature = "listen")]
        let look_again = unwaited_port;
        #[cfg(not(feature = "listen"))]
        let look_again = false;
        match (waits.is_empty(), look_again) {
            // A port that gives no wait is looked at again after a bounded sleep.
            (true, true) if most > 0 => IdleWait::Sleep(most.min(1)),
            (true, _) => match dial_left_ms {
                Some(_) if most > 0 => IdleWait::Sleep(most),
                _ => IdleWait::None,
            },
            // The links that give a wait are waited on together, for no longer than a look when
            // something beside them cannot be waited on.
            (false, _) if most > 0 => {
                let most = if own_loop || look_again {
                    most.min(1)
                } else {
                    most
                };
                IdleWait::Input(waits, most)
            }
            _ => IdleWait::None,
        }
    }

    /// End every face's link, whatever it is doing, telling an established peer so. The dial
    /// role's face stays, with no link and no redial; the others go.
    fn end_links(&mut self) {
        // The ports are let go of first, so no connection is taken while the faces are ended.
        #[cfg(feature = "listen")]
        self.listeners.clear();
        for face in &mut self.faces {
            face.replay.discard();
            let link = core::mem::replace(&mut face.link, Link::Waiting { at_us: u64::MAX });
            if let Link::Up(wire) | Link::Opening { wire, .. } = link {
                if wire.actions.is_established() {
                    wire.actions.send_close_with_reason(CloseReason::Generic);
                }
                wire.task.abort();
            }
        }
        drop(self.faces.split_off(1));
        self.registry.borrow_mut().remove_accepted_faces();
        self.local.run_until_idle();
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
    /// Open a session over `links` to the first endpoint of `config` that completes the
    /// handshake, stepping it on this thread until it does. `entropy` mints the zid the config
    /// does not state and each attempt's cookie key, for this open and every redial after it.
    /// An open that no endpoint answers fails: the session redials only a link it had.
    pub fn open(
        links: L,
        clock: C,
        entropy: impl EntropySource + Send + 'static,
        config: CoopConfig,
    ) -> Result<Arc<Self>, OpenError> {
        let mut entropy = SharedEntropy::new(entropy);
        let wire = match &config.zid {
            Some(zid) => wire_zid(zid),
            None => fresh_zid(&mut entropy)?,
        };
        let mut zid = [0u8; 16];
        let n = wire.len().min(16);
        zid[..n].copy_from_slice(&wire[..n]);
        let runtime = CoopRuntime::new(clock.clone());
        let local = CoopLocalSet::new(&runtime);
        let mut core = Core {
            local,
            runtime,
            clock,
            registry: Rc::new(RefCell::new(Registry::new())),
            faces: vec![Face {
                id: DIAL_FACE,
                link: Link::Waiting { at_us: u64::MAX },
                replay: Replay::new(),
            }],
            next_face: 1,
            #[cfg(feature = "connectivity")]
            watchers: Arc::new(FacePlane::default()),
            links,
            #[cfg(feature = "listen")]
            listeners: Vec::new(),
            entropy,
            config,
            wire_zid: wire,
            subscribers: Vec::new(),
            keyexprs: Vec::new(),
            next_mapping: 1,
            filters: Vec::new(),
            next_filter: 1,
            interests: Vec::new(),
            matches: Vec::new(),
            next_match: 1,
            #[cfg(feature = "queryable")]
            queryables: Vec::new(),
            #[cfg(feature = "queryable")]
            plane: Arc::new(QueryPlane::default()),
            #[cfg(feature = "query")]
            pending_gets: Vec::new(),
            #[cfg(feature = "query")]
            gets: Arc::new(GetPlane::default()),
            #[cfg(feature = "liveliness")]
            tokens: Vec::new(),
            #[cfg(feature = "liveliness")]
            live_subs: Vec::new(),
            #[cfg(feature = "ticker")]
            tickers: Tickers::default(),
        };
        #[cfg(feature = "queryable")]
        let plane = core.plane.clone();
        #[cfg(feature = "query")]
        let gets = core.gets.clone();
        #[cfg(feature = "connectivity")]
        let faces = core.watchers.clone();
        // The ports are bound before anything is dialled: a session that cannot listen where it was
        // told to does not open.
        core.listen_on_config()?;
        // A session that only listens is open once it is bound; one that dials is open once a
        // link completes its handshake.
        if !(core.config.endpoints.is_empty() && core.listens()) {
            core.faces[0].link = core.dial_from(0, OpenError::NoEndpoint)?;
            while !matches!(core.dial().link, Link::Up(_)) {
                core.idle_wait().wait();
                core.local.run_until_idle();
                core.poll_links(None)?;
            }
        }
        Ok(Arc::new_cyclic(|this| Self {
            core: Mutex::new(Confined(core)),
            samples: Arc::new(Mutex::new(VecDeque::new())),
            matching: Arc::new(Mutex::new(VecDeque::new())),
            targets: Mutex::new(Vec::new()),
            #[cfg(feature = "queryable")]
            plane,
            #[cfg(feature = "query")]
            gets,
            #[cfg(feature = "connectivity")]
            faces,
            #[cfg(feature = "liveliness")]
            live_samples: Arc::new(Mutex::new(VecDeque::new())),
            zid,
            closed: AtomicBool::new(false),
            next_entity: AtomicU64::new(1),
            reader: Mutex::new(None),
            delivering: Lock::new(Vec::new()),
            this: this.clone(),
        }))
    }

    /// Dial `endpoint` as a face of its own, beside the dial role's, and return the id it is
    /// known by. What the session declares is declared over it once its handshake completes (the
    /// session steps it as it does the first face's), what is declared after goes to it too, a
    /// publish and a get reach its peer, and what its peer declares counts with the others'. It
    /// is dialled once: a link that is lost or never completes takes the face with it, where the
    /// dial role's face is dialled again. [`OpenError::Unreachable`] when the session is closed
    /// or the endpoint is not reached.
    pub fn attach_face(&self, endpoint: &str) -> Result<u64, OpenError> {
        let Some(mut guard) = self.live() else {
            return Err(OpenError::Unreachable(String::from(
                "the session is closed",
            )));
        };
        let core = &mut guard.0;
        let id = core.next_face;
        // The tables first: the link's task dispatches to them from its first step.
        core.registry.borrow_mut().add_face(id);
        let wire = match core.dial_endpoint(id, endpoint) {
            Ok(wire) => wire,
            Err(refused) => {
                core.registry.borrow_mut().remove_face(id);
                return Err(refused);
            }
        };
        core.next_face += 1;
        let deadline_us = core.open_deadline_us();
        core.push_opening(id, wire, deadline_us);
        Ok(id)
    }

    /// The endpoints the session listens on, as bound: a port the config named as 0 is the one
    /// the stack chose. Empty once the session is closed (`listen`).
    #[cfg(feature = "listen")]
    pub fn listening(&self) -> Vec<String> {
        self.live().map_or_else(Vec::new, |core| {
            core.0
                .listeners
                .iter()
                .map(|listening| listening.listener.local().to_string())
                .collect()
        })
    }

    /// How many faces have a link that is up, whose handshake has completed.
    pub fn faces_up(&self) -> usize {
        self.live().map_or(0, |core| {
            core.0
                .ups()
                .filter(|actions| actions.is_established())
                .count()
        })
    }

    /// State how the declarations of a link go out, for a caller that wants a pace regardless of
    /// the build (a test, or a program whose image is built for another policy); the build states
    /// it by default (`ReplayPacing::from_build`). `Some` sends a burst of declarations a step and
    /// waits at least the interval before the next burst; `None` sends them all in one.
    pub fn set_replay_pacing(&self, pacing: Option<ReplayPacing>) {
        if let Some(mut core) = self.live() {
            for face in &mut core.0.faces {
                face.replay.set_pacing(pacing);
            }
        }
    }

    /// Whether the peer of every established link has been told every declaration the session
    /// holds. A session with no link established owes nothing yet, so it is synced, as the slot
    /// node's is before a client has come (`docs/declaration-sync-pacing.md`, rule 9).
    pub fn declarations_synced(&self) -> bool {
        self.live().map_or(true, |core| {
            core.0.faces.iter().all(|face| face.replay.finished())
        })
    }

    /// The session's state, for one operation. `None` once the session is closed.
    fn live(&self) -> Option<MutexGuard<'_, Confined<Core<L, C>>>> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        let guard = lock(&self.core);
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        Some(guard)
    }

    /// Run the periodic jobs that are due, with no lock held: what a job does (a beacon is a
    /// publish) takes the session's lock itself. One is taken at a time, so a job that stops
    /// another finds it not yet started, and each is put back a period after its run ended. What
    /// is due is read against the time this call began, so a job that takes longer than its own
    /// period runs once per call and does not keep the caller here.
    #[cfg(feature = "ticker")]
    fn run_due_tickers(&self) {
        let Some(started_ms) = self.live().map(|core| core.0.clock.now_us() / 1000) else {
            return;
        };
        loop {
            let next = self
                .live()
                .and_then(|mut core| core.0.tickers.take_next_due(started_ms));
            let Some((id, tick)) = next else {
                return;
            };
            let goes_on = tick();
            if let Some(mut core) = self.live() {
                let now_ms = core.0.clock.now_us() / 1000;
                core.0.tickers.rearm(id, goes_on, now_ms);
            }
        }
    }

    /// Hand out what the session delivered, with no lock held.
    ///
    /// A callback may step its session again (`zp_read` from inside a subscriber), and that step
    /// delivers nothing itself: the delivery this thread is already making goes on to hand out
    /// what the inner step queued, in order. Delivering from the inner call would run a callback
    /// inside itself, waiting on its own lock.
    fn deliver(&self) {
        let Some(_delivering) = Delivering::enter(&self.delivering) else {
            return;
        };
        // Each popped under its queue's lock alone, which is released before the callback runs:
        // the pop is its own statement, since a guard in a `while let` condition would live
        // through the body and a callback that steps the session again would wait on it.
        loop {
            let next = lock(&self.samples).pop_front();
            let Some((id, sample)) = next else {
                break;
            };
            let callback = lock(&self.targets)
                .iter()
                .find_map(|(t, target)| match target {
                    Target::Subscriber(cb) if *t == id => Some(cb.clone()),
                    _ => None,
                });
            if let Some(callback) = callback {
                (lock(&callback))(&sample);
            }
        }
        #[cfg(feature = "liveliness")]
        loop {
            let next = lock(&self.live_samples).pop_front();
            let Some((id, sample)) = next else {
                break;
            };
            let callback = lock(&self.targets)
                .iter()
                .find_map(|(t, target)| match target {
                    Target::Liveliness(cb) if *t == id => Some(cb.clone()),
                    _ => None,
                });
            if let Some(callback) = callback {
                (lock(&callback))(sample.as_sample());
            }
        }
        // A face that came up or went down, told to each watcher as it stands now: the list is
        // cloned out of its lock, so a sink that undeclares a watcher does not wait on it.
        #[cfg(feature = "connectivity")]
        while let Some((kind, face)) = self.faces.next_event() {
            for sink in self.faces.sinks() {
                sink(kind, &face);
            }
        }
        loop {
            let next = lock(&self.matching).pop_front();
            let Some((id, matching)) = next else {
                break;
            };
            let sink = lock(&self.targets)
                .iter()
                .find_map(|(t, target)| match target {
                    Target::Matching(sink) if *t == id => Some(sink.clone()),
                    _ => None,
                });
            if let Some(sink) = sink {
                sink(matching);
            }
        }
        #[cfg(feature = "queryable")]
        loop {
            let next = lock(&self.plane.queries).pop_front();
            let Some((id, query, generation)) = next else {
                break;
            };
            let callback = lock(&self.targets)
                .iter()
                .find_map(|(t, target)| match target {
                    Target::Queryable(cb) if *t == id => Some(cb.clone()),
                    _ => None,
                });
            let mut replies = ReplyStage::new();
            if let Some(callback) = callback {
                let _answering =
                    query::Answering::enter(self as *const Self as usize, generation, query.rid());
                let mut responder = query.responder(&mut replies);
                (lock(&callback))(&query, &mut responder);
            }
            // The callback's replies go out, then its hold on the Final is let go; a queryable
            // undeclared before its query was delivered lets go of the hold all the same.
            self.answer(generation, query.rid(), replies, true);
        }
        #[cfg(feature = "query")]
        loop {
            let next = lock(&self.gets.events).pop_front();
            match next {
                None => break,
                Some(GetEvent::Reply(leg, reply)) => {
                    let callback =
                        lock(&self.targets)
                            .iter()
                            .find_map(|(t, target)| match target {
                                Target::Reply(cb) if *t == leg => Some(cb.clone()),
                                _ => None,
                            });
                    if let Some(callback) = callback {
                        (lock(&callback))(&reply);
                    }
                }
                // The leg is over: its callback is dropped here, with no lock held, which is
                // how the C program learns it (the reply closure's `drop(context)`).
                Some(GetEvent::End(leg)) => {
                    if let Some(mut core) = self.live() {
                        core.0.pending_gets.retain(|pending| pending.leg != leg);
                    }
                    drop(self.take_target(leg));
                }
            }
        }
    }

    /// A publish's leg to the peer the link reaches, when its destination admits the wire. A link
    /// that is down skips it, as a send over it would.
    fn publish_to_link(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        if !opts.allowed_destination.allows_remote() {
            return Ok(0);
        }
        let Some(core) = self.live() else {
            return Ok(0);
        };
        let meta = opts.push_metadata();
        let reliable = opts.reliable_bool();
        let express = meta.is_express();
        let priority = opts.priority_band();
        let suffix = wire.suffix.as_deref();
        // Each face is sent the put, and one a face's link could not have carried is the one that
        // is reported; a face whose link is down is skipped, as a send over it would.
        let mut outcome = Ok(0);
        for actions in core.0.ups() {
            // A plain Put is sent from the borrowed bytes, as the tokio engine sends it.
            let sent = if opts.kind == SampleKind::Put && meta.is_plain_apart_from_qos() {
                let (mapping_id, suffix) = if wire.is_literal() {
                    (0, Some(keyexpr))
                } else {
                    (wire.mapping_id, suffix)
                };
                leg(actions.send_plain_put_qos(
                    mapping_id, suffix, payload, meta.qos, reliable, express, priority,
                ))
            } else {
                let push = match (opts.kind, wire.mapping_id) {
                    (SampleKind::Put, 0) => {
                        push_build::build_push_literal_with_meta(keyexpr, payload, &meta)
                    }
                    (SampleKind::Del, 0) => {
                        push_build::build_push_del_literal_with_meta(keyexpr, &meta)
                    }
                    (SampleKind::Put, mapping_id) => {
                        push_build::build_push_aliased_with_meta(mapping_id, suffix, payload, &meta)
                    }
                    (SampleKind::Del, mapping_id) => {
                        push_build::build_push_del_aliased_with_meta(mapping_id, suffix, &meta)
                    }
                };
                match push {
                    Ok(push) => leg(actions.send_network_message_qos(
                        NetworkMessage::Push(Box::new(push)),
                        reliable,
                        express,
                        priority,
                    )),
                    Err(_) => Err(FanoutError::ExceedsCapacity),
                }
            };
            if sent.is_err() {
                outcome = sent;
            }
        }
        outcome
    }

    /// A publish's leg to the session's own subscribers, when its destination admits them: the
    /// sample goes through the registry's loopback, which fires the subscribers whose origin
    /// admits it, and what they queued is handed out here with no lock held, so a callback runs
    /// inside the put as zenoh-pico's does. The number of subscribers it reached.
    #[cfg(feature = "local-subscriber")]
    fn publish_to_subscribers(
        &self,
        keyexpr: &str,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> usize {
        if !opts.allowed_destination.allows_local() {
            return 0;
        }
        let Some(core) = self.live() else {
            return 0;
        };
        let sample = opts.loopback_sample(keyexpr, payload);
        let reached = core
            .0
            .registry
            .borrow_mut()
            .app
            .subscribers
            .local_publish(&sample);
        drop(core);
        self.deliver();
        reached
    }

    /// Tell `fan`, when the get can be cancelled, how to undo leg `leg`: a token cancelled while
    /// the leg is issued undoes it at once (`record` runs it). Whether the legs may go on being
    /// issued: `false` once the token cancelled.
    #[cfg(feature = "query")]
    fn cancelling(&self, fan: Option<&CancellableFan>, leg: u64) -> bool {
        let Some(fan) = fan else {
            return true;
        };
        let engine = self.this.clone();
        fan.record(move || {
            if let Some(engine) = engine.upgrade() {
                engine.cancel_get(leg);
            }
        })
    }

    /// Cancel leg `leg` (its get's cancellation token was cancelled): its pending entry is
    /// dropped, and its callback with it, here, with no lock held, so a `cancel` that waits for
    /// the leg's callback to be dropped returns whether or not the session is stepped.
    #[cfg(feature = "query")]
    fn cancel_get(&self, leg: u64) {
        if let Some(mut core) = self.live() {
            let core = &mut core.0;
            if let Some(at) = core.pending_gets.iter().position(|p| p.leg == leg) {
                let pending = core.pending_gets.remove(at);
                pending.unregister(&mut core.registry.borrow_mut());
            }
        }
        drop(self.take_target(leg));
    }

    /// Send `replies` to the query `rid` on the link of `generation` and, with `release`, let go
    /// of one hold on its Final, sending the Final when it was owed and this was the last hold.
    /// Nothing is sent on a link that is no longer the session's.
    #[cfg(feature = "queryable")]
    fn answer(&self, generation: u64, rid: u64, replies: ReplyStage, release: bool) {
        let Some(core) = self.live() else {
            return;
        };
        // The session's own get is answered to its pending entry, which is the registry's.
        #[cfg(feature = "local-queryable")]
        if generation == query::LOCAL_QUERY {
            let mut registry = core.0.registry.borrow_mut();
            let gets = &mut registry.local;
            for reply in replies {
                gets.replies.deliver_local_reply(&reply.into());
            }
            if release && lock(&self.plane.holds).release(generation, rid).is_some() {
                gets.replies.deliver_local_final(rid);
            }
            drop(registry);
            drop(core);
            self.deliver();
            return;
        }
        let actions = core.0.up_as(generation);
        if let Some(actions) = actions {
            for reply in replies {
                if let Ok(response) = reply.into_response() {
                    actions.send_response(response);
                }
            }
        }
        if release {
            let due = lock(&self.plane.holds).release(generation, rid);
            if let (Some(qos), Some(actions)) = (due, actions) {
                actions.send_response_final(rid, qos);
            }
        }
    }

    /// Take the callback of entity `id` out of the targets; the caller drops it with no lock
    /// held.
    fn take_target(&self, id: u64) -> Option<Target> {
        let mut targets = lock(&self.targets);
        let at = targets.iter().position(|(t, _)| *t == id)?;
        Some(targets.remove(at).1)
    }

    /// Step the session until it has nothing more to do, move its link on, and notice a session
    /// that ended.
    fn step(&self, core: &mut Core<L, C>) -> bool {
        core.local.run_until_idle();
        // A get whose deadline has passed ends with zenoh's timeout reply and its Final, here,
        // because this is what runs on every step and the entries are the registry's.
        #[cfg(feature = "query")]
        {
            let now_ms = core.clock.now_us() / 1000;
            let mut registry = core.registry.borrow_mut();
            for gets in registry.all_gets_mut() {
                gets.replies.sweep_timed_out(now_ms);
                // A liveliness snapshot that expired ends the same way. Its terminated ids are
                // staged for a reconnect cache this engine does not keep (it declares again from
                // its own entries), so they are drained and dropped: staged ones would pile up.
                #[cfg(feature = "liveliness-get")]
                {
                    gets.liveliness_gets.sweep_timed_out(now_ms);
                    drop(gets.liveliness_gets.take_finalized());
                }
            }
        }
        let redial_ms = core.config.redial_ms;
        if core.poll_links(redial_ms).is_err() {
            self.closed.store(true, Ordering::Release);
            return false;
        }
        true
    }

    /// Hold the Interest for `keyexpr` on `plane`, sending it in `form` for its first holder.
    fn acquire_interest(
        &self,
        core: &mut Core<L, C>,
        plane: FilterPlane,
        keyexpr: &str,
        form: &InterestForm,
    ) {
        if let Some(hold) = core
            .interests
            .iter_mut()
            .find(|h| h.plane.same_kind(plane) && h.keyexpr == keyexpr)
        {
            hold.holds += 1;
            return;
        }
        // zenoh-pico's Interest takes the session's next entity id
        // (`vendor/zenoh-pico/src/net/primitives.c` @ `intr._id = _z_get_entity_id(zn);`).
        let hold = InterestHold {
            plane,
            keyexpr: keyexpr.to_owned(),
            interest_id: self.next_entity_id(),
            form: form.clone(),
            holds: 1,
        };
        core.announce(Kind::Interest, |actions| hold.send(actions));
        core.interests.push(hold);
    }

    /// Let go of one hold on the Interest for `keyexpr` on `plane`; the last one ends it.
    fn release_interest(core: &mut Core<L, C>, plane: FilterPlane, keyexpr: &str) {
        let Some(at) = core
            .interests
            .iter()
            .position(|h| h.plane.same_kind(plane) && h.keyexpr == keyexpr)
        else {
            return;
        };
        core.interests[at].holds -= 1;
        if core.interests[at].holds == 0 {
            let links = core.retract(Kind::Interest, at);
            let hold = core.interests.remove(at);
            for actions in links {
                actions.send_interest_final(hold.interest_id);
            }
        }
    }

    /// Whether a peer declared what `plane` counts on `keyexpr`.
    fn peer_matches(core: &Core<L, C>, plane: FilterPlane, keyexpr: &str) -> bool {
        let registry = core.registry.borrow();
        let subscribers = PublisherCriterion::new(keyexpr, Locality::Remote);
        // Any face's peer: a write filter holds a write back only when none of them wants it.
        let matched = registry.faces().any(|face| match plane {
            FilterPlane::Subscribers => face.peer.remote_subscribers.has_matching_for(&subscribers),
            FilterPlane::Queryables { complete_required } => face
                .peer
                .remote_queryables
                .has_matching_for(&QuerierCriterion::new(
                    keyexpr,
                    Locality::Remote,
                    complete_required,
                )),
        });
        matched
    }

    /// Whether the session's own entities of `plane`'s kind match `keyexpr`: a subscriber of its
    /// own that a local put reaches (`local-subscriber`). The session answers nothing else
    /// locally, as zenoh-pico's default build does not.
    fn local_matches(core: &Core<L, C>, plane: FilterPlane, keyexpr: &str) -> bool {
        #[cfg(feature = "local-subscriber")]
        if matches!(plane, FilterPlane::Subscribers) {
            return core
                .registry
                .borrow()
                .app
                .subscribers
                .has_local_matching(keyexpr);
        }
        #[cfg(feature = "local-queryable")]
        if let FilterPlane::Queryables { complete_required } = plane {
            return core
                .registry
                .borrow()
                .app
                .queryables
                .has_local_matching(keyexpr, complete_required);
        }
        let _ = (core, plane, keyexpr);
        false
    }

    /// Hand a get of this session to the session's own queryables, as zenoh-pico's
    /// `_z_session_deliver_query_locally` does after the query went out: each queryable that
    /// matches holds the get's Final and answers when its callback runs, and the Final is owed
    /// now, so it reaches the get once the last of them has answered.
    #[cfg(feature = "local-queryable")]
    fn ask_own_queryables(
        &self,
        core: &mut Core<L, C>,
        rid: u64,
        keyexpr: &str,
        opts: &QueryOptions,
    ) {
        let qos = opts.qos.unwrap_or(QosLevel::DEFAULT);
        let envelope = QueryEnvelope {
            rid,
            target: opts.effective_target(),
            qos,
        };
        let query = opts.loopback_query();
        let mut staged = ReplyStage::new();
        let mut registry = core.registry.borrow_mut();
        self.plane.asking_locally(|| {
            registry.app.queryables.local_query_with_value(
                envelope,
                keyexpr,
                &query,
                None,
                &mut staged,
            )
        });
        let gets = &mut registry.local;
        for reply in staged {
            gets.replies.deliver_local_reply(&reply.into());
        }
        if lock(&self.plane.holds).owe(query::LOCAL_QUERY, rid, qos) {
            gets.replies.deliver_local_final(rid);
        }
    }

    /// The queryables' plane's counterpart of [`Self::reevaluate_subscriber_matching`].
    #[cfg(feature = "local-queryable")]
    fn reevaluate_queryable_matching(core: &Core<L, C>) {
        core.registry.borrow_mut().reevaluate_querier_watches();
    }

    /// What a write filter or a matching listener on `plane` reads: a peer's declaration, or with
    /// `count_local` one of the session's own.
    fn plane_matches(
        core: &Core<L, C>,
        plane: FilterPlane,
        keyexpr: &str,
        count_local: bool,
    ) -> bool {
        Self::peer_matches(core, plane, keyexpr)
            || (count_local && Self::local_matches(core, plane, keyexpr))
    }

    /// Tell every matching listener on the subscribers' plane that counts the session's own
    /// subscribers whether it now matches, after one was declared or retracted here: the
    /// registry reads the remote half off its own membership and asks this for the local half.
    #[cfg(feature = "local-subscriber")]
    fn reevaluate_subscriber_matching(core: &Core<L, C>) {
        core.registry.borrow_mut().reevaluate_publisher_watches();
    }

    /// Stop the read task, from a thread that is not it.
    fn stop_reader(&self) -> Result<(), CalledFromReadTask> {
        let task = {
            let mut reader = lock(&self.reader);
            match reader.as_ref() {
                None => return Ok(()),
                Some(task) if task.id == os::current() => return Err(CalledFromReadTask),
                Some(_) => reader.take(),
            }
        };
        if let Some(task) = task {
            task.stop.store(true, Ordering::Release);
            task.thread.join();
        }
        Ok(())
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> SessionEngine
    for CoopEngine<L, C>
{
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn zid(&self) -> [u8; 16] {
        self.zid
    }

    fn now_ms(&self) -> u64 {
        // The session's own clock, which is what its deadlines and its jobs run on. Read under the
        // session's lock, which nothing here holds while a callback runs.
        lock(&self.core).0.clock.now_us() / 1000
    }

    fn next_entity_id(&self) -> u64 {
        self.next_entity.fetch_add(1, Ordering::Relaxed)
    }

    #[cfg(feature = "ticker")]
    fn start_ticker(&self, period_ms: u64, tick: Tick) -> Option<TickerId> {
        let mut core = self.live()?;
        let id = self.next_entity_id();
        let now_ms = core.0.clock.now_us() / 1000;
        core.0.tickers.start(id, period_ms, tick, now_ms);
        Some(id)
    }

    #[cfg(feature = "ticker")]
    fn stop_ticker(&self, id: TickerId) {
        if let Some(mut core) = self.live() {
            core.0.tickers.stop(id);
        }
    }

    fn peer_identities(&self) -> Vec<(Vec<u8>, u8)> {
        let Some(core) = self.live() else {
            return Vec::new();
        };
        core.0
            .ups()
            .filter(|actions| actions.is_established())
            .filter_map(
                |actions| match (actions.peer_zid(), actions.peer_whatami_wire()) {
                    (Some(zid), Some(role)) => Some((zid, role)),
                    _ => None,
                },
            )
            .collect()
    }

    #[cfg(feature = "connectivity")]
    fn face_snapshots(&self) -> Vec<FaceSnapshot> {
        self.live()
            .map_or_else(Vec::new, |core| core.0.standing_faces())
    }

    #[cfg(feature = "connectivity")]
    fn watch_faces(&self, sink: FaceEventSink) -> u64 {
        self.faces.watch(sink)
    }

    #[cfg(feature = "connectivity")]
    fn unwatch_faces(&self, id: u64) -> bool {
        self.faces.unwatch(id)
    }

    fn has_router_peer(&self) -> bool {
        self.live().is_some_and(|core| {
            core.0
                .ups()
                .any(|actions| actions.peer_whatami_wire() == Some(0))
        })
    }

    fn publish_on_wire_all(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        // The link first, then the session's own subscribers, as zenoh-pico's `_z_write` does,
        // and nothing local when the link refused it.
        let sent = self.publish_to_link(keyexpr, wire, payload, opts)?;
        #[cfg(feature = "local-subscriber")]
        let sent = sent + self.publish_to_subscribers(keyexpr, payload, opts);
        Ok(sent)
    }

    fn declare_subscriber_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        allowed_origin: Locality,
        retraction: Option<RetractionKey>,
        sink: SubscriberSink,
    ) -> SubId {
        let id = self.next_entity_id();
        let Some(mut guard) = self.live() else {
            return id;
        };
        let core = &mut guard.0;
        let queue = self.samples.clone();
        let registration = core.registry.borrow_mut().app.subscribers.register_sink(
            &keyexpr,
            allowed_origin,
            BoxedSink::new(move |sample: &dyn SampleView| {
                lock(&queue).push_back((id, Sample::from_view(sample)));
            }),
        );
        let Ok(registration) = registration else {
            return id;
        };
        lock(&self.targets).push((id, Target::Subscriber(Arc::new(Mutex::new(sink())))));
        let entry = SubEntry {
            id,
            registration,
            retraction,
            keyexpr,
            wire,
        };
        core.announce(Kind::Subscriber, |actions| entry.declare(actions));
        core.subscribers.push(entry);
        // A matching listener that counts the session's own subscribers may now match: it is
        // told, outside the lock.
        #[cfg(feature = "local-subscriber")]
        {
            Self::reevaluate_subscriber_matching(core);
            drop(guard);
            self.deliver();
        }
        id
    }

    fn undeclare_subscriber(&self, id: SubId) {
        // A liveliness subscriber's id is one of these too (the port's one id space): its
        // registration goes and its Interest ends.
        #[cfg(feature = "liveliness")]
        let live = self.live().and_then(|mut core| {
            let core = &mut core.0;
            let at = core.live_subs.iter().position(|s| s.id == id)?;
            let links = core.retract(Kind::LiveSub, at);
            let entry = core.live_subs.remove(at);
            core.registry
                .borrow_mut()
                .app
                .liveliness_subscribers
                .unregister(id);
            for actions in links {
                actions.send_interest_final(id);
            }
            Some(entry)
        });
        #[cfg(feature = "liveliness")]
        if live.is_some() {
            let callback = self.take_target(id);
            drop((live, callback));
            return;
        }
        let entry = self.live().and_then(|mut core| {
            let core = &mut core.0;
            let at = core.subscribers.iter().position(|s| s.id == id)?;
            let links = core.retract(Kind::Subscriber, at);
            let entry = core.subscribers.remove(at);
            core.registry
                .borrow_mut()
                .app
                .subscribers
                .unregister(entry.registration);
            for actions in links {
                match &entry.retraction {
                    Some(key) => {
                        actions.send_undeclare_subscriber_naming(id, key.mapping_id, &key.suffix)
                    }
                    None => actions.send_undeclare_subscriber(id),
                }
            }
            // One that counted it may now match no more.
            #[cfg(feature = "local-subscriber")]
            Self::reevaluate_subscriber_matching(core);
            Some(entry)
        });
        let callback = self.take_target(id);
        drop((entry, callback));
        #[cfg(feature = "local-subscriber")]
        self.deliver();
    }

    fn acquire_keyexpr(&self, keyexpr: String) -> Option<u64> {
        let mut core = self.live()?;
        let core = &mut core.0;
        if let Some(entry) = core.keyexprs.iter_mut().find(|e| e.keyexpr == keyexpr) {
            entry.holds += 1;
            return Some(entry.id);
        }
        let id = core.next_mapping;
        // A declaration a link refuses is not made, and the links that took it take it back; one
        // made while a link is down, or that a replay has not reached, is sent in its turn.
        let taken = core.announce_or_undo(
            Kind::Keyexpr,
            |actions| actions.send_declare_keyexpr(id, &keyexpr).is_ok(),
            |actions| actions.send_undeclare_kexpr(id),
        );
        if !taken {
            return None;
        }
        core.next_mapping += 1;
        core.keyexprs.push(KexprEntry {
            id,
            keyexpr,
            holds: 1,
        });
        Some(id)
    }

    fn release_keyexpr(&self, mapping_id: u64) {
        let Some(mut core) = self.live() else {
            return;
        };
        let core = &mut core.0;
        let Some(at) = core.keyexprs.iter().position(|e| e.id == mapping_id) else {
            return;
        };
        core.keyexprs[at].holds -= 1;
        if core.keyexprs[at].holds == 0 {
            let links = core.retract(Kind::Keyexpr, at);
            core.keyexprs.remove(at);
            for actions in links {
                actions.send_undeclare_kexpr(mapping_id);
            }
        }
    }

    fn keyexpr_declarations(&self) -> Vec<(u64, String)> {
        self.live()
            .map(|core| {
                core.0
                    .keyexprs
                    .iter()
                    .map(|e| (e.id, e.keyexpr.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn declare_matching_listener(
        &self,
        plane: FilterPlane,
        keyexpr: String,
        sink: MatchingSink,
        // The session's own subscribers count with `local-subscriber` and its own queryables with
        // `local-queryable`, and nothing of its own does otherwise: zenoh-pico's default build
        // (`Z_FEATURE_LOCAL_SUBSCRIBER` and `Z_FEATURE_LOCAL_QUERYABLE` 0) delivers nothing
        // locally.
        count_local: bool,
    ) -> MatchId {
        let Some(mut guard) = self.live() else {
            return 0;
        };
        let core = &mut guard.0;
        let id = core.next_match;
        core.next_match += 1;
        self.acquire_interest(
            core,
            plane,
            &keyexpr,
            &InterestForm {
                mapping_id: 0,
                suffix: Some(keyexpr.clone()),
                aggregate: false,
            },
        );
        let local = count_local && Self::local_matches(core, plane, &keyexpr);
        let now = Self::peer_matches(core, plane, &keyexpr) || local;
        let queue = self.matching.clone();
        let report = BoxedMatchingSink::new(move |matching| {
            lock(&queue).push_back((id, matching));
        });
        // The watch is in the registry of what `plane` counts, with the criterion its write
        // filter reads ([`Self::plane_matches`]), so the listener and the filter cannot differ.
        let watch = {
            let mut registry = core.registry.borrow_mut();
            match plane {
                FilterPlane::Subscribers => registry.watch_publishers(
                    PublisherCriterion::new(&keyexpr, counted(plane, count_local)),
                    local,
                    report,
                ),
                FilterPlane::Queryables { complete_required } => registry.watch_queriers(
                    QuerierCriterion::new(&keyexpr, counted(plane, count_local), complete_required),
                    local,
                    report,
                ),
            }
        };
        lock(&self.targets).push((id, Target::Matching(sink)));
        // An already-matching registration is told so at once, as zenoh-pico tells it
        // (`vendor/zenoh-pico/src/net/filtering.c` @ `_z_write_filter_ctx_add_callback`).
        if now {
            lock(&self.matching).push_back((id, true));
        }
        core.matches.push(MatchEntry {
            id,
            plane,
            watch,
            keyexpr,
        });
        drop(guard);
        self.deliver();
        id
    }

    fn undeclare_matching_listener(&self, id: MatchId) {
        if let Some(mut core) = self.live() {
            let core = &mut core.0;
            if let Some(at) = core.matches.iter().position(|m| m.id == id) {
                let entry = core.matches.remove(at);
                {
                    let mut registry = core.registry.borrow_mut();
                    match entry.plane {
                        FilterPlane::Subscribers => registry
                            .app
                            .remote_subscribers
                            .undeclare_matching_listener(entry.watch),
                        FilterPlane::Queryables { .. } => registry
                            .app
                            .remote_queryables
                            .undeclare_matching_listener(entry.watch),
                    };
                }
                Self::release_interest(core, entry.plane, &entry.keyexpr);
            }
        }
        drop(self.take_target(id));
    }

    fn declare_write_filter(
        &self,
        plane: FilterPlane,
        keyexpr: String,
        _wire: &WireKey,
        ask: Option<InterestForm>,
        // See `declare_matching_listener`: the session's own subscribers count with
        // `local-subscriber`.
        count_local: bool,
    ) -> FilterId {
        let Some(mut core) = self.live() else {
            return 0;
        };
        let core = &mut core.0;
        let id = core.next_filter;
        core.next_filter += 1;
        if let Some(form) = &ask {
            self.acquire_interest(core, plane, &keyexpr, form);
        } else {
            // The entity id is taken whether the Interest is sent or not, as zenoh-pico's
            // `_z_add_interest` takes it before it decides.
            let _ = self.next_entity_id();
        }
        core.filters.push(FilterEntry {
            id,
            plane,
            keyexpr,
            asked: ask.is_some(),
            count_local,
        });
        id
    }

    fn write_filter_active(&self, id: FilterId) -> bool {
        let Some(core) = self.live() else {
            return false;
        };
        let core = &core.0;
        // A filter is created suppressing, until a peer declares what it counts, or the session
        // itself does when it counts its own (`vendor/zenoh-pico/src/net/filtering.c` @
        // `ctx->state = WRITE_FILTER_ACTIVE`).
        core.filters
            .iter()
            .find(|f| f.id == id)
            .is_some_and(|f| !Self::plane_matches(core, f.plane, &f.keyexpr, f.count_local))
    }

    fn write_filter_holds_back(&self, id: FilterId) -> bool {
        // A unicast session has no group a write must reach regardless.
        self.write_filter_active(id)
    }

    fn undeclare_write_filter(&self, id: FilterId) {
        let Some(mut core) = self.live() else {
            return;
        };
        let core = &mut core.0;
        let Some(at) = core.filters.iter().position(|f| f.id == id) else {
            return;
        };
        let entry = core.filters.remove(at);
        if entry.asked {
            Self::release_interest(core, entry.plane, &entry.keyexpr);
        }
    }

    fn put_plain_filtered(
        &self,
        filter: FilterId,
        keyexpr: &str,
        mapping_id: u64,
        payload: &[u8],
        params: &PlainPutParams,
    ) -> FilteredPut {
        if self.write_filter_holds_back(filter) {
            return FilteredPut::Suppressed;
        }
        // A put one of the session's own subscribers wants is not plain: the general publish
        // sends it and delivers it there.
        #[cfg(feature = "local-subscriber")]
        if params.destination.allows_local() {
            let wanted = self.live().is_some_and(|core| {
                core.0
                    .registry
                    .borrow()
                    .app
                    .subscribers
                    .has_local_matching(keyexpr)
            });
            if wanted {
                return FilteredPut::NotPlain;
            }
        }
        if !params.destination.allows_remote() {
            return FilteredPut::Sent(Ok(0));
        }
        let Some(core) = self.live() else {
            return FilteredPut::Sent(Ok(0));
        };
        let suffix = (mapping_id == 0).then_some(keyexpr);
        let mut outcome = Ok(0);
        for actions in core.0.ups() {
            let sent = leg(actions.send_plain_put_qos(
                mapping_id,
                suffix,
                payload,
                params.qos,
                params.reliable,
                params.express,
                params.priority,
            ));
            if sent.is_err() {
                outcome = sent;
            }
        }
        FilteredPut::Sent(outcome)
    }

    fn batch_start_all(&self) -> usize {
        self.live().map_or(0, |core| {
            core.0
                .ups()
                .filter(|actions| actions.batch_start().is_ok())
                .count()
        })
    }

    fn batch_flush_all(&self) -> usize {
        self.live().map_or(0, |core| {
            core.0
                .ups()
                .filter(|actions| actions.batch_flush().is_ok())
                .count()
        })
    }

    fn batch_stop_all(&self) -> usize {
        self.live().map_or(0, |core| {
            core.0
                .ups()
                .filter(|actions| actions.batch_stop().is_ok())
                .count()
        })
    }

    #[cfg(feature = "queryable")]
    fn declare_queryable_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        complete: bool,
        allowed_origin: Locality,
        retraction: Option<RetractionKey>,
        sink: QueryableSink,
    ) -> Option<QblId> {
        let id = self.next_entity_id();
        let mut guard = self.live()?;
        let core = &mut guard.0;
        // The registry's queryable only copies a query out and holds its Final; the callback
        // `sink` mints runs when the deliveries are handed out (`query`).
        let plane = self.plane.clone();
        let registration = core
            .registry
            .borrow_mut()
            .app
            .queryables
            .register_sink(
                &keyexpr,
                allowed_origin,
                complete,
                BoxedQuerySink::new(move |query, _in_place| plane.arrive(id, query)),
            )
            .ok()?;
        let holder = Arc::new(CoopHolder {
            engine: self.this.clone(),
        });
        lock(&self.targets).push((id, Target::Queryable(Arc::new(Mutex::new(sink(holder))))));
        let entry = QblEntry {
            id,
            registration,
            retraction,
            keyexpr,
            wire,
            complete,
        };
        core.announce(Kind::Queryable, |actions| entry.declare(actions));
        core.queryables.push(entry);
        // A matching listener that counts the session's own queryables may now match: it is told,
        // outside the lock.
        #[cfg(feature = "local-queryable")]
        {
            Self::reevaluate_queryable_matching(core);
            drop(guard);
            self.deliver();
        }
        Some(id)
    }

    #[cfg(feature = "query")]
    fn get_on_wire(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        opts: &QueryOptions,
        fan: Option<&CancellableFan>,
        leg: &mut dyn FnMut() -> ReplyCallback,
    ) -> Option<usize> {
        // One leg for each face whose link is up, when the destination admits a peer, and one to
        // the session's own queryables, when it admits the session and the build has them
        // (`local-queryable`: zenoh-pico's default build asks none, `Z_FEATURE_LOCAL_QUERYABLE`
        // 0). A get that reaches nobody, because its destination admits neither or because no
        // link is up, is over at once. Each leg is issued under the session's lock and no lock is
        // held between two of them.
        let faces = {
            let Some(guard) = self.live() else {
                return Some(0);
            };
            if opts.allowed_destination.allows_remote() {
                guard.0.up_faces()
            } else {
                Vec::new()
            }
        };
        let mut issued = 0;
        for face in faces {
            let leg_id = self.next_entity_id();
            let Some(mut guard) = self.live() else {
                return Some(issued);
            };
            let core = &mut guard.0;
            let Some(actions) = core.up_actions(face).cloned() else {
                continue;
            };
            // A request id the face's actions allocate, so its peer's answer names it.
            let rid = actions.alloc_next_request_id();
            let timeout_ms = opts.effective_timeout_ms();
            // Rounded up, so a get whose deadline the sweep reads in whole milliseconds never
            // ends before its timeout.
            let deadline_ms = (timeout_ms > 0)
                .then(|| core.clock.now_us().div_ceil(1000) + u64::from(timeout_ms));
            let sink = ConsolidatingSink::new(
                opts.resolved_consolidation(),
                get::reply_sink(leg_id, &self.gets),
            );
            // One Final: the face's peer's. Registered before the request goes out, so no answer
            // can arrive before its entry.
            let registered = core
                .registry
                .borrow_mut()
                .face_mut(face)
                .map(|tables| {
                    tables.gets.replies.register_sink(
                        rid,
                        1,
                        deadline_ms,
                        ReplyAcceptance::for_query(keyexpr, opts.effective_accept_replies()),
                        sink,
                    )
                })
                .is_some_and(|registered| registered.is_ok());
            if !registered {
                continue;
            }
            lock(&self.targets).push((leg_id, Target::Reply(Arc::new(Mutex::new(leg())))));
            let (mapping_id, suffix) = if wire.is_literal() {
                (0, Some(keyexpr))
            } else {
                (wire.mapping_id, wire.suffix.as_deref())
            };
            if actions
                .send_request_query_with_meta(rid, mapping_id, suffix, &opts.query_metadata())
                .is_err()
            {
                // Nothing went out: the entry and the leg go, and the leg is over.
                if let Some(tables) = core.registry.borrow_mut().face_mut(face) {
                    tables.gets.replies.unregister(rid);
                }
                drop(guard);
                drop(self.take_target(leg_id));
                continue;
            }
            core.pending_gets.push(PendingGet {
                face,
                leg: leg_id,
                rid,
                kind: GetKind::Query,
            });
            drop(guard);
            issued += 1;
            // A fan cancelled while the legs are issued stops the issuing.
            if !self.cancelling(fan, leg_id) {
                return Some(issued);
            }
        }
        #[cfg(feature = "local-queryable")]
        if opts.allowed_destination.allows_local() {
            let leg_id = self.next_entity_id();
            let Some(mut guard) = self.live() else {
                return Some(issued);
            };
            let core = &mut guard.0;
            // An id no link will ever hand out, so no peer's answer can be taken for the session's
            // own (`LOCAL_REQUEST`).
            let rid = LOCAL_REQUEST | self.next_entity_id();
            let timeout_ms = opts.effective_timeout_ms();
            let deadline_ms = (timeout_ms > 0)
                .then(|| core.clock.now_us().div_ceil(1000) + u64::from(timeout_ms));
            let sink = ConsolidatingSink::new(
                opts.resolved_consolidation(),
                get::reply_sink(leg_id, &self.gets),
            );
            let registered = core.registry.borrow_mut().local.replies.register_sink(
                rid,
                1,
                deadline_ms,
                ReplyAcceptance::for_query(keyexpr, opts.effective_accept_replies()),
                sink,
            );
            if registered.is_ok() {
                lock(&self.targets).push((leg_id, Target::Reply(Arc::new(Mutex::new(leg())))));
                core.pending_gets.push(PendingGet {
                    face: LOCAL_FACE,
                    leg: leg_id,
                    rid,
                    kind: GetKind::Query,
                });
                // Asked once the legs to the peers were, as zenoh-pico asks it only once the send
                // succeeded.
                self.ask_own_queryables(core, rid, keyexpr, opts);
                drop(guard);
                issued += 1;
                let _ = self.cancelling(fan, leg_id);
                // What the session's own queryables were handed runs inside the get, outside the
                // lock, as zenoh-pico's `_z_session_deliver_query_locally` does on the caller's
                // thread.
                self.deliver();
            }
        }
        Some(issued)
    }

    #[cfg(feature = "liveliness-get")]
    fn liveliness_get_on_wire(
        &self,
        keyexpr: &str,
        wire: &WireKey,
        timeout_ms: u32,
        fan: Option<&CancellableFan>,
        leg: &mut dyn FnMut() -> ReplyCallback,
    ) -> Option<usize> {
        // One leg for each face whose link is up; a session with no link up reaches nobody, and
        // the snapshot is over at once.
        let faces = {
            let Some(guard) = self.live() else {
                return Some(0);
            };
            guard.0.up_faces()
        };
        // `0` is the platform default and never no deadline, as pico's `z_liveliness_get`
        // rewrites it (`vendor/zenoh-pico/src/api/liveliness.c` @
        // `if (opt.timeout_ms == 0) {`); rounded up as a query's deadline is.
        let timeout_ms = match timeout_ms {
            0 => DEFAULT_QUERY_TIMEOUT_MS,
            set => set,
        };
        let mut issued = 0;
        for face in faces {
            let leg_id = self.next_entity_id();
            let Some(mut guard) = self.live() else {
                return Some(issued);
            };
            let core = &mut guard.0;
            let Some(actions) = core.up_actions(face).cloned() else {
                continue;
            };
            let interest_id = actions.alloc_next_interest_id();
            let deadline_ms = Some(core.clock.now_us().div_ceil(1000) + u64::from(timeout_ms));
            // One DeclFinal: the face's peer's. Registered before the Interest goes out, so no
            // answer can arrive before its entry.
            let registered = core
                .registry
                .borrow_mut()
                .face_mut(face)
                .map(|tables| {
                    tables.gets.liveliness_gets.register(
                        interest_id,
                        deadline_ms,
                        get::reply_sink(leg_id, &self.gets),
                    )
                })
                .is_some_and(|registered| matches!(registered, Ok(true)));
            if !registered {
                continue;
            }
            lock(&self.targets).push((leg_id, Target::Reply(Arc::new(Mutex::new(leg())))));
            let (mapping_id, suffix) = if wire.is_literal() {
                (0, Some(keyexpr))
            } else {
                (wire.mapping_id, wire.suffix.as_deref())
            };
            if actions
                .send_interest_liveliness_get(interest_id, mapping_id, suffix)
                .is_err()
            {
                // Nothing went out: the entry and the leg go, and the leg is over.
                if let Some(tables) = core.registry.borrow_mut().face_mut(face) {
                    tables.gets.liveliness_gets.unregister(interest_id);
                }
                drop(guard);
                drop(self.take_target(leg_id));
                continue;
            }
            core.pending_gets.push(PendingGet {
                face,
                leg: leg_id,
                rid: interest_id,
                kind: GetKind::Liveliness,
            });
            drop(guard);
            issued += 1;
            // A fan cancelled while the legs are issued stops the issuing.
            if !self.cancelling(fan, leg_id) {
                return Some(issued);
            }
        }
        Some(issued)
    }

    #[cfg(feature = "queryable")]
    fn undeclare_queryable(&self, id: QblId) {
        let entry = self.live().and_then(|mut core| {
            let core = &mut core.0;
            let at = core.queryables.iter().position(|q| q.id == id)?;
            let links = core.retract(Kind::Queryable, at);
            let entry = core.queryables.remove(at);
            core.registry
                .borrow_mut()
                .app
                .queryables
                .unregister(entry.registration);
            for actions in links {
                entry.retract(&actions);
            }
            // One that counted it may now match no more.
            #[cfg(feature = "local-queryable")]
            Self::reevaluate_queryable_matching(core);
            Some(entry)
        });
        let callback = self.take_target(id);
        drop((entry, callback));
        #[cfg(feature = "local-queryable")]
        self.deliver();
    }

    #[cfg(feature = "liveliness")]
    fn declare_liveliness_token_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        retraction: Option<RetractionKey>,
    ) -> Option<TokenId> {
        // zenoh-pico's token takes the session's next entity id
        // (`vendor/zenoh-pico/src/net/liveliness.c` @ `uint32_t id = _z_get_entity_id(_Z_RC_IN_VAL(zn));`).
        let id = self.next_entity_id();
        let mut core = self.live()?;
        let core = &mut core.0;
        core.registry
            .borrow_mut()
            .app
            .local_tokens
            .register(id, &keyexpr)
            .ok()?;
        let entry = TokenEntry {
            id,
            keyexpr,
            wire,
            retraction,
        };
        core.announce(Kind::Token, |actions| entry.declare(actions));
        core.tokens.push(entry);
        Some(id)
    }

    #[cfg(feature = "liveliness")]
    fn undeclare_liveliness_token(&self, id: TokenId) {
        let entry = self.live().and_then(|mut core| {
            let core = &mut core.0;
            let at = core.tokens.iter().position(|t| t.id == id)?;
            let links = core.retract(Kind::Token, at);
            let entry = core.tokens.remove(at);
            core.registry.borrow_mut().app.local_tokens.unregister(id);
            for actions in links {
                entry.retract(&actions);
            }
            Some(entry)
        });
        // Its key may hold a declaration whose release reaches the session: after the lock.
        drop(entry);
    }

    #[cfg(feature = "liveliness")]
    fn declare_liveliness_subscriber_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        history: bool,
        sink: LivelinessSink,
    ) -> Option<SubId> {
        let id = self.next_entity_id();
        let Some(mut guard) = self.live() else {
            return Some(id);
        };
        let core = &mut guard.0;
        lock(&self.targets).push((id, Target::Liveliness(Arc::new(Mutex::new(sink())))));
        // With `history`, the registration hands the sink the tokens the session already knows,
        // before the peer answers with the rest, as zenoh-pico's does
        // (`vendor/zenoh-pico/src/net/liveliness.c` @ `_z_liveliness_subscription_trigger_history`).
        let registered = core.registry.borrow_mut().register_liveliness_subscriber(
            id,
            &keyexpr,
            history,
            liveliness::sample_sink(id, &self.live_samples),
        );
        if registered.is_err() {
            drop(guard);
            drop(self.take_target(id));
            return Some(id);
        }
        let entry = LiveSubEntry {
            id,
            keyexpr,
            wire,
            history,
        };
        core.announce(Kind::LiveSub, |actions| entry.ask(actions));
        core.live_subs.push(entry);
        drop(guard);
        self.deliver();
        Some(id)
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> SessionDrive
    for CoopEngine<L, C>
{
    fn engine(&self) -> Arc<dyn SessionEngine> {
        self.this
            .upgrade()
            .expect("a live engine is held by an Arc")
    }

    fn engine_ref(&self) -> &dyn SessionEngine {
        self
    }

    fn zid(&self) -> [u8; 16] {
        self.zid
    }

    fn close(&self) {
        // The read task stops first, so the close is the last thing the session does. A close
        // from the read task itself stops nothing and leaves the thread to see the session
        // closed.
        let _ = self.stop_reader();
        let mut guard = lock(&self.core);
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let core = &mut guard.0;
        core.end_links();
        let subscribers: Vec<SubId> = core.subscribers.drain(..).map(|s| s.id).collect();
        let matches: Vec<MatchId> = core.matches.drain(..).map(|m| m.id).collect();
        #[cfg(feature = "queryable")]
        let queryables: Vec<QblId> = core.queryables.drain(..).map(|q| q.id).collect();
        #[cfg(not(feature = "queryable"))]
        let queryables: Vec<u64> = Vec::new();
        // A get still pending ends with its session: its entry and its leg's callback go.
        #[cfg(feature = "query")]
        let gets: Vec<u64> = {
            let mut registry = core.registry.borrow_mut();
            core.pending_gets
                .drain(..)
                .map(|pending| {
                    pending.unregister(&mut registry);
                    pending.leg
                })
                .collect()
        };
        #[cfg(not(feature = "query"))]
        let gets: Vec<u64> = Vec::new();
        // The session's tokens end with its link; its liveliness subscribers' callbacks go.
        #[cfg(feature = "liveliness")]
        let live_subs: Vec<SubId> = {
            core.tokens.clear();
            core.live_subs.drain(..).map(|s| s.id).collect()
        };
        #[cfg(not(feature = "liveliness"))]
        let live_subs: Vec<SubId> = Vec::new();
        drop(guard);
        #[cfg(feature = "liveliness")]
        drop(core::mem::take(&mut *lock(&self.live_samples)));
        #[cfg(feature = "query")]
        drop(core::mem::take(&mut *lock(&self.gets.events)));
        // The queries no callback will now answer, and the callbacks' C contexts, are dropped
        // with no lock held.
        #[cfg(feature = "queryable")]
        drop(core::mem::take(&mut *lock(&self.plane.queries)));
        let taken: Vec<_> = subscribers
            .into_iter()
            .chain(matches)
            .chain(queryables)
            .chain(gets)
            .chain(live_subs)
            .filter_map(|id| self.take_target(id))
            .collect();
        drop(taken);
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn start_read_task(&self) -> Result<(), CalledFromReadTask> {
        let mut reader = lock(&self.reader);
        if let Some(task) = reader.as_ref() {
            if task.id == os::current() {
                return Err(CalledFromReadTask);
            }
            return Ok(());
        }
        let Some(engine) = self.this.upgrade() else {
            return Ok(());
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let Some((thread, id)) =
            os::spawn(
                move || {
                    while !stopped.load(Ordering::Acquire) && engine.read(false).is_ok() {}
                },
            )
        else {
            // What `std::thread::spawn` did when the system gave no thread, kept as it was: the
            // ABI's guard answers the C call with an error. The port's start has no answer for
            // "no thread" yet (zenoh-pico's `_Z_ERR_SYSTEM_TASK_FAILED`), which is where this
            // belongs.
            panic!("the system gave no thread for the read task");
        };
        *reader = Some(ReadTask { stop, thread, id });
        Ok(())
    }

    fn stop_read_task(&self) -> Result<(), CalledFromReadTask> {
        self.stop_reader()
    }

    fn read_task_is_running(&self) -> bool {
        lock(&self.reader)
            .as_ref()
            .is_some_and(|task| !task.thread.is_finished())
    }

    fn read(&self, _single: bool) -> Result<(), SessionClosed> {
        // The wait comes first and holds nothing of the session, so what arrives during it is
        // read by this call and a publisher on another thread is not held up by it.
        let wait = self
            .live()
            .map_or(IdleWait::None, |core| core.0.idle_wait());
        wait.wait();
        // One pass of the session's task reads what its link holds, a batch at a time, and does
        // what is due: `single` asks for one message, and a pass is the least this engine reads.
        let stepped = match self.live() {
            Some(mut core) => self.step(&mut core.0),
            None => false,
        };
        self.deliver();
        #[cfg(feature = "ticker")]
        self.run_due_tickers();
        if stepped {
            Ok(())
        } else {
            Err(SessionClosed)
        }
    }

    fn send_keep_alive(&self) -> Result<(), SessionClosed> {
        let core = self.live().ok_or(SessionClosed)?;
        // A link that is down has no lease to keep; the session is not closed.
        for actions in core.0.ups() {
            actions.send_keep_alive();
        }
        Ok(())
    }

    fn spin_once(&self) -> bool {
        self.read(false).is_ok()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
    /// This session as the C handle's drive. Made HERE (out of line), so the session's drop glue
    /// is this crate's and not a second copy in the ABI crate that holds the handle, as the tokio
    /// engine's `SessionState::into_drive` is.
    #[inline(never)]
    pub fn into_drive(self: Arc<Self>) -> Box<dyn SessionDrive> {
        Box::new(Drive(self))
    }
}

/// The C handle's hold on an engine: the engine is shared with the entities declared on it and
/// with its read task, so the handle holds it as one of its `Arc`s.
struct Drive<L: SessionLinks + 'static, C: ClockSource + Clone + 'static>(Arc<CoopEngine<L, C>>);

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> SessionDrive for Drive<L, C> {
    fn engine(&self) -> Arc<dyn SessionEngine> {
        self.0.clone()
    }

    fn engine_ref(&self) -> &dyn SessionEngine {
        &*self.0
    }

    fn zid(&self) -> [u8; 16] {
        self.0.zid
    }

    fn close(&self) {
        SessionDrive::close(&*self.0)
    }

    fn is_closed(&self) -> bool {
        SessionDrive::is_closed(&*self.0)
    }

    fn start_read_task(&self) -> Result<(), CalledFromReadTask> {
        self.0.start_read_task()
    }

    fn stop_read_task(&self) -> Result<(), CalledFromReadTask> {
        self.0.stop_read_task()
    }

    fn read_task_is_running(&self) -> bool {
        self.0.read_task_is_running()
    }

    fn read(&self, single: bool) -> Result<(), SessionClosed> {
        self.0.read(single)
    }

    fn send_keep_alive(&self) -> Result<(), SessionClosed> {
        self.0.send_keep_alive()
    }

    fn spin_once(&self) -> bool {
        self.0.spin_once()
    }

    fn as_any(&self) -> &dyn Any {
        &*self.0
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> Drop for Drive<L, C> {
    /// The C program let go of its session (zenoh-pico's `z_session_drop`), which closes it: the
    /// read task, which holds the engine too, is stopped and joined, and an entity declared on the
    /// session that outlives it finds it closed.
    fn drop(&mut self) {
        SessionDrive::close(&*self.0);
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> Drop for CoopEngine<L, C> {
    fn drop(&mut self) {
        // The last handle is gone, so no read task holds one: it has stopped, or is about to
        // drop the handle it held. A session never closed is closed now; a closed one has no
        // link left to end.
        self.core.get_mut().0.end_links();
    }
}
