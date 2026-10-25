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

use std::any::Any;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::thread::{JoinHandle, ThreadId};

use wz_capi_port::{
    CalledFromReadTask, FanoutError, FilterId, FilterPlane, FilteredPut, MatchId, MatchingSink,
    SessionClosed, SessionDrive, SessionEngine, SubId, SubscriberSink, WireKey,
};
use wz_runtime_coop::session_drive::{
    spawn_session, LinkReadiness, OpenedLink, SessionDatagramLink, SessionDriveConfig,
    SessionLinks, SessionRole,
};
use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopRuntime, CoopTime};
use wz_session_core::close_reason::CloseReason;
use wz_session_core::declare::matching::BoxedMatchingSink;
use wz_session_core::declare::queryable::QuerierCriterion;
use wz_session_core::declare::subscriber::PublisherCriterion;
use wz_session_core::declare_form::{InterestForm, RetractionKey};
use wz_session_core::driver_loop::DriverOutcome;
use wz_session_core::entropy::EntropySource;
use wz_session_core::interest_build::InterestKinds;
use wz_session_core::locality::Locality;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::observer::ApplicationLayerObserver;
use wz_session_core::publish_options::{PlainPutParams, PublishError, PublishOptions};
use wz_session_core::pubsub::SubscriptionId;
use wz_session_core::push_build;
use wz_session_core::sample::{Sample, SampleKind};
use wz_session_core::send_wire_error::SendWireError;
use wz_session_core::session_init_params::{LinkRxConf, SessionInitParams, TxQueueConf};
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::sink::{BoxedSink, SampleView};
use wz_session_core::WhatAmI;
#[cfg(not(feature = "queryable"))]
use wz_session_mcu::app_layer::dispatch_to;
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
}

/// Why no session was opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// The configuration names no endpoint.
    NoEndpoint,
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
    /// What the liveliness subscribers' sinks queued for their callbacks (`liveliness`).
    #[cfg(feature = "liveliness")]
    live_samples: LivelinessQueue,
    zid: [u8; 16],
    closed: AtomicBool,
    next_entity: AtomicU64,
    reader: Mutex<Option<ReadTask>>,
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

std::thread_local! {
    /// The engines this thread is handing deliveries out for, by address.
    static DELIVERING: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

/// This thread's delivery for one engine, from `enter` to drop.
struct Delivering(usize);

impl Delivering {
    /// `None` when this thread is already delivering for `engine`.
    fn enter(engine: usize) -> Option<Self> {
        DELIVERING.with(|set| {
            let mut set = set.borrow_mut();
            if set.contains(&engine) {
                return None;
            }
            set.push(engine);
            Some(Self(engine))
        })
    }
}

impl Drop for Delivering {
    fn drop(&mut self) {
        DELIVERING.with(|set| set.borrow_mut().retain(|e| *e != self.0));
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
    thread: JoinHandle<()>,
    id: ThreadId,
}

struct Core<L: SessionLinks + 'static, C: ClockSource + 'static> {
    local: CoopLocalSet<C>,
    runtime: CoopRuntime<C>,
    clock: C,
    /// What the application holds and what the peer declared. It is the session's, so it
    /// outlives each link: a new link is dispatched to the same observer.
    observer: Rc<RefCell<ApplicationLayerObserver>>,
    link: Link<C>,
    /// The network the session's links are opened on; it outlives them.
    links: L,
    /// Each handshake's cookie key comes from here.
    entropy: Box<dyn EntropySource>,
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
}

/// The session's link: up, being dialled, or waiting to be.
enum Link<C: ClockSource + 'static> {
    /// Established: the session's sends go through it.
    Up(Wire<C>),
    /// A handshake under way with the endpoint before `next`, given up at `deadline_us`.
    Dialing {
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
    /// The link's next input, for at most this many milliseconds.
    Input(Arc<dyn LinkReadiness>, u32),
    /// The next dial, for at most this many milliseconds.
    Dial(u32),
}

impl IdleWait {
    fn wait(self) {
        match self {
            IdleWait::None => {}
            IdleWait::Input(readiness, ms) => readiness.wait_readable(ms),
            IdleWait::Dial(ms) => std::thread::sleep(std::time::Duration::from_millis(ms.into())),
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
    /// Declare this subscriber over `actions`.
    fn declare<C: ClockSource + 'static>(&self, actions: &McuActions<C>) {
        let _ = if self.wire.is_literal() {
            actions.send_declare_subscriber(self.id, 0, Some(&self.keyexpr))
        } else {
            actions.send_declare_subscriber(
                self.id,
                self.wire.mapping_id,
                self.wire.suffix.as_deref(),
            )
        };
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
    /// Declare this queryable over `actions`.
    fn declare<C: ClockSource + 'static>(&self, actions: &McuActions<C>) {
        let _ = if self.wire.is_literal() {
            actions.send_declare_queryable(self.id, 0, Some(&self.keyexpr), self.complete)
        } else {
            actions.send_declare_queryable(
                self.id,
                self.wire.mapping_id,
                self.wire.suffix.as_deref(),
                self.complete,
            )
        };
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
    /// Send this Interest over `actions`, for what is declared now and what is declared later.
    fn send<C: ClockSource + 'static>(&self, actions: &McuActions<C>) {
        let _ = actions.send_interest_kinds(
            self.interest_id,
            kinds(self.plane),
            /* current */ true,
            /* future */ true,
            self.form.aggregate,
            self.form.mapping_id,
            self.form.suffix.as_deref(),
        );
    }
}

struct MatchEntry {
    id: MatchId,
    /// What the listener counts, as a write filter names it: which registry `watch` is in.
    plane: FilterPlane,
    watch: u64,
    keyexpr: String,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
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

/// The `on_event` of a link whose session answers queries outside its lock: the observer's
/// dispatch, with the `ResponseFinal`s it owes held back for the queries a callback is still to
/// answer (`query`). Everything else the dispatch staged (the replies of a queryable that answers
/// in place, declare replies, get prunes) goes out at once, as `dispatch_to` sends it.
#[cfg(feature = "queryable")]
fn dispatch_holding_finals<C: ClockSource + 'static>(
    observer: Rc<RefCell<ApplicationLayerObserver>>,
    actions: Rc<McuActions<C>>,
    plane: Arc<QueryPlane>,
    generation: u64,
) -> impl FnMut(wz_session_core::driver_loop::IterationEvent<'_>) + 'static {
    move |event| {
        let mut observer = observer.borrow_mut();
        observer.dispatch_event(event);
        observer.flush_pending_replies(&*actions);
        for (rid, qos) in observer.take_pending_final_rids() {
            if lock(&plane.holds).owe(generation, rid, qos) {
                actions.send_response_final(rid, qos);
            }
        }
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> Core<L, C> {
    /// The link's actions while it is up, which is what the session sends through. `None` while
    /// it is dialled or waits to be: what is declared then is declared when it comes up.
    fn up(&self) -> Option<&Rc<McuActions<C>>> {
        match &self.link {
            Link::Up(wire) => Some(&wire.actions),
            _ => None,
        }
    }

    /// The link's actions while it is up and is the link of `generation`: where an answer to a
    /// query that came in on that link goes.
    #[cfg(feature = "queryable")]
    fn up_as(&self, generation: u64) -> Option<&Rc<McuActions<C>>> {
        match &self.link {
            Link::Up(wire) if wire.generation == generation => Some(&wire.actions),
            _ => None,
        }
    }

    /// Start a handshake with the first endpoint, from index `from` on, that a link opens to.
    /// `Err` with the reason the last endpoint tried gave (`last` when none is), or with
    /// [`OpenError::EntropyUnavailable`] when the platform gives no cookie key for the attempt.
    fn dial_from(&mut self, from: usize, mut last: OpenError) -> Result<Link<C>, OpenError> {
        for (at, endpoint) in self.config.endpoints.iter().enumerate().skip(from) {
            let to = match parse_locator(endpoint) {
                Ok(to) => to,
                Err(refused) => {
                    last = OpenError::Unreachable(format!("{endpoint}: {refused:?}"));
                    continue;
                }
            };
            let OpenedLink { sink, pump } = match self.links.open_initiator(to) {
                Ok(opened) => opened,
                Err(refused) => {
                    last = OpenError::Unreachable(format!("{endpoint}: {refused:?}"));
                    continue;
                }
            };
            // The parameters the tokio engine gives a session (`wz-capi-core`'s `init_params`),
            // with a cookie key of its own per attempt.
            let params = SessionInitParams {
                whatami: self.config.whatami,
                zid: self.wire_zid.clone(),
                seq_num_res: 2,
                req_id_res: 2,
                batch_size: self.config.batch_size,
                lease_ms: self.config.lease_ms,
                initial_sn: 0,
                cookie: Vec::new(),
                tx_queue: self.config.tx_queue,
                link_rx: LinkRxConf::default(),
                cookie_signing_key: SigningKey::from_entropy(&mut *self.entropy)
                    .map_err(|_| OpenError::EntropyUnavailable)?,
            };
            let actions = McuActions::<C>::new_generic(sink, params, CoopTime::new(&self.runtime));
            let readiness = pump.readiness().map(Arc::from);
            let link = Rc::new(pump);
            #[cfg(feature = "queryable")]
            let generation = self.plane.generation.fetch_add(1, Ordering::AcqRel) + 1;
            #[cfg(feature = "queryable")]
            let dispatch = dispatch_holding_finals(
                self.observer.clone(),
                actions.clone(),
                self.plane.clone(),
                generation,
            );
            #[cfg(not(feature = "queryable"))]
            let dispatch = dispatch_to(self.observer.clone(), actions.clone());
            let task = spawn_session(
                &self.local,
                link.clone(),
                actions.clone(),
                CoopTime::new(&self.runtime),
                SessionDriveConfig {
                    timeouts: self.config.timeouts,
                    role: SessionRole::Initiator,
                    max_iters: None,
                },
                dispatch,
            );
            // The task's first step sends the InitSyn now, not after the wait of the next read.
            self.local.run_until_idle();
            let deadline_us = self
                .clock
                .now_us()
                .saturating_add(self.config.open_timeout_ms.saturating_mul(1000));
            return Ok(Link::Dialing {
                wire: Wire {
                    actions,
                    task,
                    link,
                    readiness,
                    #[cfg(feature = "queryable")]
                    generation,
                },
                next: at + 1,
                deadline_us,
            });
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

    /// Move the link on, after the session was stepped. A handshake that completed brings the
    /// link up and declares over it what the session holds; one that ended or ran out of time
    /// gives way to the next endpoint; a lost link takes what its peer declared with it and is
    /// dialled again. `Err` when the session ends: its link was lost, or no endpoint answered,
    /// and `redial_ms` is `None`; or the platform gave no entropy.
    fn poll_link(&mut self, redial_ms: Option<u64>) -> Result<(), OpenError> {
        let now_us = self.clock.now_us();
        let link = std::mem::replace(&mut self.link, Link::Waiting { at_us: now_us });
        self.link = match link {
            // zenoh-pico's client reopens whatever ended its link: a lease that ran out, a read
            // that failed, a Close from the router (`vendor/zenoh-pico/src/transport/unicast/read.c` @
            // `return _zp_unicast_failed_result(ztu, executor);`).
            Link::Up(wire) if wire.task.is_finished() => {
                drop(wire);
                self.lose_link();
                if redial_ms.is_none() {
                    return Err(OpenError::Unreachable(String::from("the link was lost")));
                }
                self.dial_or_wait(0, OpenError::NoEndpoint, now_us, redial_ms)?
            }
            Link::Dialing {
                wire,
                next,
                deadline_us,
            } => {
                if wire.actions.is_established() {
                    self.redeclare(&wire.actions);
                    Link::Up(wire)
                } else if wire.task.is_finished() || now_us >= deadline_us {
                    let why = match (wire.actions.close_reason(), wire.task.is_finished()) {
                        (Some(reason), _) => format!("the handshake ended: {reason:?}"),
                        (None, true) => String::from("the handshake ended"),
                        (None, false) => String::from("no answer in time"),
                    };
                    let last = OpenError::Unreachable(format!(
                        "{}: {why}",
                        self.config.endpoints[next - 1]
                    ));
                    wire.task.abort();
                    self.local.run_until_idle();
                    drop(wire);
                    self.dial_or_wait(next, last, now_us, redial_ms)?
                } else {
                    Link::Dialing {
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
        Ok(())
    }

    /// What a lost link takes with it: every subscriber and queryable its peer declared, so a
    /// matching status or a write filter that counted on one reads the session as it now is.
    /// zenoh-pico drops a peer's targets from every write filter when its connection drops
    /// (`vendor/zenoh-pico/src/net/filtering.c` @ `case _Z_INTEREST_MSG_TYPE_CONNECTION_DROPPED: {`).
    fn lose_link(&mut self) {
        let mut observer = self.observer.borrow_mut();
        observer.flush_declarations_on_link_loss();
        observer.flush_liveliness_on_link_loss();
        // A get's legs went with the link: the peer that owed their Finals is gone, so each
        // pending entry is dropped, which ends its leg (`get`).
        #[cfg(feature = "query")]
        for pending in self.pending_gets.drain(..) {
            pending.unregister(&mut observer);
        }
    }

    /// Declare again, over a link that has just come up, what the session holds, under the ids it
    /// was declared with: its key expressions first, since a subscriber or an Interest may name
    /// one, then its subscribers and its Interests, its queryables, its tokens and its liveliness
    /// subscribers' Interests. zenoh-pico sends its declaration cache again
    /// once a reopen succeeds (`vendor/zenoh-pico/src/net/session.c` @
    /// `_z_fut_fn_result_t _z_client_reopen_task_fn(void *ztc_arg, _z_executor_t *executor) {`).
    fn redeclare(&self, actions: &McuActions<C>) {
        for entry in &self.keyexprs {
            let _ = actions.send_declare_keyexpr(entry.id, &entry.keyexpr);
        }
        for entry in &self.subscribers {
            entry.declare(actions);
        }
        for hold in &self.interests {
            hold.send(actions);
        }
        #[cfg(feature = "queryable")]
        for entry in &self.queryables {
            entry.declare(actions);
        }
        #[cfg(feature = "liveliness")]
        {
            for entry in &self.tokens {
                entry.declare(actions);
            }
            for entry in &self.live_subs {
                entry.ask(actions);
            }
        }
    }

    /// When the earliest pending get is due: a query's or a liveliness snapshot's.
    #[cfg(feature = "query")]
    fn next_get_deadline_ms(&self) -> Option<u64> {
        let observer = self.observer.borrow();
        let due = observer.replies.next_deadline_ms();
        #[cfg(feature = "liveliness-get")]
        let due = [due, observer.liveliness_gets.next_deadline_ms()]
            .into_iter()
            .flatten()
            .min();
        due
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
            Some(due_ms) => {
                let left_us = due_ms
                    .saturating_mul(1000)
                    .saturating_sub(self.clock.now_us());
                u32::try_from(left_us.div_ceil(1000)).map_or(most, |left| left.min(most))
            }
            None => most,
        };
        if most == 0 {
            return IdleWait::None;
        }
        match &self.link {
            Link::Up(wire) | Link::Dialing { wire, .. } => match &wire.readiness {
                Some(readiness) if !wire.link.holds_input() => {
                    IdleWait::Input(readiness.clone(), most)
                }
                _ => IdleWait::None,
            },
            Link::Waiting { at_us } => {
                let left_ms = at_us.saturating_sub(self.clock.now_us()) / 1000;
                match u32::try_from(left_ms).map_or(most, |left| left.min(most)) {
                    0 => IdleWait::None,
                    ms => IdleWait::Dial(ms),
                }
            }
        }
    }

    /// End the link, whatever it is doing, telling an established peer so.
    fn end_link(&mut self) {
        let link = std::mem::replace(&mut self.link, Link::Waiting { at_us: u64::MAX });
        if let Link::Up(wire) | Link::Dialing { wire, .. } = link {
            if wire.actions.is_established() {
                wire.actions.send_close_with_reason(CloseReason::Generic);
            }
            wire.task.abort();
        }
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
        entropy: impl EntropySource + 'static,
        config: CoopConfig,
    ) -> Result<Arc<Self>, OpenError> {
        let mut entropy: Box<dyn EntropySource> = Box::new(entropy);
        let wire = match &config.zid {
            Some(zid) => wire_zid(zid),
            None => fresh_zid(&mut *entropy)?,
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
            observer: Rc::new(RefCell::new(ApplicationLayerObserver::new())),
            link: Link::Waiting { at_us: u64::MAX },
            links,
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
        };
        #[cfg(feature = "queryable")]
        let plane = core.plane.clone();
        #[cfg(feature = "query")]
        let gets = core.gets.clone();
        core.link = core.dial_from(0, OpenError::NoEndpoint)?;
        while !matches!(core.link, Link::Up(_)) {
            core.idle_wait().wait();
            core.local.run_until_idle();
            core.poll_link(None)?;
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
            #[cfg(feature = "liveliness")]
            live_samples: Arc::new(Mutex::new(VecDeque::new())),
            zid,
            closed: AtomicBool::new(false),
            next_entity: AtomicU64::new(1),
            reader: Mutex::new(None),
            this: this.clone(),
        }))
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

    /// Hand out what the session delivered, with no lock held.
    ///
    /// A callback may step its session again (`zp_read` from inside a subscriber), and that step
    /// delivers nothing itself: the delivery this thread is already making goes on to hand out
    /// what the inner step queued, in order. Delivering from the inner call would run a callback
    /// inside itself, waiting on its own lock.
    fn deliver(&self) {
        let Some(_delivering) = Delivering::enter(self as *const Self as usize) else {
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

    /// Tell `fan`, when the get can be cancelled, how to undo leg `leg`: a token cancelled while
    /// the leg is issued undoes it at once (`record` runs it).
    #[cfg(feature = "query")]
    fn cancelling(&self, fan: Option<&CancellableFan>, leg: u64) {
        if let Some(fan) = fan {
            let engine = self.this.clone();
            fan.record(move || {
                if let Some(engine) = engine.upgrade() {
                    engine.cancel_get(leg);
                }
            });
        }
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
                pending.unregister(&mut core.observer.borrow_mut());
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
        // because this is what runs on every step and the entries are the observer's.
        #[cfg(feature = "query")]
        {
            let now_ms = core.clock.now_us() / 1000;
            let mut observer = core.observer.borrow_mut();
            observer.replies.sweep_timed_out(now_ms);
            // A liveliness snapshot that expired ends the same way. Its terminated ids are
            // staged for a reconnect cache this engine does not keep (it declares again from its
            // own entries), so they are drained and dropped: staged ones would pile up.
            #[cfg(feature = "liveliness-get")]
            {
                observer.liveliness_gets.sweep_timed_out(now_ms);
                drop(observer.liveliness_gets.take_finalized());
            }
        }
        let redial_ms = core.config.redial_ms;
        if core.poll_link(redial_ms).is_err() {
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
        if let Some(actions) = core.up() {
            hold.send(actions);
        }
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
            let hold = core.interests.remove(at);
            if let Some(actions) = core.up() {
                actions.send_interest_final(hold.interest_id);
            }
        }
    }

    /// Whether a peer declared what `plane` counts on `keyexpr`.
    fn peer_matches(core: &Core<L, C>, plane: FilterPlane, keyexpr: &str) -> bool {
        let observer = core.observer.borrow();
        match plane {
            FilterPlane::Subscribers => observer
                .remote_subscribers
                .has_matching_for(&PublisherCriterion::new(keyexpr, Locality::Remote)),
            FilterPlane::Queryables { complete_required } => observer
                .remote_queryables
                .has_matching_for(&QuerierCriterion::new(
                    keyexpr,
                    Locality::Remote,
                    complete_required,
                )),
        }
    }

    /// Stop the read task, from a thread that is not it.
    fn stop_reader(&self) -> Result<(), CalledFromReadTask> {
        let task = {
            let mut reader = lock(&self.reader);
            match reader.as_ref() {
                None => return Ok(()),
                Some(task) if task.id == std::thread::current().id() => {
                    return Err(CalledFromReadTask)
                }
                Some(_) => reader.take(),
            }
        };
        if let Some(task) = task {
            task.stop.store(true, Ordering::Release);
            let _ = task.thread.join();
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

    fn next_entity_id(&self) -> u64 {
        self.next_entity.fetch_add(1, Ordering::Relaxed)
    }

    fn peer_identities(&self) -> Vec<(Vec<u8>, u8)> {
        let Some(core) = self.live() else {
            return Vec::new();
        };
        let Some(actions) = core.0.up().filter(|actions| actions.is_established()) else {
            return Vec::new();
        };
        match (actions.peer_zid(), actions.peer_whatami_wire()) {
            (Some(zid), Some(role)) => vec![(zid, role)],
            _ => Vec::new(),
        }
    }

    fn has_router_peer(&self) -> bool {
        self.live().is_some_and(|core| {
            core.0
                .up()
                .is_some_and(|actions| actions.peer_whatami_wire() == Some(0))
        })
    }

    fn publish_on_wire_all(
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
        // A link that is down skips the publish, as a send over it would.
        let Some(actions) = core.0.up() else {
            return Ok(0);
        };
        let meta = opts.push_metadata();
        let reliable = opts.reliable_bool();
        let express = meta.is_express();
        let priority = opts.priority_band();
        let suffix = wire.suffix.as_deref();
        // A plain Put is sent from the borrowed bytes, as the tokio engine sends it.
        if opts.kind == SampleKind::Put && meta.is_plain_apart_from_qos() {
            let (mapping_id, suffix) = if wire.is_literal() {
                (0, Some(keyexpr))
            } else {
                (wire.mapping_id, suffix)
            };
            return leg(actions.send_plain_put_qos(
                mapping_id, suffix, payload, meta.qos, reliable, express, priority,
            ));
        }
        let push = match (opts.kind, wire.mapping_id) {
            (SampleKind::Put, 0) => {
                push_build::build_push_literal_with_meta(keyexpr, payload, &meta)
            }
            (SampleKind::Del, 0) => push_build::build_push_del_literal_with_meta(keyexpr, &meta),
            (SampleKind::Put, mapping_id) => {
                push_build::build_push_aliased_with_meta(mapping_id, suffix, payload, &meta)
            }
            (SampleKind::Del, mapping_id) => {
                push_build::build_push_del_aliased_with_meta(mapping_id, suffix, &meta)
            }
        };
        let Ok(push) = push else {
            return Err(FanoutError::ExceedsCapacity);
        };
        leg(actions.send_network_message_qos(
            NetworkMessage::Push(Box::new(push)),
            reliable,
            express,
            priority,
        ))
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
        let Some(mut core) = self.live() else {
            return id;
        };
        let core = &mut core.0;
        let queue = self.samples.clone();
        let registration = core.observer.borrow_mut().subscribers.register_sink(
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
        if let Some(actions) = core.up() {
            entry.declare(actions);
        }
        core.subscribers.push(entry);
        id
    }

    fn undeclare_subscriber(&self, id: SubId) {
        // A liveliness subscriber's id is one of these too (the port's one id space): its
        // registration goes and its Interest ends.
        #[cfg(feature = "liveliness")]
        let live = self.live().and_then(|mut core| {
            let core = &mut core.0;
            let at = core.live_subs.iter().position(|s| s.id == id)?;
            let entry = core.live_subs.remove(at);
            core.observer
                .borrow_mut()
                .liveliness_subscribers
                .unregister(id);
            if let Some(actions) = core.up() {
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
            let entry = core.subscribers.remove(at);
            core.observer
                .borrow_mut()
                .subscribers
                .unregister(entry.registration);
            match (core.up(), &entry.retraction) {
                (Some(actions), Some(key)) => {
                    actions.send_undeclare_subscriber_naming(id, key.mapping_id, &key.suffix)
                }
                (Some(actions), None) => actions.send_undeclare_subscriber(id),
                (None, _) => {}
            }
            Some(entry)
        });
        let callback = self.take_target(id);
        drop((entry, callback));
    }

    fn acquire_keyexpr(&self, keyexpr: String) -> Option<u64> {
        let mut core = self.live()?;
        let core = &mut core.0;
        if let Some(entry) = core.keyexprs.iter_mut().find(|e| e.keyexpr == keyexpr) {
            entry.holds += 1;
            return Some(entry.id);
        }
        let id = core.next_mapping;
        // A declaration the link refuses is not made; one made while the link is down is sent
        // when it comes up.
        if let Some(actions) = core.up() {
            actions.send_declare_keyexpr(id, &keyexpr).ok()?;
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
            core.keyexprs.remove(at);
            if let Some(actions) = core.up() {
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
        // The session's own subscribers and queryables never match: this engine delivers
        // nothing locally, as zenoh-pico's default build (`Z_FEATURE_LOCAL_SUBSCRIBER` and
        // `Z_FEATURE_LOCAL_QUERYABLE` 0) does not.
        _count_local: bool,
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
        let now = Self::peer_matches(core, plane, &keyexpr);
        let queue = self.matching.clone();
        let report = BoxedMatchingSink::new(move |matching| {
            lock(&queue).push_back((id, matching));
        });
        // The watch is in the registry of what `plane` counts, with the criterion its write
        // filter reads ([`Self::peer_matches`]), so the listener and the filter cannot differ.
        let watch = {
            let mut observer = core.observer.borrow_mut();
            match plane {
                FilterPlane::Subscribers => observer
                    .remote_subscribers
                    .declare_matching_listener_seeded(
                        PublisherCriterion::new(&keyexpr, Locality::Remote),
                        false,
                        report,
                    ),
                FilterPlane::Queryables { complete_required } => {
                    observer.remote_queryables.declare_matching_listener_seeded(
                        QuerierCriterion::new(&keyexpr, Locality::Remote, complete_required),
                        false,
                        report,
                    )
                }
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
                    let mut observer = core.observer.borrow_mut();
                    match entry.plane {
                        FilterPlane::Subscribers => observer
                            .remote_subscribers
                            .undeclare_matching_listener(entry.watch),
                        FilterPlane::Queryables { .. } => observer
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
        // See `declare_matching_listener`: no entity of this session matches.
        _count_local: bool,
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
        });
        id
    }

    fn write_filter_active(&self, id: FilterId) -> bool {
        let Some(core) = self.live() else {
            return false;
        };
        let core = &core.0;
        // A filter is created suppressing, until a peer declares what it counts
        // (`vendor/zenoh-pico/src/net/filtering.c` @ `ctx->state = WRITE_FILTER_ACTIVE`).
        core.filters
            .iter()
            .find(|f| f.id == id)
            .is_some_and(|f| !Self::peer_matches(core, f.plane, &f.keyexpr))
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
        if !params.destination.allows_remote() {
            return FilteredPut::Sent(Ok(0));
        }
        let Some(core) = self.live() else {
            return FilteredPut::Sent(Ok(0));
        };
        let Some(actions) = core.0.up() else {
            return FilteredPut::Sent(Ok(0));
        };
        let suffix = (mapping_id == 0).then_some(keyexpr);
        FilteredPut::Sent(leg(actions.send_plain_put_qos(
            mapping_id,
            suffix,
            payload,
            params.qos,
            params.reliable,
            params.express,
            params.priority,
        )))
    }

    fn batch_start_all(&self) -> usize {
        self.live().map_or(0, |core| {
            core.0
                .up()
                .map_or(0, |actions| usize::from(actions.batch_start().is_ok()))
        })
    }

    fn batch_flush_all(&self) -> usize {
        self.live().map_or(0, |core| {
            core.0
                .up()
                .map_or(0, |actions| usize::from(actions.batch_flush().is_ok()))
        })
    }

    fn batch_stop_all(&self) -> usize {
        self.live().map_or(0, |core| {
            core.0
                .up()
                .map_or(0, |actions| usize::from(actions.batch_stop().is_ok()))
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
        let mut core = self.live()?;
        let core = &mut core.0;
        // The observer's queryable only copies a query out and holds its Final; the callback
        // `sink` mints runs when the deliveries are handed out (`query`).
        let plane = self.plane.clone();
        let registration = core
            .observer
            .borrow_mut()
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
        if let Some(actions) = core.up() {
            entry.declare(actions);
        }
        core.queryables.push(entry);
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
        // The one peer this session reaches is its link's; it asks no queryable of its own
        // (`get`). A get that may not leave the session, or a session with no link up, reaches
        // nobody, and is over at once.
        if !opts.allowed_destination.allows_remote() {
            return Some(0);
        }
        let leg_id = self.next_entity_id();
        let Some(mut guard) = self.live() else {
            return Some(0);
        };
        let core = &mut guard.0;
        let Some(actions) = core.up().cloned() else {
            return Some(0);
        };
        let rid = actions.alloc_next_request_id();
        let timeout_ms = opts.effective_timeout_ms();
        // Rounded up, so a get whose deadline the sweep reads in whole milliseconds never ends
        // before its timeout.
        let deadline_ms =
            (timeout_ms > 0).then(|| core.clock.now_us().div_ceil(1000) + u64::from(timeout_ms));
        let sink = ConsolidatingSink::new(
            opts.resolved_consolidation(),
            get::reply_sink(leg_id, &self.gets),
        );
        // One Final: the link's peer's.
        let registered = core.observer.borrow_mut().replies.register_sink(
            rid,
            1,
            deadline_ms,
            ReplyAcceptance::for_query(keyexpr, opts.effective_accept_replies()),
            sink,
        );
        if registered.is_err() {
            return Some(0);
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
            // Nothing went out: the entry and the leg go, and the get is over.
            core.observer.borrow_mut().replies.unregister(rid);
            drop(guard);
            drop(self.take_target(leg_id));
            return Some(0);
        }
        core.pending_gets.push(PendingGet {
            leg: leg_id,
            rid,
            kind: GetKind::Query,
        });
        drop(guard);
        self.cancelling(fan, leg_id);
        Some(1)
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
        // The one peer this session reaches is its link's; a session with no link up reaches
        // nobody, and the snapshot is over at once.
        let leg_id = self.next_entity_id();
        let Some(mut guard) = self.live() else {
            return Some(0);
        };
        let core = &mut guard.0;
        let Some(actions) = core.up().cloned() else {
            return Some(0);
        };
        let interest_id = actions.alloc_next_interest_id();
        // `0` is the platform default and never no deadline, as pico's `z_liveliness_get`
        // rewrites it (`vendor/zenoh-pico/src/api/liveliness.c` @
        // `if (opt.timeout_ms == 0) {`); rounded up as a query's deadline is.
        let timeout_ms = match timeout_ms {
            0 => DEFAULT_QUERY_TIMEOUT_MS,
            set => set,
        };
        let deadline_ms = Some(core.clock.now_us().div_ceil(1000) + u64::from(timeout_ms));
        // One DeclFinal: the link's peer's. Registered before the Interest goes out, so no
        // answer can arrive before its entry.
        let registered = core.observer.borrow_mut().liveliness_gets.register(
            interest_id,
            deadline_ms,
            get::reply_sink(leg_id, &self.gets),
        );
        if !matches!(registered, Ok(true)) {
            return Some(0);
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
            // Nothing went out: the entry and the leg go, and the snapshot is over.
            core.observer
                .borrow_mut()
                .liveliness_gets
                .unregister(interest_id);
            drop(guard);
            drop(self.take_target(leg_id));
            return Some(0);
        }
        core.pending_gets.push(PendingGet {
            leg: leg_id,
            rid: interest_id,
            kind: GetKind::Liveliness,
        });
        drop(guard);
        self.cancelling(fan, leg_id);
        Some(1)
    }

    #[cfg(feature = "queryable")]
    fn undeclare_queryable(&self, id: QblId) {
        let entry = self.live().and_then(|mut core| {
            let core = &mut core.0;
            let at = core.queryables.iter().position(|q| q.id == id)?;
            let entry = core.queryables.remove(at);
            core.observer
                .borrow_mut()
                .queryables
                .unregister(entry.registration);
            if let Some(actions) = core.up() {
                entry.retract(actions);
            }
            Some(entry)
        });
        let callback = self.take_target(id);
        drop((entry, callback));
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
        core.observer
            .borrow_mut()
            .local_tokens
            .register(id, &keyexpr)
            .ok()?;
        let entry = TokenEntry {
            id,
            keyexpr,
            wire,
            retraction,
        };
        if let Some(actions) = core.up() {
            entry.declare(actions);
        }
        core.tokens.push(entry);
        Some(id)
    }

    #[cfg(feature = "liveliness")]
    fn undeclare_liveliness_token(&self, id: TokenId) {
        let entry = self.live().and_then(|mut core| {
            let core = &mut core.0;
            let at = core.tokens.iter().position(|t| t.id == id)?;
            let entry = core.tokens.remove(at);
            core.observer.borrow_mut().local_tokens.unregister(id);
            if let Some(actions) = core.up() {
                entry.retract(actions);
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
        let registered = core.observer.borrow_mut().liveliness_subscribers.register(
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
        if let Some(actions) = core.up() {
            entry.ask(actions);
        }
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
        core.end_link();
        let subscribers: Vec<SubId> = core.subscribers.drain(..).map(|s| s.id).collect();
        let matches: Vec<MatchId> = core.matches.drain(..).map(|m| m.id).collect();
        #[cfg(feature = "queryable")]
        let queryables: Vec<QblId> = core.queryables.drain(..).map(|q| q.id).collect();
        #[cfg(not(feature = "queryable"))]
        let queryables: Vec<u64> = Vec::new();
        // A get still pending ends with its session: its entry and its leg's callback go.
        #[cfg(feature = "query")]
        let gets: Vec<u64> = {
            let mut observer = core.observer.borrow_mut();
            core.pending_gets
                .drain(..)
                .map(|pending| {
                    pending.unregister(&mut observer);
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
        drop(std::mem::take(&mut *lock(&self.live_samples)));
        #[cfg(feature = "query")]
        drop(std::mem::take(&mut *lock(&self.gets.events)));
        // The queries no callback will now answer, and the callbacks' C contexts, are dropped
        // with no lock held.
        #[cfg(feature = "queryable")]
        drop(std::mem::take(&mut *lock(&self.plane.queries)));
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
            if task.id == std::thread::current().id() {
                return Err(CalledFromReadTask);
            }
            return Ok(());
        }
        let Some(engine) = self.this.upgrade() else {
            return Ok(());
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = std::thread::spawn(move || {
            while !stopped.load(Ordering::Acquire) && engine.read(false).is_ok() {}
        });
        let id = thread.thread().id();
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
        if stepped {
            Ok(())
        } else {
            Err(SessionClosed)
        }
    }

    fn send_keep_alive(&self) -> Result<(), SessionClosed> {
        let core = self.live().ok_or(SessionClosed)?;
        // A link that is down has no lease to keep; the session is not closed.
        if let Some(actions) = core.0.up() {
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
        self.core
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .0
            .end_link();
    }
}
