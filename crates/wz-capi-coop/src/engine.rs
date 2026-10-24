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
    spawn_session, OpenedLink, SessionDriveConfig, SessionLinks, SessionRole,
};
use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopRuntime, CoopTime};
use wz_session_core::close_reason::CloseReason;
use wz_session_core::declare::matching::BoxedMatchingSink;
use wz_session_core::declare::queryable::QuerierCriterion;
use wz_session_core::declare::subscriber::PublisherCriterion;
use wz_session_core::declare_form::{InterestForm, RetractionKey};
use wz_session_core::driver_loop::DriverOutcome;
use wz_session_core::interest_build::InterestKinds;
use wz_session_core::locality::Locality;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::observer::ApplicationLayerObserver;
use wz_session_core::publish_options::{PlainPutParams, PublishError, PublishOptions};
use wz_session_core::pubsub::SubscriptionId;
use wz_session_core::push_build;
use wz_session_core::sample::{Sample, SampleKind};
use wz_session_core::send_wire_error::SendWireError;
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::sink::{BoxedSink, SampleView};
use wz_session_mcu::app_layer::dispatch_to;
use wz_session_mcu::dial::{parse_locator, McuActions};

/// How a session is opened.
pub struct CoopConfig {
    /// The endpoints to dial (`tcp/a.b.c.d:port` or `udp/a.b.c.d:port`), in order: the session
    /// is opened to the first that answers, as zenoh-pico's client opens to the first of its
    /// `connect` locators that does.
    pub endpoints: Vec<String>,
    /// The handshake's deadlines.
    pub timeouts: SessionTimeouts,
    /// How long one endpoint is given to complete the handshake, in milliseconds.
    pub open_timeout_ms: u64,
}

/// Why no session was opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// The configuration names no endpoint.
    NoEndpoint,
    /// No endpoint could be dialled: each was refused, unreachable or did not complete the
    /// handshake in time. The last endpoint's reason.
    Unreachable(String),
}

/// One session the program steps; see the module doc.
pub struct CoopEngine<L: SessionLinks + 'static, C: ClockSource + 'static> {
    core: Mutex<Confined<Core<L, C>>>,
    /// What the session delivered under the lock, handed out after it.
    deliveries: Arc<Mutex<VecDeque<Delivery>>>,
    /// The callbacks deliveries go to, by the id of the entity that owns them. Kept outside
    /// [`Core`] so a delivery takes no session state, and a callback that undeclares another
    /// entity finds its target gone rather than the lock held.
    targets: Mutex<Vec<(u64, Target)>>,
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
// `Sample`s and `bool`s, see `Delivery`), so every handle of each `Rc` moves with the `Core` when
// another thread takes the lock, and none is used by two threads at once.
unsafe impl<T> Send for Confined<T> {}

/// What the session delivered while it was stepped.
enum Delivery {
    Sample(SubId, Sample),
    Matching(MatchId, bool),
}

/// A subscriber's callback, as the ABI's sink minted it. Locked while it runs, so a delivery
/// from the read task and one from the program's own `zp_read` never overlap.
type SubscriberCallback = Arc<Mutex<Box<dyn FnMut(&dyn SampleView) + Send + 'static>>>;

/// Where a delivery goes.
enum Target {
    Subscriber(SubscriberCallback),
    Matching(MatchingSink),
}

/// The read task: a thread that steps the session until it is told to stop.
struct ReadTask {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
    id: ThreadId,
}

struct Core<L: SessionLinks + 'static, C: ClockSource + 'static> {
    local: CoopLocalSet<C>,
    observer: Rc<RefCell<ApplicationLayerObserver>>,
    actions: Rc<McuActions<C>>,
    task: CoopLocalJoinHandle<DriverOutcome>,
    /// The network the session's link was opened on; it outlives the link.
    _links: Rc<L>,
    subscribers: Vec<SubEntry>,
    keyexprs: Vec<KexprEntry>,
    next_mapping: u64,
    filters: Vec<FilterEntry>,
    next_filter: FilterId,
    interests: Vec<InterestHold>,
    matches: Vec<MatchEntry>,
    next_match: MatchId,
}

struct SubEntry {
    id: SubId,
    registration: SubscriptionId,
    retraction: Option<RetractionKey>,
    /// Kept for what its key holds alive while the declaration stands.
    _wire: WireKey,
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
    holds: usize,
}

struct MatchEntry {
    id: MatchId,
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

fn same_plane(a: FilterPlane, b: FilterPlane) -> bool {
    matches!(
        (a, b),
        (FilterPlane::Subscribers, FilterPlane::Subscribers)
            | (
                FilterPlane::Queryables { .. },
                FilterPlane::Queryables { .. }
            )
    )
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

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
    /// Open a client session over `links` to the first endpoint of `config` that completes the
    /// handshake, stepping it on this thread until it does. `params` gives each attempt its
    /// session parameters; the zid of the first is the session's.
    pub fn open(
        links: L,
        clock: C,
        mut params: impl FnMut() -> SessionInitParams,
        config: CoopConfig,
    ) -> Result<Arc<Self>, OpenError> {
        let links = Rc::new(links);
        let runtime = CoopRuntime::new(clock.clone());
        let local = CoopLocalSet::new(&runtime);
        let observer = Rc::new(RefCell::new(ApplicationLayerObserver::new()));
        let mut last = OpenError::NoEndpoint;
        for endpoint in &config.endpoints {
            let to = match parse_locator(endpoint) {
                Ok(to) => to,
                Err(refused) => {
                    last = OpenError::Unreachable(format!("{endpoint}: {refused:?}"));
                    continue;
                }
            };
            let OpenedLink { sink, pump } = match links.open_initiator(to) {
                Ok(opened) => opened,
                Err(refused) => {
                    last = OpenError::Unreachable(format!("{endpoint}: {refused:?}"));
                    continue;
                }
            };
            let params = params();
            let mut zid = [0u8; 16];
            let n = params.zid.len().min(16);
            zid[..n].copy_from_slice(&params.zid[..n]);
            let actions = McuActions::<C>::new_generic(sink, params, CoopTime::new(&runtime));
            let task = spawn_session(
                &local,
                pump,
                actions.clone(),
                CoopTime::new(&runtime),
                SessionDriveConfig {
                    timeouts: config.timeouts,
                    role: SessionRole::Initiator,
                    max_iters: None,
                },
                dispatch_to(observer.clone(), actions.clone()),
            );
            let deadline = clock
                .now_us()
                .saturating_add(config.open_timeout_ms.saturating_mul(1000));
            while !actions.is_established() && !task.is_finished() && clock.now_us() < deadline {
                local.run_until_idle();
            }
            if !actions.is_established() {
                let why = match (actions.close_reason(), task.is_finished()) {
                    (Some(reason), _) => format!("the handshake ended: {reason:?}"),
                    (None, true) => String::from("the handshake ended"),
                    (None, false) => String::from("no answer in time"),
                };
                task.abort();
                local.run_until_idle();
                last = OpenError::Unreachable(format!("{endpoint}: {why}"));
                continue;
            }
            let core = Core {
                local,
                observer,
                actions,
                task,
                _links: links,
                subscribers: Vec::new(),
                keyexprs: Vec::new(),
                next_mapping: 1,
                filters: Vec::new(),
                next_filter: 1,
                interests: Vec::new(),
                matches: Vec::new(),
                next_match: 1,
            };
            return Ok(Arc::new_cyclic(|this| Self {
                core: Mutex::new(Confined(core)),
                deliveries: Arc::new(Mutex::new(VecDeque::new())),
                targets: Mutex::new(Vec::new()),
                zid,
                closed: AtomicBool::new(false),
                next_entity: AtomicU64::new(1),
                reader: Mutex::new(None),
                this: this.clone(),
            }));
        }
        Err(last)
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
    fn deliver(&self) {
        loop {
            let Some(delivery) = lock(&self.deliveries).pop_front() else {
                return;
            };
            match delivery {
                Delivery::Sample(id, sample) => {
                    let callback =
                        lock(&self.targets)
                            .iter()
                            .find_map(|(t, target)| match target {
                                Target::Subscriber(cb) if *t == id => Some(cb.clone()),
                                _ => None,
                            });
                    if let Some(callback) = callback {
                        (lock(&callback))(&sample);
                    }
                }
                Delivery::Matching(id, matching) => {
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

    /// Step the session until it has nothing more to do, and notice a session that ended.
    fn step(&self, core: &mut Core<L, C>) -> bool {
        core.local.run_until_idle();
        if core.task.is_finished() {
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
            .find(|h| same_plane(h.plane, plane) && h.keyexpr == keyexpr)
        {
            hold.holds += 1;
            return;
        }
        // zenoh-pico's Interest takes the session's next entity id
        // (`vendor/zenoh-pico/src/net/primitives.c` @ `intr._id = _z_get_entity_id(zn);`).
        let interest_id = self.next_entity_id();
        let _ = core.actions.send_interest_kinds(
            interest_id,
            kinds(plane),
            /* current */ true,
            /* future */ true,
            form.aggregate,
            form.mapping_id,
            form.suffix.as_deref(),
        );
        core.interests.push(InterestHold {
            plane,
            keyexpr: keyexpr.to_owned(),
            interest_id,
            holds: 1,
        });
    }

    /// Let go of one hold on the Interest for `keyexpr` on `plane`; the last one ends it.
    fn release_interest(core: &mut Core<L, C>, plane: FilterPlane, keyexpr: &str) {
        let Some(at) = core
            .interests
            .iter()
            .position(|h| same_plane(h.plane, plane) && h.keyexpr == keyexpr)
        else {
            return;
        };
        core.interests[at].holds -= 1;
        if core.interests[at].holds == 0 {
            let hold = core.interests.remove(at);
            core.actions.send_interest_final(hold.interest_id);
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
        let actions = &core.0.actions;
        if !actions.is_established() {
            return Vec::new();
        }
        match (actions.peer_zid(), actions.peer_whatami_wire()) {
            (Some(zid), Some(role)) => vec![(zid, role)],
            _ => Vec::new(),
        }
    }

    fn has_router_peer(&self) -> bool {
        self.live()
            .is_some_and(|core| core.0.actions.peer_whatami_wire() == Some(0))
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
        let actions = &core.0.actions;
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
        let queue = self.deliveries.clone();
        let registration = core.observer.borrow_mut().subscribers.register_sink(
            &keyexpr,
            allowed_origin,
            BoxedSink::new(move |sample: &dyn SampleView| {
                lock(&queue).push_back(Delivery::Sample(id, Sample::from_view(sample)));
            }),
        );
        let Ok(registration) = registration else {
            return id;
        };
        lock(&self.targets).push((id, Target::Subscriber(Arc::new(Mutex::new(sink())))));
        let _ = if wire.is_literal() {
            core.actions.send_declare_subscriber(id, 0, Some(&keyexpr))
        } else {
            core.actions
                .send_declare_subscriber(id, wire.mapping_id, wire.suffix.as_deref())
        };
        core.subscribers.push(SubEntry {
            id,
            registration,
            retraction,
            _wire: wire,
        });
        id
    }

    fn undeclare_subscriber(&self, id: SubId) {
        let entry = self.live().and_then(|mut core| {
            let core = &mut core.0;
            let at = core.subscribers.iter().position(|s| s.id == id)?;
            let entry = core.subscribers.remove(at);
            core.observer
                .borrow_mut()
                .subscribers
                .unregister(entry.registration);
            match &entry.retraction {
                Some(key) => {
                    core.actions
                        .send_undeclare_subscriber_naming(id, key.mapping_id, &key.suffix)
                }
                None => core.actions.send_undeclare_subscriber(id),
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
        core.actions.send_declare_keyexpr(id, &keyexpr).ok()?;
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
            core.actions.send_undeclare_kexpr(mapping_id);
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

    fn declare_matching_listener_counting_local(
        &self,
        keyexpr: String,
        sink: MatchingSink,
        // The session's own subscribers never match: this engine delivers nothing locally, as
        // zenoh-pico's default build (`Z_FEATURE_LOCAL_SUBSCRIBER` 0) does not.
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
            FilterPlane::Subscribers,
            &keyexpr,
            &InterestForm {
                mapping_id: 0,
                suffix: Some(keyexpr.clone()),
                aggregate: false,
            },
        );
        let now = Self::peer_matches(core, FilterPlane::Subscribers, &keyexpr);
        let queue = self.deliveries.clone();
        let watch = core
            .observer
            .borrow_mut()
            .remote_subscribers
            .declare_matching_listener_seeded(
                PublisherCriterion::new(&keyexpr, Locality::Remote),
                false,
                BoxedMatchingSink::new(move |matching| {
                    lock(&queue).push_back(Delivery::Matching(id, matching));
                }),
            );
        lock(&self.targets).push((id, Target::Matching(sink)));
        // An already-matching registration is told so at once, as zenoh-pico tells it
        // (`vendor/zenoh-pico/src/net/filtering.c` @ `_z_write_filter_ctx_add_callback`).
        if now {
            lock(&self.deliveries).push_back(Delivery::Matching(id, true));
        }
        core.matches.push(MatchEntry { id, watch, keyexpr });
        drop(guard);
        self.deliver();
        id
    }

    fn undeclare_matching_listener(&self, id: MatchId) {
        if let Some(mut core) = self.live() {
            let core = &mut core.0;
            if let Some(at) = core.matches.iter().position(|m| m.id == id) {
                let entry = core.matches.remove(at);
                core.observer
                    .borrow_mut()
                    .remote_subscribers
                    .undeclare_matching_listener(entry.watch);
                Self::release_interest(core, FilterPlane::Subscribers, &entry.keyexpr);
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
        // See `declare_matching_listener_counting_local`: no entity of this session matches.
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
        let suffix = (mapping_id == 0).then_some(keyexpr);
        FilteredPut::Sent(leg(core.0.actions.send_plain_put_qos(
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
        self.live()
            .map_or(0, |core| usize::from(core.0.actions.batch_start().is_ok()))
    }

    fn batch_flush_all(&self) -> usize {
        self.live()
            .map_or(0, |core| usize::from(core.0.actions.batch_flush().is_ok()))
    }

    fn batch_stop_all(&self) -> usize {
        self.live()
            .map_or(0, |core| usize::from(core.0.actions.batch_stop().is_ok()))
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
        if core.actions.is_established() {
            core.actions.send_close_with_reason(CloseReason::Generic);
        }
        core.task.abort();
        core.local.run_until_idle();
        let subscribers: Vec<SubId> = core.subscribers.drain(..).map(|s| s.id).collect();
        let matches: Vec<MatchId> = core.matches.drain(..).map(|m| m.id).collect();
        drop(guard);
        // The callbacks' C contexts are dropped with no lock held.
        let taken: Vec<_> = subscribers
            .into_iter()
            .chain(matches)
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
        core.0.actions.send_keep_alive();
        Ok(())
    }

    fn spin_once(&self) -> bool {
        self.read(false).is_ok()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<L: SessionLinks + 'static, C: ClockSource + 'static> Drop for CoopEngine<L, C> {
    fn drop(&mut self) {
        // The last handle is gone, so no read task holds one: it has stopped, or is about to
        // drop the handle it held. A session never closed is closed now.
        let core = &mut self
            .core
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .0;
        if !self.closed.load(Ordering::Acquire) && core.actions.is_established() {
            core.actions.send_close_with_reason(CloseReason::Generic);
        }
        core.task.abort();
    }
}
