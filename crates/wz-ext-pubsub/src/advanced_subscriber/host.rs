// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! An advanced subscriber hosted on an engine's port: what declares its entities, asks its gets,
//! runs its two periodic jobs and takes it down, written over [`SessionEngine`] and nothing else.
//!
//! The host is generic over the engine `E`: the port's object by default, or an engine's own type,
//! which an ABI built with one engine names so that every call is resolved when the build is made
//! and no table of all the session's operations is made for the subscriber.
//!
//! The ordering machine ([`super::state`]) and the plans ([`super::plans`]) decide; this module
//! does what they ask. It names no runtime: the subscription, the liveliness subscriptions and the
//! detection token are the port's declarations, a get is the port's `get_on_wire` with one
//! callback per leg, and a periodic job is the port's ticker. So the same host runs on the
//! cooperative engine, where a tick is as late as the program is slow to step the session, and on
//! the tokio engine, where it is a task.
//!
//! # How a get ends
//!
//! The port ends a leg by dropping its callback. A get is over when the LAST leg's callback is, so
//! every callback of one get holds the same `GetEnd`, and what the machine does when a get ends
//! (close its slot, flush what it buffered) is that value's `Drop`. The host holds one more
//! reference while it issues the get, which is what makes a get that no leg was issued for, or
//! that every leg ended while it was still being issued, end exactly once and after the call
//! returned, with no lock of the engine held.
//!
//! # How a subscriber is taken down
//!
//! Dropping the handle retracts the entities in the order the tokio runtime's does, and in the
//! middle of them cancels the gets in flight, so that nothing arriving afterwards reaches the
//! application's callback, which the application may free the moment the handle is dropped. A
//! cancelled get's callbacks are dropped by the engine, and a dropped callback is a leg's end for
//! any reason, so the host sets `closing` first: a get that ends because it was cancelled does not
//! flush into a callback that is going away.
//!
//! This is the widest form (history, which implies recovery), the one a C ABI's option struct
//! asks for. A build that wants less links the machine and the plans alone.

use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, Ordering};

use wz_capi_port::cancellation::{register_fan, CancellationToken, Registration};
use wz_capi_port::{
    LivelinessSink, Refusal, ReplyCallback, SessionEngine, SubId, SubscriberSink, Ticker, TokenId,
    WireKey,
};
use wz_session_core::declare::liveliness_sample::{LivelinessSample, LivelinessSampleKind};
use wz_session_core::declare_form::RetractionKey;
use wz_session_core::locality::Locality;
use wz_session_core::query_mode::{ConsolidationMode, QueryTarget};
use wz_session_core::query_options::QueryOptions;
use wz_session_core::reply_sink::ReplyView;
use wz_session_core::sample::{EntityGlobalId, Sample};
use wz_session_core::sample_kind::SampleKind;
use wz_session_core::serde_codec::z_deserialize;
use wz_session_core::session_zid::SessionZid;
use wz_session_core::sink::SampleView;
use wz_session_core::zid_hex::zid_to_zenoh_hex;

use super::options::{AdvancedSubscriberOptions, DeclarationForms, EntityForm, FormsHandle};
use super::plans::{
    history_selector, parse_heartbeat_source, recovered_sample_from_reply,
    recovery_query_timeout_ms, AdvPublisherSource,
};
use super::state::{Miss, MissHandlers, RecoveryRequest, SampleMissListener, State};
use crate::prelude::*;
use crate::sync::{lock_or_panic, Mutex, MutexGuard};

/// Why declaring an advanced subscriber on an engine failed.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HostError {
    /// The engine is closed, or does not carry what the subscriber needs in this build (a
    /// liveliness plane, a requesting end, periodic jobs); the text says which. A refusal and not
    /// a degradation: the caller asked for it, and a subscriber that quietly lacks it is the
    /// failure nobody can see from outside.
    Refused(&'static str),
    /// The session has handed out every declaration id it can put on the wire, so the
    /// subscription was not declared.
    IdsExhausted,
    /// A history bound was zero, which upstream refuses at construction.
    HistoryBoundZero {
        /// Which knob: `"max_samples"` or `"max_age"`.
        knob: &'static str,
    },
    /// The engine refused a declaration the subscriber is made of, for this cause.
    Declined(Refusal),
}

impl HostError {
    /// The engine's refusal of `what`, one of the declarations a subscriber is made of: a spent
    /// id space and a plane this build does not hold keep the names they had, and any other
    /// cause is carried as the engine gave it.
    fn of(what: &'static str) -> impl FnOnce(Refusal) -> Self {
        move |refused| match refused {
            Refusal::NoEntityId => Self::IdsExhausted,
            Refusal::NotBuilt => Self::Refused(what),
            other => Self::Declined(other),
        }
    }
}

impl core::fmt::Display for HostError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Refused(what) => write!(f, "the engine refused an advanced subscriber: {what}"),
            Self::IdsExhausted => {
                f.write_str("the session has handed out every 32-bit declaration id")
            }
            Self::HistoryBoundZero { knob } => write!(f, "history {knob} must not be zero"),
            Self::Declined(refused) => {
                write!(f, "the engine refused an advanced subscriber: {refused}")
            }
        }
    }
}

impl core::error::Error for HostError {}

/// What every callback and job of one subscriber shares.
struct Shared<E: SessionEngine + ?Sized> {
    /// Held weakly: the engine holds the callbacks that hold this.
    engine: Weak<E>,
    state: Arc<Mutex<State>>,
    /// The cancellation of the gets in flight, and what teardown cancels through.
    token: Arc<CancellationToken>,
    /// Set before the gets are cancelled, and never cleared: from then on nothing reaches the
    /// application's callback.
    closing: AtomicBool,
    /// The key expression this subscriber subscribes to.
    base_keyexpr: String,
    /// The destination of every get.
    dest: Locality,
    /// The timeout of every get, in milliseconds.
    timeout_ms: u32,
}

impl<E: SessionEngine + ?Sized> Shared<E> {
    fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Acquire)
    }

    /// The engine's clock, or zero when the engine is gone (and then nothing is asked of it).
    fn now_ms(&self) -> u64 {
        self.engine.upgrade().map_or(0, |engine| engine.now_ms())
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        lock_or_panic(&self.state, super::state::STATE_POISONED)
    }
}

/// The end of one get: runs what the machine does when it is over, once, when the last holder is
/// dropped. See the module doc.
struct GetEnd<E: SessionEngine + ?Sized> {
    shared: Arc<Shared<E>>,
    finish: Box<dyn Fn(&mut State) + Send + Sync>,
    /// Held to the end of the get, so a teardown waits for it.
    _registration: Registration,
}

impl<E: SessionEngine + ?Sized> Drop for GetEnd<E> {
    fn drop(&mut self) {
        if self.shared.is_closing() {
            return;
        }
        (self.finish)(&mut self.shared.lock());
    }
}

/// A subscription (or liveliness subscription) the engine holds, retracted when this is dropped.
struct Subscription<E: SessionEngine + ?Sized> {
    engine: Arc<E>,
    id: SubId,
    retract: bool,
}

impl<E: SessionEngine + ?Sized> Drop for Subscription<E> {
    fn drop(&mut self) {
        if self.retract {
            self.engine.undeclare_subscriber(self.id);
        }
    }
}

/// A liveliness token the engine holds, retracted when this is dropped.
struct Token<E: SessionEngine + ?Sized> {
    engine: Arc<E>,
    id: TokenId,
    retract: bool,
}

impl<E: SessionEngine + ?Sized> Drop for Token<E> {
    fn drop(&mut self) {
        if self.retract {
            self.engine.undeclare_liveliness_token(self.id);
        }
    }
}

/// An entity and what keeps its wire name valid. The entity is the FIRST field, so it is
/// retracted first and the name goes right after it, which is the order a host that declares keys
/// shows a peer.
struct Held<T> {
    entity: T,
    keeps: Option<Arc<dyn Send + Sync>>,
}

/// The teardown of the gets in flight. Armed until the subscriber goes to the background, which
/// leaves them running to their Final.
struct GetCancel<E: SessionEngine + ?Sized> {
    shared: Arc<Shared<E>>,
    armed: bool,
}

impl<E: SessionEngine + ?Sized> Drop for GetCancel<E> {
    fn drop(&mut self) {
        if self.armed {
            self.shared.closing.store(true, Ordering::Release);
            self.shared.token.cancel();
        }
    }
}

/// A live advanced subscriber on an engine's port, named by the engine's type `E` (the port's
/// object unless the holder names its engine's own).
pub struct EngineSubscriber<E: SessionEngine + ?Sized = dyn SessionEngine> {
    // THE FIELD ORDER IS THE RETRACTION ORDER, the tokio runtime's: the subscription, the two
    // jobs, the gets in flight, the late-publisher subscription, the heartbeat subscription and
    // the detection token.
    subscriber: Held<Subscription<E>>,
    periodic: Option<Ticker<E>>,
    retention: Option<Ticker<E>>,
    cancel: GetCancel<E>,
    late_publishers: Option<Held<Subscription<E>>>,
    heartbeat: Option<Held<Subscription<E>>>,
    detection_token: Option<Held<Token<E>>>,
    shared: Arc<Shared<E>>,
    id: EntityGlobalId,
    keyexpr: String,
    /// Kept for [`Self::background`], which hands the names back to the host that made them.
    forms: Option<FormsHandle>,
}

/// The wire form of an entity as the host named it.
fn wire_of(form: &EntityForm) -> WireKey {
    let wire = if form.is_literal() {
        WireKey::literal()
    } else {
        WireKey::aliased(form.mapping_id(), form.suffix().map(str::to_owned))
    };
    match form.kept() {
        Some(anchor) => wire.keeping(Arc::clone(anchor)),
        None => wire,
    }
}

/// What forms says about one entity, the literal form when it says nothing.
fn form_of(
    forms: Option<&FormsHandle>,
    ask: impl FnOnce(&dyn DeclarationForms) -> EntityForm,
) -> EntityForm {
    forms.map(|f| ask(f.forms())).unwrap_or_default()
}

impl<E: SessionEngine + ?Sized> EngineSubscriber<E> {
    /// Declare an advanced subscriber on `keyexpr` over `engine`, delivering to `on_sample`.
    ///
    /// What `options` asks for is declared and refused if the engine cannot carry it: a
    /// subscription always; a heartbeat subscription and a periodic job when recovery asks for
    /// them; the startup get and the late-publisher subscription when history asks for them; the
    /// detection token when detection does. The order is the tokio runtime's.
    pub fn declare(
        engine: &Arc<E>,
        keyexpr: impl Into<String>,
        options: AdvancedSubscriberOptions,
        on_sample: impl FnMut(Sample) + Send + 'static,
    ) -> Result<Self, HostError> {
        Self::declare_with_misses(engine, keyexpr, options, on_sample, MissHandlers::default())
    }

    /// [`Self::declare`] with one miss listener registered from the start, which never leaves.
    pub fn declare_with_miss_listener(
        engine: &Arc<E>,
        keyexpr: impl Into<String>,
        options: AdvancedSubscriberOptions,
        on_sample: impl FnMut(Sample) + Send + 'static,
        on_miss: impl FnMut(Miss) + Send + 'static,
    ) -> Result<Self, HostError> {
        let mut misses = MissHandlers::default();
        misses.register(Box::new(on_miss));
        Self::declare_with_misses(engine, keyexpr, options, on_sample, misses)
    }

    fn declare_with_misses(
        engine: &Arc<E>,
        keyexpr: impl Into<String>,
        options: AdvancedSubscriberOptions,
        on_sample: impl FnMut(Sample) + Send + 'static,
        misses: MissHandlers,
    ) -> Result<Self, HostError> {
        // Upstream's own config check opens its builder, before a single entity is declared.
        if let Some(history) = options.history.as_ref() {
            if history.sample_depth == Some(0) {
                return Err(HostError::HistoryBoundZero {
                    knob: "max_samples",
                });
            }
            if history.max_age == Some(0.0) {
                return Err(HostError::HistoryBoundZero { knob: "max_age" });
            }
        }
        if engine.is_closed() {
            return Err(HostError::Refused("the session is closed"));
        }
        let zid = engine.session_zid();
        let recovery = options.recovery;
        let retransmission = recovery.is_some();
        let history = options.history;
        let base_keyexpr: String = keyexpr.into();
        let dest = options.get_locality;
        let timeout_ms = recovery_query_timeout_ms(options.query_timeout);
        let forms = options.forms.clone();

        let state = State::new(Box::new(on_sample), misses)
            .with_retransmission(retransmission)
            .with_history(
                usize::from(history.is_some()),
                history
                    .as_ref()
                    .and_then(|h| h.sample_depth)
                    .unwrap_or(usize::MAX),
            );
        let shared = Arc::new(Shared {
            engine: Arc::downgrade(engine),
            state: Arc::new(Mutex::new(state)),
            token: CancellationToken::new(),
            closing: AtomicBool::new(false),
            base_keyexpr: base_keyexpr.clone(),
            dest,
            timeout_ms,
        });

        // The live subscription.
        let subscriber_form = form_of(forms.as_ref(), |f| f.subscriber(&base_keyexpr));
        let live_shared = Arc::clone(&shared);
        let live_sink = SubscriberSink::shared(move |view: &dyn SampleView| {
            let shared = &live_shared;
            if shared.is_closing() {
                return;
            }
            let now = shared.now_ms();
            let request = shared.lock().handle_live(view, now);
            // Issued OUTSIDE the state lock: the get re-enters the engine, and a loopback answer
            // re-enters the state.
            if let Some(request) = request {
                issue_recovery_query(shared, request);
            }
        });
        let subscriber = declare_subscription(
            engine,
            &base_keyexpr,
            &subscriber_form,
            options.allowed_origin,
            live_sink,
        )?;
        let id = identity_of(zid, subscriber.entity.id, forms.as_ref());

        // The retention sweep and the periodic re-ask: jobs the engine runs.
        let retention = match recovery.map(|c| c.retention_period()) {
            Some(period) => {
                let weak = Arc::downgrade(&shared);
                let period_ms = u64::try_from(period.as_millis()).unwrap_or(u64::MAX);
                Some(
                    Ticker::start_on(
                        Arc::clone(engine),
                        period_ms,
                        Arc::new(move || {
                            let Some(shared) = weak.upgrade() else {
                                return false;
                            };
                            if shared.is_closing() {
                                return false;
                            }
                            let now = shared.now_ms();
                            shared.lock().reclaim_expired_sources(now, period);
                            true
                        }),
                    )
                    .map_err(HostError::of("the engine runs no periodic jobs"))?,
                )
            }
            None => None,
        };
        let periodic = match recovery.and_then(|c| c.periodic_queries()) {
            Some(period) => {
                let weak = Arc::downgrade(&shared);
                let period_ms = u64::try_from(period.as_millis()).unwrap_or(u64::MAX);
                Some(
                    Ticker::start_on(
                        Arc::clone(engine),
                        period_ms,
                        Arc::new(move || {
                            let Some(shared) = weak.upgrade() else {
                                return false;
                            };
                            if shared.is_closing() {
                                return false;
                            }
                            run_periodic_tick(&shared);
                            true
                        }),
                    )
                    .map_err(HostError::of("the engine runs no periodic jobs"))?,
                )
            }
            None => None,
        };

        // The startup get, after the live subscription, so a live sample that arrives during it
        // is held until the history is in.
        if let Some(history) = history {
            issue_history_query(&shared, history.sample_depth, history.max_age);
        }

        // The late-publisher subscription, declared to replay the tokens already alive: the
        // startup get is a snapshot, and a publisher whose cache filled after it is met here.
        let late_publishers = if history.is_some_and(|h| h.detect_late_publishers) {
            let keyexpr = crate::advanced_ke::publisher_detection_ke(&base_keyexpr);
            let form = form_of(forms.as_ref(), |f| f.late_publishers(&keyexpr));
            let (depth, age) = history
                .map(|h| (h.sample_depth, h.max_age))
                .unwrap_or((None, None));
            let lp_shared = Arc::clone(&shared);
            let sink = LivelinessSink::shared(move |sample: LivelinessSample<'_>| {
                let shared = &lp_shared;
                if shared.is_closing() {
                    return;
                }
                on_late_publisher_detected(shared, sample.kind, sample.keyexpr, depth, age);
            });
            Some(declare_liveliness_subscription(
                engine, &keyexpr, &form, true, sink,
            )?)
        } else {
            None
        };

        // The heartbeat subscription, in the place pico declares it, and degraded rather than
        // failing when its derived key is one the outbound gate refuses.
        let heartbeat = if recovery.is_some_and(|c| c.heartbeat()) {
            let keyexpr = crate::advanced_ke::publisher_detection_ke(&base_keyexpr);
            if crate::advanced_ke::adv_ke_is_outbound_safe(&keyexpr) {
                let form = form_of(forms.as_ref(), |f| f.heartbeat(&keyexpr));
                let hb_shared = Arc::clone(&shared);
                let sink = SubscriberSink::shared(move |view: &dyn SampleView| {
                    let shared = &hb_shared;
                    if shared.is_closing() || view.kind() != SampleKind::Put {
                        return;
                    }
                    // Sequenced only: a heartbeat's payload IS a sequence number.
                    let Some(AdvPublisherSource::Sequenced { zid, eid }) =
                        parse_heartbeat_source(view.keyexpr())
                    else {
                        return;
                    };
                    let Ok(last_sn) = z_deserialize::<u32>(view.payload()) else {
                        return;
                    };
                    let now = shared.now_ms();
                    let request = shared.lock().handle_heartbeat(zid, eid, last_sn, now);
                    if let Some(request) = request {
                        issue_recovery_query(shared, request);
                    }
                });
                Some(declare_subscription(
                    engine,
                    &keyexpr,
                    &form,
                    options.allowed_origin,
                    sink,
                )?)
            } else {
                log::warn!(
                    "advanced subscriber on '{base_keyexpr}': heartbeat recovery was REQUESTED \
                     but its derived keyexpr '{keyexpr}' is refused by the outbound pico-safety \
                     gate, so the channel is DEGRADED; the live subscription is unaffected"
                );
                None
            }
        } else {
            None
        };

        // The detection token, last: a subscriber advertises itself once it can receive.
        let detection_token = declare_detection_token(engine, &base_keyexpr, &options, id)?;

        Ok(Self {
            subscriber,
            periodic,
            retention,
            cancel: GetCancel {
                shared: Arc::clone(&shared),
                armed: true,
            },
            late_publishers,
            heartbeat,
            detection_token,
            shared,
            id,
            keyexpr: base_keyexpr,
            forms,
        })
    }

    /// This subscriber's global identity: the session's zid and the id its subscription carries.
    pub fn id(&self) -> EntityGlobalId {
        self.id
    }

    /// The key expression this subscriber subscribes to.
    pub fn keyexpr(&self) -> &str {
        &self.keyexpr
    }

    /// Whether the heartbeat channel is actually live: a request that the derived key made
    /// impossible degrades, and this is the outcome.
    pub fn heartbeat_channel_is_live(&self) -> bool {
        self.heartbeat.is_some()
    }

    /// Declare a sample-miss listener. Any number may be declared and each is retracted on its
    /// own, by dropping the handle or [`SampleMissListener::undeclare`].
    pub fn sample_miss_listener(
        &self,
        callback: impl FnMut(Miss) + Send + 'static,
    ) -> SampleMissListener {
        let id = self
            .shared
            .lock()
            .miss_handlers()
            .register(Box::new(callback));
        SampleMissListener::new(id, Arc::downgrade(&self.shared.state))
    }

    /// Undeclare this subscriber. Consuming and infallible: everything it holds retracts on drop.
    pub fn undeclare(self) {
        drop(self);
    }

    /// Run this subscriber in the background until the engine is dropped, with no handle left to
    /// retract it. The entities stay declared, the gets in flight run to their Final, and the
    /// jobs run on until their weak references stop upgrading. What names an entity is handed to
    /// the host that made it, since nothing is left to let it go after the entity.
    pub fn background(self) {
        let Self {
            subscriber,
            periodic,
            retention,
            mut cancel,
            late_publishers,
            heartbeat,
            detection_token,
            shared: _,
            id: _,
            keyexpr: _,
            forms,
        } = self;
        cancel.armed = false;
        let retain = |keeps: Option<Arc<dyn Send + Sync>>| {
            if let (Some(forms), Some(keeps)) = (forms.as_ref(), keeps) {
                forms.forms().retain(keeps);
            }
        };
        let Held { mut entity, keeps } = subscriber;
        entity.retract = false;
        retain(keeps);
        for ticker in [periodic, retention].into_iter().flatten() {
            ticker.detach();
        }
        for held in [late_publishers, heartbeat].into_iter().flatten() {
            let Held { mut entity, keeps } = held;
            entity.retract = false;
            retain(keeps);
        }
        if let Some(Held { mut entity, keeps }) = detection_token {
            entity.retract = false;
            retain(keeps);
        }
    }
}

/// The identity a subscriber reports: its host's, when the host has one, else its subscription's
/// own id, which is the entity id its declaration carries.
fn identity_of(
    zid: SessionZid,
    subscription: SubId,
    forms: Option<&FormsHandle>,
) -> EntityGlobalId {
    let eid = forms
        .and_then(|f| f.forms().entity_id())
        .unwrap_or(subscription);
    EntityGlobalId::of_session(zid, eid)
}

/// Declare a plain subscription on `keyexpr` in `form`.
fn declare_subscription<E: SessionEngine + ?Sized>(
    engine: &Arc<E>,
    keyexpr: &str,
    form: &EntityForm,
    origin: Locality,
    sink: SubscriberSink,
) -> Result<Held<Subscription<E>>, HostError> {
    let id = engine
        .declare_subscriber_on_wire(
            keyexpr,
            wire_of(form),
            origin,
            form.retraction().cloned(),
            sink,
        )
        .map_err(HostError::of("the engine has no subscribers"))?;
    Ok(Held {
        entity: Subscription {
            engine: Arc::clone(engine),
            id,
            retract: true,
        },
        keeps: form.kept().cloned(),
    })
}

/// Declare a liveliness subscription on `keyexpr` in `form`.
fn declare_liveliness_subscription<E: SessionEngine + ?Sized>(
    engine: &Arc<E>,
    keyexpr: &str,
    form: &EntityForm,
    history: bool,
    sink: LivelinessSink,
) -> Result<Held<Subscription<E>>, HostError> {
    let id = engine
        .declare_liveliness_subscriber_on_wire(keyexpr, wire_of(form), history, sink)
        .map_err(HostError::of("the engine has no liveliness plane"))?;
    Ok(Held {
        entity: Subscription {
            engine: Arc::clone(engine),
            id,
            retract: true,
        },
        keeps: form.kept().cloned(),
    })
}

/// Declare the `@adv/sub` detection token when the caller asked for it, else `None`.
fn declare_detection_token<E: SessionEngine + ?Sized>(
    engine: &Arc<E>,
    keyexpr: &str,
    options: &AdvancedSubscriberOptions,
    id: EntityGlobalId,
) -> Result<Option<Held<Token<E>>>, HostError> {
    let Some(detection) = options.subscriber_detection.as_ref() else {
        return Ok(None);
    };
    // Named with the subscriber's OWN identity, the pair its `id()` reports.
    let ke = crate::advanced_ke::subscriber_adv_ke(
        keyexpr,
        &zid_to_zenoh_hex(id.zid()),
        id.eid(),
        detection.metadata.as_deref(),
    );
    let form = form_of(options.forms.as_ref(), |f| f.token(&ke));
    let retraction = form.names_key_on_retraction().then(|| RetractionKey {
        mapping_id: form.mapping_id(),
        suffix: if form.is_literal() {
            ke.clone()
        } else {
            form.suffix().unwrap_or_default().to_owned()
        },
    });
    let token = engine
        .declare_liveliness_token_on_wire(&ke, wire_of(&form), retraction)
        .map_err(HostError::of("the engine has no liveliness plane"))?;
    Ok(Some(Held {
        entity: Token {
            engine: Arc::clone(engine),
            id: token,
            retract: true,
        },
        keeps: form.kept().cloned(),
    }))
}

/// The options every get of this subscriber carries: it reads each reply's timestamp (it is the
/// runtime's own query, not an entity of the application), goes where the subscriber was told to,
/// is bounded by the timeout so a get nobody answers ends, asks every queryable and not the best
/// match, and takes every sample of a range and not the latest of each key.
fn get_options<E: SessionEngine + ?Sized>(shared: &Shared<E>, parameters: String) -> QueryOptions {
    QueryOptions::get()
        .with_expose_timestamp(true)
        .with_allowed_destination(shared.dest)
        .with_timeout_ms(shared.timeout_ms)
        .with_parameters(parameters.into_bytes())
        .with_target(QueryTarget::All)
        .with_consolidation(ConsolidationMode::None)
}

/// Issue one get on `keyexpr` with `opts`, feeding each reply to the machine and running `finish`
/// when the get is over. MUST be called with the state lock released.
///
/// A reply keyed outside the subscription is dropped here: `_anyke` opts out of the responder's
/// reply-keyexpr guard, and this is the local half upstream pairs it with.
fn issue_get<E: SessionEngine + ?Sized>(
    shared: &Arc<Shared<E>>,
    keyexpr: &str,
    opts: QueryOptions,
    finish: impl Fn(&mut State) + Send + Sync + 'static,
) {
    let Some(engine) = shared.engine.upgrade() else {
        return;
    };
    // Registered before the first leg is issued, as upstream orders it, so a teardown that
    // starts now stops the issuing. `None` is a teardown already under way.
    let Some((fan, registration)) = register_fan(&shared.token) else {
        return;
    };
    let end = Arc::new(GetEnd {
        shared: Arc::clone(shared),
        finish: Box::new(finish),
        _registration: registration,
    });
    let mut leg = || -> ReplyCallback {
        let end = Arc::clone(&end);
        ReplyCallback::shared(move |reply: &dyn ReplyView| {
            let shared = &end.shared;
            if shared.is_closing() {
                return;
            }
            if !wz_session_core::keyexpr_match::keyexpr_intersects(
                &shared.base_keyexpr,
                reply.keyexpr(),
            ) {
                return;
            }
            // `live = false`: the get that produced this reply is the one in flight, so a gap
            // here must not fan another.
            if let Some(sample) = recovered_sample_from_reply(reply) {
                let now = shared.now_ms();
                let _ = shared.lock().ingest(sample, false, now);
            }
        })
    };
    let _ = engine.get_on_wire(keyexpr, &WireKey::literal(), &opts, Some(&fan), &mut leg);
    // The reference held while issuing goes last: a get with no leg ends here, and one whose legs
    // all ended during the call ends here too, after the call returned.
    drop(end);
}

/// Issue a `_sn` recovery get against the gapped source's `@adv` cache: the open range from the
/// next sequence number, or the bounded one a heartbeat asks for.
fn issue_recovery_query<E: SessionEngine + ?Sized>(
    shared: &Arc<Shared<E>>,
    request: RecoveryRequest,
) {
    let zid_hex = zid_to_zenoh_hex(&request.zid);
    let keyexpr = crate::advanced_ke::recovery_get_ke(&shared.base_keyexpr, &zid_hex, request.eid);
    let range = match request.to_sn {
        Some(to) => format!("_sn={}..{}", request.from_sn, to),
        None => format!("_sn={}..", request.from_sn),
    };
    let opts = get_options(
        shared,
        wz_session_core::selector_params::anyke_params(&[range]),
    );
    let key = (request.zid, request.eid);
    issue_get(shared, &keyexpr, opts, move |state| {
        state.finish_recovery(&key)
    });
}

/// Issue the startup get over `<base>/@adv/**`, capped and bounded as the history config says.
fn issue_history_query<E: SessionEngine + ?Sized>(
    shared: &Arc<Shared<E>>,
    depth: Option<usize>,
    age: Option<f64>,
) {
    let keyexpr = crate::advanced_ke::history_get_ke(&shared.base_keyexpr);
    let opts = get_options(shared, history_selector(depth, age));
    issue_get(shared, &keyexpr, opts, |state| state.finish_history());
}

/// Issue the history get of one detected late publisher `(zid, eid)`.
fn issue_late_publisher_query<E: SessionEngine + ?Sized>(
    shared: &Arc<Shared<E>>,
    zid: Vec<u8>,
    eid: u32,
    depth: Option<usize>,
    age: Option<f64>,
) {
    let zid_hex = zid_to_zenoh_hex(&zid);
    let keyexpr = crate::advanced_ke::recovery_get_ke(&shared.base_keyexpr, &zid_hex, eid);
    let opts = get_options(shared, history_selector(depth, age));
    let key = (zid, eid);
    issue_get(shared, &keyexpr, opts, move |state| {
        state.finish_recovery(&key)
    });
}

/// The timestamped twin: the target is the token's own key expression, which is the one the
/// publisher declared its cache queryable on.
fn issue_timestamped_late_publisher_query<E: SessionEngine + ?Sized>(
    shared: &Arc<Shared<E>>,
    token_keyexpr: &str,
    zid: Vec<u8>,
    depth: Option<usize>,
    age: Option<f64>,
) {
    let opts = get_options(shared, history_selector(depth, age));
    issue_get(shared, token_keyexpr, opts, move |state| {
        state.finish_timestamped_recovery(&zid)
    });
}

/// The get for a publisher whose token's zid does not decode: counted globally, since there is no
/// source to count it against.
fn issue_unidentified_late_publisher_query<E: SessionEngine + ?Sized>(
    shared: &Arc<Shared<E>>,
    token_keyexpr: &str,
    depth: Option<usize>,
    age: Option<f64>,
) {
    let opts = get_options(shared, history_selector(depth, age));
    issue_get(shared, token_keyexpr, opts, |state| state.finish_history());
}

/// The late-publisher liveliness callback: on a `Put`, open a slot for the detected publisher and
/// issue its history get (outside the lock); on a `Delete`, only mark it gone.
fn on_late_publisher_detected<E: SessionEngine + ?Sized>(
    shared: &Arc<Shared<E>>,
    kind: LivelinessSampleKind,
    token_keyexpr: &str,
    depth: Option<usize>,
    age: Option<f64>,
) {
    if kind != LivelinessSampleKind::Put {
        // A departed publisher has nothing to recover, but its retention flag is how the sweep
        // learns it is not alive any more.
        if let Some(source) = parse_heartbeat_source(token_keyexpr) {
            if let Some((zid, eid)) = match source {
                AdvPublisherSource::Sequenced { zid, eid } => Some((zid, Some(eid))),
                AdvPublisherSource::Timestamped { zid } => Some((zid, None)),
                AdvPublisherSource::Unidentified => None,
            } {
                shared.lock().set_source_alive(&zid, eid, false);
            }
        }
        return;
    }
    let now = shared.now_ms();
    match parse_heartbeat_source(token_keyexpr) {
        Some(AdvPublisherSource::Sequenced { zid, eid }) => {
            let issue = {
                let mut state = shared.lock();
                let issue = state.handle_late_publisher(zid.clone(), eid, now);
                state.set_source_alive(&zid, Some(eid), true);
                issue
            };
            if issue {
                issue_late_publisher_query(shared, zid, eid, depth, age);
            }
        }
        Some(AdvPublisherSource::Timestamped { zid }) => {
            let issue = {
                let mut state = shared.lock();
                let issue = state.handle_late_timestamped_publisher(zid.clone(), now);
                state.set_source_alive(&zid, None, true);
                issue
            };
            if issue {
                issue_timestamped_late_publisher_query(shared, token_keyexpr, zid, depth, age);
            }
        }
        Some(AdvPublisherSource::Unidentified) => {
            shared.lock().open_global_history_slot();
            issue_unidentified_late_publisher_query(shared, token_keyexpr, depth, age);
        }
        None => {}
    }
}

/// One periodic recovery tick: collect each source's `_sn=last+1..` request under the state lock,
/// then issue the gets with it released.
fn run_periodic_tick<E: SessionEngine + ?Sized>(shared: &Arc<Shared<E>>) {
    let requests = shared.lock().periodic_requests();
    for request in requests {
        issue_recovery_query(shared, request);
    }
}

#[cfg(test)]
mod tests;
