// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A router node as the port's [`SessionEngine`].
//!
//! What a C ABI declares through an engine (a subscriber, a queryable, a liveliness token, a get,
//! a periodic job) is what the node's data plane already does for the program that holds it
//! ([`RouterState`]); this is the same operations in the port's vocabulary, so that what is
//! written over the port (the advanced subscriber's host, the first) runs on a node as it does on
//! the registry of faces.
//!
//! A node names every key whole on the wire, so the operations that exist to hold a key as an alias
//! (a declared key, a write filter that sends by it) have nothing to hold here: the declared keys
//! are none and a write is not held back. The batch windows are zenoh-pico's and a node opens
//! none.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use wz_capi_port::cancellation::CancellableFan;
use wz_capi_port::{
    BatchStep, FanoutError, FilterId, FilterPlane, FilteredPut, HeldQueryId, HeldSlab,
    LivelinessSink, MatchId, MatchingSink, PeerIdentity, QblId, QueryableSink, Refusal,
    ReplyCallback, SessionEngine, StatementNotHonoured, SubId, SubscriberSink, Tick, TickerId,
    TokenId, WireKey,
};
use wz_runtime_tokio::router_forward::MatchPlane;
use wz_session_core::declare_form::{InterestAsk, RetractionKey};
use wz_session_core::face::{FaceEventSink, FaceSnapshot};
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::{PlainPutParams, PublishOptions};
use wz_session_core::query_options::QueryOptionsOf;
use wz_session_core::session_zid::SessionZid;
use wz_session_core::wire_id::{next_u32_id, u32_id_taken, EntityId};

use super::{RouterKept, RouterState};
use crate::caller_span::CallerSpan;
use crate::deliveries::Deliveries;
use crate::faces::{Released, SinkRelease};

/// A job that runs `tick` every period on a thread of its own, until `tick` answers `false` or this
/// is dropped. Dropping tells the thread, which ends at its next wake and is not waited for: the
/// tick may be what drops it.
pub struct PeriodicJob {
    stop: Arc<(Mutex<bool>, Condvar)>,
}

impl PeriodicJob {
    /// Start the job; `None` when the thread could not be made. The first run is one period after
    /// the call, and each next one a period after the previous run ended.
    pub fn start(period: Duration, tick: Arc<dyn Fn() -> bool + Send + Sync>) -> Option<Self> {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let waiting = Arc::clone(&stop);
        // Each tick runs in the span current where the job is started.
        let starter = CallerSpan::current();
        std::thread::Builder::new()
            .name("wz-node-periodic".into())
            .spawn(move || {
                let (flag, wake) = &*waiting;
                loop {
                    let guard = flag.lock().unwrap_or_else(PoisonError::into_inner);
                    let (guard, _) = wake
                        .wait_timeout_while(guard, period, |stopped| !*stopped)
                        .unwrap_or_else(PoisonError::into_inner);
                    if *guard {
                        return;
                    }
                    drop(guard);
                    if !starter.in_scope(&*tick) {
                        return;
                    }
                }
            })
            .ok()?;
        Some(Self { stop })
    }
}

impl Drop for PeriodicJob {
    fn drop(&mut self) {
        let (flag, wake) = &*self.stop;
        *flag.lock().unwrap_or_else(PoisonError::into_inner) = true;
        wake.notify_all();
    }
}

/// What a subscription the engine holds is, in the one id space the port gives subscribers and
/// liveliness subscribers together.
enum Held {
    /// A subscriber hosted on the node's data plane, by its id there, with what tells when its
    /// callback has been let go of.
    Plain(u64, SinkRelease),
    /// A liveliness subscriber of the node's own face, by its id there, with what tells when its
    /// callback has been let go of.
    Liveliness(u64, SinkRelease),
}

/// A subscription of the program's: what the node holds for it, and the key it was declared on,
/// which the program is lent back ([`SessionEngine::declare_subscriber_on_wire`]). The key is a buffer of
/// its own, so it stays where it is when the map moves the entry.
struct Subscribed {
    held: Held,
    key: Box<str>,
}

/// A queryable of the program's: the id the node's data plane holds it under, and the key it was
/// declared on, which the program is lent back ([`SessionEngine::queryable_keyexpr`]). The key is
/// a buffer of its own, so it stays where it is when the map moves the entry.
struct Hosted {
    host: u64,
    key: Box<str>,
}

/// What the node keeps to be an engine: the clock, the ids, the subscriptions and the periodic
/// jobs it holds for the program.
pub(super) struct EngineState {
    epoch: Instant,
    /// The entity ids the program's declarations take, from 1: `u32`, upstream's `EntityId`, and
    /// refused once spent rather than wrapped ([`Self::entity_id`]).
    next_entity_id: AtomicU64,
    /// The ids of what the node holds for the program and never names to a peer: its write
    /// filters and its periodic jobs. A space of their own, so they are not refused when the
    /// entity ids are spent.
    next_local_id: AtomicU64,
    subscriptions: Mutex<HashMap<SubId, Subscribed>>,
    /// The key each write filter of the program's was declared on, the node's record of the
    /// filter, which a publisher or a querier is lent its key from
    /// ([`SessionEngine::declare_write_filter`]). Each key is a buffer of its own, so it stays where it
    /// is when the map moves the entry.
    filters: Mutex<HashMap<FilterId, Box<str>>>,
    /// The program's queryables, each with the id the node's data plane holds it under. That id is
    /// the data plane's key for its own face's declaration, which no peer reads; the program is
    /// given an entity id, as every other declaration of its session.
    queryables: Mutex<HashMap<QblId, Hosted>>,
    /// The program's liveliness tokens, each by the id the node's data plane holds it under, as
    /// `queryables` names its queryables.
    tokens: Mutex<HashMap<TokenId, u64>>,
    jobs: Mutex<HashMap<u64, PeriodicJob>>,
    /// What each connectivity listener whose history is being replayed was told of the node's
    /// faces ([`SessionEngine::told_ledger`]).
    told: wz_capi_port::os::Mutex<wz_capi_port::told::ToldLedger>,
    /// The queries the program keeps past the handlers of the node's queryables, each under the
    /// id its keep answers ([`wz_capi_port::QueryHolder::keep_query`]).
    kept: Arc<HeldSlab<RouterKept>>,
    /// The deliveries of the node's own session: every callback the node calls for the program
    /// runs as one, so an undeclare made inside one does not wait for a call it may be under.
    deliveries: Deliveries,
}

impl EngineState {
    pub(super) fn new() -> Self {
        Self {
            epoch: Instant::now(),
            next_entity_id: AtomicU64::new(1),
            next_local_id: AtomicU64::new(1),
            subscriptions: Mutex::new(HashMap::new()),
            filters: Mutex::new(HashMap::new()),
            queryables: Mutex::new(HashMap::new()),
            tokens: Mutex::new(HashMap::new()),
            jobs: Mutex::new(HashMap::new()),
            told: wz_capi_port::os::Mutex::new(wz_capi_port::told::ToldLedger::new()),
            kept: Arc::new(HeldSlab::new()),
            deliveries: Deliveries::new(),
        }
    }

    /// The node's kept queries, as a holder of its queryables keeps them: weakly, the slab being
    /// the node's.
    pub(super) fn kept_queries(&self) -> std::sync::Weak<HeldSlab<RouterKept>> {
        Arc::downgrade(&self.kept)
    }

    /// The next entity id, or `None` once every `u32` one has been handed out.
    fn entity_id(&self) -> Option<EntityId> {
        u32_id_taken(self.next_entity_id.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            next_u32_id,
        ))
    }

    fn local_id(&self) -> u64 {
        self.next_local_id.fetch_add(1, Ordering::Relaxed)
    }

    /// A write filter on `keyexpr`: its id, the key kept as the filter's record. The node holds
    /// no write back, so the record is all there is of the filter.
    fn filter_declared(&self, keyexpr: &str) -> wz_capi_port::Declared<FilterId> {
        let id = self.local_id();
        // Named whole, as the node names every key: the text its record keeps, at one address
        // until the filter is undeclared.
        let key: Box<str> = keyexpr.into();
        let lent = wz_capi_port::KeyView::literal(&key);
        self.filters
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, key);
        wz_capi_port::Declared { id, key: lent }
    }

    /// Filter `id` undeclared: its record goes, the key with it.
    fn filter_retracted(&self, id: FilterId) {
        let gone = self
            .filters
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
        drop(gone);
    }
}

impl RouterState {
    /// This node as the engine an ABI keeps. Made here and handed out, as the registry's is
    /// ([`SharedSession::as_engine`](crate::faces::SharedSession::as_engine)): turning an
    /// `Arc<RouterState>` into an `Arc<dyn SessionEngine>` in an ABI crate would instantiate the
    /// vtable's drop glue there a second time.
    #[inline(never)]
    pub fn as_engine(self: &Arc<Self>) -> Arc<dyn SessionEngine> {
        self.clone()
    }
}

fn plane_of(plane: FilterPlane) -> MatchPlane {
    match plane {
        FilterPlane::Subscribers => MatchPlane::Subscribers,
        FilterPlane::Queryables { complete_required } => {
            MatchPlane::Queryables { complete_required }
        }
    }
}

impl wz_capi_port::KeyHolds for RouterState {
    fn release_keyexpr(&self, _row: wz_session_core::session_tables::KeyexprHandle) {}

    /// The node holds no declaration: `acquire_keyexpr` refuses every key, so no hold reaches
    /// here and there is nothing to count.
    fn retain_keyexpr(
        &self,
        _row: wz_session_core::session_tables::KeyexprHandle,
    ) -> Result<(), wz_capi_port::HoldRefused> {
        Err(wz_capi_port::HoldRefused::Gone)
    }

    // No row is the node's: every key is named whole.
    fn declared_prefix(
        &self,
        _row: wz_session_core::session_tables::KeyexprHandle,
        _key: &str,
    ) -> Option<(wz_session_core::wire_id::ExprId, usize)> {
        None
    }
}

impl wz_capi_port::Tickers for RouterState {
    fn start_ticker(&self, period_ms: u64, tick: Tick) -> Result<TickerId, Refusal> {
        // At least a millisecond, so that a job cannot make the node spin. A job runs on a thread
        // of its own, so a host with no thread left to give holds no more of them.
        let job = PeriodicJob::start(Duration::from_millis(period_ms.max(1)), tick)
            .ok_or(Refusal::TableFull)?;
        let id = self.engine.local_id();
        self.engine
            .jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, job);
        Ok(id)
    }

    fn stop_ticker(&self, id: TickerId) {
        // Dropped outside the lock: the job's tick may be what called in.
        let job = self
            .engine
            .jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
        drop(job);
    }
}

impl SessionEngine for RouterState {
    fn is_closed(&self) -> bool {
        RouterState::is_closed(self)
    }

    fn session_zid(&self) -> wz_session_core::session_zid::SessionZid {
        *RouterState::zid(self)
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.engine.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn next_entity_id(&self) -> Option<EntityId> {
        self.engine.entity_id()
    }

    /// A peer's key is its place among the node's faces.
    fn next_peer(&self, from: u64) -> Option<(u64, PeerIdentity)> {
        self.forwarder
            .face_snapshots()
            .into_iter()
            .enumerate()
            .skip(usize::try_from(from).ok()?)
            .find_map(|(at, face)| {
                Some((
                    at as u64,
                    PeerIdentity {
                        zid: SessionZid::new(&face.zid).ok()?,
                        whatami: face.whatami,
                    },
                ))
            })
    }

    fn face_snapshots(&self) -> Vec<FaceSnapshot> {
        self.forwarder.face_snapshots()
    }

    fn told_ledger(&self) -> Option<&wz_capi_port::os::Mutex<wz_capi_port::told::ToldLedger>> {
        Some(&self.engine.told)
    }

    fn watch_faces(&self, sink: FaceEventSink) -> Result<u64, Refusal> {
        if RouterState::is_closed(self) {
            return Err(Refusal::Closed);
        }
        Ok(self.forwarder.watch_faces(sink))
    }

    fn unwatch_faces(&self, id: u64) -> bool {
        self.forwarder.unwatch_faces(id)
    }

    fn listen_locators(&self) -> Vec<String> {
        RouterState::listen_locators(self).to_vec()
    }

    fn has_router_peer(&self) -> bool {
        // 0 is the router's role in its 2-bit wire form.
        self.forwarder
            .face_snapshots()
            .iter()
            .any(|face| face.whatami == 0)
    }

    fn publish_on_wire_all(
        &self,
        keyexpr: &str,
        _wire: &WireKey,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        // The router writes to its faces by its own tables: it numbers no link, offers no frame
        // without waiting and reserves none, so a publish that states a set of links, a retry or
        // the all-or-none form is refused by name, before anything is sent.
        StatementNotHonoured::of_publish(opts)?;
        self.forwarder
            .publish_with(keyexpr, payload, opts)
            .map(|()| payload.len())
            .map_err(|_| FanoutError::ExceedsCapacity)
    }

    #[cfg(feature = "transport-shm")]
    fn has_shm_peer(&self) -> bool {
        RouterState::has_shm_peer(self)
    }

    #[cfg(feature = "transport-shm")]
    fn publish_shm_on_wire_all(
        &self,
        keyexpr: &str,
        _wire: &WireKey,
        payload: wz_session_core::extshm::ShmSendHandle,
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        StatementNotHonoured::of_publish(opts)?;
        let size = payload.bytes().len();
        self.publish_shm(keyexpr, payload, opts)
            .map(|()| size)
            .map_err(|_| FanoutError::ExceedsCapacity)
    }

    fn declare_subscriber_on_wire(
        &self,
        keyexpr: &str,
        _wire: WireKey,
        allowed_origin: Locality,
        _retraction: Option<RetractionKey>,
        sink: SubscriberSink,
    ) -> Result<wz_capi_port::Declared<SubId>, Refusal> {
        // The id first, so a session with none left hosts nothing.
        let id = self.engine.entity_id().ok_or(Refusal::NoEntityId)?;
        let deliveries = self.engine.deliveries;
        let (sink, release) = Released::new(sink, deliveries);
        // One callback for the node's one data plane, where a registry mints one for each face.
        let host = self.forwarder.host_subscriber_from(
            keyexpr,
            allowed_origin,
            Box::new(move |sample: &dyn wz_session_core::sink::SampleView| {
                deliveries.within(|| sink.call(sample));
            }),
        );
        // Named whole, as the node names every key: the text its record keeps, a buffer of its own
        // that stays where it is when the map moves the entry.
        let key: Box<str> = keyexpr.into();
        let lent = wz_capi_port::KeyView::literal(&key);
        self.engine
            .subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                id,
                Subscribed {
                    held: Held::Plain(host, release),
                    key,
                },
            );
        Ok(wz_capi_port::Declared { id, key: lent })
    }

    // Returns once the callback has been let go of after its last call, unless this thread
    // delivers for the node now (`SinkRelease::wait`).
    fn undeclare_subscriber(&self, id: SubId) {
        let gone = self
            .engine
            .subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
        let Some(Subscribed { held, key }) = gone else {
            return;
        };
        match held {
            Held::Plain(host, release) => {
                self.forwarder.unhost_subscriber(host);
                release.wait();
            }
            Held::Liveliness(face, release) => {
                self.liveliness.unsubscribe(face);
                release.wait();
            }
        }
        // The key the program was lent goes once the subscription is let go of.
        drop(key);
    }

    fn acquire_keyexpr(&self, _keyexpr: &str) -> Result<wz_capi_port::KeyHold, Refusal> {
        // A node names every key whole: there is no alias to hold.
        Err(Refusal::NotBuilt)
    }

    fn declare_matching_listener(
        &self,
        plane: FilterPlane,
        keyexpr: &str,
        sink: MatchingSink,
        count_local: bool,
    ) -> Result<MatchId, Refusal> {
        let origin = if count_local {
            Locality::Any
        } else {
            Locality::Remote
        };
        let deliveries = self.engine.deliveries;
        Ok(self.watch_matching(
            plane_of(plane),
            keyexpr,
            origin,
            Box::new(move |matching| deliveries.within(|| sink.call(matching))),
        ))
    }

    fn declare_matching_listener_in(
        &self,
        plane: FilterPlane,
        keyexpr: &str,
        sink: MatchingSink,
        locality: Locality,
    ) -> Result<MatchId, Refusal> {
        let deliveries = self.engine.deliveries;
        Ok(self.watch_matching(
            plane_of(plane),
            keyexpr,
            locality,
            Box::new(move |matching| deliveries.within(|| sink.call(matching))),
        ))
    }

    fn matching_status(
        &self,
        plane: FilterPlane,
        keyexpr: &str,
        locality: Locality,
    ) -> Option<bool> {
        Some(RouterState::matching_status(
            self,
            plane_of(plane),
            keyexpr,
            locality,
        ))
    }

    fn declare_filter_matching_listener(
        &self,
        _filter: FilterId,
        _sink: MatchingSink,
    ) -> Result<MatchId, Refusal> {
        // A node keeps no write filter (`declare_write_filter`), so there is none to read; its
        // listeners are declared on their key.
        Err(Refusal::NotBuilt)
    }

    fn undeclare_matching_listener(&self, id: MatchId) {
        self.unwatch_matching(id);
    }

    fn declare_write_filter(
        &self,
        _plane: FilterPlane,
        keyexpr: &str,
        _wire: &WireKey,
        _ask: Option<InterestAsk<'_>>,
        _count_local: bool,
    ) -> Result<wz_capi_port::Declared<FilterId>, Refusal> {
        // A node holds no write back: the router forwards by what the faces declared, and asks
        // nothing, so the filter takes no entity id. It keeps the key, which its entity is lent.
        Ok(self.engine.filter_declared(keyexpr))
    }

    fn write_filter_active(&self, _id: FilterId) -> bool {
        false
    }

    fn write_filter_holds_back(&self, _id: FilterId) -> bool {
        false
    }

    fn undeclare_write_filter(&self, id: FilterId) {
        self.engine.filter_retracted(id);
    }

    fn put_plain_filtered(
        &self,
        _filter: FilterId,
        _keyexpr: &str,
        _declared: wz_session_core::session_tables::KeyexprRef,
        _payload: &[u8],
        _params: &PlainPutParams,
    ) -> FilteredPut {
        // The caller takes the general publish, which is the node's.
        FilteredPut::NotPlain
    }

    // The node keeps no plain form: every write goes its general publish.
    fn keep_write_filter_plain(
        &self,
        _filter: FilterId,
        _plain: Option<(PlainPutParams, wz_session_core::session_tables::KeyexprRef)>,
    ) {
    }

    fn publish_filtered(
        &self,
        _filter: FilterId,
        keyexpr: &str,
        wire: &WireKey,
        payload: &[u8],
        opts: Option<&PublishOptions>,
    ) -> FilteredPut {
        // The node's filters hold nothing back; a bare write is answered for the caller to send
        // the general way.
        match opts {
            Some(opts) => FilteredPut::Sent(self.publish_on_wire_all(keyexpr, wire, payload, opts)),
            None => FilteredPut::NotPlain,
        }
    }

    fn batch_all(&self, _step: BatchStep) -> usize {
        0
    }

    fn declare_queryable_on_wire(
        &self,
        keyexpr: &str,
        _wire: WireKey,
        complete: bool,
        allowed_origin: Locality,
        _retraction: Option<RetractionKey>,
        sink: QueryableSink,
    ) -> Result<QblId, Refusal> {
        // The id first, so a session with none left hosts nothing.
        let id = self.engine.entity_id().ok_or(Refusal::NoEntityId)?;
        // The node's queries are held through the node itself, which the one sink is called with.
        let holder = self.query_holder();
        let deliveries = self.engine.deliveries;
        let host = self.forwarder.host_queryable_from(
            keyexpr,
            complete,
            allowed_origin,
            Box::new(
                move |query: &dyn wz_session_core::query_sink::QueryView,
                      out: &mut dyn wz_session_core::query_sink::ReplyOut| {
                    deliveries.within(|| sink.call(query, out, &*holder));
                },
            ),
        );
        self.engine
            .queryables
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                id,
                Hosted {
                    host,
                    key: keyexpr.into(),
                },
            );
        Ok(id)
    }

    fn undeclare_queryable(&self, id: QblId) {
        let hosted = self
            .engine
            .queryables
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
        if let Some(hosted) = hosted {
            self.forwarder.unhost_queryable(hosted.host);
        }
    }

    // A node names every key whole and declares none, so the key is lent as a literal, the text
    // the node keeps for the queryable.
    fn queryable_keyexpr(&self, id: QblId) -> Option<wz_capi_port::KeyView> {
        self.engine
            .queryables
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id)
            .map(|hosted| wz_capi_port::KeyView::literal(&hosted.key))
    }

    // A reply holds the keep's value while it runs, so a release from another thread meanwhile
    // sends the final once the reply has gone out. The forwarder's hold answers under the key it
    // keeps itself, so the caller's is not read.
    fn reply_held(
        &self,
        id: HeldQueryId,
        _key: &str,
        answer: &mut dyn FnMut(&mut dyn wz_session_core::query_sink::ReplyOut),
    ) {
        if RouterState::is_closed(self) {
            return;
        }
        if let Some(kept) = self.engine.kept.get(id) {
            kept.held.reply(answer);
        }
    }

    fn release_held(&self, id: HeldQueryId) {
        self.engine.kept.release(id);
    }
    fn declare_liveliness_token_on_wire(
        &self,
        keyexpr: &str,
        _wire: WireKey,
        _retraction: Option<RetractionKey>,
    ) -> Result<TokenId, Refusal> {
        // The id first, so a session with none left declares nothing.
        let id = self.engine.entity_id().ok_or(Refusal::NoEntityId)?;
        let host = self.declare_token(keyexpr);
        self.engine
            .tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, host);
        Ok(id)
    }

    fn undeclare_liveliness_token(&self, id: TokenId) {
        let host = self
            .engine
            .tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
        if let Some(host) = host {
            self.undeclare_token(host);
        }
    }

    fn declare_liveliness_subscriber_on_wire(
        &self,
        keyexpr: &str,
        _wire: WireKey,
        history: bool,
        sink: LivelinessSink,
    ) -> Result<wz_capi_port::Declared<SubId>, Refusal> {
        // The id first, so a session with none left subscribes nothing.
        let id = self.engine.entity_id().ok_or(Refusal::NoEntityId)?;
        let deliveries = self.engine.deliveries;
        let (sink, release) = Released::new(sink, deliveries);
        let face = self.liveliness.subscribe(
            keyexpr,
            history,
            Box::new(
                move |sample: wz_session_core::declare::liveliness_sample::LivelinessSample<'_>| {
                    deliveries.within(|| sink.call(sample));
                },
            ),
        );
        // Named whole, as the node names every key: the text its record keeps, a buffer of its own
        // that stays where it is when the map moves the entry.
        let key: Box<str> = keyexpr.into();
        let lent = wz_capi_port::KeyView::literal(&key);
        self.engine
            .subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                id,
                Subscribed {
                    held: Held::Liveliness(face, release),
                    key,
                },
            );
        Ok(wz_capi_port::Declared { id, key: lent })
    }

    fn get_on_wire(
        &self,
        keyexpr: &str,
        _wire: &WireKey,
        opts: &QueryOptionsOf<'_>,
        fan: Option<&CancellableFan>,
        leg: &mut dyn FnMut() -> ReplyCallback,
    ) -> Result<usize, Refusal> {
        // A get limited to some links or addressed to one node is refused by that statement: the
        // router reads neither, and asking every link would widen it.
        StatementNotHonoured::of_query(opts)?;
        // The node keeps the query's options past the call: the slots the caller lent are copied.
        let opts = &opts.to_owned_options();
        // One leg: the node's own face asks, and the router routes the query to the queryables of
        // every face and of the node itself. Its callback is let go when the query ends, which is
        // the leg's end.
        let callback = leg();
        let deliveries = self.engine.deliveries;
        let id = self
            .get_numbered(
                keyexpr,
                opts,
                None,
                Box::new(move |view| deliveries.within(|| callback.call(view))),
                Box::new(|| {}),
            )
            // The one way the node fails to ask: a query its codec cannot build.
            .map_err(|_| Refusal::ExceedsCapacity)?;
        if let Some(fan) = fan {
            let face = Arc::clone(&self.liveliness);
            crate::fan_undo::record(fan, Box::new(move || face.cancel_query(id)));
        }
        Ok(1)
    }

    #[cfg(feature = "transport-shm")]
    fn get_shm_on_wire(
        &self,
        keyexpr: &str,
        _wire: &WireKey,
        opts: &QueryOptionsOf<'_>,
        value: wz_session_core::extshm::ShmSendHandle,
        fan: Option<&CancellableFan>,
        leg: &mut dyn FnMut() -> ReplyCallback,
    ) -> Result<usize, Refusal> {
        // Refused when it states what the router does not read, as `get_on_wire` is.
        StatementNotHonoured::of_query(opts)?;
        // The node keeps the query's options past the call: the slots the caller lent are copied.
        let opts = &opts.to_owned_options();
        // One leg, as `get_on_wire`'s: the node's own face asks, with the chunk as the value, and
        // the router sends its descriptor to a face that negotiated shared memory and its bytes
        // to any other (`RouterState::get_numbered_shm`).
        let callback = leg();
        let deliveries = self.engine.deliveries;
        let id = self
            .get_numbered_shm(
                keyexpr,
                opts,
                value,
                None,
                Box::new(move |view| deliveries.within(|| callback.call(view))),
                Box::new(|| {}),
            )
            // The node fails to ask a query its codec cannot build, or a chunk it cannot send.
            .map_err(|_| Refusal::ExceedsCapacity)?;
        if let Some(fan) = fan {
            let face = Arc::clone(&self.liveliness);
            crate::fan_undo::record(fan, Box::new(move || face.cancel_query(id)));
        }
        Ok(1)
    }

    #[cfg(feature = "liveliness-get")]
    fn liveliness_get_on_wire(
        &self,
        keyexpr: &str,
        _wire: &WireKey,
        _timeout_ms: u32,
        fan: Option<&CancellableFan>,
        leg: &mut dyn FnMut() -> ReplyCallback,
    ) -> Result<usize, Refusal> {
        // One leg: the node's own face tells the tokens the router's tables hold and the ones the
        // program declared, and then those a router above the node answers, as upstream's peer
        // hat sends its session's current interest to a gateway; a router tells a peer below it
        // no token it was not asked for. The leg ends at that router's end of its answers (or the
        // node's deadline for them), or at once on a node that asks no router: its callback is
        // let go then. A token whose cancel has already started is told nothing, and a cancel
        // ends the leg with what it was told.
        use super::{FinalHandler, KeyHandler};
        let callback: Arc<Mutex<Option<ReplyCallback>>> = Arc::new(Mutex::new(None));
        let told = Arc::clone(&callback);
        let ended = Arc::clone(&callback);
        let face = Arc::clone(&self.liveliness);
        let deliveries = self.engine.deliveries;
        let on_key: KeyHandler = Box::new(move |key: &str| {
            let held = told.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(callback) = held.as_ref() {
                deliveries.within(|| {
                    callback.call(&wz_runtime_tokio::reply_sink::BorrowedReply {
                        rid: 0,
                        keyexpr: key,
                        kind: wz_runtime_tokio::reply_sink::ReplyKind::Put,
                        payload: &[],
                        err_encoding: None,
                        attachment: None,
                        put_encoding: None,
                    });
                });
            }
        });
        let on_final: FinalHandler = Box::new(move || {
            ended
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
        });
        // The get's id is taken before its cancel is recorded, so a cancel at any point names it;
        // one that comes before the get is asked ends nothing, and the leg's callback, not yet
        // held, is not called.
        let id = face.tokens_get_id();
        let cancel_face = Arc::clone(&face);
        // A fan already cancelled issues no leg: the get is over, having asked nobody.
        if fan.is_some_and(|fan| {
            !crate::fan_undo::record(fan, Box::new(move || cancel_face.end_tokens_get(id)))
        }) {
            return Ok(0);
        }
        *callback.lock().unwrap_or_else(PoisonError::into_inner) = Some(leg());
        face.get_tokens(id, keyexpr, on_key, on_final);
        Ok(1)
    }
}

// A client of the registry offers QoS in its handshake, and a node built without
// `transport-qos` answers it with an unsupported capability and no link: a `wz-capi-core` test
// build that leaves the feature out (the crate's default does) has no link to test over.
#[cfg(all(test, feature = "transport-qos"))]
mod port_tests;

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::AtomicUsize;

    /// The node's entity ids are `u32`: it hands out `u32::MAX` and then refuses, and stays
    /// refusing, while the ids of what it never names to a peer go on.
    #[test]
    fn the_node_hands_out_its_last_entity_id_and_then_refuses() {
        let state = EngineState::new();
        assert_eq!(state.entity_id(), Some(1), "the first entity id is 1");
        state
            .next_entity_id
            .store(u64::from(u32::MAX), Ordering::Relaxed);
        assert_eq!(state.entity_id(), Some(u32::MAX));
        assert_eq!(state.entity_id(), None);
        assert_eq!(state.entity_id(), None, "a spent space stays spent");
        let local = state.local_id();
        assert_eq!(
            state.local_id(),
            local + 1,
            "a write filter or a job takes no entity id"
        );
    }

    /// A write filter's record keeps the key it was declared on, which its publisher or querier is
    /// lent named whole: the text lies where the record keeps it, stays there while other filters
    /// come and go, and goes with the filter's undeclaration. Turned red by a record that keeps no
    /// key, lends a copy, moves the text when the map grows, names a declaration, or outlives the
    /// undeclaration.
    #[test]
    fn a_write_filters_record_lends_its_key_until_it_is_undeclared() {
        let state = EngineState::new();
        let key = "demo/node/pub";
        let wz_capi_port::Declared {
            id: filter,
            key: lent,
        } = state.filter_declared(key);
        assert_eq!(lent.own, None, "a node names every key whole");
        assert_ne!(
            lent.start,
            key.as_ptr(),
            "the record's own text, not the caller's"
        );
        let others: Vec<FilterId> = (0..64)
            .map(|at| state.filter_declared(&format!("demo/node/other/{at}")).id)
            .collect();
        let record = |id: FilterId| {
            state
                .filters
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&id)
                .map(|kept| (kept.as_ptr(), kept.len()))
        };
        assert_eq!(
            record(filter),
            Some((lent.start, lent.len)),
            "the text stays where it was lent while the records move"
        );
        // SAFETY: the record keeps the text where it lent it until the filter is undeclared below.
        let text = unsafe { core::slice::from_raw_parts(lent.start, lent.len) };
        assert_eq!(text, key.as_bytes());
        state.filter_retracted(filter);
        assert_eq!(record(filter), None, "gone with the filter");
        assert!(
            others.iter().all(|&other| record(other).is_some()),
            "CONTROL: the other filters stand"
        );
    }

    /// A periodic job ticks on its period and stops when it is dropped: the count rises while the
    /// job lives and does not move once it is let go.
    ///
    /// # Control
    ///
    /// Making `Drop for PeriodicJob` do nothing reds the last assertion, the count still rising
    /// after the drop.
    #[test]
    fn a_periodic_job_ticks_until_it_is_dropped() {
        let ticks = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&ticks);
        let job = PeriodicJob::start(
            Duration::from_millis(10),
            Arc::new(move || {
                counted.fetch_add(1, Ordering::SeqCst);
                true
            }),
        )
        .expect("a thread for the job");
        let deadline = Instant::now() + Duration::from_secs(5);
        while ticks.load(Ordering::SeqCst) < 3 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(ticks.load(Ordering::SeqCst) >= 3, "the job never ticked");

        drop(job);
        // A tick that was already under way may land; none starts after the thread has woken.
        std::thread::sleep(Duration::from_millis(100));
        let settled = ticks.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            ticks.load(Ordering::SeqCst),
            settled,
            "the job went on ticking after it was dropped"
        );
    }

    /// A job whose tick answers `false` ends by itself.
    #[test]
    fn a_periodic_job_ends_when_its_tick_says_so() {
        let ticks = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&ticks);
        let _job = PeriodicJob::start(
            Duration::from_millis(10),
            Arc::new(move || counted.fetch_add(1, Ordering::SeqCst) + 1 < 2),
        )
        .expect("a thread for the job");
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(
            ticks.load(Ordering::SeqCst),
            2,
            "the job ticks until its tick says stop, and no more"
        );
    }
}
