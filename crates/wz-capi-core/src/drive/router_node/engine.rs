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
    FanoutError, FilterId, FilterPlane, FilteredPut, LivelinessSink, MatchId, MatchingSink, QblId,
    QueryableSink, ReplyCallback, SessionEngine, SubId, SubscriberSink, Tick, TickerId, TokenId,
    WireKey,
};
use wz_runtime_tokio::router_forward::MatchPlane;
use wz_session_core::declare_form::{InterestForm, RetractionKey};
use wz_session_core::face::{FaceEventSink, FaceSnapshot};
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::{PlainPutParams, PublishOptions};
use wz_session_core::query_options::QueryOptions;

use super::RouterState;

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
                    if !tick() {
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
    /// A subscriber hosted on the node's data plane, by its id there.
    Plain(u64),
    /// A liveliness subscriber of the node's own face, by its id there.
    Liveliness(u64),
}

/// What the node keeps to be an engine: the clock, the ids, the subscriptions and the periodic
/// jobs it holds for the program.
pub(super) struct EngineState {
    epoch: Instant,
    next_id: AtomicU64,
    subscriptions: Mutex<HashMap<u64, Held>>,
    jobs: Mutex<HashMap<u64, PeriodicJob>>,
}

impl EngineState {
    pub(super) fn new() -> Self {
        Self {
            epoch: Instant::now(),
            next_id: AtomicU64::new(1),
            subscriptions: Mutex::new(HashMap::new()),
            jobs: Mutex::new(HashMap::new()),
        }
    }

    fn id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
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

impl SessionEngine for RouterState {
    fn is_closed(&self) -> bool {
        RouterState::is_closed(self)
    }

    fn zid(&self) -> [u8; 16] {
        let mut padded = [0u8; 16];
        let zid = RouterState::zid(self);
        let len = zid.len().min(16);
        padded[..len].copy_from_slice(&zid[..len]);
        padded
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.engine.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn next_entity_id(&self) -> u64 {
        self.engine.id()
    }

    fn peer_identities(&self) -> Vec<(Vec<u8>, u8)> {
        self.forwarder
            .face_snapshots()
            .into_iter()
            .map(|face| (face.zid.to_vec(), face.whatami))
            .collect()
    }

    fn face_snapshots(&self) -> Vec<FaceSnapshot> {
        self.forwarder.face_snapshots()
    }

    fn watch_faces(&self, sink: FaceEventSink) -> u64 {
        self.forwarder.watch_faces(sink)
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
        let size = payload.bytes().len();
        self.publish_shm(keyexpr, payload, opts)
            .map(|()| size)
            .map_err(|_| FanoutError::ExceedsCapacity)
    }

    fn declare_subscriber_on_wire(
        &self,
        keyexpr: String,
        _wire: WireKey,
        allowed_origin: Locality,
        _retraction: Option<RetractionKey>,
        sink: SubscriberSink,
    ) -> SubId {
        // One callback for the node's one data plane, where a registry mints one for each face.
        let host = self
            .forwarder
            .host_subscriber_from(&keyexpr, allowed_origin, sink());
        let id = self.engine.id();
        self.engine
            .subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, Held::Plain(host));
        id
    }

    fn undeclare_subscriber(&self, id: SubId) {
        let held = self
            .engine
            .subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
        match held {
            Some(Held::Plain(host)) => {
                self.forwarder.unhost_subscriber(host);
            }
            Some(Held::Liveliness(face)) => self.liveliness.unsubscribe(face),
            None => {}
        }
    }

    fn acquire_keyexpr(&self, _keyexpr: String) -> Option<u64> {
        // A node names every key whole: there is no alias to hold.
        None
    }

    fn release_keyexpr(&self, _mapping_id: u64) {}

    fn keyexpr_declarations(&self) -> Vec<(u64, String)> {
        Vec::new()
    }

    fn declare_matching_listener(
        &self,
        plane: FilterPlane,
        keyexpr: String,
        sink: MatchingSink,
        count_local: bool,
    ) -> MatchId {
        let origin = if count_local {
            Locality::Any
        } else {
            Locality::Remote
        };
        self.watch_matching(
            plane_of(plane),
            &keyexpr,
            origin,
            Box::new(move |matching| sink(matching)),
        )
    }

    fn declare_matching_listener_in(
        &self,
        plane: FilterPlane,
        keyexpr: String,
        sink: MatchingSink,
        locality: Locality,
    ) -> Option<MatchId> {
        Some(self.watch_matching(
            plane_of(plane),
            &keyexpr,
            locality,
            Box::new(move |matching| sink(matching)),
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

    fn undeclare_matching_listener(&self, id: MatchId) {
        self.unwatch_matching(id);
    }

    fn declare_write_filter(
        &self,
        _plane: FilterPlane,
        _keyexpr: String,
        _wire: &WireKey,
        _ask: Option<InterestForm>,
        _count_local: bool,
    ) -> FilterId {
        // A node holds no write back: the router forwards by what the faces declared.
        self.engine.id()
    }

    fn write_filter_active(&self, _id: FilterId) -> bool {
        false
    }

    fn write_filter_holds_back(&self, _id: FilterId) -> bool {
        false
    }

    fn undeclare_write_filter(&self, _id: FilterId) {}

    fn put_plain_filtered(
        &self,
        _filter: FilterId,
        _keyexpr: &str,
        _mapping_id: u64,
        _payload: &[u8],
        _params: &PlainPutParams,
    ) -> FilteredPut {
        // The caller takes the general publish, which is the node's.
        FilteredPut::NotPlain
    }

    fn batch_start_all(&self) -> usize {
        0
    }

    fn batch_flush_all(&self) -> usize {
        0
    }

    fn batch_stop_all(&self) -> usize {
        0
    }

    fn declare_queryable_on_wire(
        &self,
        keyexpr: String,
        _wire: WireKey,
        complete: bool,
        allowed_origin: Locality,
        _retraction: Option<RetractionKey>,
        sink: QueryableSink,
    ) -> Option<QblId> {
        Some(self.forwarder.host_queryable_from(
            &keyexpr,
            complete,
            allowed_origin,
            Box::new(sink(self.query_holder())),
        ))
    }

    fn undeclare_queryable(&self, id: QblId) {
        self.forwarder.unhost_queryable(id);
    }

    fn declare_liveliness_token_on_wire(
        &self,
        keyexpr: String,
        _wire: WireKey,
        _retraction: Option<RetractionKey>,
    ) -> Option<TokenId> {
        Some(self.declare_token(&keyexpr))
    }

    fn undeclare_liveliness_token(&self, id: TokenId) {
        self.undeclare_token(id);
    }

    fn declare_liveliness_subscriber_on_wire(
        &self,
        keyexpr: String,
        _wire: WireKey,
        history: bool,
        sink: LivelinessSink,
    ) -> Option<SubId> {
        let face = self.liveliness.subscribe(&keyexpr, history, sink());
        let id = self.engine.id();
        self.engine
            .subscriptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, Held::Liveliness(face));
        Some(id)
    }

    fn get_on_wire(
        &self,
        keyexpr: &str,
        _wire: &WireKey,
        opts: &QueryOptions,
        fan: Option<&CancellableFan>,
        leg: &mut dyn FnMut() -> ReplyCallback,
    ) -> Option<usize> {
        // One leg: the node's own face asks, and the router routes the query to the queryables of
        // every face and of the node itself. Its callback is let go when the query ends, which is
        // the leg's end.
        let mut callback = leg();
        let id = self
            .get_numbered(
                keyexpr,
                opts,
                None,
                Box::new(move |view| callback(view)),
                Box::new(|| {}),
            )
            .ok()?;
        if let Some(fan) = fan {
            let face = Arc::clone(&self.liveliness);
            fan.record(move || face.cancel_query(id));
        }
        Some(1)
    }

    #[cfg(feature = "liveliness-get")]
    fn liveliness_get_on_wire(
        &self,
        keyexpr: &str,
        _wire: &WireKey,
        _timeout_ms: u32,
        fan: Option<&CancellableFan>,
        leg: &mut dyn FnMut() -> ReplyCallback,
    ) -> Option<usize> {
        // One leg: the node's own face answers from the tokens the router's tables hold and the
        // ones the program declared, as the C door's snapshot does (`liveliness_get_on_node` in
        // wz-capi-c). The snapshot is whole when it is read, so the leg ends here, its callback
        // let go once each key is told, and no timeout has anything to bound. A token whose cancel
        // has already started is told nothing.
        if fan.is_some_and(|fan| !fan.record(|| {})) {
            return Some(0);
        }
        let mut callback = leg();
        for alive in self.liveliness().alive(keyexpr) {
            callback(&wz_runtime_tokio::reply_sink::BorrowedReply {
                rid: 0,
                keyexpr: &alive,
                kind: wz_runtime_tokio::reply_sink::ReplyKind::Put,
                payload: &[],
                err_encoding: None,
                attachment: None,
                put_encoding: None,
            });
        }
        Some(1)
    }

    fn start_ticker(&self, period_ms: u64, tick: Tick) -> Option<TickerId> {
        // At least a millisecond, so that a job cannot make the node spin.
        let job = PeriodicJob::start(Duration::from_millis(period_ms.max(1)), tick)?;
        let id = self.engine.id();
        self.engine
            .jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, job);
        Some(id)
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

// A client of the registry offers QoS in its handshake, and a node built without
// `transport-qos` answers it with an unsupported capability and no link: a `wz-capi-core` test
// build that leaves the feature out (the crate's default does) has no link to test over.
#[cfg(all(test, feature = "transport-qos"))]
mod port_tests;

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::AtomicUsize;

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
