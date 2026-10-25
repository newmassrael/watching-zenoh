// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y69 — `ext-pubsub-advanced-publisher` (§5.25): a publisher that
//! stamps a per-sample `SourceInfo` sequence number, retains its samples
//! in a `CacheStore` for recovery, and announces its existence with
//! an `@adv` liveliness token.
//!
//! The composition (what is validated, in what order the four entities are declared and
//! retracted, what a put stamps and retains, what a beacon says) is `wz-ext-pubsub`'s,
//! `AdvancedPublisherOn`, and is re-exported here at the paths it has always had. What this
//! module keeps is what only the tokio runtime can be: `SessionPlane`, the plane of a runtime
//! `Session` (each entity is the session's own plain declaration, on its literal key), the
//! timer a beacon runs on (`BeaconTimer`, a task of the process's `net` runtime), the shared-memory
//! chunk this runtime maps, and `AdvancedPublisher`, the handle a caller declares from a session.
//!
//! Composes on already-active wz primitives: the user `Session::publish`
//! (`pubsub-put`) carrying `source_info` (`pubsub-source-info`) +
//! `timestamp` (`pubsub-timestamp`), the cache `Queryable`
//! (`query-queryable`), and the `LivelinessToken` (`liveliness-token`).

use std::sync::Arc;
use std::time::Duration;

use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;

#[cfg(feature = "ext-pubsub-sample-miss-detection")]
use wz_ext_pubsub::advanced_publisher::heartbeat_publish_options;
#[cfg(feature = "transport-shm")]
pub use wz_ext_pubsub::advanced_publisher::ShmChunk;
pub use wz_ext_pubsub::advanced_publisher::{
    AdvancedPublisherError, AdvancedPublisherOn, AdvancedPublisherOptions, AdvancedPublisherPlane,
    AdvancedPutOptions, DeclaredPublisher, MissDetectionConfig, PlaneError, Sequencing,
};

use crate::advanced_cache::{CacheStore, Retained};
use crate::node_clock::NodeHlc;
use crate::session::{
    LivelinessAliasError, LivelinessOptions, LivelinessToken, PublishError, PublishOptions,
    Publisher, Queryable, QueryableError, Session, Unicast,
};
use crate::session_glue::SessionLinkActions;

impl From<QueryableError> for AdvancedPublisherError {
    fn from(e: QueryableError) -> Self {
        AdvancedPublisherError::Cache(PlaneError::new(e))
    }
}

impl From<LivelinessAliasError> for AdvancedPublisherError {
    fn from(e: LivelinessAliasError) -> Self {
        AdvancedPublisherError::Token(PlaneError::new(e))
    }
}

/// The timer of a heartbeat beacon on this runtime: a task of the process's `net` runtime that
/// calls the beacon's tick every period, until the tick answers `false` or this handle is
/// dropped, which aborts the loop so a torn-down publisher stops emitting.
///
/// It is the `net` subsystem, which is where upstream puts this exact beacon: both arms of zenoh's
/// advanced-publisher heartbeat are `TerminatableTask::spawn_abortable(ZRuntime::Net, ..)`
/// (`zenoh-ext/src/advanced_publisher.rs` @ `TerminatableTask::spawn_abortable(`). A beacon is
/// upkeep the application never waits on, so it belongs beside gossip rather than beside the API
/// surface, and the declaring thread need not be inside a tokio runtime (R3064).
pub struct BeaconTimer {
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for BeaconTimer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Start a [`BeaconTimer`]: sleep `period` on `clock`, then run `tick`, over and over.
///
/// `period` is clamped to a millisecond, so a sub-millisecond `Duration` (which truncates to zero)
/// cannot turn the loop into a busy spin (R311y87, review C4). Every host of this runtime that
/// runs a beacon starts it through here, so the loop is written once: the runtime session's plane
/// and the pico C ABI's plane both do.
pub fn spawn_beacon_timer<T: TimeSource + Send + Sync + 'static>(
    clock: Arc<T>,
    period: Duration,
    tick: Arc<dyn Fn() -> bool + Send + Sync>,
) -> BeaconTimer {
    let period_ms = (period.as_millis() as u64).max(1);
    BeaconTimer {
        handle: crate::runtime_pool::WzRuntime::Net.spawn(async move {
            loop {
                clock.sleep(period_ms).await;
                if !tick() {
                    return;
                }
            }
        }),
    }
}

#[cfg(feature = "transport-shm")]
impl ShmChunk for crate::shm_provider::ShmBackedPayload {
    fn bytes(&self) -> &[u8] {
        crate::shm_provider::ShmBackedPayload::bytes(self)
    }

    fn send_handle(self: Arc<Self>) -> wz_session_core::extshm::ShmSendHandle {
        crate::shm_provider::ShmBackedPayload::send_handle(&self)
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
        self
    }
}

/// [`AdvancedPublisherPlane`] for a runtime [`Session`]: each entity is the
/// session's own plain declaration, announced on its literal key.
pub struct SessionPlane<R: SessionRuntime, T: TimeSource> {
    session: Session<R, T, Unicast>,
}

impl<R: SessionRuntime, T: TimeSource> SessionPlane<R, T> {
    /// The plane of `session`.
    pub fn new(session: &Session<R, T, Unicast>) -> Self {
        Self {
            session: session.clone(),
        }
    }
}

impl<R, T> AdvancedPublisherPlane for SessionPlane<R, T>
where
    R: SessionRuntime + 'static,
    T: TimeSource + Send + Sync + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
    Session<R, T, Unicast>: Send + Sync + 'static,
{
    type Publisher = Publisher<R, T>;
    type Queryable = Queryable<R, T>;
    type Token = LivelinessToken<R, T>;
    type Beacon = ();
    type Timer = BeaconTimer;

    fn node_hlc(&self) -> &NodeHlc {
        self.session.node_hlc()
    }

    fn declare_publisher(
        &self,
        keyexpr: &str,
        options: PublishOptions,
    ) -> Result<DeclaredPublisher<Publisher<R, T>>, AdvancedPublisherError> {
        // Allocate the publisher entity id from the session's dedicated
        // entity-id SSOT (the `SourceInfo.eid` id-space). zenoh-pico draws
        // every entity id from one `_z_get_entity_id`; wz keeps per-purpose
        // id counters, so the publisher eid has its own (R311y72: it was
        // minted from the token-id counter — a conflated namespace + a
        // truncating `as u32`; now a real u32 entity counter).
        let eid = self.session.actions().alloc_next_entity_id();
        Ok(DeclaredPublisher {
            handle: self.session.declare_publisher(keyexpr.to_owned(), options),
            eid,
        })
    }

    fn declare_cache_queryable(
        &self,
        keyexpr: &str,
        store: &CacheStore,
    ) -> Result<Queryable<R, T>, AdvancedPublisherError> {
        // R2556 — INCOMPLETE, which is upstream's default: see
        // [`crate::advanced_cache::AdvancedCache::declare`], whose declaration this is.
        Ok(self.session.declare_queryable(
            keyexpr.to_owned(),
            crate::session::QueryableOptions::default(),
            store.query_handler(crate::timestamp_source::wall_clock_ntp64),
        )?)
    }

    fn declare_token(
        &self,
        keyexpr: &str,
    ) -> Result<LivelinessToken<R, T>, AdvancedPublisherError> {
        Ok(self
            .session
            .declare_token(keyexpr.to_owned(), LivelinessOptions::default())?)
    }

    /// A runtime session sends the beacon on its literal key with no publisher
    /// of its own; there is nothing to declare.
    fn declare_beacon(
        &self,
        _keyexpr: &str,
        _sporadic: bool,
    ) -> Result<(), AdvancedPublisherError> {
        Ok(())
    }

    fn start_beacon_timer(
        &self,
        period: Duration,
        tick: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> BeaconTimer {
        spawn_beacon_timer(Arc::clone(self.session.clock()), period, tick)
    }

    fn publish(
        &self,
        _publisher: &Publisher<R, T>,
        keyexpr: &str,
        payload: &[u8],
        options: PublishOptions,
    ) -> Result<usize, PublishError> {
        self.session.publish(keyexpr, payload, options)
    }

    #[cfg(feature = "transport-shm")]
    fn publish_shm(
        &self,
        publisher: &Publisher<R, T>,
        keyexpr: &str,
        payload: &Arc<dyn ShmChunk>,
        options: PublishOptions,
    ) -> Result<usize, PublishError> {
        // A chunk this runtime mapped is sent as the descriptor; any other chunk is something
        // this plane cannot send a descriptor for, and goes as its bytes.
        match Arc::clone(payload)
            .into_any()
            .downcast::<crate::shm_provider::ShmBackedPayload>()
        {
            Ok(chunk) => self.session.publish_shm(keyexpr, &chunk, options),
            Err(_) => self.publish(publisher, keyexpr, payload.bytes(), options),
        }
    }

    #[cfg(feature = "ext-pubsub-sample-miss-detection")]
    fn publish_beacon(&self, _beacon: Option<&()>, keyexpr: &str, payload: &[u8], sporadic: bool) {
        let _ = self
            .session
            .publish(keyexpr, payload, heartbeat_publish_options(sporadic));
    }

    #[cfg(not(feature = "ext-pubsub-sample-miss-detection"))]
    fn publish_beacon(
        &self,
        _beacon: Option<&()>,
        _keyexpr: &str,
        _payload: &[u8],
        _sporadic: bool,
    ) {
    }

    fn retained_key(&self, _publisher: &Publisher<R, T>) -> Option<Retained> {
        None
    }
}

/// An advanced publisher on a runtime [`Session`] — the plain declarations, with
/// every entity on its literal key.
///
/// It is [`AdvancedPublisherOn`] over this runtime's plane, which a caller reaches through
/// `Deref` (`put`, `put_with`, `delete`, `eid`, `id`, `keyexpr`, `cache`, `emit_heartbeat_once`), plus
/// what only a publisher on a runtime session does: declare itself from the session handle, and
/// ask its wrapped publisher about matching.
pub struct AdvancedPublisher<R, T>(AdvancedPublisherOn<SessionPlane<R, T>>)
where
    R: SessionRuntime + 'static,
    T: TimeSource + Send + Sync + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
    Session<R, T, Unicast>: Send + Sync + 'static;

impl<R, T> std::ops::Deref for AdvancedPublisher<R, T>
where
    R: SessionRuntime + 'static,
    T: TimeSource + Send + Sync + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
    Session<R, T, Unicast>: Send + Sync + 'static,
{
    type Target = AdvancedPublisherOn<SessionPlane<R, T>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<R, T> AdvancedPublisher<R, T>
where
    R: SessionRuntime + 'static,
    T: TimeSource + Send + Sync + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
    Session<R, T, Unicast>: Send + Sync + 'static,
{
    /// Declare an advanced publisher on `keyexpr`. `local_zid` (1..=16
    /// bytes) is this publisher's source identity, stamped into every
    /// sample's `SourceInfo` and rendered into the `@adv` KE. Allocates the
    /// publisher entity id from the session counter, then (per `options`)
    /// declares the cache queryable + the liveliness token on
    /// `<keyexpr>/@adv/pub/<zid>/<eid|uhlc>/_`.
    pub fn declare(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        options: AdvancedPublisherOptions,
        local_zid: Vec<u8>,
    ) -> Result<Self, AdvancedPublisherError> {
        AdvancedPublisherOn::declare_on(
            Arc::new(SessionPlane::new(session)),
            keyexpr,
            options,
            local_zid,
        )
        .map(Self)
    }

    /// [`AdvancedPublisherOn::put_shm_with`] for a chunk this runtime mapped: the same
    /// stamping and sequence number, sent as the descriptor to a face that negotiated shared
    /// memory and cached as the chunk.
    #[cfg(feature = "transport-shm")]
    pub fn put_shm_with(
        &self,
        payload: &Arc<crate::shm_provider::ShmBackedPayload>,
        options: AdvancedPutOptions,
    ) -> Result<usize, PublishError> {
        let chunk: Arc<dyn ShmChunk> = Arc::clone(payload) as Arc<dyn ShmChunk>;
        self.0.put_shm_with(&chunk, options)
    }

    /// Undeclare this publisher: [`AdvancedPublisherOn::undeclare`], which drops the handle and
    /// with it every entity it declared.
    pub fn undeclare(self) {
        self.0.undeclare();
    }
}

/// What only a publisher on a runtime [`Session`] can do: ask its wrapped
/// publisher about matching, which is the plain publisher's own state.
#[cfg(feature = "session-matching")]
impl<R, T> AdvancedPublisher<R, T>
where
    R: SessionRuntime + 'static,
    T: TimeSource + Send + Sync + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
    Session<R, T, Unicast>: Send + Sync + 'static,
{
    /// R2619 — the matching status of this publisher, upstream's
    /// `zenoh-ext/src/advanced_publisher.rs` @ `pub fn matching_status(&self) -> impl Resolve<ZResult<zenoh::matching::MatchingStatus>> + '_ {`,
    /// which delegates exactly as this does.
    ///
    /// The delegation is the whole point rather than a shortcut: the answer is
    /// only meaningful because declaring the wrapped publisher ASKED the
    /// neighbour for the matching subscriber declarations (R2577). A method
    /// re-implemented here would have read the same registry without anyone
    /// having filled it.
    pub fn get_matching_status(&self) -> crate::session::MatchingStatus {
        self.0.publisher().get_matching_status()
    }

    /// R2619 — the listener sibling of [`Self::get_matching_status`], upstream's
    /// `zenoh-ext/src/advanced_publisher.rs` @ `pub fn matching_listener(`,
    /// whose body is `self.publisher.matching_listener()` — the same
    /// delegation this one is.
    pub fn declare_matching_listener(
        &self,
        callback: impl FnMut(crate::session::MatchingStatus) + Send + 'static,
    ) -> Result<crate::session::MatchingListener<R, T>, crate::session::MatchingListenerError> {
        self.0.publisher().declare_matching_listener(callback)
    }
}

#[cfg(test)]
mod tests;
