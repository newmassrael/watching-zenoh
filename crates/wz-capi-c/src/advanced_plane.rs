// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The zenoh-c C session as the plane an advanced publisher lives on.
//!
//! An advanced publisher is a composition: a plain publisher, a cache queryable, a liveliness
//! token and, for the heartbeat, a beacon. What is validated, in what order the entities are
//! declared, what a put stamps and retains and what a beacon says is the neutral composite's
//! ([`AdvancedPublisherOn`], in `wz-ext-pubsub`); this file is the plane that composite is hosted
//! on for a C session, so the zenoh-c ABI and the pico ABI run one publisher and differ only in
//! how a session names its entities on the wire.
//!
//! zenoh-c names every entity by its literal key, so each declaration here is the engine's plain
//! one with the literal wire form. The engine fans a declaration out to every face the session
//! has and replays it onto each face that comes up, the session's own plane included, so ONE
//! composite (one cache ring, one token) serves every peer. That replaces the shape this file
//! retired, where the registry kept one advanced publisher per face, each with a cache of its
//! own.
//!
//! [`AdvancedPublisherOn`]: wz_ext_pubsub::advanced_publisher::AdvancedPublisherOn

use std::sync::Arc;
use std::time::Duration;

use wz_capi_core::faces::SharedSession;
use wz_capi_port::{
    QblId, QueryCallback, QueryHolder, QueryableSink, SessionEngine, Ticker, TokenId, WireKey,
};
use wz_ext_pubsub::advanced_cache::{CacheStore, Retained};
use wz_ext_pubsub::advanced_publisher::{
    AdvancedPublisherError, AdvancedPublisherPlane, DeclaredPublisher,
};
use wz_runtime_tokio::locality::Locality;
use wz_runtime_tokio::node_clock::NodeHlc;
use wz_runtime_tokio::session::{PublishError, PublishOptions};

/// The plane of one zenoh-c session.
pub(crate) struct CPlane {
    shared: Arc<SharedSession>,
    engine: Arc<dyn SessionEngine>,
}

impl CPlane {
    /// The plane of `shared`.
    pub(crate) fn new(shared: &Arc<SharedSession>) -> Self {
        Self {
            shared: Arc::clone(shared),
            engine: shared.as_engine(),
        }
    }

    /// What the plane names a declaration the engine refused.
    fn refusal(what: &str) -> AdvancedPublisherError {
        AdvancedPublisherError::Plane(format!("{what}: the session refused the declaration"))
    }
}

/// A cache queryable the engine holds, retracted when this is dropped.
pub(crate) struct CacheQueryable {
    engine: Arc<dyn SessionEngine>,
    id: QblId,
}

impl Drop for CacheQueryable {
    fn drop(&mut self) {
        self.engine.undeclare_queryable(self.id);
    }
}

/// A liveliness token the engine holds, retracted when this is dropped.
pub(crate) struct Token {
    engine: Arc<dyn SessionEngine>,
    id: TokenId,
}

impl Drop for Token {
    fn drop(&mut self) {
        self.engine.undeclare_liveliness_token(self.id);
    }
}

impl AdvancedPublisherPlane for CPlane {
    /// A zenoh-c publisher is the key it sends on: a send is a fan-out of the session's.
    type Publisher = ();
    type Queryable = CacheQueryable;
    type Token = Token;
    /// The beacon is sent on its literal key with no publisher of its own, as the runtime's is.
    type Beacon = ();
    /// The engine's periodic job, which is its own to run.
    type Timer = Option<Ticker>;

    fn node_hlc(&self) -> &NodeHlc {
        self.shared.local_session().node_hlc()
    }

    fn declare_publisher(
        &self,
        _keyexpr: &str,
        _options: PublishOptions,
    ) -> Result<DeclaredPublisher<()>, AdvancedPublisherError> {
        // The entity id of the `SourceInfo.eid` id space, one for the publisher and not one for
        // each face: the token and every sample name this publisher with it.
        let eid = self.shared.local_session().actions().alloc_next_entity_id();
        Ok(DeclaredPublisher { handle: (), eid })
    }

    fn declare_cache_queryable(
        &self,
        keyexpr: &str,
        store: &CacheStore,
    ) -> Result<CacheQueryable, AdvancedPublisherError> {
        let store = store.clone();
        // One handler per face: each is a fresh closure over the same ring, and none needs the
        // face's session, a reply going out on the query's own.
        let sink: QueryableSink = Arc::new(move |_face: Arc<dyn QueryHolder>| {
            Box::new(store.query_handler(wz_runtime_tokio::timestamp_source::wall_clock_ntp64))
                as QueryCallback
        });
        // INCOMPLETE, which is upstream's default and the only honest answer a bounded ring can
        // give.
        let id = self
            .engine
            .declare_queryable_on_wire(
                keyexpr.to_owned(),
                WireKey::literal(),
                false,
                Locality::Any,
                None,
                sink,
            )
            .ok_or_else(|| Self::refusal("cache queryable"))?;
        Ok(CacheQueryable {
            engine: Arc::clone(&self.engine),
            id,
        })
    }

    fn declare_token(&self, keyexpr: &str) -> Result<Token, AdvancedPublisherError> {
        let id = self
            .engine
            .declare_liveliness_token_on_wire(keyexpr.to_owned(), WireKey::literal(), None)
            .ok_or_else(|| Self::refusal("liveliness token"))?;
        Ok(Token {
            engine: Arc::clone(&self.engine),
            id,
        })
    }

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
    ) -> Option<Ticker> {
        // A period under a millisecond is raised to one by the engine, as the composite does.
        let period_ms = u64::try_from(period.as_millis()).unwrap_or(u64::MAX);
        Ticker::start(&self.engine, period_ms, tick)
    }

    fn publish(
        &self,
        _publisher: &(),
        keyexpr: &str,
        payload: &[u8],
        options: PublishOptions,
    ) -> Result<usize, PublishError> {
        // Every face and the session's own plane, so the put reaches a subscriber of this very
        // session as well as every peer.
        self.shared
            .publish_all(keyexpr, payload, &options)
            .map_err(|_| PublishError::ExceedsCapacity)
    }

    #[cfg(feature = "zenoh-c-shared-memory")]
    fn publish_shm(
        &self,
        publisher: &(),
        keyexpr: &str,
        payload: &Arc<dyn wz_ext_pubsub::advanced_publisher::ShmChunk>,
        options: PublishOptions,
    ) -> Result<usize, PublishError> {
        // A chunk this runtime mapped is sent as the descriptor where a face negotiated shared
        // memory; any other chunk goes as its bytes.
        match Arc::clone(payload)
            .into_any()
            .downcast::<wz_runtime_tokio::shm_provider::ShmBackedPayload>()
        {
            Ok(chunk) => self
                .shared
                .publish_shm_all(keyexpr, chunk, &options)
                .map_err(|_| PublishError::ExceedsCapacity),
            Err(_) => self.publish(publisher, keyexpr, payload.bytes(), options),
        }
    }

    fn publish_beacon(&self, _beacon: Option<&()>, keyexpr: &str, payload: &[u8], sporadic: bool) {
        let _ = self.shared.publish_all(
            keyexpr,
            payload,
            &wz_ext_pubsub::advanced_publisher::heartbeat_publish_options(sporadic),
        );
    }

    fn retained_key(&self, _publisher: &()) -> Option<Retained> {
        None
    }
}

/// The entity ids of the advanced publishers of every node, one counter for all: an id need only
/// be unique within a session, and a process-wide counter is unique within each.
#[cfg(feature = "router-node")]
static NEXT_NODE_ENTITY: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

/// A node, as the plane an advanced publisher lives on.
///
/// The composite is the same one the registry hosts ([`AdvancedPublisherOn`]); what differs is
/// that a node's declarations are the router data plane's own: the cache queryable is hosted on
/// it, so that the queries of its faces and of its session reach the ring, the token is its own
/// liveliness token, and a put is the node's publication, stamped by the node's one clock.
#[cfg(feature = "router-node")]
pub(crate) struct NodePlane {
    node: Arc<wz_capi_core::drive::RouterState>,
    /// The node's clock, shared with the node (never a second clock of the same identity).
    hlc: NodeHlc,
}

#[cfg(feature = "router-node")]
impl NodePlane {
    /// The plane of `node`.
    pub(crate) fn new(node: &Arc<wz_capi_core::drive::RouterState>) -> Self {
        Self {
            node: Arc::clone(node),
            hlc: node.forwarder().node_hlc(),
        }
    }
}

/// A cache queryable the node hosts, retracted when this is dropped.
#[cfg(feature = "router-node")]
pub(crate) struct NodeCacheQueryable {
    forwarder: Arc<wz_runtime_tokio::router_forward::RouterForwarder>,
    id: u64,
}

#[cfg(feature = "router-node")]
impl Drop for NodeCacheQueryable {
    fn drop(&mut self) {
        self.forwarder.unhost_queryable(self.id);
    }
}

/// A liveliness token the node declared, retracted when this is dropped.
#[cfg(feature = "router-node")]
pub(crate) struct NodeToken {
    node: Arc<wz_capi_core::drive::RouterState>,
    id: u64,
}

#[cfg(feature = "router-node")]
impl Drop for NodeToken {
    fn drop(&mut self) {
        self.node.undeclare_token(self.id);
    }
}

/// The period of a heartbeat beacon: a thread that ticks until it is told to stop. Dropping it
/// tells the thread, which ends at its next wake without being waited for (the tick may be what
/// drops it).
#[cfg(feature = "router-node")]
pub(crate) struct NodeTimer {
    stop: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

#[cfg(feature = "router-node")]
impl Drop for NodeTimer {
    fn drop(&mut self) {
        let (flag, wake) = &*self.stop;
        *flag
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        wake.notify_all();
    }
}

#[cfg(feature = "router-node")]
impl AdvancedPublisherPlane for NodePlane {
    type Publisher = ();
    type Queryable = NodeCacheQueryable;
    type Token = NodeToken;
    type Beacon = ();
    type Timer = Option<NodeTimer>;

    fn node_hlc(&self) -> &NodeHlc {
        &self.hlc
    }

    fn declare_publisher(
        &self,
        _keyexpr: &str,
        _options: PublishOptions,
    ) -> Result<DeclaredPublisher<()>, AdvancedPublisherError> {
        let eid = NEXT_NODE_ENTITY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(DeclaredPublisher { handle: (), eid })
    }

    fn declare_cache_queryable(
        &self,
        keyexpr: &str,
        store: &CacheStore,
    ) -> Result<NodeCacheQueryable, AdvancedPublisherError> {
        // INCOMPLETE, as the registry's is: the only honest answer a bounded ring can give.
        let id = self.node.forwarder().host_queryable_from(
            keyexpr,
            false,
            Locality::Any,
            Box::new(store.query_handler(wz_runtime_tokio::timestamp_source::wall_clock_ntp64)),
        );
        Ok(NodeCacheQueryable {
            forwarder: self.node.shared_forwarder(),
            id,
        })
    }

    fn declare_token(&self, keyexpr: &str) -> Result<NodeToken, AdvancedPublisherError> {
        Ok(NodeToken {
            node: Arc::clone(&self.node),
            id: self.node.declare_token(keyexpr),
        })
    }

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
    ) -> Option<NodeTimer> {
        let stop = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let waiting = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("wz-node-beacon".into())
            .spawn(move || {
                let (flag, wake) = &*waiting;
                loop {
                    let guard = flag
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let (guard, _) = wake
                        .wait_timeout_while(guard, period, |stopped| !*stopped)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        Some(NodeTimer { stop })
    }

    fn publish(
        &self,
        _publisher: &(),
        keyexpr: &str,
        payload: &[u8],
        options: PublishOptions,
    ) -> Result<usize, PublishError> {
        // The node's publication: its own subscribers and every face whose subscription matches.
        self.node
            .forwarder()
            .publish_with(keyexpr, payload, &options)
            .map(|()| payload.len())
            .map_err(|_| PublishError::ExceedsCapacity)
    }

    #[cfg(feature = "zenoh-c-shared-memory")]
    fn publish_shm(
        &self,
        publisher: &(),
        keyexpr: &str,
        payload: &Arc<dyn wz_ext_pubsub::advanced_publisher::ShmChunk>,
        options: PublishOptions,
    ) -> Result<usize, PublishError> {
        match Arc::clone(payload)
            .into_any()
            .downcast::<wz_runtime_tokio::shm_provider::ShmBackedPayload>()
        {
            Ok(chunk) => self
                .node
                .publish_shm(keyexpr, chunk.send_handle(), &options)
                .map(|()| payload.bytes().len())
                .map_err(|_| PublishError::ExceedsCapacity),
            Err(_) => self.publish(publisher, keyexpr, payload.bytes(), options),
        }
    }

    fn publish_beacon(&self, _beacon: Option<&()>, keyexpr: &str, payload: &[u8], sporadic: bool) {
        let _ = self.node.forwarder().publish_with(
            keyexpr,
            payload,
            &wz_ext_pubsub::advanced_publisher::heartbeat_publish_options(sporadic),
        );
    }

    fn retained_key(&self, _publisher: &()) -> Option<Retained> {
        None
    }
}

/// What a C advanced publisher's declaration answers, and whether a subscriber of the SAME session
/// hears it, with no peer and no drive thread: every delivery here is one `drain_local_plane` made.
/// The differential (`zenoh_c_advanced_publisher_declare_twice_and_diff`) is the proof against the
/// real library; these are the cases that need no oracle. They stood on the registry's own advanced
/// publisher and subscriber until those were retired, and are the same cases on the hosts that
/// replaced them.
#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use wz_ext_pubsub::advanced_cache::CacheConfig;
    use wz_ext_pubsub::advanced_publisher::{
        AdvancedPublisherOn, AdvancedPublisherOptions, MissDetectionConfig, Sequencing,
    };
    use wz_ext_pubsub::advanced_subscriber::{
        AdvancedSubscriberOptions, EngineSubscriber, HistoryConfig, RecoveryConfig,
    };
    use wz_runtime_tokio::node_clock::TimestampingEnabled;
    use wz_runtime_tokio::runtime_impl::TokioTime;
    use wz_runtime_tokio::session_glue::WhatAmI;

    fn test_zid() -> Vec<u8> {
        vec![0x22; 16]
    }

    /// A session of a node that holds a clock.
    fn clocked() -> Arc<SharedSession> {
        let clock = NodeHlc::for_node(&test_zid(), WhatAmI::Peer, TimestampingEnabled::all(true));
        Arc::new(
            SharedSession::new_with_node_clock(TokioTime::new(), test_zid(), clock)
                .expect("test host entropy"),
        )
    }

    fn declare(
        shared: &Arc<SharedSession>,
        keyexpr: &str,
        options: AdvancedPublisherOptions,
    ) -> Result<AdvancedPublisherOn<CPlane>, AdvancedPublisherError> {
        AdvancedPublisherOn::declare_on(
            Arc::new(CPlane::new(shared)),
            keyexpr.to_owned(),
            options,
            test_zid(),
        )
    }

    /// A cache with no miss detection: it sequences by timestamp, so it needs a node clock.
    fn cache_only() -> AdvancedPublisherOptions {
        // Assigned field by field and not written as a literal: the options are
        // `#[non_exhaustive]`, which is how the C ABI's own mapping fills them too.
        let mut options = AdvancedPublisherOptions::default();
        options.sequencing = Sequencing::Timestamp;
        options.cache = Some(CacheConfig::default());
        options
    }

    /// THE REFUSAL IS THE DECLARATION'S. A node that holds no clock refuses a publisher that
    /// sequences by timestamp, as upstream's does, and leaves nothing declared; a node that holds
    /// one accepts it, and the plane holds the publisher so a put has somewhere to go.
    #[test]
    fn a_cache_without_miss_detection_is_refused_on_a_node_with_no_clock_and_accepted_on_one_with()
    {
        let bare =
            Arc::new(SharedSession::new(TokioTime::new(), test_zid()).expect("test host entropy"));
        assert!(
            matches!(
                declare(&bare, "wz/adv", cache_only()),
                Err(AdvancedPublisherError::TimestampingDisabled)
            ),
            "a node with no clock must refuse a publisher that sequences by timestamp"
        );

        let clocked = clocked();
        let publisher = declare(&clocked, "wz/adv", cache_only())
            .unwrap_or_else(|_| panic!("a node that holds a clock accepts it"));
        publisher.put(b"x").expect("the put is accepted");
        assert_eq!(
            publisher.cache().map(CacheStore::len),
            Some(1),
            "the publisher holds the sample it put, so it was declared and is live"
        );
    }

    /// A publisher with a cache and miss detection on a node that holds a clock, and a subscriber
    /// of the SAME session built with `subscriber`, and three puts. Returns how many the
    /// subscriber's callback ran for once the plane has been drained to quiescence.
    fn same_session_received(subscriber: AdvancedSubscriberOptions) -> usize {
        let shared = clocked();
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = seen.clone();
        let _subscriber = EngineSubscriber::declare(
            &shared.as_engine(),
            "wz/adv/same",
            subscriber,
            move |_sample| {
                counter.fetch_add(1, Ordering::SeqCst);
            },
        )
        .expect("the subscriber declares on the session's engine");
        let mut options = AdvancedPublisherOptions::default();
        options.sequencing = Sequencing::SequenceNumber;
        options.cache = Some(CacheConfig::default());
        options.sample_miss_detection =
            MissDetectionConfig::default().heartbeat(Duration::from_millis(50));
        let publisher = declare(&shared, "wz/adv/same", options)
            .unwrap_or_else(|_| panic!("a clocked node accepts it"));
        for _ in 0..3 {
            let _ = publisher.put(b"x");
        }
        // Drained until two passes in a row find nothing, with a bound so a plane that never
        // quiesces fails the count and not the run.
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut quiet = 0;
        while quiet < 2 && Instant::now() < deadline {
            if shared.drain_local_plane() == 0 {
                quiet += 1;
                std::thread::sleep(Duration::from_millis(20));
            } else {
                quiet = 0;
            }
        }
        seen.load(Ordering::SeqCst)
    }

    /// THE SUBSCRIBER'S OPTIONS DO NOT DECIDE WHETHER A SAME-SESSION PUBLISHER IS HEARD. MEASURED
    /// against the real library, all of these hear all three puts.
    #[test]
    fn a_history_subscriber_of_the_publishers_own_session_hears_it() {
        let history = AdvancedSubscriberOptions::default().with_history(HistoryConfig::new());
        assert_eq!(same_session_received(history), 3);
    }

    /// A subscriber with PERIODIC recovery: the job is the engine's, and not a task of a runtime the
    /// calling thread would have to be inside.
    #[test]
    fn a_periodic_recovery_subscriber_of_the_publishers_own_session_hears_it() {
        let periodic = AdvancedSubscriberOptions::default()
            .with_recovery(RecoveryConfig::new().with_periodic_queries(Duration::from_millis(500)));
        assert_eq!(same_session_received(periodic), 3);
    }

    /// Recovery driven by the publisher's HEARTBEAT, and recovery with history together.
    #[test]
    fn heartbeat_recovery_and_recovery_with_history_hear_the_publishers_own_session() {
        let heartbeat = AdvancedSubscriberOptions::default()
            .with_recovery(RecoveryConfig::new().with_heartbeat());
        assert_eq!(same_session_received(heartbeat), 3);
        let all = AdvancedSubscriberOptions::default()
            .with_history(HistoryConfig::new())
            .with_recovery(RecoveryConfig::new().with_periodic_queries(Duration::from_millis(500)));
        assert_eq!(same_session_received(all), 3);
    }

    /// THE PLANE ACCEPTS A HEARTBEAT FROM THE CALLING THREAD. This `#[test]` runs on a thread that is
    /// inside no tokio runtime, as a C application thread is; the beacon is the engine's job and
    /// asks the thread for none. The count is what separates a plane that holds the publisher from
    /// one that does not.
    #[test]
    fn a_heartbeat_declares_on_the_plane_from_a_thread_that_is_inside_no_runtime() {
        let shared =
            Arc::new(SharedSession::new(TokioTime::new(), test_zid()).expect("test host entropy"));
        let mut options = AdvancedPublisherOptions::default();
        options.sequencing = Sequencing::SequenceNumber;
        options.sample_miss_detection =
            MissDetectionConfig::default().heartbeat(Duration::from_millis(50));
        let publisher = declare(&shared, "wz/adv", options)
            .unwrap_or_else(|_| panic!("a heartbeat asks the calling thread for no runtime"));
        publisher
            .put(b"x")
            .expect("the plane holds the publisher that was declared on it");
    }
}
