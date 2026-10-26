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
