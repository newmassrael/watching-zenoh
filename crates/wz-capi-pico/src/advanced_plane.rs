// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The pico C session as the plane an advanced publisher lives on.
//!
//! zenoh-pico builds its advanced publisher out of its own primitives: a plain
//! publisher, a cache queryable, a liveliness token and, for the heartbeat, a
//! second plain publisher (`vendor/zenoh-pico/src/api/advanced_publisher.c` @
//! `z_result_t ze_declare_advanced_publisher(const z_loaned_session_t *zs, ze_owned_advanced_publisher_t *pub,`).
//! Each of those is an ordinary pico declaration — a key declared and named on
//! the wire by its id, a write filter on the publishers, a retraction that names
//! the key — so what an advanced publisher puts on the wire is what four
//! ordinary entities put there, and that is what this plane makes it.
//!
//! The composition itself is [`AdvancedPublisherOn`]: what is validated, in what
//! order the four are declared, what a put stamps and retains, what a beacon
//! says. This file is only the four declarations and the sends, each one the
//! same function the plain C entry point of that entity calls, so the two cannot
//! describe one entity two ways.
//!
//! [`AdvancedPublisherOn`]: wz_runtime_tokio::advanced_publisher::AdvancedPublisherOn

use std::sync::Arc;

use wz_capi_core::faces::QueryableSink;
use wz_runtime_tokio::advanced_cache::{CacheStore, Retained};
use wz_runtime_tokio::advanced_publisher::{
    AdvancedPublisherError, AdvancedPublisherPlane, DeclaredPublisher,
};
use wz_runtime_tokio::locality::Locality;
use wz_runtime_tokio::node_clock::NodeHlc;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::sample::SampleKind;
use wz_runtime_tokio::session::{PublishError, PublishOptions, TokioSession};
use wz_runtime_tokio::Reliability;

use crate::liveliness::TokenState;
use crate::pubsub::PlainPublisher;
use crate::query::PlainQueryable;
use crate::result::{ZResult, Z_OK};
use crate::write_filter::PicoSession;

/// The plane of one pico session.
pub(crate) struct PicoPlane {
    session: PicoSession,
    /// The session's own clock: the plane's stamps come from it, as pico's do
    /// from the session's ([`crate::write_filter::PicoSessionMode::new`]).
    hlc: NodeHlc,
    /// What a beacon's period is slept on. Any clock would do — the period is a
    /// duration — and the session's is the one the rest of the session reads.
    time: Arc<TokioTime>,
}

impl PicoPlane {
    /// The plane of `session`.
    pub(crate) fn new(session: PicoSession) -> Self {
        Self {
            hlc: session.hlc.clone(),
            time: Arc::clone(session.shared.local_session().clock()),
            session,
        }
    }

    /// What the plane names a failed declaration.
    fn refusal(what: &str, code: ZResult) -> AdvancedPublisherError {
        AdvancedPublisherError::Plane(format!("{what}: pico result {code}"))
    }
}

/// The options every plain publish of this ABI carries: delivered to peers only,
/// reliable.
///
/// `Locality::Remote`, because a pico session's own put is not delivered to its
/// own subscribers by default (`Z_FEATURE_LOCAL_SUBSCRIBER` is 0), and this
/// crate's plain put says so ([`crate::pubsub`]'s `put_options`). An advanced
/// publisher that took the composite's own `Any` would deliver in-process where
/// the plain publisher it wraps does not.
fn remote_only(options: PublishOptions) -> PublishOptions {
    options
        .with_reliability(Reliability::Reliable)
        .with_locality(Locality::Remote)
}

impl AdvancedPublisherPlane for PicoPlane {
    type Time = TokioTime;
    type Publisher = PlainPublisher;
    type Queryable = PlainQueryable;
    type Token = TokenState;
    type Beacon = PlainPublisher;

    fn node_hlc(&self) -> &NodeHlc {
        &self.hlc
    }

    fn clock(&self) -> &Arc<TokioTime> {
        &self.time
    }

    /// Always: a pico session stamps from its own clock and zid with no
    /// configuration to consult (`vendor/zenoh-pico/src/net/session.c` @
    /// `z_timestamp_new`), where zenoh's node clock exists only when
    /// `timestamping` is enabled for the node's role. A cache without miss
    /// detection sequences by timestamp, so refusing it here would refuse a
    /// program pico runs.
    fn stamps(&self) -> bool {
        true
    }

    /// The beacon runs on the process's own `net` runtime, which no calling
    /// thread has to be inside of: a C program declares from its own thread.
    fn check_can_spawn(&self) -> Result<(), AdvancedPublisherError> {
        Ok(())
    }

    fn declare_publisher(
        &self,
        keyexpr: &str,
        _options: PublishOptions,
    ) -> Result<DeclaredPublisher<PlainPublisher>, AdvancedPublisherError> {
        let publisher = PlainPublisher::declare(&self.session, keyexpr, None)
            .map_err(|code| Self::refusal("publisher", code))?;
        Ok(DeclaredPublisher {
            eid: publisher.entity_id() as u32,
            handle: publisher,
        })
    }

    fn declare_cache_queryable(
        &self,
        keyexpr: &str,
        store: &CacheStore,
    ) -> Result<PlainQueryable, AdvancedPublisherError> {
        let store = store.clone();
        // One handler per face: each is a fresh closure over the same ring, and
        // none needs the face's session — a reply goes out on the query's own.
        let sink: QueryableSink =
            Arc::new(move |_face: &TokioSession| Box::new(store.query_handler()) as Box<_>);
        // INCOMPLETE, which is the only honest answer a bounded ring can give
        // (R2556, [`wz_runtime_tokio::advanced_cache::AdvancedCache::declare`]).
        PlainQueryable::declare(&self.session, keyexpr, None, false, sink)
            .map_err(|code| Self::refusal("cache queryable", code))
    }

    fn declare_token(&self, keyexpr: &str) -> Result<TokenState, AdvancedPublisherError> {
        TokenState::declare(&self.session, keyexpr, None)
            .map_err(|code| Self::refusal("liveliness token", code))
    }

    fn declare_beacon(
        &self,
        keyexpr: &str,
        _sporadic: bool,
    ) -> Result<PlainPublisher, AdvancedPublisherError> {
        PlainPublisher::declare(&self.session, keyexpr, None)
            .map_err(|code| Self::refusal("beacon publisher", code))
    }

    fn publish(
        &self,
        publisher: &PlainPublisher,
        _keyexpr: &str,
        payload: &[u8],
        options: PublishOptions,
    ) -> Result<usize, PublishError> {
        // The publisher sends on its own key, in its own declared form, through
        // its own write filter: the same call `z_publisher_put` makes. The byte
        // count the runtime reports is the number of peers a put reached, which
        // a filter that held the sample back makes 0 — a put with no recipient,
        // and `Z_OK`.
        match publisher.publish(payload, &remote_only(options)) {
            code if code == Z_OK => Ok(payload.len()),
            _ => Err(PublishError::ExceedsCapacity),
        }
    }

    fn publish_beacon(
        &self,
        beacon: Option<&PlainPublisher>,
        keyexpr: &str,
        payload: &[u8],
        _sporadic: bool,
    ) {
        let mut options = remote_only(PublishOptions::default());
        options.kind = SampleKind::Put;
        match beacon {
            // Through the beacon publisher, as pico's heartbeat task does, so
            // the beacon is held back while nothing subscribes to it.
            Some(publisher) => {
                let _ = publisher.publish(payload, &options);
            }
            // An on-demand beacon from a publisher that declared none: on the
            // key itself.
            None => {
                let _ = self.session.shared.publish_all(keyexpr, payload, &options);
            }
        }
    }

    fn retained_key(&self, publisher: &PlainPublisher) -> Option<Retained> {
        // The cached sample holds a reference to the key it was published on, as
        // pico's does (`_z_declared_keyexpr_copy` in `_z_sample_copy_data`), so
        // the key stays declared until the ring lets the sample go.
        Some(Retained::new(Arc::new(publisher.key().share())))
    }
}
