// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
//! [`AdvancedPublisherOn`]: wz_capi_core::runtime::advanced_publisher::AdvancedPublisherOn

use std::sync::Arc;

use wz_capi_core::runtime::advanced_cache::{CacheStore, Retained};
use wz_capi_core::runtime::advanced_publisher::{
    AdvancedPublisherError, AdvancedPublisherPlane, DeclaredPublisher,
};
use wz_capi_core::runtime::node_clock::NodeHlc;
use wz_capi_core::runtime::runtime_impl::TokioTime;
use wz_capi_port::{QueryCallback, QueryHolder, QueryableSink};
use wz_session_core::publish_options::{PublishError, PublishOptions};
use wz_session_core::reliability::Reliability;
use wz_session_core::sample::SampleKind;

use crate::liveliness::TokenState;
use crate::pubsub::{PlainPublisher, PublisherQos};
use crate::query::PlainQueryable;
use crate::result::{ZResult, Z_OK};
use crate::write_filter::PicoSession;

/// The plane of one pico session.
pub(crate) struct PicoPlane {
    session: PicoSession,
    /// The session's own clock: the plane's stamps come from it, as pico's do
    /// from the session's ([`crate::session_ext::PicoSessionExt::new`]).
    hlc: NodeHlc,
    /// What a beacon's period is slept on. Any clock would do — the period is a
    /// duration — and the session's is the one the rest of the session reads.
    time: Arc<TokioTime>,
    /// What the advanced publisher's own publisher is declared with: the
    /// `publisher_options` the program embedded in its advanced options, which
    /// pico hands to the `z_declare_publisher` that builds it. The heartbeat
    /// publisher is not declared with them: pico declares it with the defaults
    /// (`vendor/zenoh-pico/src/api/advanced_publisher.c` @
    /// `z_publisher_options_default(&heatbeat_opts);`).
    declared: PublisherQos,
}

impl PicoPlane {
    /// The plane of `session`, whose advanced publisher's publisher is declared
    /// with `declared`.
    pub(crate) fn new(session: PicoSession, declared: PublisherQos) -> Self {
        Self {
            hlc: session.hlc.clone(),
            time: Arc::clone(session.shared.local_session().clock()),
            session,
            declared,
        }
    }

    /// What the plane names a failed declaration.
    fn refusal(what: &str, code: ZResult) -> AdvancedPublisherError {
        AdvancedPublisherError::Plane(format!("{what}: pico result {code}"))
    }
}

/// The options every plain publish of this ABI carries: reliable, and the
/// destination a pico put takes by default.
///
/// That destination is `Locality::Remote` without `local-subscriber`, because a
/// pico session's own put is not delivered to its own subscribers by default
/// (`Z_FEATURE_LOCAL_SUBSCRIBER` is 0), and `Any` with it, as this crate's plain
/// put has it ([`crate::pubsub`]'s `put_options`). An advanced publisher that took
/// the composite's own `Any` regardless would deliver in-process where the plain
/// publisher it wraps does not. A publish through a publisher then takes that
/// publisher's own destination ([`crate::pubsub::PublisherQos`]).
fn pico_publish(options: PublishOptions) -> PublishOptions {
    options
        .with_reliability(Reliability::Reliable)
        .with_locality(crate::locality::default_locality!("local-subscriber"))
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

    fn declare_publisher(
        &self,
        keyexpr: &str,
        _options: PublishOptions,
    ) -> Result<DeclaredPublisher<PlainPublisher>, AdvancedPublisherError> {
        // The QoS the program declared the composite with, and not the
        // `PublishOptions` the composite folds its own knobs into: those reach the
        // publisher as the options of each put, and the publisher's declared QoS
        // is what it sends with (`PlainPublisher::publish`).
        let publisher =
            PlainPublisher::declare(&self.session, keyexpr, None, self.declared.clone())
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
        let sink: QueryableSink = Arc::new(move |_face: Arc<dyn QueryHolder>| {
            Box::new(store.query_handler()) as QueryCallback
        });
        // INCOMPLETE, which is the only honest answer a bounded ring can give
        // (R2556, [`wz_capi_core::runtime::advanced_cache::AdvancedCache::declare`]).
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
        PlainPublisher::declare(&self.session, keyexpr, None, PublisherQos::pico_default())
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
        match publisher.publish(payload, &pico_publish(options)) {
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
        let mut options = pico_publish(PublishOptions::default());
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
