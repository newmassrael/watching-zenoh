// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y69 — `ext-pubsub-advanced-publisher` (§5.25): a publisher that
//! stamps a per-sample `SourceInfo` sequence number, retains its samples
//! in an [`AdvancedCache`] for recovery, and announces its existence with
//! an `@adv` liveliness token.
//!
//! The wz mirror of zenoh-ext `advanced_publisher.rs`. On each
//! [`AdvancedPublisher::put`] it (1) reads-and-increments a per-publisher
//! sequence counter and stamps it onto the wire sample's `SourceInfo`
//! (`(zid, eid, sn)`), (2) stamps a timestamp, (3) publishes, and (4)
//! pushes the sample into its cache ring. A subscriber detects the
//! publisher via the liveliness token on
//! `<key_expr>/@adv/pub/<zid>/<eid|uhlc>/_` and recovers missed samples by
//! `get`-ing the cache there with an `_sn` range (the
//! `ext-pubsub-advanced-recovery` round).
//!
//! Composes on already-active wz primitives: the user [`Session::publish`]
//! (`pubsub-put`) carrying `source_info` (`pubsub-source-info`) +
//! `timestamp` (`pubsub-timestamp`), the cache [`Queryable`]
//! (`query-queryable`), and the [`LivelinessToken`] (`liveliness-token`).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;
use wz_session_core::sample::SourceInfo;
use wz_session_core::zid_hex::zid_to_zenoh_hex;

use crate::advanced_cache::{AdvancedCache, CacheConfig, CachedSample};
use crate::session::{
    LivelinessAliasError, LivelinessOptions, LivelinessToken, PublishError, PublishOptions,
    QueryableError, Session, Unicast,
};
use crate::session_glue::SessionLinkActions;
use crate::timestamp_source::FallbackStamp;

/// How an advanced publisher tags its samples for downstream detection /
/// recovery. Mirror of zenoh-ext `Sequencing` (advanced_publisher.rs:55-59).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sequencing {
    /// No per-sample tag (a plain publisher with the `@adv` decorations).
    None,
    /// Tag the timestamp only (the `uhlc` discriminator in the `@adv` KE).
    Timestamp,
    /// Tag a per-publisher monotonic sequence number into `SourceInfo`
    /// (the recovery-capable mode; the `<eid>` discriminator in the KE).
    SequenceNumber,
}

/// Construction options for an [`AdvancedPublisher`].
#[derive(Clone, Copy, Debug)]
pub struct AdvancedPublisherOptions {
    /// Per-sample tagging mode.
    pub sequencing: Sequencing,
    /// When `Some`, retain published samples in a cache of this depth for
    /// recovery / history (declares the `@adv` cache queryable).
    pub cache: Option<CacheConfig>,
    /// When `true`, declare the `@adv` liveliness token so subscribers can
    /// detect this publisher (zenoh `publisher_detection`).
    pub publisher_detection: bool,
}

impl Default for AdvancedPublisherOptions {
    fn default() -> Self {
        Self {
            sequencing: Sequencing::SequenceNumber,
            cache: Some(CacheConfig::default()),
            publisher_detection: true,
        }
    }
}

/// Why declaring an [`AdvancedPublisher`] failed.
#[derive(Debug)]
pub enum AdvancedPublisherError {
    /// `local_zid` was empty or longer than 16 bytes (the `SourceInfo`
    /// wire constraint).
    InvalidZid,
    /// The cache queryable declaration was rejected.
    Cache(QueryableError),
    /// The `@adv` liveliness token declaration was rejected.
    Token(LivelinessAliasError),
}

impl From<QueryableError> for AdvancedPublisherError {
    fn from(e: QueryableError) -> Self {
        AdvancedPublisherError::Cache(e)
    }
}
impl From<LivelinessAliasError> for AdvancedPublisherError {
    fn from(e: LivelinessAliasError) -> Self {
        AdvancedPublisherError::Token(e)
    }
}

/// The `@adv` key-expr prefix (zenoh `KE_ADV_PREFIX`, admin.rs:48).
const KE_ADV_PREFIX: &str = "@adv";

/// The trailing empty chunk zenoh appends to the `@adv` suffix
/// (`KE_EMPTY = ke!("_")`, zenoh admin.rs:58). zenoh adds it
/// "because of a routing matching bug" (advanced_publisher.rs:328-329):
/// the publisher-detection / recovery queries are wildcard-tailed
/// (`.../@adv/*/<zid>/<eid>/**`), and the concrete `_` chunk keeps the
/// declared keyexpr matchable through a zenoh router. wz mirrors it so
/// the `@adv` namespace is byte-identical to zenoh (a wz<->zenoh-router
/// mesh would otherwise re-trip the bug zenoh shaped this to dodge).
const KE_EMPTY: &str = "_";

/// A live advanced publisher bound to a [`Session`]. Owns the (optional)
/// cache + liveliness token (RAII: dropping it tears them down) and the
/// per-publisher sequence counter.
pub struct AdvancedPublisher<R: SessionRuntime, T: TimeSource> {
    session: Session<R, T, Unicast>,
    keyexpr: String,
    zid: Vec<u8>,
    eid: u32,
    seqnum: Option<Arc<AtomicU32>>,
    stamp: FallbackStamp,
    cache: Option<AdvancedCache<R, T>>,
    _token: Option<LivelinessToken<R, T>>,
}

impl<R, T> AdvancedPublisher<R, T>
where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
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
        if local_zid.is_empty() || local_zid.len() > 16 {
            return Err(AdvancedPublisherError::InvalidZid);
        }
        let keyexpr = keyexpr.into();
        // Allocate the publisher entity id from the session's dedicated
        // entity-id SSOT (the `SourceInfo.eid` id-space). zenoh-pico draws
        // every entity id from one `_z_get_entity_id`; wz keeps per-purpose
        // id counters, so the publisher eid has its own (R311y72: it was
        // minted from the token-id counter — a conflated namespace + a
        // truncating `as u32`; now a real u32 entity counter).
        let eid = session.actions().alloc_next_entity_id();

        // `@adv/pub/<zid>/<eid|uhlc>/_` — the detection + recovery suffix
        // (zenoh advanced_publisher.rs:317-329). The `<eid>` discriminator
        // marks sequence-number sequencing; `uhlc` marks timestamp/none.
        // The trailing `_` (KE_EMPTY) is the empty meta chunk zenoh appends
        // (no publisher_detection_metadata set here = the empty case).
        let discriminator = match options.sequencing {
            Sequencing::SequenceNumber => eid.to_string(),
            Sequencing::Timestamp | Sequencing::None => "uhlc".to_string(),
        };
        let adv_keyexpr = format!(
            "{keyexpr}/{KE_ADV_PREFIX}/pub/{}/{}/{KE_EMPTY}",
            zid_to_zenoh_hex(&local_zid),
            discriminator
        );

        let cache = match options.cache {
            Some(config) => Some(AdvancedCache::declare(
                session,
                adv_keyexpr.clone(),
                config,
            )?),
            None => None,
        };

        let token = if options.publisher_detection {
            Some(session.declare_token(adv_keyexpr, LivelinessOptions::default())?)
        } else {
            None
        };

        let seqnum = match options.sequencing {
            Sequencing::SequenceNumber => Some(Arc::new(AtomicU32::new(0))),
            Sequencing::Timestamp | Sequencing::None => None,
        };

        Ok(Self {
            session: session.clone(),
            keyexpr,
            zid: local_zid.clone(),
            eid,
            seqnum,
            stamp: FallbackStamp::new(local_zid),
            cache,
            _token: token,
        })
    }

    /// Publish `payload`, stamping the next `SourceInfo` sequence number
    /// (in `SequenceNumber` mode) + a timestamp, and retaining the sample in
    /// the cache. Returns the [`Session::publish`] byte count.
    pub fn put(&self, payload: &[u8]) -> Result<usize, PublishError> {
        // fetch_add returns the pre-increment value, so the first sample
        // carries sn=0 (zenoh advanced_publisher.rs:490-501).
        let sn = self
            .seqnum
            .as_ref()
            .map(|counter| counter.fetch_add(1, Ordering::Relaxed));
        let timestamp = self.stamp.stamp();

        let mut opts = PublishOptions::put().with_timestamp(timestamp.clone());
        if let Some(sn) = sn {
            opts = opts.with_source_info(SourceInfo::new(&self.zid, self.eid, sn));
        }
        let written = self.session.publish(&self.keyexpr, payload, opts)?;

        if let Some(cache) = &self.cache {
            cache.cache_sample(CachedSample {
                keyexpr: self.keyexpr.clone(),
                payload: payload.to_vec(),
                source_sn: sn,
                timestamp,
            });
        }
        Ok(written)
    }

    /// The publisher's allocated entity id (test / introspection seam).
    pub fn eid(&self) -> u32 {
        self.eid
    }

    /// Borrow the cache, if one was declared (test / recovery seam).
    pub fn cache(&self) -> Option<&AdvancedCache<R, T>> {
        self.cache.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Composed session-API loopback e2e (a real `session.query` through
    /// the declared queryable, NOT a kernel-proxy — though SessionLocal
    /// dispatch stays in-process and does NOT traverse the Push/Response
    /// wire codec, so this is "session-API loopback", not "wire-level"):
    /// an `AdvancedPublisher` with a cache publishes three sequenced
    /// samples, then a loopback `session.query` over the `@adv` namespace
    /// fires the cache queryable inline and recovers all three. Proves
    /// publisher -> cache_sample -> queryable -> get composition.
    #[cfg(feature = "query-get")]
    #[test]
    fn published_samples_recover_via_loopback_cache_query() {
        use std::sync::Mutex;

        use crate::observer::ApplicationLayerObserver;
        use crate::reply_sink::ReplyView;
        use crate::runtime_impl::TokioTime;
        use crate::session::{QueryOptions, TokioSession};
        use wz_session_core::locality::Locality;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        // SequenceNumber sequencing + a cache deep enough to hold all three.
        let options = AdvancedPublisherOptions {
            sequencing: Sequencing::SequenceNumber,
            cache: Some(CacheConfig { max_samples: 8 }),
            publisher_detection: true,
        };
        let publisher = AdvancedPublisher::declare(&session, "demo/data", options, vec![0x01])
            .expect("advanced publisher declares against the test link");

        for v in 0u8..3 {
            publisher
                .put(&[v])
                .expect("advanced put publishes + caches");
        }
        assert_eq!(
            publisher.cache().map(|c| c.len()),
            Some(3),
            "the cache retained all three sequenced samples"
        );

        // A loopback GET over `demo/data/**` covers BOTH the cache
        // queryable KE (`demo/data/@adv/pub/<zid>/<eid>/_`) and the reply
        // keys (`demo/data`, the original sample key the cache replies
        // under) — the `reply ⊆ query` contract holds.
        let replies = Arc::new(Mutex::new(Vec::<(String, Vec<u8>)>::new()));
        let rec = Arc::clone(&replies);
        session
            .query(
                "demo/data/**",
                QueryOptions::get().with_allowed_destination(Locality::SessionLocal),
                move |reply: &dyn ReplyView| {
                    rec.lock()
                        .expect("reply recorder poisoned")
                        .push((reply.keyexpr().to_string(), reply.payload().to_vec()));
                },
                |_rid| {},
            )
            .expect("loopback query fires the cache queryable inline");

        let mut got = replies.lock().expect("reply recorder poisoned").clone();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("demo/data".to_string(), vec![0]),
                ("demo/data".to_string(), vec![1]),
                ("demo/data".to_string(), vec![2]),
            ],
            "the loopback query recovered all three cached samples under their original key"
        );
    }
}
