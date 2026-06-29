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
use std::time::Duration;

use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;
use wz_session_core::sample::SourceInfo;
use wz_session_core::zid_hex::zid_to_zenoh_hex;

#[cfg(feature = "ext-pubsub-sample-miss-detection")]
use wz_session_core::serde_codec::z_serialize;

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

/// Heartbeat (last-sample-miss-detection) configuration. Mirror of zenoh-ext
/// `MissDetectionConfig` (advanced_publisher.rs:66-104). `heartbeat` /
/// `sporadic_heartbeat` are mutually exclusive (the last one wins); both set the
/// `(period, sporadic)` state-publisher tuple. Always present (signature-stable);
/// the beacon-emit task is `ext-pubsub-sample-miss-detection`-gated, so the
/// option is a documented no-op when the feature is off.
#[derive(Clone, Copy, Debug, Default)]
pub struct MissDetectionConfig {
    /// `Some((period, sporadic))` enables the heartbeat beacon: every `period`
    /// the publisher emits its last published sn. `sporadic = false` emits every
    /// period regardless; `true` emits only when the sn advanced since the last
    /// beacon (zenoh advanced_publisher.rs:385-419).
    state_publisher: Option<(Duration, bool)>,
}

impl MissDetectionConfig {
    /// Periodic heartbeat: emit the last sn every `period` (zenoh
    /// `MissDetectionConfig::heartbeat`).
    pub fn heartbeat(mut self, period: Duration) -> Self {
        self.state_publisher = Some((period, false));
        self
    }

    /// Sporadic heartbeat: emit the last sn every `period` but only when it
    /// changed since the last beacon (zenoh `sporadic_heartbeat`).
    pub fn sporadic_heartbeat(mut self, period: Duration) -> Self {
        self.state_publisher = Some((period, true));
        self
    }
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
    /// R311y85 — last-sample-miss-detection: when its `state_publisher` is set,
    /// spawn the heartbeat beacon task. Requires `SequenceNumber` sequencing and
    /// the `ext-pubsub-sample-miss-detection` feature (a documented no-op
    /// otherwise), plus a tokio runtime at declare time for the spawn.
    pub sample_miss_detection: MissDetectionConfig,
}

impl Default for AdvancedPublisherOptions {
    fn default() -> Self {
        Self {
            sequencing: Sequencing::SequenceNumber,
            cache: Some(CacheConfig::default()),
            publisher_detection: true,
            sample_miss_detection: MissDetectionConfig::default(),
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
    /// R311y85 — the publisher's `@adv` KE, retained so the heartbeat-beacon
    /// emit (the background task + the `emit_heartbeat_once` seam) can publish on it.
    #[cfg(feature = "ext-pubsub-sample-miss-detection")]
    adv_keyexpr: String,
    /// R311y85 — the heartbeat beacon task (RAII abort-on-drop), `Some` only
    /// when `MissDetectionConfig` set a `state_publisher` + sequencing is on.
    #[cfg(feature = "ext-pubsub-sample-miss-detection")]
    _heartbeat_task: Option<HeartbeatTask>,
}

impl<R, T> AdvancedPublisher<R, T>
where
    R: SessionRuntime + 'static,
    T: TimeSource + Send + Sync + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
    Session<R, T, Unicast>: Send + 'static,
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
            Some(session.declare_token(adv_keyexpr.clone(), LivelinessOptions::default())?)
        } else {
            None
        };

        let seqnum = match options.sequencing {
            Sequencing::SequenceNumber => Some(Arc::new(AtomicU32::new(0))),
            Sequencing::Timestamp | Sequencing::None => None,
        };

        // R311y85 — the heartbeat beacon task: every `period`, publish the last
        // published sn (`z_serialize::<u32>(seqnum-1)`) on the `@adv` KE so a
        // heartbeat-recovering subscriber can detect + recover a lost last
        // sample (zenoh advanced_publisher.rs:373-419). Needs the `SequenceNumber`
        // seqnum (no seqnum -> no beacon); sporadic emits only when the sn
        // advanced. Spawned here (the caller is in a tokio runtime), aborted on
        // drop; the loop is thin glue over the deterministic `emit_heartbeat`.
        #[cfg(feature = "ext-pubsub-sample-miss-detection")]
        let heartbeat_task = match (
            options.sample_miss_detection.state_publisher,
            seqnum.as_ref(),
        ) {
            (Some((period, sporadic)), Some(seqnum)) => {
                let hb_session = session.clone();
                let hb_keyexpr = adv_keyexpr.clone();
                let hb_seqnum = Arc::clone(seqnum);
                let clock = Arc::clone(session.clock());
                // R311y87 (review C4) — clamp to >=1ms: a sub-ms Duration
                // truncates to 0, turning the beacon loop into a busy spin.
                let period_ms = (period.as_millis() as u64).max(1);
                Some(HeartbeatTask {
                    handle: tokio::spawn(async move {
                        let mut last_emitted = 0u32;
                        loop {
                            clock.sleep(period_ms).await;
                            let sn = hb_seqnum.load(Ordering::Relaxed);
                            // Non-sporadic emits every tick (emit_heartbeat skips
                            // sn==0); sporadic only when the sn advanced.
                            if (!sporadic || sn > last_emitted)
                                && emit_heartbeat(&hb_session, &hb_keyexpr, sn)
                            {
                                last_emitted = sn;
                            }
                        }
                    }),
                })
            }
            _ => None,
        };

        // adv_keyexpr is consumed by the cache / token clones + (feature-on) the
        // struct; explicitly drop it on the feature-off path so the cache-None +
        // detection-false combination does not warn unused.
        #[cfg(not(feature = "ext-pubsub-sample-miss-detection"))]
        let _ = adv_keyexpr;

        Ok(Self {
            session: session.clone(),
            keyexpr,
            zid: local_zid.clone(),
            eid,
            seqnum,
            stamp: FallbackStamp::new(local_zid),
            cache,
            _token: token,
            #[cfg(feature = "ext-pubsub-sample-miss-detection")]
            adv_keyexpr,
            #[cfg(feature = "ext-pubsub-sample-miss-detection")]
            _heartbeat_task: heartbeat_task,
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

        // Construct the SourceInfo ONCE (SSOT): the same `(zid, eid, sn)` rides
        // BOTH the wire publish (pubsub-source-info) AND the cache ring, so a
        // recovery reply re-stamps the identical identity the live sample
        // carried. zenoh caches the whole `Sample` with its `SourceInfo`; this
        // mirrors that without the prior dual source_sn-vs-SourceInfo::new
        // construction. `None` under timestamp / no sequencing.
        let source_info = sn.map(|sn| SourceInfo::new(&self.zid, self.eid, sn));

        let mut opts = PublishOptions::put().with_timestamp(timestamp.clone());
        if let Some(si) = &source_info {
            opts = opts.with_source_info(si.clone());
        }
        let written = self.session.publish(&self.keyexpr, payload, opts)?;

        if let Some(cache) = &self.cache {
            cache.cache_sample(CachedSample {
                keyexpr: self.keyexpr.clone(),
                payload: payload.to_vec(),
                source_info,
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

#[cfg(feature = "ext-pubsub-sample-miss-detection")]
impl<R, T> AdvancedPublisher<R, T>
where
    R: SessionRuntime + 'static,
    T: TimeSource + Send + Sync + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
    Session<R, T, Unicast>: Send + 'static,
{
    /// Emit ONE heartbeat beacon now — the publisher's last published sn on its
    /// `@adv` KE — the deterministic core the background task loops. Returns
    /// whether a beacon was emitted (`false` if nothing has been published yet,
    /// or this is a non-`SequenceNumber` publisher). Both an on-demand trigger
    /// (a wz superset over zenoh's timer-only beacon) and the test seam over the
    /// same path the timer drives.
    pub fn emit_heartbeat_once(&self) -> bool {
        match self.seqnum.as_ref() {
            Some(seqnum) => emit_heartbeat(
                &self.session,
                &self.adv_keyexpr,
                seqnum.load(Ordering::Relaxed),
            ),
            None => false,
        }
    }
}

/// R311y85 — publish ONE heartbeat beacon: the last published sn
/// (`z_serialize::<u32>(seqnum_now - 1)`; the counter is the NEXT sn) on the
/// `@adv` KE. Returns `false` (no beacon) when nothing has been published yet
/// (`seqnum_now == 0`). A publish error (e.g. a torn-down link) is non-fatal —
/// the next tick re-emits (zenoh advanced_publisher.rs:392-394).
#[cfg(feature = "ext-pubsub-sample-miss-detection")]
fn emit_heartbeat<R, T>(
    session: &Session<R, T, Unicast>,
    adv_keyexpr: &str,
    seqnum_now: u32,
) -> bool
where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    if seqnum_now == 0 {
        return false;
    }
    let payload = z_serialize::<u32>(&(seqnum_now - 1));
    let _ = session.publish(adv_keyexpr, &payload, PublishOptions::put());
    true
}

/// RAII handle for the heartbeat beacon task: dropping it aborts the loop so a
/// torn-down publisher stops emitting (the `_periodic` / DigestPublisher shape).
#[cfg(feature = "ext-pubsub-sample-miss-detection")]
struct HeartbeatTask {
    handle: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "ext-pubsub-sample-miss-detection")]
impl Drop for HeartbeatTask {
    fn drop(&mut self) {
        self.handle.abort();
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
            sample_miss_detection: MissDetectionConfig::default(),
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

    /// R311y85 — the heartbeat beacon emits the publisher's last published sn on
    /// its `@adv` KE. A plain subscriber on the `@adv/pub/**` namespace records
    /// beacons; `emit_heartbeat_once` (the deterministic core the timer loops)
    /// publishes one, and its payload decodes to `last_sn` (= seqnum-1). The
    /// publisher is declared WITHOUT a heartbeat period (no background task -> no
    /// tokio runtime needed); the on-demand seam drives the same emit.
    #[cfg(all(
        feature = "ext-pubsub-sample-miss-detection",
        feature = "declare-subscriber",
        feature = "pubsub-allow-loop"
    ))]
    #[test]
    fn heartbeat_beacon_emits_last_sn_on_adv_ke() {
        use std::sync::Mutex;

        use crate::observer::ApplicationLayerObserver;
        use crate::runtime_impl::TokioTime;
        use crate::session::{SubscribeOptions, TokioSession};
        use wz_session_core::serde_codec::z_deserialize;
        use wz_session_core::sink::SampleView;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let beacons = Arc::new(Mutex::new(Vec::<(String, Vec<u8>)>::new()));
        let b = Arc::clone(&beacons);
        let _hb_rec = session
            .declare_subscriber(
                "demo/data/@adv/pub/**",
                SubscribeOptions::default(),
                move |v: &dyn SampleView| {
                    b.lock()
                        .unwrap()
                        .push((v.keyexpr().to_string(), v.payload().to_vec()))
                },
            )
            .expect("beacon recorder subscribes");

        let publisher = AdvancedPublisher::declare(
            &session,
            "demo/data",
            AdvancedPublisherOptions::default(),
            vec![0x09],
        )
        .expect("advanced publisher declares");

        // Nothing published yet -> no beacon.
        assert!(
            !publisher.emit_heartbeat_once(),
            "no beacon before any sample is published"
        );
        for v in 0u8..3 {
            publisher.put(&[v]).expect("advanced put");
        }
        // seqnum = 3 -> last published sn = 2.
        assert!(publisher.emit_heartbeat_once(), "beacon emitted after puts");

        let got = beacons.lock().unwrap().clone();
        let last = got.last().expect("a beacon was recorded");
        assert!(
            last.0.starts_with("demo/data/@adv/pub/"),
            "beacon published on the @adv KE, got {}",
            last.0
        );
        assert_eq!(
            z_deserialize::<u32>(&last.1).unwrap(),
            2,
            "the beacon carries the last published sn = 2"
        );
    }

    /// R311y85 composed PRODUCER->CONSUMER heartbeat recovery e2e: a real
    /// producer's beacon drives a real consumer's recovery. The publisher
    /// publishes 0,1,2 (cached) BEFORE the subscriber exists, so the
    /// heartbeat-recovering subscriber is a LATE JOINER that genuinely missed
    /// them live (last_delivered = None — a faithful in-loopback model of loss).
    /// The producer's beacon (last sn = 2) fires the consumer's heartbeat sub ->
    /// a bounded `_sn=0..2` GET -> the cache refills the whole stream. Co-compiles
    /// the producer (sample-miss-detection) + consumer (advanced-recovery) atoms.
    #[cfg(all(
        feature = "ext-pubsub-sample-miss-detection",
        feature = "ext-pubsub-advanced-recovery",
        feature = "pubsub-allow-loop"
    ))]
    #[test]
    fn composed_producer_beacon_drives_late_joiner_recovery() {
        use std::sync::Mutex;

        use crate::advanced_subscriber::{AdvancedSubscriber, Miss, RecoveryConfig};
        use crate::observer::ApplicationLayerObserver;
        use crate::runtime_impl::TokioTime;
        use crate::session::TokioSession;
        use wz_session_core::locality::Locality;
        use wz_session_core::sample::Sample;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        // A real publisher with a cache deep enough to hold the whole stream
        // (the Default cache depth is 1) + miss-detection. Publish 0,1,2 BEFORE
        // the subscriber exists -> it never saw them live.
        let publisher = AdvancedPublisher::declare(
            &session,
            "demo/data",
            AdvancedPublisherOptions {
                sequencing: Sequencing::SequenceNumber,
                cache: Some(CacheConfig { max_samples: 8 }),
                publisher_detection: true,
                sample_miss_detection: MissDetectionConfig::default(),
            },
            vec![0x09],
        )
        .expect("advanced publisher declares");
        publisher.put(&[0xA0]).expect("put 0");
        publisher.put(&[0xA1]).expect("put 1");
        publisher.put(&[0xA2]).expect("put 2"); // cache {0,1,2}, seqnum = 3

        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let misses = Arc::new(Mutex::new(0usize));
        let d = Arc::clone(&delivered);
        let m = Arc::clone(&misses);
        let _sub = AdvancedSubscriber::declare_with_recovery(
            &session,
            "demo/data",
            RecoveryConfig::new()
                .with_heartbeat()
                .with_allowed_destination(Locality::SessionLocal),
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
            move |_miss: Miss| *m.lock().unwrap() += 1,
        )
        .expect("late-joiner heartbeat-recovering subscriber declares");

        // The producer's heartbeat beacon (last sn = 2) -> the consumer's
        // heartbeat sub -> bounded _sn=0..2 GET (last_delivered None) -> refill.
        assert!(publisher.emit_heartbeat_once(), "producer beacon emitted");

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0xA0, 0xA1, 0xA2],
            "the late joiner recovered the full cached stream via the producer's beacon"
        );
        assert_eq!(
            *misses.lock().unwrap(),
            0,
            "the beacon-driven recovery filled every hole -> no Miss"
        );
    }

    /// R311y87 (review C1) regression: a degenerate `max_samples == 0` cache must
    /// not hang on push. Pre-fix `while ring.len() >= 0 { pop_front }` spins
    /// forever (the empty-ring pop never reduces len) while holding the ring
    /// mutex; the `if`-evict bounds it at one. The test COMPLETING is the proof
    /// of no-hang; the retained count is the zenoh-faithful degenerate 1.
    #[test]
    fn cache_max_samples_zero_does_not_hang() {
        use std::sync::Mutex;

        use crate::observer::ApplicationLayerObserver;
        use crate::runtime_impl::TokioTime;
        use crate::session::TokioSession;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let publisher = AdvancedPublisher::declare(
            &session,
            "demo/data",
            AdvancedPublisherOptions {
                sequencing: Sequencing::SequenceNumber,
                cache: Some(CacheConfig { max_samples: 0 }),
                publisher_detection: true,
                sample_miss_detection: MissDetectionConfig::default(),
            },
            vec![0x01],
        )
        .expect("advanced publisher declares");
        for v in 0u8..3 {
            publisher
                .put(&[v])
                .expect("put into a 0-depth cache must not hang");
        }
        assert_eq!(
            publisher.cache().map(|c| c.len()),
            Some(1),
            "a 0-depth cache degenerately retains exactly one (if-evict, zenoh-faithful)"
        );
    }
}
