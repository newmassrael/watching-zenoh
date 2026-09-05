// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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

/// R311y562 — per-put value metadata for [`AdvancedPublisher::put_with`].
///
/// Deliberately just the two fields upstream lets a caller set on an advanced
/// put. `ze_advanced_publisher_put` takes the caller's whole
/// `ze_advanced_publisher_put_options_t` and then overwrites
/// `put_options.timestamp` and `put_options.source_info` with the publisher's
/// own sequencing values before publishing
/// (`vendor/zenoh-pico/src/api/advanced_publisher.c:396-407`) — so on this
/// publisher those two are not caller-settable anywhere, and modelling them
/// here would advertise a knob whose value is discarded one line later.
///
/// `#[non_exhaustive]`, matching [`AdvancedPublisherOptions`]: the QoS trio
/// (priority / congestion control / express) also rides upstream's struct and
/// is a later round's wiring, which must not break a struct literal here.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct AdvancedPutOptions {
    /// The value's encoding — the inner `MsgPut` E-flag. Rides both the wire
    /// publish and the cache entry, so a recovered sample renders identically.
    pub encoding: Option<wz_session_core::sample::EncodingHint>,
    /// An opaque attachment side-band — the inner body ext id 0x03. Put-only
    /// on the wire, so there is no delete-side counterpart.
    pub attachment: Option<Vec<u8>>,
}

impl AdvancedPutOptions {
    /// Set the value encoding.
    pub fn with_encoding(mut self, encoding: wz_session_core::sample::EncodingHint) -> Self {
        self.encoding = Some(encoding);
        self
    }
    /// Set the attachment side-band.
    pub fn with_attachment(mut self, attachment: impl Into<Vec<u8>>) -> Self {
        self.attachment = Some(attachment.into());
        self
    }
}

/// Construction options for an [`AdvancedPublisher`].
///
/// R311y93 (review S3) — `#[non_exhaustive]` for additive-field stability (the
/// sibling [`crate::advanced_subscriber::AdvancedSubscriberOptions`] and
/// [`AdvancedPublisherError`] carry it too): a future option field cannot break a
/// downstream struct-literal construction. External callers build from [`Default`]
/// plus the public fields; in-crate construction is unaffected.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
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
#[non_exhaustive]
pub enum AdvancedPublisherError {
    /// `local_zid` was empty or longer than 16 bytes (the `SourceInfo`
    /// wire constraint).
    InvalidZid,
    /// The cache queryable declaration was rejected.
    Cache(QueryableError),
    /// The `@adv` liveliness token declaration was rejected.
    Token(LivelinessAliasError),
    /// R311y90 (review C5) — the heartbeat beacon task could not be spawned: no
    /// tokio runtime was active. An [`AdvancedPublisher`] with a
    /// `sample_miss_detection` heartbeat spawns a background beacon task, so it
    /// must be declared from within a tokio runtime context. Fail-clear instead
    /// of the `tokio::spawn` panic.
    #[cfg(feature = "ext-pubsub-sample-miss-detection")]
    NoRuntime,
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

        // R311y90 (review C5) — fail fast & clear if off-runtime: the heartbeat
        // beacon (below) is a tokio::spawn task, which PANICS without a runtime.
        // Check the spawn precondition BEFORE declaring the cache / token so no
        // half-declared publisher needs rollback. `heartbeat_spawn_params` is the
        // SSOT for "will spawn the beacon" — the spawn arm below gates on the same.
        #[cfg(feature = "ext-pubsub-sample-miss-detection")]
        if heartbeat_spawn_params(&options).is_some() {
            tokio::runtime::Handle::try_current().map_err(|_| AdvancedPublisherError::NoRuntime)?;
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
        // marks sequence-number sequencing; `uhlc` marks timestamp/none. The
        // KE shape is the shared `@adv` SSOT ([`crate::advanced_ke`]).
        let discriminator = match options.sequencing {
            Sequencing::SequenceNumber => eid.to_string(),
            Sequencing::Timestamp | Sequencing::None => "uhlc".to_string(),
        };
        let adv_keyexpr = crate::advanced_ke::publisher_adv_ke(
            &keyexpr,
            &zid_to_zenoh_hex(&local_zid),
            &discriminator,
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
        let heartbeat_task = heartbeat_spawn_params(&options)
            // `zip(seqnum.as_ref())`: `heartbeat_spawn_params` already requires
            // `SequenceNumber`, so `seqnum` is `Some` whenever it returns `Some` —
            // the zip never drops a configured beacon, it just pairs the params with
            // the counter without an unwrap.
            .zip(seqnum.as_ref())
            .map(|((period, sporadic), seqnum)| {
                let hb_session = session.clone();
                let hb_keyexpr = adv_keyexpr.clone();
                let hb_seqnum = Arc::clone(seqnum);
                let clock = Arc::clone(session.clock());
                // R311y87 (review C4) — clamp to >=1ms: a sub-ms Duration
                // truncates to 0, turning the beacon loop into a busy spin.
                let period_ms = (period.as_millis() as u64).max(1);
                HeartbeatTask {
                    // The NET subsystem, which is where upstream puts this exact
                    // beacon: both arms of zenoh's advanced-publisher heartbeat
                    // are `TerminatableTask::spawn_abortable(ZRuntime::Net, ..)`
                    // (`zenoh-ext/src/advanced_publisher.rs`
                    // @ `TerminatableTask::spawn_abortable(`, both the
                    // sporadic-off and sporadic-on arm). A beacon is upkeep the application
                    // never waits on, so it belongs beside gossip rather than
                    // beside the API surface.
                    handle: crate::runtime_pool::WzRuntime::Net.spawn(async move {
                        let mut last_emitted = 0u32;
                        loop {
                            clock.sleep(period_ms).await;
                            let sn = hb_seqnum.load(Ordering::Relaxed);
                            // Non-sporadic emits every tick (emit_heartbeat skips
                            // sn==0); sporadic only when the sn advanced.
                            if should_emit_heartbeat(sporadic, sn, last_emitted)
                                && emit_heartbeat(&hb_session, &hb_keyexpr, sn)
                            {
                                last_emitted = sn;
                            }
                        }
                    }),
                }
            });

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
            // R311y450 — the §5.18 clock is BORROWED from the session (an Arc
            // bump), not constructed here. Building one from `local_zid` is what
            // made this site and `storage_service`'s the two same-`uhlc::ID`
            // clocks the round removed.
            stamp: FallbackStamp::new(local_zid, session.node_hlc().clone()),
            cache,
            _token: token,
            #[cfg(feature = "ext-pubsub-sample-miss-detection")]
            adv_keyexpr,
            #[cfg(feature = "ext-pubsub-sample-miss-detection")]
            _heartbeat_task: heartbeat_task,
        })
    }

    /// Publish `payload` with no value metadata — [`Self::put_with`] under
    /// [`AdvancedPutOptions::default`]. Returns the [`Session::publish`] byte
    /// count.
    pub fn put(&self, payload: &[u8]) -> Result<usize, PublishError> {
        self.put_with(payload, AdvancedPutOptions::default())
    }

    /// R311y562 — publish `payload` carrying a value `encoding` and/or an
    /// opaque `attachment`, stamping the next `SourceInfo` sequence number
    /// (in `SequenceNumber` mode) + a timestamp, and retaining the sample —
    /// metadata included — in the cache.
    ///
    /// These are exactly the two fields upstream's advanced put lets a caller
    /// set. `ze_advanced_publisher_put` copies the caller's options and then
    /// OVERWRITES `put_options.timestamp` and `put_options.source_info` with
    /// the publisher's own sequencing values
    /// (`vendor/zenoh-pico/src/api/advanced_publisher.c:402-407`), so those two
    /// are the publisher's to own and are deliberately NOT parameters here —
    /// letting a caller supply an `sn` would break the miss-detection contract
    /// the shared counter exists to hold. Encoding and attachment pass straight
    /// through to `_z_publisher_put_impl`, which is handed `pub->_cache`, so
    /// upstream's cache retains them with the sample.
    pub fn put_with(
        &self,
        payload: &[u8],
        options: AdvancedPutOptions,
    ) -> Result<usize, PublishError> {
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
        // The SSOT discipline the source_info already followed, extended to the
        // value metadata: the SAME encoding / attachment ride the wire publish
        // AND the cache entry, so a recovered sample cannot render differently
        // from the live one it replaces.
        //
        // Each fold sits behind the gate of the SETTER it calls —
        // `PublishOptions::with_encoding` is `pubsub-encoding` and
        // `with_attachment` is `pubsub-attachment`, and
        // `ext-pubsub-advanced-publisher` composes NEITHER (it pulls
        // `pubsub-put` / `-source-info` / `-timestamp` only). An ungated call
        // therefore compiled under this crate's default features and broke the
        // `wz` facade's `--features ext-pubsub-advanced-publisher` build, which
        // is the narrow set Layer C1aq builds. The ring below stays ungated on
        // purpose: it retains what it was given regardless, and the wire
        // emission is the codec's decision — the same split
        // `advanced_cache`'s source_info already follows.
        #[cfg(feature = "pubsub-encoding")]
        if let Some(enc) = &options.encoding {
            opts = opts.with_encoding(enc.clone());
        }
        #[cfg(feature = "pubsub-attachment")]
        if let Some(att) = &options.attachment {
            opts = opts.with_attachment(att.clone());
        }
        let written = self.session.publish(&self.keyexpr, payload, opts)?;

        if let Some(cache) = &self.cache {
            cache.cache_sample(
                CachedSample::new(
                    self.keyexpr.clone(),
                    payload.to_vec(),
                    source_info,
                    timestamp,
                    crate::sample::SampleKind::Put,
                )
                .with_encoding(options.encoding)
                .with_attachment(options.attachment),
            );
        }
        Ok(written)
    }

    /// Publish a DELETE on this publisher's keyexpr, stamping the same
    /// `(zid, eid, sn)` + timestamp a [`Self::put`] would (R311y559).
    ///
    /// The sequence number is drawn from the SAME counter as `put`, which is
    /// what keeps a subscriber's miss detection correct across a mixed stream:
    /// a Del that skipped the counter would leave a permanent apparent gap.
    ///
    /// R311y561 — the Del IS cached now, closing the divergence R311y559
    /// shipped. [`CachedSample`] carries the sample KIND, so the ring retains
    /// the retraction and [`crate::advanced_cache::answer_from_ring`] replays it
    /// on the Del arm ([`wz_session_core::query_sink::ReplyOut::reply_keyed_del_sourced`]).
    /// The old behaviour — skip the cache — was the right call only while a
    /// cached Del would have come back as a Put and resurrected the deleted key
    /// on a recovering subscriber; with the kind stored that failure mode is
    /// gone, and a recovering subscriber now sees the retraction it missed.
    pub fn delete(&self) -> Result<usize, PublishError> {
        let sn = self
            .seqnum
            .as_ref()
            .map(|counter| counter.fetch_add(1, Ordering::Relaxed));
        let timestamp = self.stamp.stamp();
        let source_info = sn.map(|sn| SourceInfo::new(&self.zid, self.eid, sn));

        let mut opts = PublishOptions::put()
            .with_kind(crate::sample::SampleKind::Del)
            .with_timestamp(timestamp.clone());
        if let Some(si) = &source_info {
            opts = opts.with_source_info(si.clone());
        }
        let written = self.session.publish(&self.keyexpr, &[], opts)?;

        if let Some(cache) = &self.cache {
            // No `with_encoding` / `with_attachment` chain: a Del body carries
            // neither ext on the wire (`has_attachment` is `_is_put && ..`, and
            // the encoding is read only in the `_is_put` branch —
            // `message.c:263,269-276`), and upstream's
            // `ze_advanced_publisher_delete_options_t` has no slot for either.
            // The absence is structural, not an omission.
            cache.cache_sample(CachedSample::new(
                self.keyexpr.clone(),
                Vec::new(),
                source_info,
                timestamp,
                crate::sample::SampleKind::Del,
            ));
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

/// R311y96 (review-arbiter LOW) — the heartbeat-beacon SPAWN decision SSOT:
/// `Some((period, sporadic))` iff a `state_publisher` is configured AND sequencing
/// is `SequenceNumber` (so a seqnum counter for the beacon exists). Both the
/// off-runtime fail-fast guard (`.is_some()`) and the actual spawn
/// (`.zip(seqnum).map(...)`) gate on this ONE predicate, so the precondition cannot
/// drift between the guard and the spawn arm (previously hand-mirrored twice).
#[cfg(feature = "ext-pubsub-sample-miss-detection")]
fn heartbeat_spawn_params(options: &AdvancedPublisherOptions) -> Option<(Duration, bool)> {
    match (
        options.sample_miss_detection.state_publisher,
        options.sequencing,
    ) {
        (Some(period_sporadic), Sequencing::SequenceNumber) => Some(period_sporadic),
        _ => None,
    }
}

/// R311y93 (review V1) — the sporadic-heartbeat emit gate, a pure deterministic
/// seam so the spawn loop's decision is unit-testable (previously the
/// `!sporadic || sn > last_emitted` check was only compiled inside the background
/// task, never asserted). A non-sporadic beacon emits every tick (always `true`);
/// a sporadic beacon emits only when the put-count `sn` ADVANCED past
/// `last_emitted` (zenoh `sporadic_heartbeat`, advanced_publisher.rs:385-419).
/// The `sn == 0` "nothing published" case is filtered separately by
/// [`emit_heartbeat`].
#[cfg(feature = "ext-pubsub-sample-miss-detection")]
fn should_emit_heartbeat(sporadic: bool, sn: u32, last_emitted: u32) -> bool {
    !sporadic || sn > last_emitted
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

    /// R311y833 — the options an `@adv` recovery GET must carry, and the reason
    /// these three tests share one constructor rather than spelling
    /// `QueryOptions::get()` inline.
    ///
    /// The GET is asked under `<ke>/@adv/**` and the cache answers under the
    /// CACHED SAMPLE'S OWN key (`demo/data`), which does not intersect it. That
    /// is precisely the case `_anyke` exists for, and production already carries
    /// it unconditionally — `advanced_subscriber::history_selector` returns the
    /// bare `"_anyke"` even with no other knobs (R311y442). These tests
    /// hand-rolled the GET without it, so before y833 they asserted a delivery
    /// that neither zenoh (`zenoh/src/api/session.rs:2847`) nor zenoh-pico
    /// (`vendor/zenoh-pico/src/session/query.c:121`) performs. The acceptance
    /// gate made that visible; the tests were what was wrong, not the cache.
    ///
    /// Written as the `parameters` field rather than through
    /// `QueryOptions::with_accept_replies` deliberately: that setter is
    /// `query-selector-parameters`-gated, and adding that gate to these tests
    /// would change WHICH LANES RUN THEM for a reason orthogonal to what they
    /// prove. The value itself comes from the same
    /// [`wz_session_core::selector_params::anyke_params`] SSOT the production
    /// selector is built from, so the two cannot drift.
    ///
    /// R311y836 — the SAME class again, one axis over, and the same remedy.
    /// These three tests ask the cache for a RING and assert they get all of it;
    /// they named no consolidation mode, and y836 made the unnamed mode resolve
    /// to LATEST (`zenoh/src/api/session.rs:2250`), which collapses a ring to one
    /// sample per keyexpr. MEASURED: all three went red together, e.g.
    /// `left: [("demo/data", [2])]` against `right: [("demo/data", [0]),
    /// ("demo/data", [1]), ("demo/data", [2])]`. Once more the TEST was what
    /// diverged from production, not the cache — the real advanced subscriber
    /// pins `None` on every one of its recovery / history GETs, as zenoh-ext
    /// (`zenoh-ext/src/advanced_subscriber.rs` @ `global_pending_queries`, at every
    /// site that issues one) and
    /// zenoh-pico (`vendor/zenoh-pico/src/api/advanced_subscriber.c:915`) do.
    /// Set as the FIELD for the same lane-preserving reason as `parameters`
    /// above; with `query-consolidation` off the field is inert, because
    /// `effective_consolidation` hard-returns `None` there.
    #[cfg(feature = "query-get")]
    fn adv_recovery_get_options() -> crate::session::QueryOptions {
        use crate::session::QueryOptions;
        use wz_session_core::locality::Locality;

        QueryOptions {
            parameters: Some(wz_session_core::selector_params::anyke_params(&[]).into_bytes()),
            consolidation: Some(wz_session_core::query_mode::ConsolidationMode::None),
            ..QueryOptions::get().with_allowed_destination(Locality::SessionLocal)
        }
    }

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
        use crate::session::TokioSession;

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

        // The loopback GET goes over `demo/data/@adv/**`, which is exactly what
        // `advanced_ke::history_get_ke` builds and what a real advanced
        // SUBSCRIBER puts on the wire.
        //
        // R311y543 — it used to be `demo/data/**`, and that stopped covering the
        // cache queryable when the @verbatim rule landed. The change is the rule
        // working rather than a regression: `@adv` is zenoh's ADMIN namespace and
        // a `**` does not reach into it (`zenoh-keyexpr` classical.rs:65-72), so
        // upstream's own `demo/data/**` would not have found this cache either.
        // A user GET reaching a router's internal namespace was the same defect
        // this round found on the SUBSCRIBE side, measured against the real
        // `libzenohc.so`.
        let replies = Arc::new(Mutex::new(Vec::<(String, Vec<u8>)>::new()));
        let rec = Arc::clone(&replies);
        session
            .query(
                "demo/data/@adv/**",
                adv_recovery_get_options(),
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

    /// R311y561 — `delete()` RETAINS the retraction in the cache, and a loopback
    /// recovery GET gets it back as a **Del** reply carrying its own sn.
    ///
    /// R311y559 shipped `delete()` deliberately skipping the cache, because a
    /// ring with no sample kind could only have replayed the Del as a Put —
    /// resurrecting the deleted key on any recovering subscriber. `CachedSample`
    /// carries the kind now, so the reason is gone and the retraction is
    /// retained like any other sample.
    ///
    /// Two things are asserted that a payload-only check would miss. The reply
    /// KIND, because a Del and an empty Put have the same (empty) payload and
    /// only the kind tells a subscriber whether the key still holds a value. And
    /// the ring DEPTH plus the recovered sn set, because the delete draws from
    /// the same sequence counter as `put` — a Del that skipped the counter, or
    /// one dropped from the ring, leaves a permanent apparent gap that a
    /// gap-detecting subscriber re-asks for forever.
    #[cfg(feature = "query-get")]
    #[test]
    fn deleted_sample_is_cached_and_recovers_as_a_del_reply() {
        use std::sync::Mutex;

        use crate::observer::ApplicationLayerObserver;
        use crate::reply_sink::{ReplyKind, ReplyView};
        use crate::runtime_impl::TokioTime;
        use crate::session::TokioSession;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let options = AdvancedPublisherOptions {
            sequencing: Sequencing::SequenceNumber,
            cache: Some(CacheConfig { max_samples: 8 }),
            publisher_detection: true,
            sample_miss_detection: MissDetectionConfig::default(),
        };
        let publisher = AdvancedPublisher::declare(&session, "demo/data", options, vec![0x01])
            .expect("advanced publisher declares against the test link");

        // put(sn 0), put(sn 1), delete(sn 2), put(sn 3) — one mixed stream.
        publisher.put(&[0]).expect("advanced put");
        publisher.put(&[1]).expect("advanced put");
        publisher.delete().expect("advanced delete");
        publisher.put(&[3]).expect("advanced put");

        assert_eq!(
            publisher.cache().map(|c| c.len()),
            Some(4),
            "the DELETE is retained alongside the three puts (3 before y561)"
        );

        /// One recorded reply: its kind, its concrete key, its payload, and the
        /// `sn` off its source_info (`None` when the build emits no
        /// `reply-source-info` — see the assertions below).
        type RecordedReply = (ReplyKind, String, Vec<u8>, Option<u32>);

        let replies: Arc<Mutex<Vec<RecordedReply>>> = Arc::new(Mutex::new(Vec::new()));
        let rec = Arc::clone(&replies);
        session
            .query(
                "demo/data/@adv/**",
                adv_recovery_get_options(),
                move |reply: &dyn ReplyView| {
                    rec.lock().expect("reply recorder poisoned").push((
                        reply.kind(),
                        reply.keyexpr().to_string(),
                        reply.payload().to_vec(),
                        reply.source_info().map(|si| si.sn),
                    ));
                },
                |_rid| {},
            )
            .expect("loopback query fires the cache queryable inline");

        let got = replies.lock().expect("reply recorder poisoned").clone();
        // The cache replies oldest-first, so ring order IS reply order and no
        // sort is needed — which also keeps this arm meaningful on a build that
        // emits no source_info to sort by.
        let shapes: Vec<(ReplyKind, String, Vec<u8>)> = got
            .iter()
            .map(|(k, ke, p, _)| (*k, ke.clone(), p.clone()))
            .collect();
        assert_eq!(
            shapes,
            vec![
                (ReplyKind::Put, "demo/data".to_string(), vec![0]),
                (ReplyKind::Put, "demo/data".to_string(), vec![1]),
                (ReplyKind::Del, "demo/data".to_string(), Vec::new()),
                (ReplyKind::Put, "demo/data".to_string(), vec![3]),
            ],
            "the delete comes back as a Del reply under its own key, in ring \
             order between the puts around it"
        );

        // The sn sequence needs the source_info ext on the wire, which the codec
        // gates `reply-source-info` — composed by `ext-pubsub-advanced-recovery`
        // (Cargo.toml), NOT by advanced-cache alone. Without it the recovery
        // reply is deliberately source_info-free (pico-faithful), so asserting
        // the sequence unconditionally would fail a lane that is behaving
        // correctly. This is the arm that pins the DELETE occupying sn 2: a Del
        // that skipped the shared counter would leave a permanent apparent gap.
        #[cfg(feature = "ext-pubsub-advanced-recovery")]
        {
            let sns: Vec<Option<u32>> = got.iter().map(|(_, _, _, sn)| *sn).collect();
            assert_eq!(
                sns,
                vec![Some(0), Some(1), Some(2), Some(3)],
                "an unbroken 0..=3 sequence with the DELETE at sn 2 — the delete \
                 draws from the same counter as put"
            );
        }
    }

    /// R311y562 — a sample published with an ENCODING and an ATTACHMENT comes
    /// back through the recovery path carrying both.
    ///
    /// This is the end-to-end arm of the y561 residual, and it is deliberately
    /// driven through the whole chain — `put_with` -> `PublishOptions` ->
    /// `CachedSample` -> `answer_from_ring` -> the reply -> `ReplyView` — rather
    /// than asserted on the ring, because the ring was never the only place the
    /// two fields could be lost: before this round `answer_from_ring` had no
    /// attachment slot to pass them through even if the ring had held them.
    /// A unit test on `CachedSample` would have been green with the wire half
    /// still broken.
    ///
    /// The negative arm (sn 1, published by plain `put`) is what makes the
    /// positive one a claim: it pins that the accessors report absence as
    /// `None` rather than defaulting, so `Some(..)` on sn 0 cannot be an
    /// artifact of the reader.
    #[cfg(all(feature = "query-get", feature = "pubsub-encoding"))]
    #[test]
    fn published_encoding_and_attachment_survive_recovery() {
        use std::sync::Mutex;

        use crate::observer::ApplicationLayerObserver;
        use crate::reply_sink::ReplyView;
        use crate::runtime_impl::TokioTime;
        use crate::session::TokioSession;
        use wz_session_core::sample::EncodingHint;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let options = AdvancedPublisherOptions {
            sequencing: Sequencing::SequenceNumber,
            cache: Some(CacheConfig { max_samples: 8 }),
            publisher_detection: true,
            sample_miss_detection: MissDetectionConfig::default(),
        };
        let publisher = AdvancedPublisher::declare(&session, "demo/data", options, vec![0x01])
            .expect("advanced publisher declares against the test link");

        // sn 0 carries both metadata fields; sn 1 carries neither.
        publisher
            .put_with(
                &[0xAA],
                AdvancedPutOptions::default()
                    .with_encoding(EncodingHint {
                        packed_id: 0x0B,
                        schema: None,
                    })
                    .with_attachment(b"side-band".to_vec()),
            )
            .expect("advanced put with metadata");
        publisher.put(&[0xBB]).expect("advanced put");

        /// One recorded reply: `(payload, encoding packed_id, attachment)`.
        type RecordedMeta = (Vec<u8>, Option<u32>, Option<Vec<u8>>);

        let replies: Arc<Mutex<Vec<RecordedMeta>>> = Arc::new(Mutex::new(Vec::new()));
        let rec = Arc::clone(&replies);
        session
            .query(
                "demo/data/@adv/**",
                adv_recovery_get_options(),
                move |reply: &dyn ReplyView| {
                    rec.lock().expect("reply recorder poisoned").push((
                        reply.payload().to_vec(),
                        reply.put_encoding().map(|(id, _schema)| id),
                        reply.attachment().map(<[u8]>::to_vec),
                    ));
                },
                |_rid| {},
            )
            .expect("loopback query fires the cache queryable inline");

        let got = replies.lock().expect("reply recorder poisoned").clone();
        assert_eq!(
            got[0],
            (vec![0xAA], Some(0x0B), Some(b"side-band".to_vec())),
            "the recovered sample carries the encoding and the attachment it \
             was published with",
        );
        assert_eq!(
            got[1],
            (vec![0xBB], None, None),
            "a sample published without either reports both absent — the \
             accessors do not manufacture a default",
        );
    }

    /// R311y562 — the LIVE half of [`AdvancedPublisher::put_with`]: the
    /// encoding and attachment reach a subscriber on the ordinary publish path,
    /// not only the recovery one.
    ///
    /// This test exists because a damage probe said it had to. Deleting the
    /// wire-side fold in `put_with` — the two `opts.with_encoding` /
    /// `with_attachment` lines — left
    /// `published_encoding_and_attachment_survive_recovery` GREEN, because that
    /// test reads the reply the CACHE answers and the cache is populated from
    /// the options directly. Two folds, one witness: the live half was
    /// unpinned, and a future edit could have deleted it silently. Now each
    /// fold has a test that reds when it goes.
    #[cfg(all(feature = "declare-subscriber", feature = "pubsub-allow-loop"))]
    #[test]
    fn put_with_metadata_reaches_a_live_subscriber() {
        use std::sync::Mutex;

        use crate::observer::ApplicationLayerObserver;
        use crate::runtime_impl::TokioTime;
        use crate::session::{SubscribeOptions, TokioSession};
        use wz_session_core::sample::EncodingHint;
        use wz_session_core::sink::SampleView;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        /// One live sample: `(payload, encoding packed_id, attachment)`.
        type LiveSample = (Vec<u8>, Option<u32>, Option<Vec<u8>>);

        let seen: Arc<Mutex<Vec<LiveSample>>> = Arc::new(Mutex::new(Vec::new()));
        let s = Arc::clone(&seen);
        let _rec = session
            .declare_subscriber(
                "demo/data",
                SubscribeOptions::default(),
                move |v: &dyn SampleView| {
                    s.lock().expect("live recorder poisoned").push((
                        v.payload().to_vec(),
                        v.encoding().map(|e| e.packed_id),
                        v.attachment().map(<[u8]>::to_vec),
                    ));
                },
            )
            .expect("live recorder subscribes");

        let publisher = AdvancedPublisher::declare(
            &session,
            "demo/data",
            AdvancedPublisherOptions::default(),
            vec![0x09],
        )
        .expect("advanced publisher declares");

        publisher
            .put_with(
                &[0xAA],
                AdvancedPutOptions::default()
                    .with_encoding(EncodingHint {
                        packed_id: 0x0B,
                        schema: None,
                    })
                    .with_attachment(b"side-band".to_vec()),
            )
            .expect("advanced put with metadata");
        publisher.put(&[0xBB]).expect("advanced put");

        let got = seen.lock().expect("live recorder poisoned").clone();
        assert_eq!(
            got,
            vec![
                (vec![0xAA], Some(0x0B), Some(b"side-band".to_vec())),
                (vec![0xBB], None, None),
            ],
            "the live sample carries the metadata put_with was given, and a \
             plain put carries neither",
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

        use crate::advanced_subscriber::{
            AdvancedSubscriber, AdvancedSubscriberOptions, Miss, RecoveryConfig,
        };
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
        let _sub = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_recovery(RecoveryConfig::new().with_heartbeat())
                .with_get_locality(Locality::SessionLocal),
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

    /// R311y90 (review C5) regression: declaring an advanced publisher with a
    /// heartbeat beacon OFF a tokio runtime must FAIL CLEAR with NoRuntime, not
    /// panic inside tokio::spawn. This `#[test]` runs outside any runtime, so
    /// Handle::try_current() returns Err -> the declare returns NoRuntime before
    /// any cache / token is declared. Pre-fix the beacon spawn panicked (aborting
    /// the test); the guard makes it a clean Result.
    #[cfg(feature = "ext-pubsub-sample-miss-detection")]
    #[test]
    fn declare_with_heartbeat_off_runtime_fails_clear_not_panic() {
        use std::sync::Mutex;
        use std::time::Duration;

        use crate::observer::ApplicationLayerObserver;
        use crate::runtime_impl::TokioTime;
        use crate::session::TokioSession;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let result = AdvancedPublisher::declare(
            &session,
            "demo/data",
            AdvancedPublisherOptions {
                sequencing: Sequencing::SequenceNumber,
                cache: None,
                publisher_detection: false,
                sample_miss_detection: MissDetectionConfig::default()
                    .heartbeat(Duration::from_millis(100)),
            },
            vec![0x09],
        );
        assert!(
            matches!(result, Err(AdvancedPublisherError::NoRuntime)),
            "heartbeat beacon off-runtime must fail clear with NoRuntime, not panic"
        );
    }

    /// R311y93 (review V1) — the sporadic-heartbeat emit gate. Non-sporadic emits
    /// every tick regardless of sn movement; sporadic emits only when the put-count
    /// advanced past `last_emitted`, so a stalled publisher (sn unchanged) stops
    /// re-beaconing. Previously this decision was only compiled inside the spawn
    /// loop, never asserted.
    #[cfg(feature = "ext-pubsub-sample-miss-detection")]
    #[test]
    fn should_emit_heartbeat_gates_sporadic_on_advance() {
        // Non-sporadic: always emit (every period), even at an unchanged sn.
        assert!(should_emit_heartbeat(false, 0, 0));
        assert!(should_emit_heartbeat(false, 5, 5));
        assert!(should_emit_heartbeat(false, 3, 7));
        // Sporadic: emit only when sn advanced past last_emitted.
        assert!(should_emit_heartbeat(true, 5, 3), "advanced -> emit");
        assert!(!should_emit_heartbeat(true, 3, 3), "unchanged -> skip");
        assert!(!should_emit_heartbeat(true, 2, 3), "behind -> skip");
        assert!(
            !should_emit_heartbeat(true, 0, 0),
            "nothing published -> skip"
        );
    }
}
