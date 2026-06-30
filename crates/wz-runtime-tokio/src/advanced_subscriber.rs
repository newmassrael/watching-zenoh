// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y70 — `ext-pubsub-advanced-subscriber` (§5.25): the per-source
//! ordering / de-duplication subscriber that consumes the `SourceInfo`
//! sequence numbers an [`crate::advanced_publisher::AdvancedPublisher`]
//! stamps. R311y82 adds the gap-recovery half (`ext-pubsub-advanced-recovery`).
//!
//! The wz mirror of zenoh-ext `advanced_subscriber.rs`'s `handle_sample`
//! state machine (advanced_subscriber.rs:476-566). It wraps a plain
//! subscriber and tracks, per source, the last in-order delivered marker:
//!
//! - **Sequenced** (the sample carries `SourceInfo(zid, eid, sn)`): keyed
//!   by `(zid, eid)`. `sn == last + 1` delivers in order; `sn <= last` is a
//!   duplicate / out-of-order-late sample and is DROPPED. A forward GAP
//!   (`sn > last + 1`) is handled per the recovery mode (below).
//! - **No sequenced source-id**: delivered immediately, no de-duplication.
//!
//! The TIMESTAMPED de-duplication path (a `Sequencing::Timestamp`
//! publisher's samples, keyed by the timestamp id) is DEFERRED to the
//! round that composes + tests a Timestamp-mode publisher. Its ordering
//! primitive — `wz_session_core::sample::timestamp_strictly_newer` — is now
//! a shared SSOT (R311y73 lifted it out of the storage-backend-gated
//! `storage_state` so this ext-pubsub atom can consume it WITHOUT pulling
//! storage), so the path is unblocked: when built it imports that fn. This
//! round builds the SEQUENCED path the `SequenceNumber` publisher (the
//! R311y69 default) produces.
//!
//! ## Forward-gap handling: `Miss` vs recovery (R311y82)
//!
//! What happens on a forward gap is set at declare time:
//!
//! - **Plain** ([`AdvancedSubscriber::declare`], the always-present form):
//!   the gap fires a [`Miss`] callback (`nb = sn - last - 1`), then delivers
//!   the just-received sample and advances past the hole (zenoh
//!   advanced_subscriber.rs:521-535 no-retransmission path). Lost samples are
//!   reported, never recovered.
//! - **Recovering** ([`AdvancedSubscriber::declare_with_options`], gated
//!   `ext-pubsub-advanced-recovery`): the gap is BUFFERED into a per-source
//!   sn-ordered reorder buffer ([`SourceState::pending_samples`]) instead of
//!   delivered, and a sample-driven `_sn=last+1..` recovery GET is issued to
//!   the publisher's `@adv` cache. The recovered (retransmitted) replies —
//!   each carrying the original `(zid, eid, sn)` on its inner-body source_info
//!   ext (the R311y74-y81 `reply-source-info` seam) — are re-keyed back into
//!   the per-source stream and the buffer drains in order as the holes fill;
//!   a hole the recovery does NOT fill surfaces a [`Miss`] at flush. This is
//!   the wz mirror of zenoh's `retransmission` path (advanced_subscriber.rs:
//!   517-540) + the sub_callback recovery get (:704-748) +
//!   `flush_sequenced_source` (:1266-1306).
//!
//! Issuing the GET re-enters `Session::query` from inside the subscriber
//! callback; this is safe because the wz subscriber callback runs at a
//! deferred-fire drain site OUTSIDE the observer lock (R311lh), so the
//! re-entrant query (and the loopback cache replies it drains) cannot
//! self-deadlock.
//!
//! ### Recovery triggers (all three built)
//!
//! zenoh drives recovery from THREE triggers, all mirrored here:
//! - **sample-driven** (R311y82) — the forward-gap handling above issues an
//!   open `_sn=last+1..` GET when a live gap leaves the buffer non-empty.
//! - **periodic** (R311y83, [`RecoveryConfig::periodic_queries`]) — a
//!   background task re-asks every source `_sn=last+1..` every period, catching
//!   a lost LAST sample no later live sample would trigger recovery for (zenoh
//!   advanced_subscriber.rs:585-643).
//! - **heartbeat** (R311y84, [`RecoveryConfig::heartbeat`]) — a second
//!   subscriber on `<key_expr>/@adv/pub/**` decodes each publisher's last-sn
//!   beacon (`z_deserialize::<u32>`) and issues a BOUNDED `_sn=last+1..hb` GET
//!   when the beacon is ahead of `last_delivered` (zenoh :1045-1149). The
//!   producer beacon is the separate `ext-pubsub-sample-miss-detection` atom.
//!
//! A recovered reply cannot carry its original body timestamp (the
//! [`crate::reply_sink::ReplyView`] seam surfaces source_info / encoding /
//! attachment, not the reply timestamp), so a retransmitted sample is delivered
//! timestamp-less — a documented fidelity gap, not silent (the recovery
//! essential is the source identity that re-keys it).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;
use wz_session_core::sample::Sample;
use wz_session_core::sink::SampleView;

use crate::session::{Session, SubscribeError, SubscribeOptions, Subscriber, Unicast};
use crate::session_glue::SessionLinkActions;

#[cfg(feature = "ext-pubsub-advanced-recovery")]
use std::collections::BTreeMap;
#[cfg(feature = "ext-pubsub-advanced-recovery")]
use std::time::Duration;
#[cfg(feature = "ext-pubsub-advanced-recovery")]
use wz_session_core::locality::Locality;
#[cfg(feature = "ext-pubsub-advanced-recovery")]
use wz_session_core::reply_sink::{ReplyKind, ReplyView};
#[cfg(feature = "ext-pubsub-advanced-recovery")]
use wz_session_core::sample::EncodingHint;
#[cfg(feature = "ext-pubsub-advanced-recovery")]
use wz_session_core::sample_kind::SampleKind;
#[cfg(feature = "ext-pubsub-advanced-recovery")]
use wz_session_core::serde_codec::z_deserialize;
#[cfg(feature = "ext-pubsub-advanced-recovery")]
use wz_session_core::zid_hex::{zenoh_hex_to_zid, zid_to_zenoh_hex};

#[cfg(feature = "ext-pubsub-advanced-recovery")]
use crate::session::QueryOptions;

/// A detected gap in a sequenced source's stream: `nb` samples between the
/// last in-order delivery and the just-received `sn` were missed. Mirror
/// of zenoh-ext `Miss` (advanced_subscriber.rs:1409-1427); `source` is
/// split into the `(zid, eid)` the wz `SourceInfo` carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Miss {
    /// The missing source's zenoh id (the meaningful `zid_prefix` bytes).
    pub source_zid: Vec<u8>,
    /// The missing source's entity id.
    pub source_eid: u32,
    /// How many samples were skipped (`sn - last_delivered - 1`).
    pub nb: u32,
}

/// Per-source ordering state. Tracks the last in-order delivered sequence
/// number; the recovery build adds the reorder buffer ([`Self::pending_samples`],
/// sn-ordered) + the in-flight recovery-GET count ([`Self::pending_queries`])
/// — the wz mirror of zenoh-ext `SourceState<u32>` (advanced_subscriber.rs:
/// 444-448).
#[derive(Default)]
struct SourceState {
    /// Last in-order delivered sequence number (`None` before the first
    /// sample from this source).
    last_delivered: Option<u32>,
    /// Recovery reorder buffer: forward-gap samples held sn-ordered until a
    /// `_sn`-range recovery GET back-fills the hole, then drained in order.
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    pending_samples: BTreeMap<u32, Sample>,
    /// In-flight recovery GETs for this source (zenoh `pending_queries`): a
    /// new GET is only issued when this is 0, and the buffer is flushed when
    /// it returns to 0.
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    pending_queries: u64,
}

/// R311y90 (review C5) — why declaring a RECOVERING advanced subscriber failed.
/// Distinct from the base [`SubscribeError`] (which stays the plain
/// `Session::declare_subscriber` surface): the recovery form additionally spawns
/// the periodic-recovery background task, so it has one extra failure mode
/// ([`Self::NoRuntime`]). Kept OUT of `SubscribeError` so toggling the additive
/// `ext-pubsub-advanced-recovery` feature cannot change `SubscribeError`'s shape
/// and break a base-subscriber caller's exhaustive match (the H1
/// signature-stability invariant); mirrors the publisher's dedicated
/// [`crate::advanced_publisher::AdvancedPublisherError`].
#[cfg(feature = "ext-pubsub-advanced-recovery")]
#[derive(Debug)]
#[non_exhaustive]
pub enum AdvancedSubscribeError {
    /// The base / recovery / heartbeat subscriber declaration was rejected.
    Subscribe(SubscribeError),
    /// The periodic-recovery task could not be spawned: no tokio runtime was
    /// active. `declare_with_options` with `periodic_queries` set must be called
    /// from within a tokio runtime context. Fail-clear instead of the
    /// `tokio::spawn` panic.
    NoRuntime,
}

#[cfg(feature = "ext-pubsub-advanced-recovery")]
impl From<SubscribeError> for AdvancedSubscribeError {
    fn from(e: SubscribeError) -> Self {
        AdvancedSubscribeError::Subscribe(e)
    }
}

/// Retransmission (gap-recovery) configuration
/// ([`AdvancedSubscriberOptions::with_recovery`]). Mirror of zenoh-ext
/// `RecoveryConfig` (advanced_subscriber.rs:91-134): it carries ONLY the
/// retransmission triggers. The sample-driven `_sn`-range recovery GET is implied
/// by recovering at all (`RecoveryConfig::default()`); [`Self::periodic_queries`] +
/// [`Self::heartbeat`] add the periodic / beacon triggers. The GET locality + GET
/// timeout + the (independent) startup history live on [`AdvancedSubscriberOptions`],
/// NOT here — zenoh keeps `.recovery()` and `.history()` SEPARATE so
/// history-without-retransmission is representable (R311y91, review M1).
#[cfg(feature = "ext-pubsub-advanced-recovery")]
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct RecoveryConfig {
    /// R311y83 — when `Some(period)`, a background task re-asks every known
    /// source `_sn=last+1..` every `period`, catching a lost LAST sample that
    /// no further live sample would trigger sample-driven recovery for (zenoh's
    /// `RecoveryConfig::periodic_queries`, advanced_subscriber.rs:111-116 + the
    /// `PeriodicQuery` TimedEvent :580-643). `None` (default) = sample-driven
    /// recovery only. NB enabling this spawns a tokio task at declare time, so
    /// the caller MUST be inside a tokio runtime context (the sample-driven and
    /// no-recovery paths have no such requirement).
    pub periodic_queries: Option<Duration>,
    /// R311y84 — when `true`, declare a second subscriber on
    /// `<key_expr>/@adv/pub/**` that decodes each publisher's last-sn heartbeat
    /// beacon (`z_deserialize::<u32>`) and issues a BOUNDED `_sn=last+1..hb`
    /// recovery GET when the beacon reports samples past `last_delivered` (zenoh
    /// heartbeat subscriber, advanced_subscriber.rs:1045-1149). Catches a lost
    /// last sample like the periodic trigger, but driven by the publisher's
    /// beacon instead of a local timer (the producer beacon is the separate
    /// `ext-pubsub-sample-miss-detection` atom). `false` (default) = off.
    pub heartbeat: bool,
}

#[cfg(feature = "ext-pubsub-advanced-recovery")]
impl RecoveryConfig {
    /// Sample-driven recovery (no periodic / heartbeat trigger).
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable the periodic recovery trigger with the given re-ask period (see
    /// [`Self::periodic_queries`]). Requires a tokio runtime at declare time.
    pub fn with_periodic_queries(mut self, period: Duration) -> Self {
        self.periodic_queries = Some(period);
        self
    }

    /// Enable the heartbeat recovery trigger (see [`Self::heartbeat`]).
    pub fn with_heartbeat(mut self) -> Self {
        self.heartbeat = true;
        self
    }
}

/// Options for a configured advanced subscriber
/// ([`AdvancedSubscriber::declare_with_options`]). Mirror of the zenoh-ext
/// `AdvancedSubscriberBuilder` knobs wz implements: the (independent) retransmission
/// and startup-history configs, the shared GET locality, and the shared GET timeout.
/// zenoh exposes `.recovery()` / `.history()` as SEPARATE builder methods
/// (advanced_subscriber.rs:261/287), so [`Self::recovery`] and [`Self::history`] are
/// independent `Option`s — a `history`-only subscriber (no retransmission) is
/// representable (R311y91, review M1: the prior `RecoveryConfig`-carries-everything
/// shape made history-without-retransmission unrepresentable).
#[cfg(feature = "ext-pubsub-advanced-recovery")]
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct AdvancedSubscriberOptions {
    /// Retransmission (gap recovery). `None` (default) = no recovery: a forward gap
    /// reports a [`Miss`] and delivers past the hole. `Some` enables the reorder
    /// buffer + the sample-driven `_sn`-range recovery GET (+ the periodic /
    /// heartbeat triggers the [`RecoveryConfig`] selects). Mirror of zenoh
    /// `.recovery()`.
    pub recovery: Option<RecoveryConfig>,
    /// Startup history query. `None` (default) = no history. `Some` issues a
    /// `<key_expr>/@adv/**` GET on declare so a LATE JOINER recovers the publishers'
    /// cached history. INDEPENDENT of [`Self::recovery`] (zenoh `.history()` is a
    /// separate builder method): history-without-retransmission is valid.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    pub history: Option<HistoryConfig>,
    /// Locality for the recovery + history GETs. `Any` (default) reaches a remote
    /// publisher's `@adv` cache AND the local loopback; `SessionLocal` pins it to
    /// loopback (single-host composition tests). Mirror of zenoh's GET target /
    /// `allowed_origin`.
    pub allowed_destination: Locality,
    /// Timeout applied to BOTH the recovery + history GETs (zenoh's builder
    /// `query_timeout`, shared by history + retransmission; default 10s). A
    /// no-answerer GET (no `@adv` cache replies) would otherwise wait on a peer
    /// `Final` that never arrives; the non-zero timeout lets the reply registry's
    /// deadline sweep ([`crate::reply::ReplyRegistry::sweep_timed_out`]) fire the
    /// synthetic `Final` so [`State::finish_recovery`] / [`State::finish_history`]
    /// run (R311y89, review C3). Converted by [`recovery_query_timeout_ms`].
    pub query_timeout: Duration,
}

#[cfg(feature = "ext-pubsub-advanced-recovery")]
impl Default for AdvancedSubscriberOptions {
    fn default() -> Self {
        Self {
            recovery: None,
            #[cfg(feature = "ext-pubsub-advanced-history")]
            history: None,
            allowed_destination: Locality::Any,
            query_timeout: Duration::from_secs(10),
        }
    }
}

#[cfg(feature = "ext-pubsub-advanced-recovery")]
impl AdvancedSubscriberOptions {
    /// Default options: no recovery, no history, `Locality::Any`, 10s GET timeout.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable retransmission (gap recovery) with the given [`RecoveryConfig`]
    /// (zenoh `.recovery()`).
    pub fn with_recovery(mut self, recovery: RecoveryConfig) -> Self {
        self.recovery = Some(recovery);
        self
    }

    /// Enable the startup history query with the given [`HistoryConfig`]
    /// (zenoh `.history()`). Independent of [`Self::with_recovery`].
    #[cfg(feature = "ext-pubsub-advanced-history")]
    pub fn with_history(mut self, history: HistoryConfig) -> Self {
        self.history = Some(history);
        self
    }

    /// Pin the recovery + history GET locality (e.g. `SessionLocal` for a loopback
    /// composition).
    pub fn with_allowed_destination(mut self, locality: Locality) -> Self {
        self.allowed_destination = locality;
        self
    }

    /// Pin the recovery + history GET timeout (zenoh `.query_timeout()`). Converted
    /// to the `QueryOptions::with_timeout_ms` value by [`recovery_query_timeout_ms`],
    /// clamped to `>= 1` ms (a `0` re-opens the C3 no-answerer wedge).
    pub fn with_query_timeout(mut self, query_timeout: Duration) -> Self {
        self.query_timeout = query_timeout;
        self
    }
}

/// Startup-history configuration ([`AdvancedSubscriberOptions::with_history`]).
/// Mirror of zenoh-ext `HistoryConfig` (advanced_subscriber.rs:54-89). R311y86
/// builds the `max_samples` (`_max`) cap; the `max_age` time-range filter +
/// late-publisher liveliness detection are documented follow-ons.
#[cfg(feature = "ext-pubsub-advanced-history")]
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct HistoryConfig {
    /// `Some(N)` caps the startup history GET to the newest `N` samples per
    /// source (the `_max=N` selector); `None` recovers the publishers' whole
    /// caches (zenoh `HistoryConfig::max_samples`).
    pub sample_depth: Option<usize>,
}

#[cfg(feature = "ext-pubsub-advanced-history")]
impl HistoryConfig {
    /// History with no cap (recover each publisher's whole cache).
    pub fn new() -> Self {
        Self::default()
    }

    /// Cap the startup history GET to the newest `depth` samples per source
    /// (the `_max` selector).
    pub fn max_samples(mut self, depth: usize) -> Self {
        self.sample_depth = Some(depth);
        self
    }
}

/// What a recovery trigger asks the caller to do AFTER releasing the state
/// lock: issue a recovery GET against `(zid, eid)`'s `@adv` cache. Returned
/// (not issued inline) so the re-entrant `Session::query` runs without the
/// state mutex held. `to_sn = None` is the OPEN `_sn={from_sn}..` selector
/// (sample-driven + periodic); `Some(hb)` is the BOUNDED `_sn={from_sn}..{hb}`
/// the heartbeat trigger uses (it knows the publisher's last sn).
#[cfg(feature = "ext-pubsub-advanced-recovery")]
struct RecoveryRequest {
    zid: Vec<u8>,
    eid: u32,
    from_sn: u32,
    to_sn: Option<u32>,
}

/// Per-source last-in-order-delivered tracking + the user callbacks.
/// Behind an `Arc<Mutex>` because the session may fire the subscriber
/// callback from different worker threads (the storage-service idiom).
struct State {
    /// `(zid, eid)` -> per-source ordering state.
    sequenced: HashMap<(Vec<u8>, u32), SourceState>,
    on_sample: Box<dyn FnMut(Sample) + Send>,
    on_miss: Box<dyn FnMut(Miss) + Send>,
    /// R311y82 — whether forward gaps BUFFER + trigger a recovery GET (true,
    /// [`AdvancedSubscriber::declare_with_options`]) or report a [`Miss`] and
    /// deliver past the gap (false, the plain [`AdvancedSubscriber::declare`]).
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    retransmission: bool,
    /// R311y86 — true while the startup history GET is in flight: a live sample
    /// from an as-yet-undelivered source BUFFERS instead of delivering, so the
    /// (older) history delivers first (zenoh `global_pending_queries`,
    /// advanced_subscriber.rs:504-516). Cleared + the buffer flushed when the
    /// history GET's terminal Final fires ([`State::finish_history`]).
    #[cfg(feature = "ext-pubsub-advanced-history")]
    history_pending: bool,
}

#[cfg(not(feature = "ext-pubsub-advanced-recovery"))]
impl State {
    /// The zenoh `handle_sample` state machine (retransmission-off subset).
    fn handle(&mut self, view: &dyn SampleView) {
        let Some(source_info) = view.source_info() else {
            // No sequenced source-id: deliver, no de-duplication (the
            // timestamped-dedup path is deferred — see the module docs).
            (self.on_sample)(Sample::from_view(view));
            return;
        };
        let key = (source_info.zid_prefix().to_vec(), source_info.eid);
        let sn = source_info.sn;
        let State {
            sequenced,
            on_sample,
            on_miss,
        } = self;
        let on_sample: &mut dyn FnMut(Sample) = &mut **on_sample;
        let on_miss: &mut dyn FnMut(Miss) = &mut **on_miss;
        let state = sequenced.entry(key.clone()).or_default();
        match state.last_delivered {
            // First sample from this source: deliver, record.
            None => {
                on_sample(Sample::from_view(view));
                state.last_delivered = Some(sn);
            }
            // In order: deliver, advance.
            Some(last) if sn == last.wrapping_add(1) => {
                on_sample(Sample::from_view(view));
                state.last_delivered = Some(sn);
            }
            // Forward gap (no retransmission): report the miss, deliver,
            // advance past it (zenoh advanced_subscriber.rs:521-535).
            Some(last) if sn > last => {
                on_miss(Miss {
                    source_zid: key.0.clone(),
                    source_eid: key.1,
                    nb: sn - last - 1,
                });
                on_sample(Sample::from_view(view));
                state.last_delivered = Some(sn);
            }
            // `sn <= last`: duplicate / out-of-order-late — drop.
            Some(_) => {}
        }
    }
}

#[cfg(feature = "ext-pubsub-advanced-recovery")]
impl State {
    /// Ingest a LIVE sample (the subscriber callback path). Returns a
    /// [`RecoveryRequest`] when a forward gap on a retransmission-enabled
    /// source needs a `_sn`-range recovery GET; the caller issues it OUTSIDE
    /// the state lock.
    fn handle_live(&mut self, view: &dyn SampleView) -> Option<RecoveryRequest> {
        let Some(source_info) = view.source_info() else {
            // No sequenced source-id: deliver, no de-duplication.
            (self.on_sample)(Sample::from_view(view));
            return None;
        };
        let key = (source_info.zid_prefix().to_vec(), source_info.eid);
        let sn = source_info.sn;
        self.ingest_sequenced(key, sn, Sample::from_view(view), true)
    }

    /// Ingest a RECOVERED (retransmitted) reply sample — re-keyed by the
    /// reply's `source_info` and ordered like a live sample, but never issues
    /// a follow-on GET (the in-flight GET is what produced it).
    fn handle_recovered(&mut self, key: (Vec<u8>, u32), sn: u32, sample: Sample) {
        let _ = self.ingest_sequenced(key, sn, sample, false);
    }

    /// The shared sequenced-ordering core (zenoh `handle_sample`
    /// advanced_subscriber.rs:497-540). `live` gates whether a forward gap may
    /// trigger a new recovery GET.
    fn ingest_sequenced(
        &mut self,
        key: (Vec<u8>, u32),
        sn: u32,
        sample: Sample,
        live: bool,
    ) -> Option<RecoveryRequest> {
        let retransmission = self.retransmission;
        #[cfg(feature = "ext-pubsub-advanced-history")]
        let history_pending = self.history_pending;
        let State {
            sequenced,
            on_sample,
            on_miss,
            ..
        } = self;
        let on_sample: &mut dyn FnMut(Sample) = &mut **on_sample;
        let on_miss: &mut dyn FnMut(Miss) = &mut **on_miss;
        let state = sequenced.entry(key.clone()).or_default();

        match state.last_delivered {
            // First sample / in order: deliver, advance, drain contiguous buffer.
            None => {
                // R311y86 — while the startup history GET is in flight, BUFFER a
                // first sample (live or recovered) so the whole history delivers
                // in order on completion (zenoh advanced_subscriber.rs:504-516).
                // Skip the recovery trigger — the history GET is recovering it.
                #[cfg(feature = "ext-pubsub-advanced-history")]
                if history_pending {
                    state.pending_samples.insert(sn, sample);
                    return None;
                }
                deliver_and_flush(state, sn, sample, on_sample);
            }
            Some(last) if sn == last.wrapping_add(1) => {
                deliver_and_flush(state, sn, sample, on_sample)
            }
            // Forward gap.
            Some(last) if sn > last => {
                if retransmission {
                    // BUFFER; the recovery GET (below) back-fills the hole.
                    state.pending_samples.insert(sn, sample);
                } else {
                    // No retransmission: report the miss, deliver, advance.
                    on_miss(Miss {
                        source_zid: key.0.clone(),
                        source_eid: key.1,
                        nb: sn - last - 1,
                    });
                    on_sample(sample);
                    state.last_delivered = Some(sn);
                }
            }
            // `sn <= last`: duplicate / out-of-order-late — drop.
            Some(_) => {}
        }

        // Sample-driven trigger (zenoh sub_callback advanced_subscriber.rs:
        // 704-712): a live sample that left the buffer non-empty with no GET
        // in flight issues one for `_sn=last_delivered+1..`.
        if live && retransmission && state.pending_queries == 0 && !state.pending_samples.is_empty()
        {
            state.pending_queries += 1;
            Some(RecoveryRequest {
                zid: key.0,
                eid: key.1,
                from_sn: state.last_delivered.map(|s| s.wrapping_add(1)).unwrap_or(0),
                to_sn: None,
            })
        } else {
            None
        }
    }

    /// A recovery GET completed (its terminal Final fired): decrement the
    /// in-flight count and, when it reaches 0, flush the reorder buffer —
    /// delivering recovered + buffered samples in order and reporting a
    /// [`Miss`] for any hole the recovery did not fill (zenoh
    /// `SequencedRepliesHandler::drop` -> `flush_sequenced_source`,
    /// advanced_subscriber.rs:1362-1382 / 1266-1306).
    fn finish_recovery(&mut self, key: &(Vec<u8>, u32)) {
        // R311y87 (review C2) — do NOT flush while the startup history GET is
        // still in flight: a per-source recovery GET (heartbeat/periodic) can
        // complete mid-history; flushing then advances `last_delivered`, so a
        // later (older-sn) history reply for this source hits the dup-drop arm
        // and is silently LOST. Defer the flush to `finish_history` (zenoh gates
        // SequencedRepliesHandler::drop on `global_pending_queries == 0`,
        // advanced_subscriber.rs:1368).
        #[cfg(feature = "ext-pubsub-advanced-history")]
        let history_pending = self.history_pending;
        let State {
            sequenced,
            on_sample,
            on_miss,
            ..
        } = self;
        let on_sample: &mut dyn FnMut(Sample) = &mut **on_sample;
        let on_miss: &mut dyn FnMut(Miss) = &mut **on_miss;
        if let Some(state) = sequenced.get_mut(key) {
            state.pending_queries = state.pending_queries.saturating_sub(1);
            let may_flush = state.pending_queries == 0;
            #[cfg(feature = "ext-pubsub-advanced-history")]
            let may_flush = may_flush && !history_pending;
            if may_flush {
                flush_sequenced(state, &key.0, key.1, on_sample, on_miss);
            }
        }
    }

    /// R311y86 — the startup history GET completed (its terminal Final fired):
    /// clear `history_pending` and flush EVERY source's buffer in order, so the
    /// history accumulated during the query delivers oldest-first (zenoh
    /// `InitialRepliesHandler::drop` -> per-source `flush_sequenced_source`,
    /// advanced_subscriber.rs:1334-1352). A source with a per-source recovery GET
    /// still in flight is left for [`Self::finish_recovery`] to flush.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    fn finish_history(&mut self) {
        self.history_pending = false;
        let State {
            sequenced,
            on_sample,
            on_miss,
            ..
        } = self;
        let on_sample: &mut dyn FnMut(Sample) = &mut **on_sample;
        let on_miss: &mut dyn FnMut(Miss) = &mut **on_miss;
        for (key, state) in sequenced.iter_mut() {
            if state.pending_queries == 0 {
                flush_sequenced(state, &key.0, key.1, on_sample, on_miss);
            }
        }
    }

    /// R311y83 — the periodic trigger: collect a `_sn=last+1..` recovery
    /// request for every sequenced source with no GET in flight. Re-asking past
    /// `last_delivered` catches a lost LAST sample that no later live sample
    /// would trigger sample-driven recovery for (zenoh `PeriodicQuery::run`,
    /// advanced_subscriber.rs:587-643). wz drives ONE shared task that iterates
    /// all sources here (vs zenoh's per-source `TimedEvent`) — observable-
    /// equivalent, the GET shape is identical. No-op when retransmission is off.
    fn periodic_requests(&mut self) -> Vec<RecoveryRequest> {
        if !self.retransmission {
            return Vec::new();
        }
        let mut requests = Vec::new();
        for (key, state) in self.sequenced.iter_mut() {
            if state.pending_queries == 0 {
                state.pending_queries += 1;
                requests.push(RecoveryRequest {
                    zid: key.0.clone(),
                    eid: key.1,
                    from_sn: state.last_delivered.map(|s| s.wrapping_add(1)).unwrap_or(0),
                    to_sn: None,
                });
            }
        }
        requests
    }

    /// R311y84 — the heartbeat trigger: a beacon reporting the publisher's last
    /// sn `hb_sn` for source `(zid, eid)`. When the beacon is ahead of
    /// `last_delivered` and no GET is in flight, request a BOUNDED
    /// `_sn=last+1..hb_sn` recovery GET (zenoh heartbeat callback,
    /// advanced_subscriber.rs:1095-1118). No-op when retransmission is off.
    fn handle_heartbeat(&mut self, zid: Vec<u8>, eid: u32, hb_sn: u32) -> Option<RecoveryRequest> {
        if !self.retransmission {
            return None;
        }
        let key = (zid, eid);
        let state = self.sequenced.entry(key.clone()).or_default();
        let caught_up = state
            .last_delivered
            .map(|last| hb_sn <= last)
            .unwrap_or(false);
        if !caught_up && state.pending_queries == 0 {
            state.pending_queries += 1;
            Some(RecoveryRequest {
                zid: key.0,
                eid: key.1,
                from_sn: state.last_delivered.map(|s| s.wrapping_add(1)).unwrap_or(0),
                to_sn: Some(hb_sn),
            })
        } else {
            None
        }
    }
}

/// Deliver `sample` (sn = `sn`), advance `last_delivered`, then drain every
/// contiguous buffered sample (`last+1`, `last+2`, ...) in order. The wz
/// mirror of zenoh's `deliver_and_flush` (advanced_subscriber.rs:482-495).
#[cfg(feature = "ext-pubsub-advanced-recovery")]
fn deliver_and_flush(
    state: &mut SourceState,
    sn: u32,
    sample: Sample,
    on_sample: &mut dyn FnMut(Sample),
) {
    on_sample(sample);
    let mut delivered = sn;
    state.last_delivered = Some(delivered);
    while let Some(next) = state.pending_samples.remove(&delivered.wrapping_add(1)) {
        on_sample(next);
        delivered = delivered.wrapping_add(1);
        state.last_delivered = Some(delivered);
    }
}

/// Flush the reorder buffer after a recovery GET completed: drain it
/// sn-ordered, delivering each contiguous sample and reporting a [`Miss`] for
/// any hole the recovery did not fill (zenoh `flush_sequenced_source`,
/// advanced_subscriber.rs:1266-1306). Caller guarantees `pending_queries == 0`.
#[cfg(feature = "ext-pubsub-advanced-recovery")]
fn flush_sequenced(
    state: &mut SourceState,
    zid: &[u8],
    eid: u32,
    on_sample: &mut dyn FnMut(Sample),
    on_miss: &mut dyn FnMut(Miss),
) {
    if state.pending_samples.is_empty() {
        return;
    }
    let pending = core::mem::take(&mut state.pending_samples);
    for (sn, sample) in pending {
        match state.last_delivered {
            None => {
                state.last_delivered = Some(sn);
                on_sample(sample);
            }
            Some(last) if sn == last.wrapping_add(1) => {
                state.last_delivered = Some(sn);
                on_sample(sample);
            }
            Some(last) if sn > last => {
                on_miss(Miss {
                    source_zid: zid.to_vec(),
                    source_eid: eid,
                    nb: sn - last - 1,
                });
                state.last_delivered = Some(sn);
                on_sample(sample);
            }
            // duplicate — drop.
            Some(_) => {}
        }
    }
}

/// R311y89 (review C3) — convert a [`RecoveryConfig::query_timeout`] `Duration`
/// into the `QueryOptions::with_timeout_ms` `u32` ms value, clamped to
/// `[1, u32::MAX]`. The lower clamp is the correctness bite: a `0` (a zero or
/// sub-ms `Duration` truncates to `0`) is the `timeout_ms == 0` "never-expire"
/// sentinel, so the GET's pending reply entry registers with `deadline_ms == None`
/// and [`crate::reply::ReplyRegistry::sweep_timed_out`] skips it on every pass —
/// a no-answerer recovery / history GET would then wedge the subscriber forever.
/// The upper clamp keeps the cast lossless (the `with_timeout_ms` field is `u32`).
#[cfg(feature = "ext-pubsub-advanced-recovery")]
fn recovery_query_timeout_ms(query_timeout: Duration) -> u32 {
    query_timeout.as_millis().clamp(1, u32::MAX as u128) as u32
}

/// Issue a sample-driven `_sn={from_sn}..` recovery GET against the gapped
/// source's `@adv` cache and feed the recovered replies back into the
/// per-source ordering. The recovery KE mirrors zenoh's
/// `key_expr/@adv/*/<zid>/<eid>/**` (advanced_subscriber.rs:710-715): the `*`
/// matches the `pub` chunk, the `**` matches the publisher's trailing empty
/// meta chunk. MUST be called with the [`State`] lock RELEASED — `Session::query`
/// re-enters the session (and locks the state again from the reply callback).
#[cfg(feature = "ext-pubsub-advanced-recovery")]
fn issue_recovery_query<R, T>(
    session: &Session<R, T, Unicast>,
    statesref: &Arc<Mutex<State>>,
    base_keyexpr: &str,
    req: RecoveryRequest,
    dest: Locality,
    timeout_ms: u32,
) where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    let zid_hex = zid_to_zenoh_hex(&req.zid);
    let recovery_ke = format!("{base_keyexpr}/@adv/*/{zid_hex}/{}/**", req.eid);
    // Open `_sn=from..` (sample-driven / periodic) or bounded `_sn=from..to`
    // (heartbeat, which knows the publisher's last sn) — zenoh `seq_num_range`.
    let params = match req.to_sn {
        Some(to) => format!("_sn={}..{}", req.from_sn, to),
        None => format!("_sn={}..", req.from_sn),
    }
    .into_bytes();
    // R311y89 (review C3) — bound the GET with a timeout so the deadline sweep can
    // fire `finish_recovery` if no `@adv` cache answers (else `pending_queries`
    // wedges this source's reorder buffer forever).
    let opts = QueryOptions::get()
        .with_allowed_destination(dest)
        .with_parameters(params)
        .with_timeout_ms(timeout_ms);

    let key = (req.zid, req.eid);
    let reply_states = Arc::clone(statesref);
    let final_states = Arc::clone(statesref);
    let final_key = key.clone();
    let issued = session.query(
        &recovery_ke,
        opts,
        move |reply: &dyn ReplyView| {
            if let Some((rkey, rsn, sample)) = recovered_sample_from_reply(reply) {
                reply_states
                    .lock()
                    .expect("advanced subscriber state mutex poisoned")
                    .handle_recovered(rkey, rsn, sample);
            }
        },
        move |_rid| {
            final_states
                .lock()
                .expect("advanced subscriber state mutex poisoned")
                .finish_recovery(&final_key);
        },
    );
    // R311y89 (review C3) — a GET that failed to issue never registered a pending
    // reply entry (`Session::query` rolls it back on a wire-emit error), so neither
    // its `on_final` nor the deadline sweep can ever fire `finish_recovery`. Roll
    // back here so the `pending_queries` the caller bumped before this GET does not
    // wedge the source's buffer behind a phantom in-flight query.
    if issued.is_err() {
        statesref
            .lock()
            .expect("advanced subscriber state mutex poisoned")
            .finish_recovery(&key);
    }
}

/// Re-key a recovery / history reply into a `(source-key, sn, Sample)` for the
/// per-source ordering: read the source identity off the reply's source_info
/// (the `reply-source-info` seam) + rebuild the Put sample. `None` for a
/// non-Put reply or one with no source identity (it cannot be re-keyed — the
/// answerer needs `reply-source-info` on). Shared by the recovery + history GETs.
#[cfg(feature = "ext-pubsub-advanced-recovery")]
fn recovered_sample_from_reply(reply: &dyn ReplyView) -> Option<((Vec<u8>, u32), u32, Sample)> {
    if reply.kind() != ReplyKind::Put {
        return None;
    }
    let source_info = reply.source_info()?;
    let key = (source_info.zid_prefix().to_vec(), source_info.eid);
    let sn = source_info.sn;
    let mut sample = Sample::new_put(reply.keyexpr(), reply.payload().to_vec());
    sample.source_info = Some(source_info.clone());
    sample.attachment = reply.attachment().map(<[u8]>::to_vec);
    if let Some((packed_id, schema)) = reply.put_encoding() {
        sample.encoding = Some(EncodingHint {
            packed_id,
            schema: schema.map(String::from),
        });
    }
    Some((key, sn, sample))
}

/// R311y86 — issue the startup history GET over `<base>/@adv/**` (capped by
/// `_max=N` when `sample_depth` is set), feeding the recovered cached samples
/// from EVERY publisher into the per-source ordering. On the terminal Final,
/// [`State::finish_history`] clears `history_pending` + flushes the buffered
/// history oldest-first. MUST be called with the [`State`] lock RELEASED.
#[cfg(feature = "ext-pubsub-advanced-history")]
fn issue_history_query<R, T>(
    session: &Session<R, T, Unicast>,
    statesref: &Arc<Mutex<State>>,
    base_keyexpr: &str,
    sample_depth: Option<usize>,
    dest: Locality,
    timeout_ms: u32,
) where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    let history_ke = format!("{base_keyexpr}/@adv/**");
    // R311y89 (review C3) — bound the GET with a timeout so the deadline sweep can
    // fire `finish_history` if no `@adv` cache answers. Without it `history_pending`
    // stays set forever and EVERY live sample buffers undelivered (the subscriber
    // delivers nothing at all).
    let opts = QueryOptions::get()
        .with_allowed_destination(dest)
        .with_timeout_ms(timeout_ms);
    let opts = match sample_depth {
        Some(max) => opts.with_parameters(format!("_max={max}").into_bytes()),
        None => opts,
    };

    let reply_states = Arc::clone(statesref);
    let final_states = Arc::clone(statesref);
    let issued = session.query(
        &history_ke,
        opts,
        move |reply: &dyn ReplyView| {
            if let Some((rkey, rsn, sample)) = recovered_sample_from_reply(reply) {
                reply_states
                    .lock()
                    .expect("advanced subscriber state mutex poisoned")
                    .handle_recovered(rkey, rsn, sample);
            }
        },
        move |_rid| {
            final_states
                .lock()
                .expect("advanced subscriber state mutex poisoned")
                .finish_history();
        },
    );
    // R311y89 (review C3) — a history GET that failed to issue never registered, so
    // `finish_history` (which clears `history_pending` + flushes the buffer) would
    // never run and the subscriber would buffer live samples forever. Clear it here.
    if issued.is_err() {
        statesref
            .lock()
            .expect("advanced subscriber state mutex poisoned")
            .finish_history();
    }
}

/// R311y83 — run ONE periodic recovery tick: collect each source's
/// `_sn=last+1..` request under the state lock, then issue the GETs OUTSIDE the
/// lock (same re-entrancy discipline as the sample-driven path). The background
/// [`PeriodicTask`] loop calls this every period; a test drives it directly so
/// the recovery path is exercised deterministically (no timer wait).
#[cfg(feature = "ext-pubsub-advanced-recovery")]
fn run_periodic_tick<R, T>(
    session: &Session<R, T, Unicast>,
    statesref: &Arc<Mutex<State>>,
    base_keyexpr: &str,
    dest: Locality,
    timeout_ms: u32,
) where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    let requests = {
        let mut state = statesref
            .lock()
            .expect("advanced subscriber state mutex poisoned");
        state.periodic_requests()
    };
    for req in requests {
        issue_recovery_query(session, statesref, base_keyexpr, req, dest, timeout_ms);
    }
}

/// RAII handle for the periodic recovery background task: dropping it aborts the
/// loop so a torn-down subscriber stops re-asking (the [`crate::storage_replication_service::DigestPublisher`]
/// teardown shape). The spawn loop is thin timer glue over the deterministically
/// tested [`run_periodic_tick`] / [`State::periodic_requests`].
#[cfg(feature = "ext-pubsub-advanced-recovery")]
struct PeriodicTask {
    handle: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "ext-pubsub-advanced-recovery")]
impl Drop for PeriodicTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// R311y84 — parse a heartbeat sample's keyexpr
/// `<base>/@adv/pub/<zid_hex>/<eid>/_` back into its source `(zid, eid)`,
/// the wz analogue of zenoh's `ke_liveliness::parse` (advanced_subscriber.rs:
/// 1062). Returns `None` on a malformed beacon KE (bad `@adv/pub` layout,
/// un-decodable zid hex, or non-numeric eid). The trailing `_` meta chunk +
/// any further chunks are ignored.
#[cfg(feature = "ext-pubsub-advanced-recovery")]
fn parse_heartbeat_source(keyexpr: &str) -> Option<(Vec<u8>, u32)> {
    let chunks: Vec<&str> = keyexpr.split('/').collect();
    let adv = chunks.iter().position(|c| *c == "@adv")?;
    if chunks.get(adv + 1) != Some(&"pub") {
        return None;
    }
    let zid = zenoh_hex_to_zid(chunks.get(adv + 2)?)?;
    let eid = chunks.get(adv + 3)?.parse::<u32>().ok()?;
    Some((zid, eid))
}

/// A live advanced subscriber bound to a [`Session`]: owns the wrapped
/// plain [`Subscriber`] (RAII: dropping it undeclares) whose callback runs
/// the per-source ordering / de-duplication state machine.
pub struct AdvancedSubscriber<R: SessionRuntime = crate::runtime_impl::TokioRuntime> {
    _subscriber: Subscriber<R>,
    /// R311y83 — the shared ordering state; retained so a test can drive a
    /// recovery tick over the live source map ([`run_periodic_tick`]). The
    /// background task captures its own clone, so prod never reads this field
    /// (underscore-prefixed like `_subscriber` / `_periodic`).
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    _statesref: Arc<Mutex<State>>,
    /// R311y83 — the periodic recovery task (RAII abort-on-drop), `Some` only
    /// when `RecoveryConfig::periodic_queries` was set.
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    _periodic: Option<PeriodicTask>,
    /// R311y84 — the heartbeat subscriber on `<ke>/@adv/pub/**` (RAII
    /// undeclare-on-drop), `Some` only when `RecoveryConfig::heartbeat` was set.
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    _heartbeat_sub: Option<Subscriber<R>>,
}

#[cfg(not(feature = "ext-pubsub-advanced-recovery"))]
impl<R: SessionRuntime> AdvancedSubscriber<R> {
    /// Declare an advanced subscriber on `keyexpr`. `on_sample` receives
    /// each in-order / de-duplicated [`Sample`]; `on_miss` receives a
    /// [`Miss`] for every detected forward gap on a sequenced source.
    pub fn declare<T, OnSample, OnMiss>(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        on_sample: OnSample,
        on_miss: OnMiss,
    ) -> Result<Self, SubscribeError>
    where
        T: TimeSource + 'static,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        SessionLinkActions<R, T>: Send + Sync + 'static,
        OnSample: FnMut(Sample) + Send + 'static,
        OnMiss: FnMut(Miss) + Send + 'static,
    {
        let state = Arc::new(Mutex::new(State {
            sequenced: HashMap::new(),
            on_sample: Box::new(on_sample),
            on_miss: Box::new(on_miss),
        }));
        let cb_state = Arc::clone(&state);
        let subscriber = session.declare_subscriber(
            keyexpr,
            SubscribeOptions::default(),
            move |view: &dyn SampleView| {
                cb_state
                    .lock()
                    .expect("advanced subscriber state mutex poisoned")
                    .handle(view);
            },
        )?;
        Ok(Self {
            _subscriber: subscriber,
        })
    }
}

#[cfg(feature = "ext-pubsub-advanced-recovery")]
impl<R: SessionRuntime> AdvancedSubscriber<R> {
    /// Declare a plain advanced subscriber (no recovery): a forward gap fires
    /// a [`Miss`] and delivers past the hole. See [`Self::declare_with_options`]
    /// for the gap-recovering form.
    ///
    /// R311y88 (review H1) — this form does NOT route through `declare_impl`
    /// (which `tokio::spawn`s + whose callback captures the session): it builds
    /// a non-spawning subscriber whose callback only orders. Its bounds are
    /// therefore IDENTICAL to the recovery-OFF build's `declare` — so toggling
    /// `ext-pubsub-advanced-recovery` (an additive feature) cannot tighten this
    /// signature and break a downstream `declare` caller (the signature-stability
    /// invariant). The spawn-requiring bounds live only on `declare_with_options`.
    pub fn declare<T, OnSample, OnMiss>(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        on_sample: OnSample,
        on_miss: OnMiss,
    ) -> Result<Self, SubscribeError>
    where
        T: TimeSource + 'static,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        SessionLinkActions<R, T>: Send + Sync + 'static,
        OnSample: FnMut(Sample) + Send + 'static,
        OnMiss: FnMut(Miss) + Send + 'static,
    {
        let state = Arc::new(Mutex::new(State {
            sequenced: HashMap::new(),
            on_sample: Box::new(on_sample),
            on_miss: Box::new(on_miss),
            retransmission: false,
            #[cfg(feature = "ext-pubsub-advanced-history")]
            history_pending: false,
        }));
        let cb_state = Arc::clone(&state);
        let subscriber = session.declare_subscriber(
            keyexpr,
            SubscribeOptions::default(),
            move |view: &dyn SampleView| {
                // retransmission off + no history -> `handle_live` never returns a
                // RecoveryRequest, so the callback neither captures the session nor
                // spawns. Identical behaviour to the recovery-OFF `handle`
                // (forward gap = Miss + deliver), with no spawn-requiring bounds.
                let _ = cb_state
                    .lock()
                    .expect("advanced subscriber state mutex poisoned")
                    .handle_live(view);
            },
        )?;
        Ok(Self {
            _subscriber: subscriber,
            _statesref: state,
            _periodic: None,
            _heartbeat_sub: None,
        })
    }

    /// Declare a configured advanced subscriber from [`AdvancedSubscriberOptions`]:
    /// any combination of retransmission (gap recovery), a startup history query,
    /// the GET locality, and the GET timeout. Recovery and history are INDEPENDENT
    /// (zenoh `.recovery()` / `.history()`): `options` with only `history` set is a
    /// history-without-retransmission subscriber. With recovery on, a forward gap is
    /// buffered and a sample-driven `_sn`-range recovery GET refills it from the
    /// publisher's `@adv` cache; `on_miss` fires only for a hole recovery does NOT
    /// fill. With recovery off, a forward gap reports a [`Miss`] and delivers past
    /// the hole.
    pub fn declare_with_options<T, OnSample, OnMiss>(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        options: AdvancedSubscriberOptions,
        on_sample: OnSample,
        on_miss: OnMiss,
    ) -> Result<Self, AdvancedSubscribeError>
    where
        R: 'static,
        T: TimeSource + Send + Sync + 'static,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        SessionLinkActions<R, T>: Send + Sync + 'static,
        Session<R, T, Unicast>: Send + 'static,
        OnSample: FnMut(Sample) + Send + 'static,
        OnMiss: FnMut(Miss) + Send + 'static,
    {
        Self::declare_impl(session, keyexpr, on_sample, on_miss, options)
    }

    fn declare_impl<T, OnSample, OnMiss>(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        on_sample: OnSample,
        on_miss: OnMiss,
        options: AdvancedSubscriberOptions,
    ) -> Result<Self, AdvancedSubscribeError>
    where
        R: 'static,
        T: TimeSource + Send + Sync + 'static,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        SessionLinkActions<R, T>: Send + Sync + 'static,
        Session<R, T, Unicast>: Send + 'static,
        OnSample: FnMut(Sample) + Send + 'static,
        OnMiss: FnMut(Miss) + Send + 'static,
    {
        // R311y91 (review M1) — recovery + history are INDEPENDENT (zenoh keeps
        // `.recovery()` / `.history()` separate): `retransmission` is driven by
        // `options.recovery`, `history_pending` by `options.history` — a
        // history-only subscriber (recovery None) is now representable.
        let recovery = options.recovery;
        let retransmission = recovery.is_some();
        let dest = options.allowed_destination;
        let periodic = recovery.and_then(|c| c.periodic_queries);
        // R311y90 (review C5) — fail fast & clear if off-runtime: the periodic
        // task (below) is a tokio::spawn, which PANICS without a runtime. Check
        // before declaring the subscriber so no half-declared subscriber needs
        // rollback. The sample-driven / heartbeat-sub / history paths do not spawn.
        if periodic.is_some() {
            tokio::runtime::Handle::try_current().map_err(|_| AdvancedSubscribeError::NoRuntime)?;
        }
        let heartbeat = recovery.map(|c| c.heartbeat).unwrap_or(false);
        // R311y89 (review C3) — the recovery + history GET timeout (zenoh's shared
        // builder `query_timeout`), threaded to every GET so the deadline sweep can
        // release a no-answerer query.
        let timeout_ms = recovery_query_timeout_ms(options.query_timeout);
        #[cfg(feature = "ext-pubsub-advanced-history")]
        let history = options.history;
        let base_keyexpr: String = keyexpr.into();

        let state = Arc::new(Mutex::new(State {
            sequenced: HashMap::new(),
            on_sample: Box::new(on_sample),
            on_miss: Box::new(on_miss),
            retransmission,
            #[cfg(feature = "ext-pubsub-advanced-history")]
            history_pending: history.is_some(),
        }));
        let cb_state = Arc::clone(&state);
        let q_session = session.clone();
        let q_base = base_keyexpr.clone();
        let subscriber = session.declare_subscriber(
            base_keyexpr.clone(),
            SubscribeOptions::default(),
            move |view: &dyn SampleView| {
                let request = cb_state
                    .lock()
                    .expect("advanced subscriber state mutex poisoned")
                    .handle_live(view);
                // Issue the recovery GET OUTSIDE the state lock: Session::query
                // re-enters the session (the loopback fan drains the cache's
                // replies, which lock `cb_state` again). R311lh deferred-fire
                // makes this re-entrant call safe.
                if let Some(request) = request {
                    issue_recovery_query(&q_session, &cb_state, &q_base, request, dest, timeout_ms);
                }
            },
        )?;

        // R311y83 — the periodic recovery trigger: a background loop that
        // re-asks every known source `_sn=last+1..` every `period`. Spawned
        // here (the caller is in a tokio runtime context), aborted on drop.
        // The loop is thin glue over `run_periodic_tick` / `periodic_requests`
        // (the deterministically tested core; the storage_replication
        // DigestPublisher pattern).
        let periodic_task = periodic.map(|period| {
            let p_session = session.clone();
            let p_state = Arc::clone(&state);
            let p_base = base_keyexpr.clone();
            let clock = Arc::clone(session.clock());
            // R311y87 (review C4) — clamp to >=1ms: a sub-ms Duration truncates
            // to 0, turning the loop into a zero-delay GET storm / busy spin.
            let period_ms = (period.as_millis() as u64).max(1);
            PeriodicTask {
                handle: tokio::spawn(async move {
                    loop {
                        clock.sleep(period_ms).await;
                        run_periodic_tick(&p_session, &p_state, &p_base, dest, timeout_ms);
                    }
                }),
            }
        });

        // R311y84 — the heartbeat subscriber: on each `<ke>/@adv/pub/**` beacon,
        // decode the publisher's last sn (`z_deserialize::<u32>`) and issue a
        // bounded `_sn=last+1..hb` recovery GET (zenoh advanced_subscriber.rs:
        // 1053-1145). Callback-driven (no task); the GET re-enters Session::query
        // OUTSIDE the state lock, the sample-driven re-entrancy discipline.
        let heartbeat_sub = if heartbeat {
            let hb_state = Arc::clone(&state);
            let hb_session = session.clone();
            let hb_base = base_keyexpr.clone();
            let hb_keyexpr = format!("{base_keyexpr}/@adv/pub/**");
            Some(session.declare_subscriber(
                hb_keyexpr,
                SubscribeOptions::default(),
                move |hb_view: &dyn SampleView| {
                    if hb_view.kind() != SampleKind::Put {
                        return;
                    }
                    let Some((zid, eid)) = parse_heartbeat_source(hb_view.keyexpr()) else {
                        return;
                    };
                    let Ok(hb_sn) = z_deserialize::<u32>(hb_view.payload()) else {
                        return;
                    };
                    let request = hb_state
                        .lock()
                        .expect("advanced subscriber state mutex poisoned")
                        .handle_heartbeat(zid, eid, hb_sn);
                    if let Some(request) = request {
                        issue_recovery_query(
                            &hb_session,
                            &hb_state,
                            &hb_base,
                            request,
                            dest,
                            timeout_ms,
                        );
                    }
                },
            )?)
        } else {
            None
        };

        // R311y86 — the startup history GET: fire it AFTER the live subscriber is
        // declared (so a live sample arriving during the GET is gated by
        // `history_pending` + buffered) to recover the publishers' cached history.
        // In loopback it completes synchronously here (the cache answers + the
        // terminal Final flushes the buffered history oldest-first).
        #[cfg(feature = "ext-pubsub-advanced-history")]
        if let Some(history) = history {
            issue_history_query(
                session,
                &state,
                &base_keyexpr,
                history.sample_depth,
                dest,
                timeout_ms,
            );
        }

        Ok(Self {
            _subscriber: subscriber,
            _statesref: state,
            _periodic: periodic_task,
            _heartbeat_sub: heartbeat_sub,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::observer::ApplicationLayerObserver;
    use crate::runtime_impl::TokioTime;
    use crate::session::{PublishOptions, TokioSession};
    use wz_session_core::locality::Locality;
    use wz_session_core::sample::SourceInfo;

    /// Drive the subscriber with one controlled sequence number under a
    /// fixed synthetic source identity. These are STATE-MACHINE unit tests:
    /// they inject specific sns (incl a deliberate gap + a duplicate) that a
    /// real, always-incrementing `AdvancedPublisher` cannot produce, so they
    /// synthesize the wire `SourceInfo` directly. The zid value is arbitrary
    /// — SessionLocal loopback applies NO self-echo dedup (that is gated
    /// `if is_remote` only, pubsub.rs; proven by
    /// `pubsub::tests::local_publish_ignores_own_zid_dedup`), so own-vs-remote
    /// zid is irrelevant here. The genuine producer->consumer link is the
    /// separate composed test (`composed_advanced_publisher_to_subscriber_*`).
    fn put_sequenced(session: &TokioSession, sn: u32) -> usize {
        session
            .publish(
                "demo/data",
                &[sn as u8],
                PublishOptions::put()
                    .with_locality(Locality::SessionLocal)
                    .with_source_info(SourceInfo::new(&[0x02], 7, sn)),
            )
            .expect("loopback sequenced publish")
    }

    /// State-machine unit test (synthetic source, controlled sns): a source
    /// feeds 0,1, then 3 (a gap at 2), then a duplicate 1. The plain advanced
    /// subscriber must deliver 0,1,3 in order, fire one Miss(nb=1) on the
    /// 1->3 gap, and DROP the duplicate.
    #[test]
    fn sequenced_in_order_gap_miss_and_dedup() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let delivered = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let misses = Arc::new(Mutex::new(Vec::<Miss>::new()));
        let d = Arc::clone(&delivered);
        let m = Arc::clone(&misses);
        let _sub = AdvancedSubscriber::declare(
            &session,
            "demo/data",
            move |sample: Sample| d.lock().unwrap().push(sample.payload.clone()),
            move |miss: Miss| m.lock().unwrap().push(miss),
        )
        .expect("advanced subscriber declares against the test link");

        put_sequenced(&session, 0);
        put_sequenced(&session, 1);
        put_sequenced(&session, 3); // gap: 2 was missed
        put_sequenced(&session, 1); // duplicate / old

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![vec![0u8], vec![1u8], vec![3u8]],
            "0,1,3 delivered in order; the duplicate 1 dropped"
        );
        let got_misses = misses.lock().unwrap().clone();
        assert_eq!(
            got_misses,
            vec![Miss {
                source_zid: vec![0x02],
                source_eid: 7,
                nb: 1,
            }],
            "one miss reported for the single skipped sample (sn 2)"
        );
    }

    /// A NEW source's first sample always delivers (no last marker yet),
    /// and a second source is tracked independently.
    #[test]
    fn distinct_sources_track_independently() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let delivered = Arc::new(Mutex::new(Vec::<(u32, u8)>::new()));
        let d = Arc::clone(&delivered);
        let _sub = AdvancedSubscriber::declare(
            &session,
            "demo/data",
            move |sample: Sample| {
                let eid = sample.source_info.as_ref().map(|s| s.eid).unwrap_or(0);
                d.lock().unwrap().push((eid, sample.payload[0]));
            },
            |_miss: Miss| {},
        )
        .expect("advanced subscriber declares");

        // Source eid=7 sends sn 0; source eid=8 sends sn 5 (its first — no
        // gap reported, a new source has no last marker).
        let send = |eid: u32, sn: u32, v: u8| {
            session
                .publish(
                    "demo/data",
                    &[v],
                    PublishOptions::put()
                        .with_locality(Locality::SessionLocal)
                        .with_source_info(SourceInfo::new(&[0x02], eid, sn)),
                )
                .expect("publish");
        };
        send(7, 0, 0xA0);
        send(8, 5, 0xB0);
        send(7, 1, 0xA1);

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![(7, 0xA0), (8, 0xB0), (7, 0xA1)],
            "each source's stream is ordered independently; eid=8's first sn=5 delivers with no miss"
        );
    }

    /// Composed producer->consumer e2e — the HIGH-priority fix from the
    /// R311y70 session review (the prior tests exercised each half in
    /// isolation; this co-compiles BOTH atoms and proves the seqnum
    /// producer/consumer contract that is the atom's whole point). A REAL
    /// `AdvancedPublisher` (its own zid + `SequenceNumber` sequencing) feeds
    /// a REAL `AdvancedSubscriber` on one session over the loopback
    /// (`Locality::Any` -> the local subscriber fires; session-API loopback,
    /// no wire codec). A contiguous 0,1,2 publish must deliver 0,1,2 in
    /// order with zero misses.
    #[cfg(all(
        feature = "ext-pubsub-advanced-publisher",
        feature = "pubsub-allow-loop"
    ))]
    #[test]
    fn composed_advanced_publisher_to_subscriber_in_order() {
        use crate::advanced_cache::CacheConfig;
        use crate::advanced_publisher::{
            AdvancedPublisher, AdvancedPublisherOptions, MissDetectionConfig, Sequencing,
        };

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let misses = Arc::new(Mutex::new(0usize));
        let d = Arc::clone(&delivered);
        let m = Arc::clone(&misses);
        let _sub = AdvancedSubscriber::declare(
            &session,
            "demo/data",
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
            move |_miss: Miss| *m.lock().unwrap() += 1,
        )
        .expect("advanced subscriber declares");

        // A REAL publisher with its OWN zid (its genuine identity) +
        // SequenceNumber sequencing; default Locality::Any -> the loopback
        // leg fires the local subscriber (own-zid loopback delivers — no
        // self-echo dedup on the loopback path).
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

        for v in 0u8..3 {
            publisher.put(&[v]).expect("advanced put");
        }

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0u8, 1, 2],
            "the real publisher's incrementing seqnums delivered in order by the real subscriber"
        );
        assert_eq!(
            *misses.lock().unwrap(),
            0,
            "a contiguous 0,1,2 stream has no gaps -> no Miss"
        );
    }

    /// R311y82 state-machine unit test (recovery core, no session): a live
    /// forward gap BUFFERS instead of delivering + asks for a recovery GET;
    /// when the recovered sample fills the hole, the buffer drains in order
    /// with no miss. Drives [`State`] directly so the buffer / drain logic is
    /// exercised without the query plane (the composed loopback test below
    /// covers the genuine GET).
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    #[test]
    fn recovery_buffers_forward_gap_and_drains_when_filled() {
        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let misses = Arc::new(Mutex::new(Vec::<Miss>::new()));
        let d = Arc::clone(&delivered);
        let m = Arc::clone(&misses);
        let mut state = State {
            sequenced: HashMap::new(),
            on_sample: Box::new(move |s: Sample| d.lock().unwrap().push(s.payload[0])),
            on_miss: Box::new(move |miss: Miss| m.lock().unwrap().push(miss)),
            retransmission: true,
            #[cfg(feature = "ext-pubsub-advanced-history")]
            history_pending: false,
        };
        let key = (vec![0x02u8], 7u32);
        let mk = |sn: u32, v: u8| {
            let mut s = Sample::new_put("demo/data", vec![v]);
            s.source_info = Some(SourceInfo::new(&[0x02], 7, sn));
            s
        };

        // Live 0,1 in order — no recovery request.
        assert!(state
            .ingest_sequenced(key.clone(), 0, mk(0, 0xA0), true)
            .is_none());
        assert!(state
            .ingest_sequenced(key.clone(), 1, mk(1, 0xA1), true)
            .is_none());
        // Live gap at 2: sn 3 arrives. retransmission -> buffer + request GET.
        let req = state
            .ingest_sequenced(key.clone(), 3, mk(3, 0xA3), true)
            .expect("a forward gap with retransmission requests recovery");
        assert_eq!(
            (req.zid.clone(), req.eid),
            key,
            "GET targets the gapped source"
        );
        assert_eq!(req.from_sn, 2, "GET starts at last_delivered+1 = 2");
        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0xA0, 0xA1],
            "sn 3 buffered, not delivered while the hole is open"
        );

        // The recovery GET returns sn 2 — drains 2 then the buffered 3.
        state.handle_recovered(key.clone(), 2, mk(2, 0xA2));
        state.finish_recovery(&key);
        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0xA0, 0xA1, 0xA2, 0xA3],
            "the recovered sn 2 fills the hole; the buffered sn 3 drains in order"
        );
        assert!(
            misses.lock().unwrap().is_empty(),
            "the recovery filled the hole -> no Miss"
        );
    }

    /// R311y82 state-machine unit test: a hole the recovery GET does NOT fill
    /// surfaces a [`Miss`] at flush, and the buffered sample past it is still
    /// delivered (zenoh `flush_sequenced_source` miss arm).
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    #[test]
    fn recovery_flush_reports_miss_for_unfilled_hole() {
        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let misses = Arc::new(Mutex::new(Vec::<Miss>::new()));
        let d = Arc::clone(&delivered);
        let m = Arc::clone(&misses);
        let mut state = State {
            sequenced: HashMap::new(),
            on_sample: Box::new(move |s: Sample| d.lock().unwrap().push(s.payload[0])),
            on_miss: Box::new(move |miss: Miss| m.lock().unwrap().push(miss)),
            retransmission: true,
            #[cfg(feature = "ext-pubsub-advanced-history")]
            history_pending: false,
        };
        let key = (vec![0x02u8], 7u32);
        let mk = |sn: u32, v: u8| {
            let mut s = Sample::new_put("demo/data", vec![v]);
            s.source_info = Some(SourceInfo::new(&[0x02], 7, sn));
            s
        };

        state.ingest_sequenced(key.clone(), 0, mk(0, 0xB0), true);
        // Gap at 1: sn 2 buffered, GET requested for _sn=1..
        let req = state
            .ingest_sequenced(key.clone(), 2, mk(2, 0xB2), true)
            .expect("gap requests recovery");
        assert_eq!(req.from_sn, 1);
        // The GET finalises with NOTHING for sn 1 (the cache never had it).
        state.finish_recovery(&key);
        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0xB0, 0xB2],
            "the unfillable hole is skipped; the buffered sn 2 still delivers"
        );
        assert_eq!(
            misses.lock().unwrap().clone(),
            vec![Miss {
                source_zid: vec![0x02],
                source_eid: 7,
                nb: 1,
            }],
            "the unfilled hole surfaces one Miss(nb=1) at flush"
        );
    }

    /// R311y82 composed loopback recovery e2e — the CONSUMER half
    /// (`ext-pubsub-advanced-recovery`) co-compiled with the PRODUCER answerer
    /// (`ext-pubsub-advanced-cache`). A real [`crate::advanced_cache::AdvancedCache`]
    /// holds the full stream 0..=4; a recovering [`AdvancedSubscriber`] sees a
    /// live stream with a hole at sn 3 (a single-session loopback cannot DROP a
    /// delivery, so the gap is injected synthetically under the publisher
    /// identity); the subscriber buffers sn 4, issues `_sn=3..` to the cache's
    /// `@adv` KE, and the cache replies sn 3 (and 4) carrying their source_info
    /// (`reply-source-info`, composed by the recovery gate) — proving the
    /// recovered sn 3 came from the CACHE (its payload `0x03`, distinct from the
    /// live `0xA*` convention), re-keyed and delivered in order with no Miss.
    /// The genuine GET runs synchronously inside the gapped publish via the
    /// R311lh deferred-fire re-entrant drain.
    #[cfg(all(
        feature = "ext-pubsub-advanced-recovery",
        feature = "ext-pubsub-advanced-cache",
        feature = "pubsub-allow-loop"
    ))]
    #[test]
    fn composed_recovery_refills_gap_from_cache_over_loopback() {
        use crate::advanced_cache::{AdvancedCache, CacheConfig, CachedSample};
        use wz_session_core::sample::TimestampHint;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        // The publisher identity the synthetic live stream + the cache both
        // stamp, so the subscriber's recovery GET targets the cache's KE.
        let pub_zid = vec![0x09u8];
        let pub_eid = 4u32;
        let zid_hex = zid_to_zenoh_hex(&pub_zid);

        // The cache answers on the publisher's `@adv` recovery suffix; populate
        // it with the FULL stream 0..=4 (cache payload = sn) so the recovery
        // GET can refill any hole.
        let cache_ke = format!("demo/data/@adv/pub/{zid_hex}/{pub_eid}/_");
        let cache = AdvancedCache::declare(&session, cache_ke, CacheConfig { max_samples: 8 })
            .expect("advanced cache declares");
        for sn in 0u8..5 {
            cache.cache_sample(CachedSample {
                keyexpr: "demo/data".to_string(),
                payload: vec![sn],
                source_info: Some(SourceInfo::new(&pub_zid, pub_eid, sn as u32)),
                timestamp: TimestampHint {
                    time: 100 + sn as u64,
                    zid: pub_zid.clone(),
                },
            });
        }

        // The recovering subscriber; recovery GET pinned to SessionLocal (the
        // loopback cache is the only answerer — the test has no remote peer).
        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let misses = Arc::new(Mutex::new(0usize));
        let d = Arc::clone(&delivered);
        let m = Arc::clone(&misses);
        let _sub = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_recovery(RecoveryConfig::new())
                .with_allowed_destination(Locality::SessionLocal),
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
            move |_miss: Miss| *m.lock().unwrap() += 1,
        )
        .expect("recovering advanced subscriber declares");

        // Drive the LIVE stream with a hole at sn 3 (live payloads 0xA*).
        let live = |sn: u32, v: u8| {
            session
                .publish(
                    "demo/data",
                    &[v],
                    PublishOptions::put()
                        .with_locality(Locality::SessionLocal)
                        .with_source_info(SourceInfo::new(&pub_zid, pub_eid, sn)),
                )
                .expect("loopback live publish");
        };
        live(0, 0xA0);
        live(1, 0xA1);
        live(2, 0xA2);
        // sn 3 missing -> buffer the live sn 4, GET _sn=3.. -> cache replies
        // sn 3 (0x03) + sn 4 (0x04, a dup, dropped). The recovered sn 3 drains
        // the hole, then the buffered live sn 4 (0xA4) drains behind it.
        live(4, 0xA4);

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0xA0, 0xA1, 0xA2, 0x03, 0xA4],
            "0,1,2 live; the recovered sn 3 (cache payload 0x03) fills the hole; \
             the buffered live sn 4 (0xA4) drains in order"
        );
        assert_eq!(
            *misses.lock().unwrap(),
            0,
            "the recovery filled the hole -> no Miss"
        );
    }

    /// R311y83 periodic-trigger unit (no session): `periodic_requests` re-asks
    /// every retransmission source `_sn=last+1..` once, marking each with a GET
    /// in flight so a second tick is a no-op until the GET finalises.
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    #[test]
    fn periodic_requests_reask_each_source_once() {
        let mut state = State {
            sequenced: HashMap::new(),
            on_sample: Box::new(|_| {}),
            on_miss: Box::new(|_| {}),
            retransmission: true,
            #[cfg(feature = "ext-pubsub-advanced-history")]
            history_pending: false,
        };
        state.sequenced.insert(
            (vec![0x01u8], 1u32),
            SourceState {
                last_delivered: Some(4),
                ..Default::default()
            },
        );
        state.sequenced.insert(
            (vec![0x02u8], 2u32),
            SourceState {
                last_delivered: Some(0),
                ..Default::default()
            },
        );

        let mut reqs = state.periodic_requests();
        reqs.sort_by_key(|r| r.eid);
        assert_eq!(reqs.len(), 2);
        assert_eq!(
            (reqs[0].zid.clone(), reqs[0].eid, reqs[0].from_sn),
            (vec![0x01], 1, 5),
            "source A re-asks from last_delivered(4)+1"
        );
        assert_eq!(
            (reqs[1].zid.clone(), reqs[1].eid, reqs[1].from_sn),
            (vec![0x02], 2, 1),
            "source B re-asks from last_delivered(0)+1"
        );
        assert!(
            state.periodic_requests().is_empty(),
            "a GET is now in flight per source -> no re-ask until it finalises"
        );

        // Retransmission OFF -> the periodic trigger is inert.
        let mut plain = State {
            sequenced: HashMap::new(),
            on_sample: Box::new(|_| {}),
            on_miss: Box::new(|_| {}),
            retransmission: false,
            #[cfg(feature = "ext-pubsub-advanced-history")]
            history_pending: false,
        };
        plain.sequenced.insert(
            (vec![0x01u8], 1u32),
            SourceState {
                last_delivered: Some(0),
                ..Default::default()
            },
        );
        assert!(
            plain.periodic_requests().is_empty(),
            "no retransmission -> periodic_requests is a no-op"
        );
    }

    /// R311y83 composed periodic recovery e2e: a lost LAST sample (no later live
    /// sample, so the sample-driven trigger never fires) is recovered by one
    /// periodic tick. The cache holds 0..=2; live 0,1 arrive but sn 2 is lost
    /// and undetected; [`run_periodic_tick`] re-asks `_sn=2..` and the cache
    /// refills sn 2. Declared WITHOUT `periodic_queries` so no background task
    /// spawns (no tokio runtime needed); the test drives the deterministic tick
    /// directly — the spawn loop is thin glue over this same path.
    #[cfg(all(
        feature = "ext-pubsub-advanced-recovery",
        feature = "ext-pubsub-advanced-cache",
        feature = "pubsub-allow-loop"
    ))]
    #[test]
    fn composed_periodic_tick_recovers_lost_last_sample() {
        use crate::advanced_cache::{AdvancedCache, CacheConfig, CachedSample};
        use wz_session_core::sample::TimestampHint;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let pub_zid = vec![0x09u8];
        let pub_eid = 4u32;
        let zid_hex = zid_to_zenoh_hex(&pub_zid);
        let cache_ke = format!("demo/data/@adv/pub/{zid_hex}/{pub_eid}/_");
        let cache = AdvancedCache::declare(&session, cache_ke, CacheConfig { max_samples: 8 })
            .expect("advanced cache declares");
        for sn in 0u8..3 {
            cache.cache_sample(CachedSample {
                keyexpr: "demo/data".to_string(),
                payload: vec![sn],
                source_info: Some(SourceInfo::new(&pub_zid, pub_eid, sn as u32)),
                timestamp: TimestampHint {
                    time: 100 + sn as u64,
                    zid: pub_zid.clone(),
                },
            });
        }

        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let misses = Arc::new(Mutex::new(0usize));
        let d = Arc::clone(&delivered);
        let m = Arc::clone(&misses);
        let sub = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_recovery(RecoveryConfig::new())
                .with_allowed_destination(Locality::SessionLocal),
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
            move |_miss: Miss| *m.lock().unwrap() += 1,
        )
        .expect("recovering advanced subscriber declares");

        let live = |sn: u32, v: u8| {
            session
                .publish(
                    "demo/data",
                    &[v],
                    PublishOptions::put()
                        .with_locality(Locality::SessionLocal)
                        .with_source_info(SourceInfo::new(&pub_zid, pub_eid, sn)),
                )
                .expect("loopback live publish");
        };
        live(0, 0xA0);
        live(1, 0xA1);
        // sn 2 (the LAST) is lost; nothing later arrives -> no gap detected.
        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0xA0, 0xA1],
            "only 0,1 delivered live; the lost last sn 2 is undetected"
        );

        // One periodic tick re-asks _sn=2.. -> the cache refills sn 2.
        run_periodic_tick(
            &session,
            &sub._statesref,
            "demo/data",
            Locality::SessionLocal,
            recovery_query_timeout_ms(Duration::from_secs(10)),
        );

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0xA0, 0xA1, 0x02],
            "the periodic tick recovered the lost LAST sample (cache payload 0x02)"
        );
        assert_eq!(
            *misses.lock().unwrap(),
            0,
            "the periodic recovery filled it -> no Miss"
        );
    }

    /// R311y84 heartbeat-source KE parser unit.
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    #[test]
    fn parse_heartbeat_source_round_trips_and_rejects_malformed() {
        let zid = vec![0x09u8, 0xAB];
        let ke = format!("demo/data/@adv/pub/{}/7/_", zid_to_zenoh_hex(&zid));
        assert_eq!(parse_heartbeat_source(&ke), Some((zid, 7)));
        // Malformed: no @adv, wrong marker, non-numeric eid.
        assert_eq!(parse_heartbeat_source("demo/data"), None);
        assert_eq!(parse_heartbeat_source("demo/@adv/sub/ff/7/_"), None);
        assert_eq!(parse_heartbeat_source("demo/@adv/pub/ff/xx/_"), None);
    }

    /// R311y84 heartbeat-trigger unit (no session): a beacon ahead of
    /// `last_delivered` requests a BOUNDED `_sn=last+1..hb` GET once; a beacon
    /// at-or-behind `last_delivered`, or one while a GET is in flight, is a
    /// no-op; retransmission-off is inert.
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    #[test]
    fn handle_heartbeat_requests_bounded_get_when_ahead() {
        let mut state = State {
            sequenced: HashMap::new(),
            on_sample: Box::new(|_| {}),
            on_miss: Box::new(|_| {}),
            retransmission: true,
            #[cfg(feature = "ext-pubsub-advanced-history")]
            history_pending: false,
        };
        let key = (vec![0x09u8], 4u32);
        state.sequenced.insert(
            key.clone(),
            SourceState {
                last_delivered: Some(1),
                ..Default::default()
            },
        );

        // Beacon last sn = 4 > last_delivered 1 -> bounded _sn=2..4.
        let req = state
            .handle_heartbeat(key.0.clone(), key.1, 4)
            .expect("a beacon ahead of last_delivered requests recovery");
        assert_eq!((req.from_sn, req.to_sn), (2, Some(4)));
        // A GET is now in flight -> a second beacon is a no-op.
        assert!(state.handle_heartbeat(key.0.clone(), key.1, 5).is_none());
        // A caught-up beacon (<= last_delivered) on a fresh source is a no-op.
        state.sequenced.get_mut(&key).unwrap().pending_queries = 0;
        assert!(state.handle_heartbeat(key.0.clone(), key.1, 1).is_none());

        let mut plain = State {
            sequenced: HashMap::new(),
            on_sample: Box::new(|_| {}),
            on_miss: Box::new(|_| {}),
            retransmission: false,
            #[cfg(feature = "ext-pubsub-advanced-history")]
            history_pending: false,
        };
        assert!(
            plain.handle_heartbeat(vec![0x01], 1, 9).is_none(),
            "no retransmission -> heartbeat is inert"
        );
    }

    /// R311y84 composed heartbeat recovery e2e: the publisher's last-sn beacon
    /// drives recovery of a lost LAST sample. The cache holds 0..=2; live 0,1
    /// arrive but sn 2 is lost and undetected; a heartbeat beacon
    /// (`z_serialize::<u32>(2)` on the publisher's `@adv` KE) fires the
    /// heartbeat subscriber, which issues a bounded `_sn=2..2` GET that the
    /// cache refills. The beacon is synthesised in-test (the producer beacon is
    /// the separate `ext-pubsub-sample-miss-detection` atom — the live-gap-
    /// injection pattern), and runs synchronously via R311lh deferred-fire.
    #[cfg(all(
        feature = "ext-pubsub-advanced-recovery",
        feature = "ext-pubsub-advanced-cache",
        feature = "ext-pubsub-serde-codec",
        feature = "pubsub-allow-loop"
    ))]
    #[test]
    fn composed_heartbeat_recovers_lost_last_sample() {
        use crate::advanced_cache::{AdvancedCache, CacheConfig, CachedSample};
        use wz_session_core::sample::TimestampHint;
        use wz_session_core::serde_codec::z_serialize;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let pub_zid = vec![0x09u8];
        let pub_eid = 4u32;
        let zid_hex = zid_to_zenoh_hex(&pub_zid);
        let adv_ke = format!("demo/data/@adv/pub/{zid_hex}/{pub_eid}/_");

        let cache =
            AdvancedCache::declare(&session, adv_ke.clone(), CacheConfig { max_samples: 8 })
                .expect("advanced cache declares");
        for sn in 0u8..3 {
            cache.cache_sample(CachedSample {
                keyexpr: "demo/data".to_string(),
                payload: vec![sn],
                source_info: Some(SourceInfo::new(&pub_zid, pub_eid, sn as u32)),
                timestamp: TimestampHint {
                    time: 100 + sn as u64,
                    zid: pub_zid.clone(),
                },
            });
        }

        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let misses = Arc::new(Mutex::new(0usize));
        let d = Arc::clone(&delivered);
        let m = Arc::clone(&misses);
        let _sub = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_recovery(RecoveryConfig::new().with_heartbeat())
                .with_allowed_destination(Locality::SessionLocal),
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
            move |_miss: Miss| *m.lock().unwrap() += 1,
        )
        .expect("heartbeat-recovering advanced subscriber declares");

        let live = |sn: u32, v: u8| {
            session
                .publish(
                    "demo/data",
                    &[v],
                    PublishOptions::put()
                        .with_locality(Locality::SessionLocal)
                        .with_source_info(SourceInfo::new(&pub_zid, pub_eid, sn)),
                )
                .expect("loopback live publish");
        };
        live(0, 0xA0);
        live(1, 0xA1);
        assert_eq!(*delivered.lock().unwrap(), vec![0xA0, 0xA1]);

        // The publisher's heartbeat beacon: last sn = 2 on its `@adv` KE.
        session
            .publish(
                &adv_ke,
                &z_serialize::<u32>(&2u32),
                PublishOptions::put().with_locality(Locality::SessionLocal),
            )
            .expect("heartbeat beacon publish");

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0xA0, 0xA1, 0x02],
            "the heartbeat beacon (last sn 2) drove a bounded GET that recovered \
             the lost sn 2 (cache payload 0x02)"
        );
        assert_eq!(
            *misses.lock().unwrap(),
            0,
            "the heartbeat recovery filled it -> no Miss"
        );
    }

    /// R311y86 history-gating unit (no session): while `history_pending`, a
    /// sample BUFFERS instead of delivering; `finish_history` flushes the
    /// buffer oldest-first so the (older) history delivers in order.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    #[test]
    fn history_pending_buffers_then_flushes_in_order() {
        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let d = Arc::clone(&delivered);
        let mut state = State {
            sequenced: HashMap::new(),
            on_sample: Box::new(move |s: Sample| d.lock().unwrap().push(s.payload[0])),
            on_miss: Box::new(|_| {}),
            retransmission: true,
            history_pending: true,
        };
        let key = (vec![0x02u8], 7u32);
        let mk = |sn: u32, v: u8| {
            let mut s = Sample::new_put("demo/data", vec![v]);
            s.source_info = Some(SourceInfo::new(&[0x02], 7, sn));
            s
        };

        // History in flight -> the recovered history buffers, nothing delivers.
        state.handle_recovered(key.clone(), 0, mk(0, 0xA0));
        state.handle_recovered(key.clone(), 1, mk(1, 0xA1));
        assert!(
            delivered.lock().unwrap().is_empty(),
            "samples buffer while the history GET is in flight"
        );
        // History completes -> flush oldest-first.
        state.finish_history();
        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0xA0, 0xA1],
            "the buffered history flushes in order on completion"
        );
    }

    /// R311y86 composed history e2e: a LATE JOINER recovers the publisher's
    /// cached history via the startup GET. The cache holds 0,1,2; a
    /// history-enabled subscriber's declare issues a GET over `demo/data/@adv/**`
    /// that the cache answers, and the buffered history flushes in order on the
    /// terminal Final — all synchronously within declare (loopback).
    #[cfg(all(
        feature = "ext-pubsub-advanced-history",
        feature = "ext-pubsub-advanced-cache",
        feature = "pubsub-allow-loop"
    ))]
    #[test]
    fn composed_history_recovers_cache_for_late_joiner() {
        use crate::advanced_cache::{AdvancedCache, CacheConfig, CachedSample};
        use wz_session_core::sample::TimestampHint;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let pub_zid = vec![0x09u8];
        let pub_eid = 4u32;
        let zid_hex = zid_to_zenoh_hex(&pub_zid);
        let cache_ke = format!("demo/data/@adv/pub/{zid_hex}/{pub_eid}/_");
        let cache = AdvancedCache::declare(&session, cache_ke, CacheConfig { max_samples: 8 })
            .expect("advanced cache declares");
        for sn in 0u8..3 {
            cache.cache_sample(CachedSample {
                keyexpr: "demo/data".to_string(),
                payload: vec![sn],
                source_info: Some(SourceInfo::new(&pub_zid, pub_eid, sn as u32)),
                timestamp: TimestampHint {
                    time: 100 + sn as u64,
                    zid: pub_zid.clone(),
                },
            });
        }

        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let d = Arc::clone(&delivered);
        // The startup history GET fires on declare and recovers the cache.
        let _sub = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_recovery(RecoveryConfig::new())
                .with_history(HistoryConfig::new())
                .with_allowed_destination(Locality::SessionLocal),
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
            |_miss: Miss| {},
        )
        .expect("history-enabled advanced subscriber declares");

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0, 1, 2],
            "the late joiner recovered the publisher's cached history (0,1,2) on declare"
        );
    }

    /// R311y87 (review C2) regression: a per-source recovery GET that completes
    /// WHILE the startup history GET is still in flight must NOT flush — flushing
    /// advances `last_delivered`, after which an older-sn history reply is
    /// silently dropped. The flush is deferred to `finish_history`. Without the
    /// `!history_pending` gate, delivered would be `[0xA1]` (sn 0 LOST); with it,
    /// `[0xA0, 0xA1]`.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    #[test]
    fn recovery_completing_mid_history_defers_flush() {
        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let d = Arc::clone(&delivered);
        let mut state = State {
            sequenced: HashMap::new(),
            on_sample: Box::new(move |s: Sample| d.lock().unwrap().push(s.payload[0])),
            on_miss: Box::new(|_| {}),
            retransmission: true,
            history_pending: true,
        };
        let key = (vec![0x02u8], 7u32);
        let mk = |sn: u32, v: u8| {
            let mut s = Sample::new_put("demo/data", vec![v]);
            s.source_info = Some(SourceInfo::new(&[0x02], 7, sn));
            s
        };
        // A per-source recovery GET is in flight (pending_queries=1) and has
        // buffered sn 1, while the startup history GET is also in flight.
        let mut buffered = BTreeMap::new();
        buffered.insert(1u32, mk(1, 0xA1));
        state.sequenced.insert(
            key.clone(),
            SourceState {
                last_delivered: None,
                pending_samples: buffered,
                pending_queries: 1,
            },
        );

        // The recovery GET completes mid-history -> must NOT flush.
        state.finish_recovery(&key);
        assert!(
            delivered.lock().unwrap().is_empty(),
            "no flush while history is pending (a flush would lose later history)"
        );
        // An older history reply (sn 0) arrives -> buffered (history-gated).
        state.handle_recovered(key.clone(), 0, mk(0, 0xA0));
        // History completes -> flush 0,1 in order; sn 0 was NOT lost.
        state.finish_history();
        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0xA0, 0xA1],
            "the deferred flush delivers 0,1 in order; the mid-history recovery did not lose sn 0"
        );
    }

    /// R311y89 (review C3) — the pure timeout-ms conversion. The lower clamp is the
    /// correctness bite: a `0`/sub-ms `Duration` must NOT pass through as the
    /// `timeout_ms == 0` "never-expire" sentinel (which registers the GET with a
    /// `None` deadline the sweep skips forever — the no-answerer wedge).
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    #[test]
    fn recovery_query_timeout_ms_clamps_to_a_live_deadline() {
        // The zenoh default (10s) maps to 10000 ms.
        assert_eq!(recovery_query_timeout_ms(Duration::from_secs(10)), 10_000);
        // A zero / sub-ms timeout clamps UP to 1 ms — never the 0 "never-expire"
        // sentinel.
        assert_eq!(recovery_query_timeout_ms(Duration::ZERO), 1);
        assert_eq!(recovery_query_timeout_ms(Duration::from_micros(500)), 1);
        // A timeout past u32::MAX ms caps at u32::MAX (the with_timeout_ms field is u32).
        assert_eq!(
            recovery_query_timeout_ms(Duration::from_millis(u64::from(u32::MAX) + 1)),
            u32::MAX
        );
    }

    /// R311y89 (review C3) regression: a startup history GET with NO `@adv` answerer
    /// must not wedge the subscriber forever. `Locality::Any` emits a wire Query
    /// (expecting a peer `Final` that never arrives) and fans loopback; with no cache
    /// declared the loopback yields only its synthetic `Final` (1 of the 2 expected),
    /// so `history_pending` stays set and a live sample buffers undelivered. The C3
    /// timeout registers the GET with a live deadline, so the reply registry's
    /// deadline sweep fires the synthetic terminal `Final` -> `finish_history` clears
    /// the gate and flushes the buffer. WITHOUT the timeout (`timeout_ms == 0` ->
    /// `deadline_ms == None`) the sweep skips the entry forever and `delivered`
    /// stays empty — the diagnose-first failing arm.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    #[test]
    fn history_get_with_no_answerer_is_rescued_by_the_timeout_sweep() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let d = Arc::clone(&delivered);
        let timeout = Duration::from_millis(50);
        let _sub = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_recovery(RecoveryConfig::new())
                .with_history(HistoryConfig::new())
                .with_allowed_destination(Locality::Any)
                .with_query_timeout(timeout),
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
            |_miss: Miss| {},
        )
        .expect("history-enabled advanced subscriber declares");

        // A live sample arrives while history is pending -> buffered, NOT delivered.
        session
            .publish(
                "demo/data",
                &[0x42],
                PublishOptions::put()
                    .with_locality(Locality::SessionLocal)
                    .with_source_info(SourceInfo::new(&[0x02], 7, 0)),
            )
            .expect("loopback live publish");
        assert!(
            delivered.lock().unwrap().is_empty(),
            "the live sample is buffered while the un-answered history GET is pending"
        );

        // Drive the reply registry's deadline sweep past the GET's timeout: the
        // synthetic terminal Final fires finish_history (clears history_pending +
        // flushes the buffered sample). now + timeout + 1 is guaranteed past the
        // deadline (= now_at_issue + timeout, now_at_issue <= now by monotonicity).
        let now_past_deadline = session.clock().now_monotonic_ms() + timeout.as_millis() as u64 + 1;
        session
            .observer()
            .lock()
            .unwrap()
            .replies
            .sweep_timed_out(now_past_deadline);
        session.drain_deferred_fires();

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0x42],
            "the timeout sweep released the wedged history; the buffered sample delivered"
        );
    }

    /// R311y90 (review C5) regression: declaring a recovering subscriber with
    /// periodic_queries OFF a tokio runtime must FAIL CLEAR with NoRuntime, not
    /// panic inside tokio::spawn. This `#[test]` runs outside any runtime, so
    /// Handle::try_current() returns Err -> the declare returns NoRuntime before
    /// any subscriber is declared. Pre-fix the periodic-task spawn panicked
    /// (aborting the test); the guard makes it a clean Result.
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    #[test]
    fn declare_with_periodic_off_runtime_fails_clear_not_panic() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let result = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new().with_recovery(
                RecoveryConfig::new().with_periodic_queries(Duration::from_millis(100)),
            ),
            |_sample: Sample| {},
            |_miss: Miss| {},
        );
        assert!(
            matches!(result, Err(AdvancedSubscribeError::NoRuntime)),
            "periodic recovery off-runtime must fail clear with NoRuntime, not panic"
        );
    }

    /// R311y91 (review M1) — history-WITHOUT-retransmission is now representable
    /// (zenoh keeps `.recovery()` / `.history()` separate). An
    /// `AdvancedSubscriberOptions` with history set but NO recovery (retransmission
    /// off) still recovers a late joiner's cached history on declare. Before the
    /// split, history rode `RecoveryConfig`, so `retransmission = recovery.is_some()`
    /// was forced ON whenever history was set -- this config was unrepresentable.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    #[test]
    fn history_only_without_recovery_recovers_late_joiner_cache() {
        use crate::advanced_cache::{AdvancedCache, CacheConfig, CachedSample};
        use wz_session_core::sample::TimestampHint;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let pub_zid = vec![0x09u8];
        let pub_eid = 4u32;
        let zid_hex = zid_to_zenoh_hex(&pub_zid);
        let cache_ke = format!("demo/data/@adv/pub/{zid_hex}/{pub_eid}/_");
        let cache = AdvancedCache::declare(&session, cache_ke, CacheConfig { max_samples: 8 })
            .expect("advanced cache declares");
        for sn in 0u8..3 {
            cache.cache_sample(CachedSample {
                keyexpr: "demo/data".to_string(),
                payload: vec![sn],
                source_info: Some(SourceInfo::new(&pub_zid, pub_eid, sn as u32)),
                timestamp: TimestampHint {
                    time: 100 + sn as u64,
                    zid: pub_zid.clone(),
                },
            });
        }

        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let d = Arc::clone(&delivered);
        // history ON, recovery OFF (no with_recovery -> recovery None -> retransmission
        // false): the startup history GET still fires and recovers the cache.
        let _sub = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_history(HistoryConfig::new())
                .with_allowed_destination(Locality::SessionLocal),
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
            |_miss: Miss| {},
        )
        .expect("history-only (no recovery) advanced subscriber declares");

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0, 1, 2],
            "history-only (retransmission off) still recovered the cache (0,1,2) on declare"
        );
    }
}
