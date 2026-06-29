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
//! - **Recovering** ([`AdvancedSubscriber::declare_with_recovery`], gated
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
//! ### Recovery triggers (sample-driven + periodic built; heartbeat follow-on)
//!
//! zenoh drives recovery from THREE triggers: the sample-driven GET (the gap
//! handling above), a periodic `Timer` GET (advanced_subscriber.rs:585-643),
//! and a heartbeat-subscriber GET keyed off the publisher's last-sn beacon
//! (:1045-1149, `z_deserialize::<u32>`). wz builds the **sample-driven**
//! (R311y82) + **periodic** (R311y83, [`RecoveryConfig::periodic_queries`]:
//! a background task re-asks every source `_sn=last+1..` every period, catching
//! a lost LAST sample no later live sample would trigger recovery for). The
//! **heartbeat** trigger is the remaining follow-on under this same
//! `ext-pubsub-advanced-recovery` gate. A recovered reply cannot carry its
//! original body timestamp (the [`crate::reply_sink::ReplyView`] seam surfaces
//! source_info / encoding / attachment, not the reply timestamp), so a
//! retransmitted sample is delivered timestamp-less — a documented fidelity
//! gap, not silent (the recovery essential is the source identity that re-keys
//! it).

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
use wz_session_core::zid_hex::zid_to_zenoh_hex;

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

/// Configuration for a recovering subscriber ([`AdvancedSubscriber::declare_with_recovery`]).
/// The sample-driven `_sn`-range recovery GET is implied by recovering at all
/// (zenoh's `retransmission.is_some()`); [`Self::periodic_queries`] adds the
/// R311y83 periodic trigger. The heartbeat trigger is a follow-on field under
/// this same gate.
#[cfg(feature = "ext-pubsub-advanced-recovery")]
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct RecoveryConfig {
    /// Locality for the recovery `_sn`-range GET. `Any` (default) reaches a
    /// remote publisher's `@adv` cache AND the local loopback; `SessionLocal`
    /// pins it to loopback (single-host composition tests). Mirrors zenoh's
    /// recovery get target (advanced_subscriber.rs:603, `query_target` All).
    pub allowed_destination: Locality,
    /// R311y83 — when `Some(period)`, a background task re-asks every known
    /// source `_sn=last+1..` every `period`, catching a lost LAST sample that
    /// no further live sample would trigger sample-driven recovery for (zenoh's
    /// `RecoveryConfig::periodic_queries`, advanced_subscriber.rs:111-116 + the
    /// `PeriodicQuery` TimedEvent :580-643). `None` (default) = sample-driven
    /// recovery only. NB enabling this spawns a tokio task at declare time, so
    /// the caller MUST be inside a tokio runtime context (the sample-driven and
    /// no-recovery paths have no such requirement).
    pub periodic_queries: Option<Duration>,
}

#[cfg(feature = "ext-pubsub-advanced-recovery")]
impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            allowed_destination: Locality::Any,
            periodic_queries: None,
        }
    }
}

#[cfg(feature = "ext-pubsub-advanced-recovery")]
impl RecoveryConfig {
    /// Sample-driven recovery with default routing (`Locality::Any`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin the recovery GET's locality (e.g. `SessionLocal` for a loopback
    /// composition).
    pub fn with_allowed_destination(mut self, locality: Locality) -> Self {
        self.allowed_destination = locality;
        self
    }

    /// Enable the periodic recovery trigger with the given re-ask period (see
    /// [`Self::periodic_queries`]). Requires a tokio runtime at declare time.
    pub fn with_periodic_queries(mut self, period: Duration) -> Self {
        self.periodic_queries = Some(period);
        self
    }
}

/// What [`State::handle_live`] asks the caller to do AFTER releasing the state
/// lock: issue a `_sn={from_sn}..` recovery GET against `(zid, eid)`'s `@adv`
/// cache. Returned (not issued inline) so the re-entrant `Session::query` runs
/// without the state mutex held.
#[cfg(feature = "ext-pubsub-advanced-recovery")]
struct RecoveryRequest {
    zid: Vec<u8>,
    eid: u32,
    from_sn: u32,
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
    /// [`AdvancedSubscriber::declare_with_recovery`]) or report a [`Miss`] and
    /// deliver past the gap (false, the plain [`AdvancedSubscriber::declare`]).
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    retransmission: bool,
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
            None => deliver_and_flush(state, sn, sample, on_sample),
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
                });
            }
        }
        requests
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
) where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    let zid_hex = zid_to_zenoh_hex(&req.zid);
    let recovery_ke = format!("{base_keyexpr}/@adv/*/{zid_hex}/{}/**", req.eid);
    let params = format!("_sn={}..", req.from_sn).into_bytes();
    let opts = QueryOptions::get()
        .with_allowed_destination(dest)
        .with_parameters(params);

    let key = (req.zid, req.eid);
    let reply_states = Arc::clone(statesref);
    let final_states = Arc::clone(statesref);
    let final_key = key;
    let _ = session.query(
        &recovery_ke,
        opts,
        move |reply: &dyn ReplyView| {
            if reply.kind() != ReplyKind::Put {
                return;
            }
            // A recovery reply with no source identity cannot be re-keyed into
            // a per-source stream (it needs `reply-source-info` on the answerer).
            let Some(source_info) = reply.source_info() else {
                return;
            };
            let rkey = (source_info.zid_prefix().to_vec(), source_info.eid);
            let rsn = source_info.sn;
            let mut sample = Sample::new_put(reply.keyexpr(), reply.payload().to_vec());
            sample.source_info = Some(source_info.clone());
            sample.attachment = reply.attachment().map(<[u8]>::to_vec);
            if let Some((packed_id, schema)) = reply.put_encoding() {
                sample.encoding = Some(EncodingHint {
                    packed_id,
                    schema: schema.map(String::from),
                });
            }
            reply_states
                .lock()
                .expect("advanced subscriber state mutex poisoned")
                .handle_recovered(rkey, rsn, sample);
        },
        move |_rid| {
            final_states
                .lock()
                .expect("advanced subscriber state mutex poisoned")
                .finish_recovery(&final_key);
        },
    );
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
        issue_recovery_query(session, statesref, base_keyexpr, req, dest);
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
    /// a [`Miss`] and delivers past the hole. See [`Self::declare_with_recovery`]
    /// for the gap-recovering form.
    pub fn declare<T, OnSample, OnMiss>(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        on_sample: OnSample,
        on_miss: OnMiss,
    ) -> Result<Self, SubscribeError>
    where
        R: 'static,
        T: TimeSource + Send + Sync + 'static,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        SessionLinkActions<R, T>: Send + Sync + 'static,
        Session<R, T, Unicast>: Send + 'static,
        OnSample: FnMut(Sample) + Send + 'static,
        OnMiss: FnMut(Miss) + Send + 'static,
    {
        Self::declare_impl(session, keyexpr, on_sample, on_miss, None)
    }

    /// Declare a gap-recovering advanced subscriber: a forward gap is buffered
    /// and a sample-driven `_sn`-range recovery GET refills it from the
    /// publisher's `@adv` cache (see the module docs). `on_miss` fires only
    /// for a hole the recovery does NOT fill.
    pub fn declare_with_recovery<T, OnSample, OnMiss>(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        recovery: RecoveryConfig,
        on_sample: OnSample,
        on_miss: OnMiss,
    ) -> Result<Self, SubscribeError>
    where
        R: 'static,
        T: TimeSource + Send + Sync + 'static,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        SessionLinkActions<R, T>: Send + Sync + 'static,
        Session<R, T, Unicast>: Send + 'static,
        OnSample: FnMut(Sample) + Send + 'static,
        OnMiss: FnMut(Miss) + Send + 'static,
    {
        Self::declare_impl(session, keyexpr, on_sample, on_miss, Some(recovery))
    }

    fn declare_impl<T, OnSample, OnMiss>(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        on_sample: OnSample,
        on_miss: OnMiss,
        recovery: Option<RecoveryConfig>,
    ) -> Result<Self, SubscribeError>
    where
        R: 'static,
        T: TimeSource + Send + Sync + 'static,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        SessionLinkActions<R, T>: Send + Sync + 'static,
        Session<R, T, Unicast>: Send + 'static,
        OnSample: FnMut(Sample) + Send + 'static,
        OnMiss: FnMut(Miss) + Send + 'static,
    {
        let retransmission = recovery.is_some();
        let dest = recovery
            .map(|c| c.allowed_destination)
            .unwrap_or(Locality::Any);
        let periodic = recovery.and_then(|c| c.periodic_queries);
        let base_keyexpr: String = keyexpr.into();

        let state = Arc::new(Mutex::new(State {
            sequenced: HashMap::new(),
            on_sample: Box::new(on_sample),
            on_miss: Box::new(on_miss),
            retransmission,
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
                    issue_recovery_query(&q_session, &cb_state, &q_base, request, dest);
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
            let p_base = base_keyexpr;
            let clock = Arc::clone(session.clock());
            let period_ms = period.as_millis() as u64;
            PeriodicTask {
                handle: tokio::spawn(async move {
                    loop {
                        clock.sleep(period_ms).await;
                        run_periodic_tick(&p_session, &p_state, &p_base, dest);
                    }
                }),
            }
        });

        Ok(Self {
            _subscriber: subscriber,
            _statesref: state,
            _periodic: periodic_task,
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
        use crate::advanced_publisher::{AdvancedPublisher, AdvancedPublisherOptions, Sequencing};

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
        let _sub = AdvancedSubscriber::declare_with_recovery(
            &session,
            "demo/data",
            RecoveryConfig::new().with_allowed_destination(Locality::SessionLocal),
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
        let sub = AdvancedSubscriber::declare_with_recovery(
            &session,
            "demo/data",
            RecoveryConfig::new().with_allowed_destination(Locality::SessionLocal),
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
}
