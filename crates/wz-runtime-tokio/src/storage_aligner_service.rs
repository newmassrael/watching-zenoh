// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Round 311 A8c-2a/A8c-2b/A8c-2c — the storage-aligner DRIVER (§5.11 storage
//! domain, aligner): the AP-side tokio binding for the alignment exchange. The
//! ANSWER leg ([`AlignerService`]) answers a peer's alignment query with the
//! entries it needs; the ASK leg ([`query_replica_aligner`]) pulls a peer's
//! diverging entries until this replica converges; the WIRE seam
//! ([`spawn_digest_aligner`]) auto-triggers an ASK pull from the digest
//! subscriber's `on_diff` when a divergence is detected.
//!
//! The no_std kernel ([`wz_session_core::storage_aligner`] +
//! [`StorageState::answer_alignment_query`](wz_session_core::storage_state::StorageState::answer_alignment_query))
//! decodes nothing and emits nothing — it takes a typed
//! [`AlignmentQuery`](wz_session_core::storage_aligner::AlignmentQuery) and
//! returns the full `Vec<AlignmentResponse>` to send back. This module is its
//! tokio binding: an [`AlignerService`] declares a [`Queryable`] on this
//! replica's aligner keyexpr (`@zid/<zid-hex>/<config-fp>/aligner`), and each
//! inbound query is decoded from its attachment
//! ([`decode_alignment_query`](wz_session_core::storage_aligner::wire::decode_alignment_query)),
//! answered by the kernel, and every response emitted on the reply seam
//! ([`ReplyOut::reply_keyed_attached`](wz_session_core::query_sink::ReplyOut::reply_keyed_attached)):
//! the serialized
//! [`AlignmentReply`](wz_session_core::storage_aligner::AlignmentReply) rides
//! the reply attachment, the retrieved value (if any) rides the payload. It
//! shares the live [`crate::storage_service::StorageService`] state (via
//! [`StorageService::shared_state`](crate::storage_service::StorageService::shared_state)),
//! so the answer reflects the actual stored data. Dropping the service
//! undeclares the queryable (RAII teardown).
//!
//! ## zenoh anchor
//!
//! Mirrors zenoh 1.5.0 `Replication::spawn_aligner_queryable` +
//! `Replication::aligner`
//! (`plugins/zenoh-plugin-storage-manager/src/replication/core.rs:415-467`
//! and `core/aligner_query.rs:73-172`): the queryable is declared on the
//! `aligner_key_expr_formatter` `@zid/${zid:*}/${hash_configuration:*}/aligner`
//! (core.rs:47) with `allowed_origin(Locality::Remote)` (core.rs:444); a query
//! with an empty attachment is skipped (core.rs:460-462, aligner_query.rs:74-80);
//! otherwise the attachment is deserialized into an `AlignmentQuery` and the
//! matching reply(s) are emitted via `reply_to_query`
//! (aligner_query.rs:340-362): `q.reply(q.key_expr(), value).encoding(enc)
//! .attachment(bincode(reply))` for a retrieval, or an empty-payload
//! `q.reply(q.key_expr(), ZBytes::new()).attachment(bincode(reply))` for a
//! metadata-only reply.
//!
//! ## Deliberate divergences (each documented)
//!
//! - **Callback-driven, not a `recv_async` loop with a task per query.** zenoh
//!   loops `while queryable.recv_async()` and spawns a fresh task per received
//!   query (core.rs:459-467) because its answer awaits an async `RwLock` over
//!   the replication log / storage. wz's [`StorageState::answer_alignment_query`]
//!   is synchronous and pure over the locked snapshot — it returns the full
//!   `Vec<AlignmentResponse>` in one shot with no awaits mid-answer — so the
//!   session's queryable registry fires the answer closure directly. There is
//!   no per-query task to spawn and nothing to block the drive loop.
//! - **No replication log.** zenoh reads `EventMetadata` and `Fingerprint`s out
//!   of its `LogLatest` (aligner_query.rs:106-264). wz has no log; the kernel
//!   recomputes interval / sub-interval buckets + `EventMetadata` from the
//!   `StorageState.latest` snapshot (the [`wz_session_core::storage_aligner`]
//!   divergence note). This module is unaffected — it consumes the kernel's
//!   `Vec`, however the kernel produced it.
//!
//! ## ASK side (A8c-2b)
//!
//! [`query_replica_aligner`] is the dual: it spawns a task that pulls a peer's
//! diverging entries. It serializes an [`AlignmentQuery`] onto a query
//! attachment, GETs the peer's aligner keyexpr
//! ([`Session::query`](crate::session::Session::query)) with the right
//! consolidation ([`consolidation_for`]), decodes each reply
//! ([`decode_reply`]) into an [`AlignmentReply`] (+ a Put `Retrieval`'s
//! value), and feeds it to the kernel
//! [`process_alignment_reply`](wz_session_core::storage_state::StorageState::process_alignment_reply),
//! which returns an [`AlignmentFollowup`] the driver follows
//! ([`next_query`]) — issuing the next, finer query until convergence. zenoh
//! `spawn_query_replica_aligner` + `process_alignment_reply`
//! (core.rs:484-577, core/aligner_reply.rs:99-303): zenoh spawns a fresh task
//! per followup; wz drains a work queue (the same request tree, one task).
//!
//! ## Coverage + the remaining live leg
//!
//! A8c-2a (answer queryable), A8c-2b (the ASK pull loop), and A8c-2c (the
//! `on_diff` → [`spawn_digest_aligner`] auto-wiring + facade + run-ci) are all
//! here. The pure decode / consolidation / followup helpers are unit tested and
//! the answer→pull convergence is proven deterministically off the wire
//! ([`tests`]). The async transport itself — [`issue_and_collect`] /
//! [`run_alignment`] / the `on_diff`→pull spawn — is exercised only by the live
//! **two-replica** A11 e2e, because the answer queryable + digest subscriber are
//! both [`Locality::Remote`] and so cannot be driven by a single-session
//! loopback; that is the one remaining live leg.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;
use wz_session_core::locality::Locality;
use wz_session_core::query_mode::ConsolidationMode;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::reply_sink::ReplyView;
use wz_session_core::sample::EncodingHint;
use wz_session_core::storage_aligner::wire::{
    decode_alignment_query, decode_alignment_reply, encode_alignment_query, encode_alignment_reply,
};
use wz_session_core::storage_aligner::{
    Action, AlignmentFollowup, AlignmentQuery, AlignmentReply, RetrievedValue,
};
use wz_session_core::storage_backend::StorageBackend;
use wz_session_core::storage_replication::{zid_to_zenoh_hex, DigestDiff, ReplicationConfig};
use wz_session_core::storage_state::StorageState;

use crate::session::{
    QueryOptions, Queryable, QueryableError, QueryableOptions, Session, SubscribeError, Unicast,
};
use crate::session_glue::SessionLinkActions;
use crate::storage_replication_service::DigestSubscriber;
use crate::timestamp_source::wall_clock_ntp64;

/// Per-query alignment timeout. The wire query is issued with this
/// `with_timeout_ms`, so a session that runs the reply-timeout **sweep** fires
/// the proper Err+Final (hence `on_final`) when the targeted replica is silent.
/// zenoh's session default get timeout is 10s (zenoh-config `defaults.rs:151`
/// `queries_default_timeout`); wz matches it.
///
/// The sweep ([`ReplyRegistry::sweep_timed_out`](crate::reply::ReplyRegistry))
/// is a SEPARATE task — R268 relocated it out of `drive_session_until_terminal`
/// — so the pull loop must NOT assume it is running. [`issue_and_collect`]
/// therefore also wraps the `on_final` await in a [`tokio::time::timeout`]
/// backstop ([`ALIGNER_QUERY_TIMEOUT_MS`] + [`ALIGNER_BACKSTOP_SLACK_MS`]): a
/// sweep-equipped session resolves on the real Err+Final first; a session
/// without a sweep still resolves on the backstop, so a spawned alignment task
/// is SELF-BOUNDED and never hangs on a silent peer regardless of how the
/// session is driven.
const ALIGNER_QUERY_TIMEOUT_MS: u32 = 10_000;

/// Extra wait the [`issue_and_collect`] backstop allows beyond the wire
/// `with_timeout_ms` before giving up on `on_final`, so a sweep-equipped
/// session's real Err+Final wins the race and the backstop only trips when no
/// sweep is reclaiming the query.
const ALIGNER_BACKSTOP_SLACK_MS: u64 = 1_000;

/// Defensive cap on the number of queries one [`run_alignment`] issues. A
/// conformant peer's refinement tree is shallow (Cold → Intervals →
/// SubIntervals → Events → Retrieval) and finite, so a real alignment stays far
/// below this. A hostile/buggy peer, however, can answer ANY query with fresh
/// `Discovery` replies to grow the followup queue without bound (zenoh has the
/// same exposure via unbounded task spawns, `aligner_reply.rs:106-138`); wz's
/// single-task drain makes a cheap cap natural. Hitting it abandons THIS pass —
/// the next digest tick re-triggers if the replica is still diverged, so a
/// genuinely deep alignment still converges over successive ticks, it is only
/// bounded per pass. A generous defensive bound, not a tuning knob.
const MAX_ALIGNMENT_QUERIES: usize = 100_000;

/// One decoded aligner reply: the typed [`AlignmentReply`] plus the
/// [`RetrievedValue`] a Put `Retrieval` carries (`None` for a metadata reply).
/// The kernel [`process_alignment_reply`](wz_session_core::storage_state::StorageState::process_alignment_reply)
/// input. Factored to a `type` per `clippy::type_complexity`.
type DecodedReply = (AlignmentReply, Option<RetrievedValue>);

/// The keyexpr this replica's aligner queryable answers on:
/// `@zid/<zid-hex>/<config-fp>/aligner`. zenoh `aligner_key_expr_formatter`
/// `@zid/${zid:*}/${hash_configuration:*}/aligner` (core.rs:47), filled with
/// this replica's zid and configuration fingerprint — the SAME two values the
/// digest keyexpr carries.
///
/// Both components render through zenoh's `keformat` `set<S: Display>`: the zid
/// via zenoh's `ZenohId` Display (the
/// [`zid_to_zenoh_hex`](wz_session_core::storage_replication::zid_to_zenoh_hex)
/// SSOT — LE id read as a `u128`, big-endian hex, one leading zero stripped,
/// NOT a naive per-byte hex) and the fingerprint via the `u64`'s decimal
/// `Display` (`Fingerprint` `Deref`s to `u64`). Using the shared SSOT keeps
/// this byte-identical to a real zenoh's keyexpr and consistent with the
/// digest keyexpr + the aligner's `AlignmentReply::Discovery` zid encoding, so
/// an asker querying `@zid/<our-zid>/<fp>/aligner` reaches this queryable.
pub fn aligner_keyexpr(config: &ReplicationConfig, local_zid: &[u8]) -> String {
    aligner_keyexpr_for_hex(config, &zid_to_zenoh_hex(local_zid))
}

/// The aligner keyexpr for a peer whose zid hex is ALREADY known —
/// `@zid/<zid-hex>/<config-fp>/aligner`. The digest-driven path uses this: the
/// digest subscriber parses a peer's zid hex out of its digest keyexpr
/// ([`digest_keyexpr_zid_hex`](crate::storage_replication_service::digest_keyexpr_zid_hex))
/// and this rebuilds the peer's aligner keyexpr from it — reaching exactly the
/// keyexpr that peer's aligner queryable ([`AlignerService`]) is declared on,
/// since both derive from the same [`zid_to_zenoh_hex`] rendering. The byte-form
/// [`aligner_keyexpr`] delegates here after rendering the zid, so the keyexpr
/// format string lives in ONE place.
pub fn aligner_keyexpr_for_hex(config: &ReplicationConfig, zid_hex: &str) -> String {
    format!("@zid/{}/{}/aligner", zid_hex, config.fingerprint().value())
}

/// Answer one inbound alignment query: decode the `AlignmentQuery` from the
/// query attachment, run the kernel answer engine over the locked shared
/// state, and emit every [`AlignmentResponse`](wz_session_core::storage_aligner::AlignmentResponse)
/// on the reply seam. `now` is the wall-clock NTP64 the kernel uses for the
/// Hot-era upper bound in a `Diff` answer (injected so the answer is
/// deterministically testable). Pure over the shared state: no Session, no
/// clock — the testable core of the queryable callback.
///
/// A query with no attachment, or an attachment that fails to decode, produces
/// no replies (zenoh skips it: core.rs:460-462 + aligner_query.rs:74-91) —
/// never fatal. Each response's reply keyexpr is the query's own keyexpr (the
/// aligner keyexpr the query arrived on), matching zenoh's
/// `q.reply(q.key_expr(), ..)` (aligner_query.rs:351/356); a metadata-only
/// response (every reply but a Put `Retrieval`) carries an empty payload, the
/// retrieved value (a Put `Retrieval`) carries its payload + encoding. The
/// serialized `AlignmentReply` always rides the attachment.
fn answer_alignment_into<B: StorageBackend>(
    state: &Arc<Mutex<StorageState<B>>>,
    config: &ReplicationConfig,
    local_zid: &[u8],
    view: &dyn QueryView,
    out: &mut dyn ReplyOut,
    now: u64,
) {
    let query_bytes = match view.attachment() {
        Some(bytes) => bytes,
        // zenoh skips a query with an empty attachment (core.rs:460-462,
        // aligner_query.rs:74-80) — there is nothing to align against.
        None => return,
    };
    let query = match decode_alignment_query(query_bytes) {
        Ok(query) => query,
        // A malformed attachment is logged + dropped by zenoh
        // (aligner_query.rs:82-91); here it is ignored, never fatal.
        Err(_) => return,
    };

    let responses = {
        let guard = state.lock().expect("storage state mutex poisoned");
        guard.answer_alignment_query(config, &query, local_zid, now)
    };

    for response in responses {
        let attachment = encode_alignment_reply(&response.reply);
        match &response.value {
            // A Put Retrieval: the stored value rides the payload (+ encoding),
            // the AlignmentReply rides the attachment.
            Some(value) => out.reply_keyed_attached(
                view.keyexpr(),
                &value.payload,
                value.encoding.as_ref(),
                &attachment,
            ),
            // A metadata-only reply (Discovery / Intervals / SubIntervals /
            // EventsMetadata / a Delete Retrieval): an empty-payload Put
            // carrying only the AlignmentReply attachment.
            None => out.reply_keyed_attached(view.keyexpr(), &[], None, &attachment),
        }
    }
}

/// A live aligner answer service bound to a [`Session`]: a [`Queryable`] on
/// this replica's aligner keyexpr (`@zid/<zid-hex>/<config-fp>/aligner`) that
/// answers a peer's [`AlignmentQuery`](wz_session_core::storage_aligner::AlignmentQuery)
/// with the entries it needs to converge. Dropping it undeclares the queryable
/// (RAII teardown), so the service's lifetime is the handle's lifetime.
///
/// The queryable uses [`Locality::Remote`] so a replica does not answer its
/// OWN alignment queries (zenoh `allowed_origin(Locality::Remote)`,
/// core.rs:444), and is left INCOMPLETE (zenoh declares the aligner queryable
/// without `.complete(..)`, core.rs:441-444): an asker targets a specific
/// replica's fully-qualified aligner keyexpr, so the BestMatching completeness
/// signal is irrelevant here.
pub struct AlignerService<R: SessionRuntime, T: TimeSource> {
    _queryable: Queryable<R, T>,
}

impl<R, T> AlignerService<R, T>
where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    /// Declare the aligner answer queryable. `state` is shared with the
    /// [`StorageService`](crate::storage_service::StorageService) (pass its
    /// `shared_state()`), so each answer reflects the live stored data.
    /// `config` + `local_zid` fix the queryable keyexpr (this replica's
    /// [`aligner_keyexpr`]) and the `AlignmentReply::Discovery` identity; both
    /// must match what this replica publishes on its digest keyexpr so an asker
    /// reaches the right queryable.
    pub fn declare<B>(
        session: &Session<R, T, Unicast>,
        state: Arc<Mutex<StorageState<B>>>,
        config: ReplicationConfig,
        local_zid: Vec<u8>,
    ) -> Result<Self, QueryableError>
    where
        B: StorageBackend + Send + 'static,
    {
        let keyexpr = aligner_keyexpr(&config, &local_zid);
        let queryable = session.declare_queryable(
            keyexpr,
            QueryableOptions::default().with_allowed_origin(Locality::Remote),
            move |view: &dyn QueryView, out: &mut dyn ReplyOut| {
                // `now` is read at answer time for the Hot-era upper bound a
                // `Diff` answer needs; the pure core is tested with a fixed one.
                answer_alignment_into(&state, &config, &local_zid, view, out, wall_clock_ntp64());
            },
        )?;
        Ok(Self {
            _queryable: queryable,
        })
    }
}

// ============================================================================
// ASK side (A8c-2b) — the pull loop.
// ============================================================================

/// The query consolidation an [`AlignmentQuery`] is issued with.
///
/// `Discovery` wants the single most-reactive replica, so `Monotonic` forwards
/// only the first answer (zenoh core.rs:506-515). Every other query may produce
/// several Samples — one reply per event — so `None` keeps them all
/// (the `ConsolidationMode::None` default, core.rs:504); `Monotonic`/`Latest`
/// would consolidate all but one away.
fn consolidation_for(query: &AlignmentQuery) -> ConsolidationMode {
    match query {
        AlignmentQuery::Discovery => ConsolidationMode::Monotonic,
        _ => ConsolidationMode::None,
    }
}

/// Project a Put reply's body into the [`RetrievedValue`] a Put `Retrieval`
/// carries: the payload bytes + the value encoding (`put_encoding`, the inner
/// `MsgPut` E-flag; A8b). zenoh reads the value off the received reply `sample`
/// (`process_event_retrieval` destructures `SampleFields { payload, encoding }`,
/// aligner_reply.rs:367-369).
fn retrieved_value(view: &dyn ReplyView) -> RetrievedValue {
    RetrievedValue {
        payload: view.payload().to_vec(),
        encoding: view.put_encoding().map(|(packed_id, schema)| EncodingHint {
            packed_id,
            schema: schema.map(String::from),
        }),
    }
}

/// Decode one inbound aligner reply into the kernel's `(AlignmentReply, value)`
/// input. The serialized [`AlignmentReply`] rides the reply attachment (A8b
/// `ReplyView::attachment`); a reply with no attachment, or one that fails to
/// decode, is skipped (zenoh core.rs:539-557) — `None`, never fatal. Only a
/// **Put** `Retrieval` carries a value (the stored payload + encoding); a
/// **Delete** `Retrieval` and every metadata reply carry `None` — matching the
/// answer side, which emits a value only for a Put `Retrieval`
/// (storage_state.rs answer engine) and an empty-payload Put otherwise. The
/// value-presence is derived from the event [`Action`] discriminant (the single
/// source the answer + kernel-consume sides also key on), not from the
/// `Retrieval` variant alone. Pure over the [`ReplyView`] — the testable core
/// of the on_reply callback.
fn decode_reply(view: &dyn ReplyView) -> Option<DecodedReply> {
    let attachment = view.attachment()?;
    let reply = decode_alignment_reply(attachment).ok()?;
    let value = match &reply {
        AlignmentReply::Retrieval(meta) if matches!(meta.action(), Action::Put) => {
            Some(retrieved_value(view))
        }
        _ => None,
    };
    Some((reply, value))
}

/// Map a kernel [`AlignmentFollowup`] to the next query to issue, if any.
///
/// - `Done` → nothing; this branch converged.
/// - `Query(q)` → re-query the SAME peer for finer detail (an Intervals /
///   SubIntervals / Events diff; zenoh re-uses `replica_aligner_ke`,
///   aligner_reply.rs:154/195/219).
/// - `DiscoveredReplica(zid)` → align with the discovered replica via `All` on
///   ITS own aligner keyexpr (zenoh derives it from the zid,
///   aligner_reply.rs:118-133).
fn next_query(
    followup: AlignmentFollowup,
    current_ke: &str,
    config: &ReplicationConfig,
) -> Option<(String, AlignmentQuery)> {
    match followup {
        AlignmentFollowup::Done => None,
        AlignmentFollowup::Query(query) => Some((current_ke.to_string(), query)),
        AlignmentFollowup::DiscoveredReplica(zid) => {
            Some((aligner_keyexpr(config, &zid), AlignmentQuery::All))
        }
    }
}

/// The wildcard keyexpr the INITIAL alignment (`Discovery`) queries:
/// `@zid/*/<config-fp>/aligner` — any replica on this configuration. The
/// `Monotonic` consolidation then selects the single most-reactive responder
/// (zenoh initial alignment); its `Discovery` reply carries that replica's zid,
/// from which the follow-up `All` derives the specific aligner keyexpr. The
/// digest-driven path instead targets a specific peer via [`aligner_keyexpr`].
pub fn discovery_keyexpr(config: &ReplicationConfig) -> String {
    format!("@zid/*/{}/aligner", config.fingerprint().value())
}

/// Issue one alignment query on `peer_aligner_ke` carrying `query_bytes` and
/// collect every decoded reply, returning once the terminal `ResponseFinal`
/// fires. The query is fire-and-forget at the [`Session::query`] seam; the
/// session drive loop delivers replies through `on_reply` (decoded by
/// [`decode_reply`]) and the terminal `on_final`, which this awaits via a
/// oneshot. A rejected query (e.g. `query-get` disabled) yields no replies.
async fn issue_and_collect<R, T>(
    session: &Session<R, T, Unicast>,
    peer_aligner_ke: &str,
    query_bytes: Vec<u8>,
    consolidation: ConsolidationMode,
) -> Vec<DecodedReply>
where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    let replies: Arc<Mutex<Vec<DecodedReply>>> = Arc::new(Mutex::new(Vec::new()));
    let replies_cb = Arc::clone(&replies);
    let (final_tx, final_rx) = tokio::sync::oneshot::channel::<()>();
    // `on_final` is `FnMut`; wrap the one-shot sender so the first fire sends
    // and any later fire is a no-op (take()).
    let final_tx = Arc::new(Mutex::new(Some(final_tx)));

    let issued = session.query(
        peer_aligner_ke,
        QueryOptions::get()
            .with_attachment(query_bytes)
            .with_consolidation(consolidation)
            .with_timeout_ms(ALIGNER_QUERY_TIMEOUT_MS),
        move |view: &dyn ReplyView| {
            if let Some(decoded) = decode_reply(view) {
                replies_cb
                    .lock()
                    .expect("aligner reply buffer poisoned")
                    .push(decoded);
            }
        },
        move |_rid: u64| {
            if let Some(tx) = final_tx
                .lock()
                .expect("aligner final oneshot poisoned")
                .take()
            {
                let _ = tx.send(());
            }
        },
    );

    // A rejected query yields nothing; never fatal to the alignment loop.
    if issued.is_err() {
        return Vec::new();
    }

    // Wait for the terminal `on_final` (the peer's ResponseFinal, or the
    // query-timeout sweep's Err+Final), BOUNDED by a backstop so a spawned
    // alignment task cannot hang on a peer that never answers AND a session that
    // is not running the reply-timeout sweep (the sweep is a separate task, not
    // part of `drive_session_until_terminal` -- R268). A sweep-equipped session
    // resolves on the real Err+Final well inside the backstop; otherwise the
    // backstop trips and we process whatever replies arrived. Self-bounded.
    let backstop =
        Duration::from_millis(u64::from(ALIGNER_QUERY_TIMEOUT_MS) + ALIGNER_BACKSTOP_SLACK_MS);
    let _ = tokio::time::timeout(backstop, final_rx).await;

    let mut guard = replies.lock().expect("aligner reply buffer poisoned");
    core::mem::take(&mut *guard)
}

/// Drive the alignment exchange against a peer to convergence: issue
/// `initial_query` on `peer_aligner_ke`, process each reply through the kernel,
/// and follow every [`AlignmentFollowup`] (a finer same-peer query, or an `All`
/// against a discovered replica) until the request tree is exhausted. zenoh
/// spawns a fresh task per followup (core.rs:559-572, aligner_reply.rs); wz
/// drains a work queue in one task — the same tree, no per-step spawn (the wz
/// answer + process are synchronous over the locked state). The state lock is
/// only ever held across the synchronous `process_alignment_reply` calls, never
/// across the query await.
async fn run_alignment<R, T, B>(
    session: &Session<R, T, Unicast>,
    state: &Arc<Mutex<StorageState<B>>>,
    config: &ReplicationConfig,
    peer_aligner_ke: String,
    initial_query: AlignmentQuery,
) where
    R: SessionRuntime,
    T: TimeSource + 'static,
    B: StorageBackend,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    let mut pending = vec![(peer_aligner_ke, initial_query)];
    let mut issued = 0usize;
    while let Some((ke, query)) = pending.pop() {
        // Defensive bound (see MAX_ALIGNMENT_QUERIES): abandon this pass if a
        // peer drives the followup queue past the cap; the next digest tick
        // re-triggers if the replica is still diverged.
        if issued >= MAX_ALIGNMENT_QUERIES {
            break;
        }
        issued += 1;

        let consolidation = consolidation_for(&query);
        let mut replies =
            issue_and_collect(session, &ke, encode_alignment_query(&query), consolidation).await;

        // Discovery selects a SINGLE replica: Monotonic should deliver one
        // reply, but zenoh defensively stops after the first (core.rs:567-572).
        // Mirror that so several Discovery replies do not fan out into several
        // `All` pulls. Every other query keeps all replies
        // (ConsolidationMode::None -- one reply per event).
        if matches!(query, AlignmentQuery::Discovery) {
            replies.truncate(1);
        }

        // Process the batch under the lock in a tight scope, collecting the
        // followups; the guard (a non-Send std lock) never spans the next await.
        let mut followups = Vec::new();
        {
            let mut guard = state.lock().expect("storage state mutex poisoned");
            for (reply, value) in replies {
                let followup = guard.process_alignment_reply(config, reply, value);
                if let Some(step) = next_query(followup, &ke, config) {
                    followups.push(step);
                }
            }
        }
        pending.extend(followups);
    }
}

/// Spawn an alignment pull against a peer replica's aligner queryable: a
/// detached task that drives [`run_alignment`] to convergence and resolves its
/// [`JoinHandle`](tokio::task::JoinHandle). `state` is shared with the
/// [`StorageService`](crate::storage_service::StorageService) (pass its
/// `shared_state()`), so pulled entries land in the live store. `peer_aligner_ke`
/// is the targeted replica's aligner keyexpr ([`aligner_keyexpr`] for a
/// digest-driven `Diff` pull, or [`discovery_keyexpr`] for an initial
/// `Discovery`); `initial_query` is what to ask first (`Diff(diff)` from the
/// digest subscriber's `on_diff`, or `Discovery`). zenoh
/// `spawn_query_replica_aligner` (core.rs:484-577).
pub fn query_replica_aligner<R, T, B>(
    session: &Session<R, T, Unicast>,
    state: Arc<Mutex<StorageState<B>>>,
    config: ReplicationConfig,
    peer_aligner_ke: String,
    initial_query: AlignmentQuery,
) -> tokio::task::JoinHandle<()>
where
    R: SessionRuntime + 'static,
    T: TimeSource + Send + Sync + 'static,
    B: StorageBackend + Send + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
    Session<R, T, Unicast>: Clone + Send + 'static,
{
    let session = session.clone();
    tokio::spawn(async move {
        run_alignment(&session, &state, &config, peer_aligner_ke, initial_query).await;
    })
}

/// Wire the digest-divergence handoff to the aligner: declare a
/// [`DigestSubscriber`] whose `on_diff` spawns an alignment pull (`Diff`)
/// against the diverging peer. This is the seam (A8c-2c) that makes a detected
/// digest divergence automatically trigger a pull: the subscriber reports
/// `(peer_zid_hex, DigestDiff)` (R311wj), this rebuilds the peer's aligner
/// keyexpr ([`aligner_keyexpr_for_hex`]) and spawns [`query_replica_aligner`]
/// with `AlignmentQuery::Diff(diff)`. `state` is shared with the
/// [`StorageService`](crate::storage_service::StorageService) (pass its
/// `shared_state()`), so the digest the subscriber diffs AND the entries the
/// pull lands both reflect the one live store. Dropping the returned subscriber
/// undeclares it (RAII), so no further auto-pulls are spawned (an in-flight pull
/// runs to completion or its 10s timeout). zenoh `spawn_digest_subscriber` ->
/// `spawn_query_replica_aligner` (core.rs:331-399 + 484-577).
pub fn spawn_digest_aligner<R, T, B>(
    session: &Session<R, T, Unicast>,
    state: Arc<Mutex<StorageState<B>>>,
    config: ReplicationConfig,
) -> Result<DigestSubscriber<R>, SubscribeError>
where
    R: SessionRuntime + 'static,
    T: TimeSource + Send + Sync + 'static,
    B: StorageBackend + Send + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
    Session<R, T, Unicast>: Clone + Send + 'static,
{
    let session_for_pull = session.clone();
    let state_for_declare = Arc::clone(&state);
    let config_for_declare = config.clone();
    DigestSubscriber::declare(
        session,
        state_for_declare,
        config_for_declare,
        move |peer_zid_hex: &str, diff: DigestDiff| {
            // Build the peer's aligner keyexpr synchronously: `peer_zid_hex` is
            // borrowed from the subscriber callback and is not valid past it, so
            // it must be resolved before the detached pull is spawned.
            let peer_aligner_ke = aligner_keyexpr_for_hex(&config, peer_zid_hex);
            // The JoinHandle is dropped -> the pull runs detached; the digest
            // subscriber's lifetime gates whether NEW pulls are spawned.
            query_replica_aligner(
                &session_for_pull,
                Arc::clone(&state),
                config.clone(),
                peer_aligner_ke,
                AlignmentQuery::Diff(diff),
            );
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::query_sink::BorrowedQuery;
    use wz_session_core::reply_sink::{BorrowedReply, ReplyKind};
    use wz_session_core::sample::TimestampHint;
    use wz_session_core::storage_backend::MemoryStorage;

    fn cfg() -> ReplicationConfig {
        ReplicationConfig::new("demo/**", None, 20, 5, 6, 30, 250)
    }

    /// One recorded `reply_keyed_attached` emit:
    /// `(keyexpr, payload, encoding packed_id, attachment bytes)`. Factored to
    /// a `type` per `clippy::type_complexity`.
    type RecordedReply = (String, Vec<u8>, Option<u32>, Vec<u8>);

    /// A reply recorder capturing each `reply_keyed_attached` emit.
    #[derive(Default)]
    struct RecordingReplies {
        keyed_attached: Vec<RecordedReply>,
        plain: u32,
    }

    impl ReplyOut for RecordingReplies {
        fn reply(&mut self, _payload: &[u8]) {
            self.plain += 1;
        }
        fn reply_del(&mut self) {}
        fn reply_err(&mut self, _encoding_id: Option<u32>, _schema: Option<&str>, _payload: &[u8]) {
        }
        fn reply_keyed_attached(
            &mut self,
            keyexpr: &str,
            payload: &[u8],
            encoding: Option<&EncodingHint>,
            attachment: &[u8],
        ) {
            self.keyed_attached.push((
                keyexpr.to_string(),
                payload.to_vec(),
                encoding.map(|e| e.packed_id),
                attachment.to_vec(),
            ));
        }
        fn with_responder(&mut self, _zid: &[u8], _eid: u32) {}
        fn clear_responder(&mut self) {}
        fn responder(&self) -> Option<(&[u8], u32)> {
            None
        }
    }

    fn query_view<'a>(keyexpr: &'a str, attachment: Option<&'a [u8]>) -> BorrowedQuery<'a> {
        BorrowedQuery {
            keyexpr,
            parameters: None,
            attachment,
            source_info: None,
            rid: 1,
            is_local: false,
        }
    }

    fn state_with_put(
        key: &str,
        payload: Vec<u8>,
        now: u64,
    ) -> Arc<Mutex<StorageState<MemoryStorage>>> {
        let mut st = StorageState::new(MemoryStorage::new());
        st.process_put(
            Some(key),
            payload,
            None,
            TimestampHint {
                time: now,
                zid: vec![0x01],
            },
        );
        Arc::new(Mutex::new(st))
    }

    #[test]
    fn aligner_keyexpr_is_zenoh_formatted() {
        let config = cfg();
        // The zid renders via zenoh's ZenohId Display (LE -> u128 -> big-endian
        // hex): [0x01, 0xab] -> u128 0xab01 -> "ab01", NOT a per-byte "01ab".
        let ke = aligner_keyexpr(&config, &[0x01, 0xab]);
        assert_eq!(
            ke,
            format!("@zid/ab01/{}/aligner", config.fingerprint().value())
        );
    }

    #[test]
    fn discovery_emits_one_empty_payload_reply_carrying_the_zid() {
        let config = cfg();
        let zid = vec![0x07];
        let now = wall_clock_ntp64();
        let state = state_with_put("demo/a", vec![1, 2, 3], now);
        let ke = aligner_keyexpr(&config, &zid);

        let query = encode_alignment_query(&AlignmentQuery::Discovery);
        let view = query_view(&ke, Some(&query));
        let mut out = RecordingReplies::default();
        answer_alignment_into(&state, &config, &zid, &view, &mut out, now);

        // Exactly one Discovery reply: empty payload, no encoding, attachment =
        // the serialized AlignmentReply::Discovery(zid), on the aligner keyexpr.
        assert_eq!(out.keyed_attached.len(), 1);
        let (got_ke, got_payload, got_enc, got_attach) = &out.keyed_attached[0];
        assert_eq!(got_ke, &ke);
        assert!(
            got_payload.is_empty(),
            "a metadata-only reply has no payload"
        );
        assert_eq!(*got_enc, None);
        assert_eq!(
            got_attach,
            &encode_alignment_reply(&AlignmentReply::Discovery(zid.clone()))
        );
        assert_eq!(
            out.plain, 0,
            "the aligner only emits via reply_keyed_attached"
        );
    }

    #[test]
    fn all_retrieval_carries_value_and_matches_the_kernel_one_for_one() {
        let config = cfg();
        let zid = vec![0x01];
        let now = wall_clock_ntp64();
        let state = state_with_put("demo/a", vec![9, 8, 7], now);
        let ke = aligner_keyexpr(&config, &zid);

        // The kernel's own answer for the SAME All query is the ground truth.
        let expected =
            state
                .lock()
                .unwrap()
                .answer_alignment_query(&config, &AlignmentQuery::All, &zid, now);
        assert!(
            !expected.is_empty(),
            "an All query over a stored Put yields at least one Retrieval"
        );

        let query = encode_alignment_query(&AlignmentQuery::All);
        let view = query_view(&ke, Some(&query));
        let mut out = RecordingReplies::default();
        answer_alignment_into(&state, &config, &zid, &view, &mut out, now);

        assert_eq!(
            out.keyed_attached.len(),
            expected.len(),
            "one reply_keyed_attached per kernel response"
        );
        for (got, response) in out.keyed_attached.iter().zip(expected.iter()) {
            assert_eq!(&got.0, &ke, "reply keyexpr is the query keyexpr");
            let (exp_payload, exp_enc) = match &response.value {
                Some(v) => (v.payload.clone(), v.encoding.as_ref().map(|e| e.packed_id)),
                None => (Vec::new(), None),
            };
            assert_eq!(got.1, exp_payload);
            assert_eq!(got.2, exp_enc);
            assert_eq!(got.3, encode_alignment_reply(&response.reply));
        }
        // The stored value (a Put) is carried back on at least one reply.
        assert!(
            out.keyed_attached
                .iter()
                .any(|(_, p, _, _)| p == &[9, 8, 7]),
            "the stored Put's value rides a Retrieval reply payload"
        );
    }

    #[test]
    fn empty_attachment_query_is_skipped() {
        let config = cfg();
        let zid = vec![0x01];
        let now = wall_clock_ntp64();
        let state = state_with_put("demo/a", vec![1], now);
        let ke = aligner_keyexpr(&config, &zid);

        let view = query_view(&ke, None);
        let mut out = RecordingReplies::default();
        answer_alignment_into(&state, &config, &zid, &view, &mut out, now);
        assert!(
            out.keyed_attached.is_empty() && out.plain == 0,
            "a query with no attachment is skipped (nothing to align)"
        );
    }

    #[test]
    fn corrupt_attachment_query_is_ignored() {
        let config = cfg();
        let zid = vec![0x01];
        let now = wall_clock_ntp64();
        let state = state_with_put("demo/a", vec![1], now);
        let ke = aligner_keyexpr(&config, &zid);

        let view = query_view(&ke, Some(&[0xff, 0x00, 0x01]));
        let mut out = RecordingReplies::default();
        answer_alignment_into(&state, &config, &zid, &view, &mut out, now);
        assert!(
            out.keyed_attached.is_empty() && out.plain == 0,
            "an undecodable attachment is ignored, not fatal"
        );
    }

    // A REAL live-session test: the aligner service declares its queryable on
    // the aligner keyexpr against a session. The cross-session answer (a remote
    // peer's AlignmentQuery -> reply) needs a TWO-INSTANCE e2e (the queryable is
    // Remote-only, so a single-session loopback cannot exercise it by
    // construction); that rides the storage-aligner track's live convergence
    // e2e. Here the decode / answer / emit core is covered by the unit tests
    // above; this asserts the declare wiring.
    #[test]
    fn aligner_service_declares_on_the_aligner_keyexpr() {
        use crate::observer::ApplicationLayerObserver;
        use crate::runtime_impl::TokioTime;
        use crate::session::TokioSession;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let config = cfg();
        let state = Arc::new(Mutex::new(StorageState::new(MemoryStorage::new())));
        let aligner = AlignerService::declare(&session, state, config, vec![0x01]);
        assert!(
            aligner.is_ok(),
            "the aligner answer queryable declares on @zid/<zid>/<fp>/aligner"
        );
    }

    // ----- ASK side (A8c-2b) -----

    fn reply_view<'a>(
        keyexpr: &'a str,
        payload: &'a [u8],
        attachment: Option<&'a [u8]>,
        put_encoding: Option<(u32, Option<&'a str>)>,
    ) -> BorrowedReply<'a> {
        BorrowedReply {
            rid: 1,
            keyexpr,
            kind: ReplyKind::Put,
            payload,
            err_encoding: None,
            attachment,
            put_encoding,
        }
    }

    #[test]
    fn consolidation_is_monotonic_for_discovery_else_none() {
        // Discovery -> Monotonic (single most-reactive replica); every other
        // query -> None (keep every per-event reply).
        assert!(matches!(
            consolidation_for(&AlignmentQuery::Discovery),
            ConsolidationMode::Monotonic
        ));
        assert!(matches!(
            consolidation_for(&AlignmentQuery::All),
            ConsolidationMode::None
        ));
        assert!(matches!(
            consolidation_for(&AlignmentQuery::Events(Vec::new())),
            ConsolidationMode::None
        ));
    }

    #[test]
    fn discovery_keyexpr_is_wildcard_zid() {
        let config = cfg();
        assert_eq!(
            discovery_keyexpr(&config),
            format!("@zid/*/{}/aligner", config.fingerprint().value())
        );
    }

    #[test]
    fn decode_reply_skips_a_reply_with_no_attachment() {
        let view = reply_view("@zid/aa/1/aligner", &[], None, None);
        assert!(
            decode_reply(&view).is_none(),
            "a reply without an attachment is skipped (zenoh core.rs:540-543)"
        );
    }

    #[test]
    fn decode_reply_skips_a_corrupt_attachment() {
        let view = reply_view("@zid/aa/1/aligner", &[], Some(&[0xff, 0x00, 0x01]), None);
        assert!(
            decode_reply(&view).is_none(),
            "an undecodable attachment is skipped, not fatal"
        );
    }

    #[test]
    fn decode_reply_metadata_reply_has_no_value() {
        // A Discovery (metadata) reply: attachment only, empty payload -> the
        // decoded value is None.
        let attachment = encode_alignment_reply(&AlignmentReply::Discovery(vec![0xaa]));
        let view = reply_view("@zid/aa/1/aligner", &[], Some(&attachment), None);
        let (reply, value) = decode_reply(&view).expect("a Discovery reply decodes");
        assert!(matches!(reply, AlignmentReply::Discovery(_)));
        assert!(value.is_none(), "a metadata reply carries no value");
    }

    #[test]
    fn decode_reply_retrieval_carries_payload_and_encoding() {
        // A Retrieval reply: the value rides the reply body (payload +
        // put_encoding), read off the ReplyView regardless of the EventMetadata.
        let config = cfg();
        let zid = vec![0x01];
        let now = wall_clock_ntp64();
        let source = state_with_put("demo/a", vec![1], now);
        let responses =
            source
                .lock()
                .unwrap()
                .answer_alignment_query(&config, &AlignmentQuery::All, &zid, now);
        let retrieval = responses
            .into_iter()
            .find(|r| matches!(r.reply, AlignmentReply::Retrieval(_)))
            .expect("All yields a Retrieval");
        let attachment = encode_alignment_reply(&retrieval.reply);

        let view = reply_view(
            "@zid/01/1/aligner",
            &[5, 6],
            Some(&attachment),
            Some((7, Some("text/plain"))),
        );
        let (reply, value) = decode_reply(&view).expect("a Retrieval reply decodes");
        assert!(matches!(reply, AlignmentReply::Retrieval(_)));
        let value = value.expect("a Retrieval carries a value");
        assert_eq!(value.payload, vec![5, 6]);
        assert_eq!(
            value.encoding,
            Some(EncodingHint {
                packed_id: 7,
                schema: Some("text/plain".to_string()),
            })
        );
    }

    #[test]
    fn decode_reply_delete_retrieval_has_no_value() {
        use wz_session_core::storage_aligner::EventMetadata;
        // A Delete Retrieval is a Put-form reply (empty payload) carrying a
        // Retrieval(meta) whose action is Delete. The kernel applies the delete
        // from the metadata alone, so decode_reply must NOT manufacture a value
        // -- matching the answer side, which emits value=None for a Delete
        // Retrieval. The value-presence keys on the event Action, not the
        // Retrieval variant.
        let meta = EventMetadata::delete(
            Some("demo/a".into()),
            TimestampHint {
                time: 1,
                zid: vec![0x01],
            },
        );
        let attachment = encode_alignment_reply(&AlignmentReply::Retrieval(meta));
        let view = reply_view("@zid/01/9/aligner", &[], Some(&attachment), None);
        let (reply, value) = decode_reply(&view).expect("a Delete Retrieval reply decodes");
        assert!(matches!(reply, AlignmentReply::Retrieval(_)));
        assert!(value.is_none(), "a Delete Retrieval carries no value");
    }

    #[test]
    fn next_query_maps_each_followup() {
        let config = cfg();
        let ke = "@zid/01/9/aligner";

        assert!(
            next_query(AlignmentFollowup::Done, ke, &config).is_none(),
            "Done converges -- no next query"
        );

        let (q_ke, q) =
            next_query(AlignmentFollowup::Query(AlignmentQuery::All), ke, &config).unwrap();
        assert_eq!(q_ke.as_str(), ke, "a finer query re-targets the same peer");
        assert!(matches!(q, AlignmentQuery::All));

        let (d_ke, d_q) = next_query(
            AlignmentFollowup::DiscoveredReplica(vec![0x01]),
            ke,
            &config,
        )
        .unwrap();
        assert_eq!(
            d_ke,
            aligner_keyexpr(&config, &[0x01]),
            "a discovered replica is aligned on its own aligner keyexpr"
        );
        assert!(
            matches!(d_q, AlignmentQuery::All),
            "a discovered replica is pulled with All"
        );
    }

    #[test]
    fn all_pull_converges_the_destination_to_the_source() {
        let config = cfg();
        let zid = vec![0x01];
        let now = wall_clock_ntp64();
        let source = state_with_put("demo/a", vec![9, 8, 7], now);
        let ke = aligner_keyexpr(&config, &zid);

        // The source answers an All query (the replies a real aligner emits).
        let responses =
            source
                .lock()
                .unwrap()
                .answer_alignment_query(&config, &AlignmentQuery::All, &zid, now);
        assert!(
            !responses.is_empty(),
            "All over a stored Put yields replies"
        );

        // The destination starts empty and pulls each reply through the ASK
        // path: decode_reply (driver) -> process_alignment_reply (kernel).
        let mut dest = StorageState::new(MemoryStorage::new());
        for response in &responses {
            let attachment = encode_alignment_reply(&response.reply);
            let (payload, put_encoding): (&[u8], Option<(u32, Option<&str>)>) =
                match &response.value {
                    Some(v) => (
                        &v.payload,
                        v.encoding
                            .as_ref()
                            .map(|e| (e.packed_id, e.schema.as_deref())),
                    ),
                    None => (&[], None),
                };
            let view = reply_view(&ke, payload, Some(&attachment), put_encoding);
            let (reply, value) = decode_reply(&view).expect("the reply decodes");
            let followup = dest.process_alignment_reply(&config, reply, value);
            assert!(
                matches!(followup, AlignmentFollowup::Done),
                "an All-flow Retrieval applies terminally"
            );
        }

        // The destination digest now equals the source's: they converged.
        let hot = config.classify(now).0;
        assert_eq!(
            dest.replication_digest(&config, hot),
            source.lock().unwrap().replication_digest(&config, hot),
            "after pulling All, the destination converges to the source"
        );
    }

    // ----- digest -> aligner wiring (A8c-2c) -----

    #[test]
    fn aligner_keyexpr_for_hex_matches_the_byte_form() {
        let config = cfg();
        // The hex form and the byte form (which renders the zid via
        // zid_to_zenoh_hex) produce the identical keyexpr.
        assert_eq!(
            aligner_keyexpr_for_hex(&config, "ab01"),
            aligner_keyexpr(&config, &[0x01, 0xab])
        );
        assert_eq!(
            aligner_keyexpr_for_hex(&config, "ab01"),
            format!("@zid/ab01/{}/aligner", config.fingerprint().value())
        );
    }

    #[test]
    fn digest_keyexpr_derives_the_peer_aligner_keyexpr() {
        use crate::storage_replication_service::{digest_keyexpr, digest_keyexpr_zid_hex};
        let config = cfg();
        let peer_zid = vec![0x01, 0xab];

        // The peer publishes its digest on its digest keyexpr and declares its
        // aligner queryable on its aligner keyexpr.
        let peer_digest_ke = digest_keyexpr(&config, &peer_zid);
        let peer_aligner_ke = aligner_keyexpr(&config, &peer_zid);

        // The asker, on receiving the peer's digest, parses the zid hex out of
        // the digest keyexpr (R311wj) and rebuilds the aligner keyexpr -- which
        // must reach exactly the peer's own aligner queryable.
        let zid_hex = digest_keyexpr_zid_hex(&peer_digest_ke).expect("digest ke parses");
        assert_eq!(
            aligner_keyexpr_for_hex(&config, zid_hex),
            peer_aligner_ke,
            "the aligner ke derived from a peer's digest ke reaches the peer's own queryable"
        );
    }

    #[test]
    fn spawn_digest_aligner_declares_the_digest_subscriber() {
        use crate::observer::ApplicationLayerObserver;
        use crate::runtime_impl::TokioTime;
        use crate::session::TokioSession;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let config = cfg();
        let state = Arc::new(Mutex::new(StorageState::new(MemoryStorage::new())));
        // Wiring declares the digest subscriber; the on_diff -> pull spawn fires
        // only on a received divergent digest (a two-replica e2e, A11).
        let sub = spawn_digest_aligner(&session, state, config);
        assert!(
            sub.is_ok(),
            "the digest -> aligner wiring declares its peer-digest subscriber"
        );
    }
}
