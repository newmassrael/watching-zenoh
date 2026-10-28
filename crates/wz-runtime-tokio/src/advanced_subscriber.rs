// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
//! - **Timestamped** (R2522; no `SourceInfo`, but a body timestamp): keyed
//!   by the TIMESTAMP's own id, ordered by the uhlc `(time, id)` relation.
//!   A sample delivers only when it is STRICTLY newer than the newest
//!   already delivered for that id, so a retransmission at an equal instant
//!   and a late arrival at an older one are both DROPPED. This is what a
//!   `Sequencing::Timestamp` publisher's samples get.
//! - **Neither**: delivered immediately, no de-duplication — the fallback,
//!   which is why it is read LAST.
//!
//! Those three are upstream's three `handle_sample` arms, in upstream's
//! order; `State::deliver_unsequenced` holds the second and third, shared
//! by both ingest paths. The ordering primitive is
//! `wz_session_core::sample::timestamp_strictly_newer`, a shared SSOT since
//! R311y73 lifted it out of the storage-backend-gated `storage_state` so
//! this ext-pubsub atom could consume it WITHOUT pulling storage.
//!
//! R2522 replaced this paragraph's predecessor, which said the timestamped
//! path was "DEFERRED to the round that composes + tests a Timestamp-mode
//! publisher". No such publisher was needed in the end: `PublishOptions`
//! already carries `with_timestamp`, so the mode's WIRE SHAPE — a Put with
//! a body timestamp and no source_info — is reachable from the ordinary
//! publish path, and that shape is all the subscriber arm keys on.
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
//!   sn-ordered reorder buffer (`SourceState::pending_samples`) instead of
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

use std::sync::{Arc, Mutex};

use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;
use wz_session_core::sample::{EntityGlobalId, Sample};
use wz_session_core::sink::SampleView;

use crate::session::{
    Session, SubscribeAliasError, SubscribeError, SubscribeOptions, Subscriber, Unicast,
};
use crate::session_glue::SessionLinkActions;

use wz_session_core::locality::Locality;
#[cfg(feature = "ext-pubsub-advanced-recovery")]
use wz_session_core::reply_sink::ReplyView;
#[cfg(feature = "ext-pubsub-advanced-recovery")]
use wz_session_core::sample_kind::SampleKind;
#[cfg(feature = "ext-pubsub-advanced-recovery")]
use wz_session_core::serde_codec::z_deserialize;
use wz_session_core::zid_hex::zid_to_zenoh_hex;

#[cfg(feature = "ext-pubsub-advanced-recovery")]
use crate::session::QueryOptions;

// R311y100 — detect_late_publishers: the liveliness subscriber + its sample.
#[cfg(feature = "ext-pubsub-advanced-history")]
use crate::declare::{LivelinessSample, LivelinessSampleKind};
#[cfg(feature = "ext-pubsub-advanced-history")]
use crate::session::{LivelinessSubscriberAliasError, LivelinessSubscriberOptions};

#[cfg(feature = "ext-pubsub-advanced-recovery")]
use wz_ext_pubsub::advanced_subscriber::RecoveryRequest;
pub use wz_ext_pubsub::advanced_subscriber::{Miss, SampleMissListener};
use wz_ext_pubsub::advanced_subscriber::{MissHandlers, State};

/// R311y90 (review C5) — why declaring an advanced subscriber failed.
/// Distinct from the base [`SubscribeError`] (which stays the plain
/// `Session::declare_subscriber` surface): the advanced form declares more than
/// one entity and has failure modes of its own. Kept OUT of `SubscribeError` so toggling the additive
/// `ext-pubsub-advanced-recovery` feature cannot change `SubscribeError`'s shape
/// and break a base-subscriber caller's exhaustive match (the H1
/// signature-stability invariant); mirrors the publisher's dedicated
/// [`crate::advanced_publisher::AdvancedPublisherError`].
///
/// R2815 — in EVERY build, and both `declare` forms return it. It was
/// recovery-gated because only `declare_with_options` could fail in an
/// advanced way; since a subscriber carries a global identity, the plain form
/// can too ([`Self::SessionZid`], [`Self::EntityIdOutOfRange`]). Returning the
/// same type from both builds keeps the signature-stability invariant the
/// plain `declare` documents.
#[derive(Debug)]
#[non_exhaustive]
pub enum AdvancedSubscribeError {
    /// The base / recovery / heartbeat subscriber declaration was rejected.
    Subscribe(SubscribeError),
    /// A subscription declared in a host's own wire form
    /// ([`EntityForm`]) was rejected: the declaration it names is not held, or
    /// the key it resolves to is not one the wire takes.
    Alias(SubscribeAliasError),
    /// R2815 — the session's own zid is not 1..=16 bytes, so this subscriber
    /// has no global identity to report through [`AdvancedSubscriber::id`] or
    /// to name its detection token with. `SessionInitParams::zid` documents
    /// that range and nothing enforces it; refused here, before anything is
    /// declared, rather than handed out as an identity no reference parses.
    ///
    /// Replaces R311y826's `DetectionZid`, which refused a zid the CALLER
    /// supplied for the token. The caller no longer supplies one.
    SessionZid {
        /// The session zid's length.
        len: usize,
    },
    /// R2815 — the subscription's declaration id does not fit the 32-bit
    /// entity id upstream's identity carries
    /// (`commons/zenoh-protocol/src/core/mod.rs` @ `pub type EntityId = u32;`).
    /// wz allocates it from a 64-bit counter; the plain declaration already
    /// sent it on the wire, and it is retracted with this refusal.
    EntityIdOutOfRange {
        /// The declaration id that did not fit.
        id: u64,
    },
    /// R311y100 — the late-publisher-detection liveliness subscriber
    /// declaration was rejected (only reachable with
    /// `HistoryConfig::detect_late_publishers`). Additive + gated, safe on the
    /// `#[non_exhaustive]` enum.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    Liveliness(LivelinessSubscriberAliasError),
    /// R311y826 — the `@adv/sub` detection token declaration was rejected
    /// (only reachable with
    /// [`AdvancedSubscriberOptions::subscriber_detection`]). A REFUSAL, not a
    /// degradation: the caller asked to be detectable, and a subscriber that
    /// silently is not is the failure mode nobody can see from the outside.
    ///
    /// R2819 — in every build, with the detection option it answers for.
    DetectionToken(crate::session::LivelinessAliasError),
    /// R2550 — a [`HistoryConfig`] bound was set to ZERO, which upstream
    /// refuses at construction rather than honouring:
    /// `zenoh-ext/src/advanced_subscriber.rs` @ `bail!("max_samples must not be zero")`
    /// and @ `bail!("max_age must not be zero")`, both inside the `// Check config`
    /// block its `AdvancedSubscriber::new` opens with.
    ///
    /// REFUSED HERE FOR THE SAME REASON IT IS REFUSED THERE, which is not
    /// tidiness: a zero bound is a request for a history GET that can return
    /// nothing, so honouring it would arm the whole history machinery — the
    /// startup GET, the liveliness trigger, the pending buffer — around a
    /// selector guaranteed to recover no sample. Upstream's own doc says the
    /// builder fails on it twice over, once per knob.
    ///
    /// AT CONSTRUCTION, NOT AT THE SETTER, because that is where upstream puts
    /// it and where wz has a `Result` to put it in: [`HistoryConfig`]'s setters
    /// return `Self` and cannot refuse.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    HistoryBoundZero {
        /// Which knob was zero — `"max_samples"` or `"max_age"`, spelled as
        /// upstream's builder names them so a reader porting a zenoh config
        /// recognises the one they set.
        knob: &'static str,
    },
}

impl From<SubscribeError> for AdvancedSubscribeError {
    fn from(e: SubscribeError) -> Self {
        AdvancedSubscribeError::Subscribe(e)
    }
}

impl From<SubscribeAliasError> for AdvancedSubscribeError {
    fn from(e: SubscribeAliasError) -> Self {
        AdvancedSubscribeError::Alias(e)
    }
}

#[cfg(feature = "ext-pubsub-advanced-history")]
impl From<LivelinessSubscriberAliasError> for AdvancedSubscribeError {
    fn from(e: LivelinessSubscriberAliasError) -> Self {
        AdvancedSubscribeError::Liveliness(e)
    }
}

impl From<crate::session::LivelinessAliasError> for AdvancedSubscribeError {
    fn from(e: crate::session::LivelinessAliasError) -> Self {
        AdvancedSubscribeError::DetectionToken(e)
    }
}

#[cfg(feature = "ext-pubsub-advanced-history")]
pub use wz_ext_pubsub::advanced_subscriber::options::HistoryConfig;
#[cfg(feature = "ext-pubsub-advanced-recovery")]
pub use wz_ext_pubsub::advanced_subscriber::options::RecoveryConfig;
pub use wz_ext_pubsub::advanced_subscriber::options::{
    AdvancedSubscriberOptions, DeclarationForms, EntityForm, FormsHandle, SubscriberDetection,
};
#[cfg(feature = "ext-pubsub-advanced-history")]
use wz_ext_pubsub::advanced_subscriber::plans::history_selector;
#[cfg(feature = "ext-pubsub-advanced-recovery")]
use wz_ext_pubsub::advanced_subscriber::plans::{
    parse_heartbeat_source, recovered_sample_from_reply, recovery_query_timeout_ms,
    AdvPublisherSource, PendingGets,
};

/// An entity and what keeps its wire name valid. The entity is the FIRST field,
/// so it is retracted first and the name goes right after it — which is the
/// order a host that declares keys shows a peer.
struct Held<E> {
    entity: E,
    _keeps: Option<Arc<dyn Send + Sync>>,
}

impl<E> Held<E> {
    fn new(entity: E, form: &EntityForm) -> Self {
        Self {
            entity,
            _keeps: form.kept().cloned(),
        }
    }
}

/// R311y95 (review L3) — the shared recovery / history GET scaffolding: issue the
/// GET on `keyexpr` with `opts`, feed each Put reply back into the per-source
/// ordering via [`recovered_sample_from_reply`] + [`State::handle_recovered`], and
/// run `finish` on the terminal Final OR (R311y89 review C3) on a GET that failed to
/// issue (the deadline sweep can never release it). The recovery and history issuers
/// differ ONLY in the KE, the selector `opts`, and the `finish` action
/// (`finish_recovery(key)` vs `finish_history()`), so both delegate here. MUST be
/// called with the [`State`] lock RELEASED — `Session::query` re-enters the session
/// (and re-locks the state from the reply callback).
#[cfg(feature = "ext-pubsub-advanced-recovery")]
/// R311y442 review (REVIEWER 1, finding 2) — `sub_keyexpr` is the subscriber's
/// OWN declared keyexpr, and the filter it drives is the other half of `_anyke`.
///
/// `_anyke` is an opt-OUT of the responder's reply-keyexpr guard, not a licence to
/// take anything: upstream pairs `.accept_replies(ReplyKeyExpr::Any)` with a local
/// `if key_expr.intersects(s.key_expr())` in EVERY one of its seven GET callbacks
/// (`zenoh-ext/src/advanced_subscriber.rs` @ `global_pending_queries`, which
/// every such pair guards).
/// The round that added `_anyke` to wz's GETs took the opt-out at all three sites
/// and added none of the narrowing, which made the RX path strictly more permissive
/// than before the fix: a reply keyed outside the subscription — previously refused
/// by a conformant responder, now explicitly invited — was delivered into the
/// subscriber's callback as though it were a sample on the subscribed keyexpr.
#[allow(clippy::too_many_arguments)]
fn issue_recovery_get<R, T>(
    session: &Session<R, T, Unicast>,
    statesref: &Arc<Mutex<State>>,
    pending: &Arc<PendingGets>,
    keyexpr: &str,
    sub_keyexpr: &str,
    opts: QueryOptions,
    finish: impl Fn(&mut State) + Clone + Send + 'static,
) where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    let reply_states = Arc::clone(statesref);
    let reply_clock = Arc::clone(session.clock());
    let final_states = Arc::clone(statesref);
    let final_pending = Arc::clone(pending);
    let final_finish = finish.clone();
    let sub_chunks: Vec<String> = sub_keyexpr.split('/').map(str::to_string).collect();
    // R2505 — EVERY recovery / history GET carries `QueryTarget::All`, and it
    // is pinned HERE rather than at the three call sites because this helper is
    // the one seam all of them pass through: `session.query` below is the only
    // GET this module issues.
    //
    // Upstream pins the same value on every one of its GETs --
    // `zenoh-ext/src/advanced_subscriber.rs` @ `query_target: QueryTarget::All,`
    // is the default its builder carries, applied at each `.get(..)`.
    //
    // ⚠ WHY IT MATTERS ON THE WIRE, which is where the defect lives: wz's own
    // `query_mode.rs` records that `BEST_MATCHING (0)` is NEVER TRANSMITTED --
    // an absent target ext reads back as BestMatching. So a GET with no target
    // is answered by ONE queryable, and a history GET answered by one queryable
    // can return a strictly smaller history. That is a delivery difference, not
    // a cosmetic one.
    //
    // Fully qualified rather than imported, following this module's existing
    // habit at the `with_consolidation` pins: a `use` is a doc-link edit here
    // (Layer C1bz), and this needs none.
    let opts = opts.with_target(wz_session_core::query_mode::QueryTarget::All);
    let issued = session.query(
        keyexpr,
        opts,
        move |reply: &dyn ReplyView| {
            // The `_anyke` counterpart (see this fn's docs): a reply keyed outside
            // the subscription is dropped here rather than delivered as if it were
            // a sample on it. Split per reply rather than cached as `&str` slices
            // because the callback is `'static`; recovery replies are rare enough
            // that the allocation is not on any hot path.
            let sub: Vec<&str> = sub_chunks.iter().map(String::as_str).collect();
            let reply_ke: Vec<&str> = reply.keyexpr().split('/').collect();
            if !wz_session_core::pubsub::keyexpr_intersect_patterns(&sub, &reply_ke) {
                return;
            }
            // R2554 — the SAME entry the live subscription uses, which is what
            // upstream's GET callbacks do (`handle_sample(states, s)`, at every
            // one of them). `live = false`: the GET that produced this reply is
            // the one already in flight, so a gap here must not fan another.
            if let Some(sample) = recovered_sample_from_reply(reply) {
                let _ = reply_states
                    .lock()
                    .expect("advanced subscriber state mutex poisoned")
                    .ingest(sample, false, reply_clock.now_monotonic_ms());
            }
        },
        move |rid| {
            // R311y592 — forget the registration BEFORE running `finish`: a
            // terminal Final means there is nothing left for a teardown to
            // cancel, and `finish` re-enters the state lock.
            final_pending.finish(rid);
            let mut guard = final_states
                .lock()
                .expect("advanced subscriber state mutex poisoned");
            final_finish(&mut guard);
        },
    );
    match issued {
        // R311y592 — record the GET so a teardown can cancel it. `record`
        // answers `false` when the subscriber was dropped WHILE this GET was
        // going out, and the only correct response is to undo the registration
        // that has just been made: the guard's `cancel` has already run and
        // will not run again, so an un-undone entry would outlive the
        // subscriber holding the only remaining handle on `State`. Same shape
        // as the cancelled-mid-fan rollback in `wz-capi-pico`'s C `z_get`.
        Ok(handle) => {
            if !pending.record(handle.rid()) {
                session.cancel_pending_query(handle.rid());
            }
        }
        Err(_) => {
            let mut guard = statesref
                .lock()
                .expect("advanced subscriber state mutex poisoned");
            finish(&mut guard);
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
#[allow(clippy::too_many_arguments)]
fn issue_recovery_query<R, T>(
    session: &Session<R, T, Unicast>,
    statesref: &Arc<Mutex<State>>,
    pending: &Arc<PendingGets>,
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
    let recovery_ke = crate::advanced_ke::recovery_get_ke(base_keyexpr, &zid_hex, req.eid);
    // Open `_sn=from..` (sample-driven / periodic) or bounded `_sn=from..to`
    // (heartbeat, which knows the publisher's last sn) — zenoh `seq_num_range`.
    // R311y442 — `_anyke` rides the recovery GET for the same reason it rides the
    // history GET: the `@adv` cache answers under the CACHED SAMPLE's keyexpr,
    // which never intersects the `<base>/@adv/*/<zid>/<eid>/**` this is addressed
    // to, and zenoh's responder refuses such a reply unless the querier said it
    // accepts any key. The `_sn` range is separator-independent on its own (it is
    // the only knob here), but it goes through the shared builder so the dialect
    // has ONE spelling rather than two that can drift apart again.
    let sn_part = match req.to_sn {
        Some(to) => format!("_sn={}..{}", req.from_sn, to),
        None => format!("_sn={}..", req.from_sn),
    };
    let params = wz_session_core::selector_params::anyke_params(&[sn_part]).into_bytes();
    // R311y89 (review C3) — bound the GET with a timeout so the deadline sweep can
    // fire `finish_recovery` if no `@adv` cache answers. R311y326 — the explicit
    // `recovery_query_timeout_ms` (>= 1 ms) is what arms the deadline; a raw 0 would
    // now resolve to the 10s platform default rather than never-expire, so the
    // pre-y326 "else pending_queries wedges the reorder buffer forever" no longer
    // holds on this build. The explicit timeout still pins the recovery bound.
    // The recovery reads each reply's timestamp (`reply.timestamp()` becomes the sample's), and
    // it is the runtime's own query, not an entity of the application: a build that makes
    // timestamps opt-in (`entity-timestamp-opt-in`) must not blind it.
    let opts = QueryOptions::get()
        .with_expose_timestamp(true)
        .with_allowed_destination(dest)
        .with_parameters(params)
        .with_timeout_ms(timeout_ms);
    // R311y836 — PIN THE MODE, do not ride the default. An `_sn` range asks for
    // EVERY sample in the gap; the resolved default is now LATEST
    // (`ConsolidationMode::resolve_auto`), which would collapse a retransmission
    // burst to one sample per keyexpr and silently unfix the very gap this GET
    // exists to close. Both upstreams pay exactly this cost explicitly and for
    // exactly this reason — zenoh-ext at every one of its recovery / history
    // GETs (`zenoh-ext/src/advanced_subscriber.rs` @ `global_pending_queries`)
    // and zenoh-pico immediately after `z_get_options_default`
    // (`vendor/zenoh-pico/src/api/advanced_subscriber.c:915`). The `_time` arm of
    // the resolution would cover the history GETs below but NOT this one, which
    // carries `_sn` and no `_time`; an explicit pin covers all three alike.
    //
    // Gated because the pin is only MEANINGFUL where the capability exists:
    // without `query-consolidation` nothing consolidates and the requirement is
    // already met, so a feature edge here would buy footprint and no behaviour.
    #[cfg(feature = "query-consolidation")]
    let opts = opts.with_consolidation(wz_session_core::query_mode::ConsolidationMode::None);

    // The finish action decrements the source's in-flight count + flushes
    // (`finish_recovery` also handles the C3 failed-to-issue rollback via the
    // shared [`issue_recovery_get`]).
    let key = (req.zid, req.eid);
    issue_recovery_get(
        session,
        statesref,
        pending,
        &recovery_ke,
        base_keyexpr,
        opts,
        move |state| state.finish_recovery(&key),
    );
}

/// R311y86 — issue the startup history GET over `<base>/@adv/**` (capped by
/// `_max=N` when `sample_depth` is set + bounded by `_time=[now(-age)..]` when
/// `max_age` is set, R311y98), feeding the recovered cached samples from EVERY
/// publisher into the per-source ordering. On the terminal Final,
/// [`State::finish_history`] clears `history_pending` + flushes the buffered
/// history oldest-first. MUST be called with the [`State`] lock RELEASED.
#[cfg(feature = "ext-pubsub-advanced-history")]
#[allow(clippy::too_many_arguments)]
fn issue_history_query<R, T>(
    session: &Session<R, T, Unicast>,
    statesref: &Arc<Mutex<State>>,
    pending: &Arc<PendingGets>,
    base_keyexpr: &str,
    sample_depth: Option<usize>,
    max_age: Option<f64>,
    dest: Locality,
    timeout_ms: u32,
) where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    let history_ke = crate::advanced_ke::history_get_ke(base_keyexpr);
    // R311y89 (review C3) — bound the GET with a timeout so the deadline sweep can
    // fire `finish_history` if no `@adv` cache answers. Without it `history_pending`
    // stays set forever and EVERY live sample buffers undelivered (the subscriber
    // delivers nothing at all).
    // The recovery reads each reply's timestamp (`reply.timestamp()` becomes the sample's), and
    // it is the runtime's own query, not an entity of the application: a build that makes
    // timestamps opt-in (`entity-timestamp-opt-in`) must not blind it.
    let opts = QueryOptions::get()
        .with_expose_timestamp(true)
        .with_allowed_destination(dest)
        .with_timeout_ms(timeout_ms);
    // R311y86 `_max=N` (sample_depth) + R311y98 `_time=[now(-age)..]` (max_age)
    // ride the one GET; the cache filters on whichever it sees. zenoh emits
    // `now({offset_secs}s)` with offset_secs = -age, i.e. `now(-{age}s)`.
    // R311y442 — the selector is now unconditional (it carries `_anyke` even when
    // neither knob is set), so there is no longer a no-parameters arm.
    let opts = opts.with_parameters(history_selector(sample_depth, max_age).into_bytes());
    // R311y836 — pin the mode; see `issue_sn_recovery_get`'s note for the full
    // reasoning and the seven upstream sites that do the same. A history GET
    // asks the cache for a RING, and `_max=N` alone carries no `_time`, so the
    // resolution's carve-out would not save this call.
    #[cfg(feature = "query-consolidation")]
    let opts = opts.with_consolidation(wz_session_core::query_mode::ConsolidationMode::None);

    // `finish_history` clears `history_pending` + flushes the buffer oldest-first
    // (the shared [`issue_recovery_get`] also runs it on the C3 failed-to-issue
    // path so the subscriber does not buffer live samples forever).
    issue_recovery_get(
        session,
        statesref,
        pending,
        &history_ke,
        base_keyexpr,
        opts,
        |state| state.finish_history(),
    );
}

/// R311y100 — issue a per-publisher HISTORY GET against a single detected late
/// publisher `(zid, eid)`'s `@adv` cache (zenoh advanced_subscriber.rs:847-870).
/// Unlike [`issue_history_query`] (which fans `<base>/@adv/**` over EVERY
/// publisher), this targets the one source via [`recovery_get_ke`] and carries
/// the same `_max` / `_time` history selector. Recovered replies feed the
/// per-source ordering; the terminal Final runs [`State::finish_recovery`] for
/// THIS source (decrement its `pending_queries`, flush when 0 + history idle).
/// MUST be called with the [`State`] lock RELEASED.
#[cfg(feature = "ext-pubsub-advanced-history")]
#[allow(clippy::too_many_arguments)]
fn issue_late_publisher_query<R, T>(
    session: &Session<R, T, Unicast>,
    statesref: &Arc<Mutex<State>>,
    pending: &Arc<PendingGets>,
    base_keyexpr: &str,
    zid: Vec<u8>,
    eid: u32,
    sample_depth: Option<usize>,
    max_age: Option<f64>,
    dest: Locality,
    timeout_ms: u32,
) where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    let zid_hex = zid_to_zenoh_hex(&zid);
    let recovery_ke = crate::advanced_ke::recovery_get_ke(base_keyexpr, &zid_hex, eid);
    // R311y442 — the late-publisher GET shares the history selector, so it picks
    // up the `;` separator and the mandatory `_anyke` with it. This is the site
    // where the omission bit hardest: a publisher detected AFTER the subscriber
    // joined is reachable ONLY through this GET, so without `_anyke` a late
    // publisher's whole cache was unreachable rather than merely stale.
    // The recovery reads each reply's timestamp (`reply.timestamp()` becomes the sample's), and
    // it is the runtime's own query, not an entity of the application: a build that makes
    // timestamps opt-in (`entity-timestamp-opt-in`) must not blind it.
    let opts = QueryOptions::get()
        .with_expose_timestamp(true)
        .with_allowed_destination(dest)
        .with_timeout_ms(timeout_ms)
        .with_parameters(history_selector(sample_depth, max_age).into_bytes());
    // R311y836 — pin the mode; see `issue_sn_recovery_get`. A late publisher's
    // WHOLE cache arrives through this one GET, so consolidating it would leave
    // the subscriber holding a single sample of a ring it just discovered.
    #[cfg(feature = "query-consolidation")]
    let opts = opts.with_consolidation(wz_session_core::query_mode::ConsolidationMode::None);
    let key = (zid, eid);
    issue_recovery_get(
        session,
        statesref,
        pending,
        &recovery_ke,
        base_keyexpr,
        opts,
        move |state| state.finish_recovery(&key),
    );
}

/// R2553 — the TIMESTAMPED twin of [`issue_late_publisher_query`]: the history
/// GET for a publisher whose `@adv` token carries the `uhlc` discriminator.
///
/// # The target is the token's OWN key expression
///
/// Upstream queries `Selector::from((s.key_expr(), params))` — the liveliness
/// sample's keyexpr verbatim, i.e. `<base>/@adv/pub/<zid>/uhlc/_`, the exact KE
/// the publisher declared its cache queryable on. The sequenced path above
/// instead builds a `<base>/@adv/*/<zid>/<eid>/**` wildcard, and both reach the
/// same queryable; the difference is that a wildcard form would have to invent a
/// spelling for the `uhlc` chunk in a second place, and this module's `@adv`
/// SSOT exists to stop exactly that. So this one takes the token KE it was
/// handed, which is both the faithful form and the one with no second spelling.
///
/// # No `_sn`, two history knobs
///
/// A timestamped source has no sequence numbers, so there is no range to ask
/// for: the selector is [`history_selector`]'s `_max` + `_time` pair and
/// nothing else — which is what upstream builds here too, the same two
/// `historyconf` knobs its sequenced arm uses. R2550's zero-bound refusal
/// therefore covers this GET as well, because it refuses the knobs before any
/// selector is built from them.
#[cfg(feature = "ext-pubsub-advanced-history")]
#[allow(clippy::too_many_arguments)]
fn issue_timestamped_late_publisher_query<R, T>(
    session: &Session<R, T, Unicast>,
    statesref: &Arc<Mutex<State>>,
    pending: &Arc<PendingGets>,
    base_keyexpr: &str,
    token_keyexpr: &str,
    zid: Vec<u8>,
    sample_depth: Option<usize>,
    max_age: Option<f64>,
    dest: Locality,
    timeout_ms: u32,
) where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    // The recovery reads each reply's timestamp (`reply.timestamp()` becomes the sample's), and
    // it is the runtime's own query, not an entity of the application: a build that makes
    // timestamps opt-in (`entity-timestamp-opt-in`) must not blind it.
    let opts = QueryOptions::get()
        .with_expose_timestamp(true)
        .with_allowed_destination(dest)
        .with_timeout_ms(timeout_ms)
        .with_parameters(history_selector(sample_depth, max_age).into_bytes());
    // R311y836 — pin the mode; see `issue_late_publisher_query`. The argument is
    // identical and the stake is the same: a timestamped publisher's WHOLE cache
    // arrives through this one GET.
    #[cfg(feature = "query-consolidation")]
    let opts = opts.with_consolidation(wz_session_core::query_mode::ConsolidationMode::None);
    issue_recovery_get(
        session,
        statesref,
        pending,
        token_keyexpr,
        base_keyexpr,
        opts,
        move |state| state.finish_timestamped_recovery(&zid),
    );
}

/// R2555 — the THIRD late-publisher GET: for a token whose zid chunk does not
/// decode, so there is no source to key a slot on
/// ([`AdvPublisherSource::Unidentified`]). Upstream's own arm,
/// `zenoh-ext/src/advanced_subscriber.rs` @ `} else if s.kind() == SampleKind::Put {`.
///
/// # Why it is accounted GLOBALLY and what that buys
///
/// The other two GETs open a per-source slot so their replies flush in that
/// source's order. This one has no identity to open a slot against, so it rides
/// the GLOBAL count instead — which is upstream's `states.global_pending_queries += 1`
/// paired with its `InitialRepliesHandler`, the same handler the startup
/// `@adv/**` GET uses. The effect is the honest one: every source's buffer
/// holds until this GET finishes too, because a reply from an unidentified
/// publisher may be older than something already buffered and nothing else can
/// say which source it belongs to.
///
/// ⚠ THIS IS THE CALLER THAT MAKES THE COUNT EXCEED ONE, which is why
/// [`State::global_pending_queries`] had to stop being a `bool` in the commit
/// before this one. On a flag, this GET's Final would have released every
/// buffer while the startup GET was still returning older samples.
#[cfg(feature = "ext-pubsub-advanced-history")]
#[allow(clippy::too_many_arguments)]
fn issue_unidentified_late_publisher_query<R, T>(
    session: &Session<R, T, Unicast>,
    statesref: &Arc<Mutex<State>>,
    pending: &Arc<PendingGets>,
    base_keyexpr: &str,
    token_keyexpr: &str,
    sample_depth: Option<usize>,
    max_age: Option<f64>,
    dest: Locality,
    timeout_ms: u32,
) where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    // The recovery reads each reply's timestamp (`reply.timestamp()` becomes the sample's), and
    // it is the runtime's own query, not an entity of the application: a build that makes
    // timestamps opt-in (`entity-timestamp-opt-in`) must not blind it.
    let opts = QueryOptions::get()
        .with_expose_timestamp(true)
        .with_allowed_destination(dest)
        .with_timeout_ms(timeout_ms)
        .with_parameters(history_selector(sample_depth, max_age).into_bytes());
    // R311y836 — pin the mode; see the two GETs above. Same argument, same stake.
    #[cfg(feature = "query-consolidation")]
    let opts = opts.with_consolidation(wz_session_core::query_mode::ConsolidationMode::None);
    issue_recovery_get(
        session,
        statesref,
        pending,
        token_keyexpr,
        base_keyexpr,
        opts,
        // The GLOBAL finish, not a per-source one: this GET was counted
        // globally because it has no source to be counted against.
        |state| state.finish_history(),
    );
}

/// R311y100 — the late-publisher liveliness callback body, factored out as a
/// single source of truth the real liveliness subscriber closure is thin glue
/// over: a plain readability extraction (the closure at the declare site calls
/// only this fn). R311y101 drives it end-to-end through the real closure via an
/// injected inbound `DeclToken` (`dispatch_declare`, see the composed test), so
/// the closure's field extraction + captured args ARE exercised. On a `Put`,
/// open a recovery slot for the detected publisher and issue its per-publisher
/// history GET (OUTSIDE the lock).
///
/// R2553 — BOTH shapes are handled now. A `uhlc` token takes the timestamped
/// arm ([`issue_timestamped_late_publisher_query`]) instead of being declined,
/// which is upstream's own branch at
/// `zenoh-ext/src/advanced_subscriber.rs` @ `if parsed.eid() == KE_UHLC {`,
/// together with its `else if let Ok(eid)` sibling.
#[cfg(feature = "ext-pubsub-advanced-history")]
#[allow(clippy::too_many_arguments)]
fn on_late_publisher_detected<R, T>(
    session: &Session<R, T, Unicast>,
    statesref: &Arc<Mutex<State>>,
    pending: &Arc<PendingGets>,
    base_keyexpr: &str,
    sample_kind: LivelinessSampleKind,
    sample_keyexpr: &str,
    sample_depth: Option<usize>,
    max_age: Option<f64>,
    dest: Locality,
    timeout_ms: u32,
) where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    // A Delete (the token's publisher left) needs no recovery — but it is no
    // longer a bare early return.
    //
    // ⚠ R2553 MEASURED WHAT UPSTREAM DOES INSTEAD OF RETURNING: its Delete arms
    // do exactly one thing, set `state.alive = false`, and that flag has exactly
    // one reader — its retention sweep. R2553 could not follow, because wz
    // reclaimed neither source map, so the flag would have been written by this
    // arm and read by nobody.
    //
    // R2621 BUILT THE READER, so the write lands. `mark_source_gone` sets the
    // flag on both shapes and the sweep is what acts on it; the recovery
    // short-circuit below is unchanged, because a departed publisher still has
    // nothing to recover.
    if sample_kind != LivelinessSampleKind::Put {
        // The write is recovery-scoped because the flag's only reader, the
        // retention sweep, is: see [`Retention`] for why that scope is the
        // configuration's and not an omission.
        #[cfg(feature = "ext-pubsub-advanced-recovery")]
        if let Some(source) = parse_heartbeat_source(sample_keyexpr) {
            // `Unidentified` names no source, so there is no state to mark —
            // the same reason it is accounted globally on the Put side.
            if let Some((zid, eid)) = match source {
                AdvPublisherSource::Sequenced { zid, eid } => Some((zid, Some(eid))),
                AdvPublisherSource::Timestamped { zid } => Some((zid, None)),
                AdvPublisherSource::Unidentified => None,
            } {
                statesref
                    .lock()
                    .expect("advanced subscriber state mutex poisoned")
                    .set_source_alive(&zid, eid, false);
            }
        }
        return;
    }
    match parse_heartbeat_source(sample_keyexpr) {
        Some(AdvPublisherSource::Sequenced { zid, eid }) => {
            let issue = {
                let mut states = statesref
                    .lock()
                    .expect("advanced subscriber state mutex poisoned");
                // R2621 — the token's PUT arm is where `alive` becomes true,
                // upstream's `state.alive = true;`. Ordered before the late-
                // publisher decision so the state exists to mark.
                let issue = states.handle_late_publisher(
                    zid.clone(),
                    eid,
                    session.clock().now_monotonic_ms(),
                );
                #[cfg(feature = "ext-pubsub-advanced-recovery")]
                states.set_source_alive(&zid, Some(eid), true);
                issue
            };
            if issue {
                issue_late_publisher_query(
                    session,
                    statesref,
                    pending,
                    base_keyexpr,
                    zid,
                    eid,
                    sample_depth,
                    max_age,
                    dest,
                    timeout_ms,
                );
            }
        }
        Some(AdvPublisherSource::Timestamped { zid }) => {
            let issue = {
                let mut states = statesref
                    .lock()
                    .expect("advanced subscriber state mutex poisoned");
                // R2621 — the `uhlc` twin of the sequenced Put arm above.
                let issue = states.handle_late_timestamped_publisher(
                    zid.clone(),
                    session.clock().now_monotonic_ms(),
                );
                #[cfg(feature = "ext-pubsub-advanced-recovery")]
                states.set_source_alive(&zid, None, true);
                issue
            };
            if issue {
                issue_timestamped_late_publisher_query(
                    session,
                    statesref,
                    pending,
                    base_keyexpr,
                    sample_keyexpr,
                    zid,
                    sample_depth,
                    max_age,
                    dest,
                    timeout_ms,
                );
            }
        }
        // R2555 — the publisher announced itself but wz cannot read its zid, so
        // no per-source slot can be keyed. Upstream queries it anyway under the
        // GLOBAL count, and so does this.
        Some(AdvPublisherSource::Unidentified) => {
            statesref
                .lock()
                .expect("advanced subscriber state mutex poisoned")
                .open_global_history_slot();
            issue_unidentified_late_publisher_query(
                session,
                statesref,
                pending,
                base_keyexpr,
                sample_keyexpr,
                sample_depth,
                max_age,
                dest,
                timeout_ms,
            );
        }
        // R2555 — this arm now means ONE thing, which it did not before: a key
        // expression that is not an `@adv/pub` token, or whose discriminator is
        // neither `uhlc` nor a `u32`. The zid case used to land here too and
        // was the hidden third shape; it has its own arm above.
        None => {}
    }
}

/// R311y83 — run ONE periodic recovery tick: collect each source's
/// `_sn=last+1..` request under the state lock, then issue the GETs OUTSIDE the
/// lock (same re-entrancy discipline as the sample-driven path). The background
/// [`AbortOnDropTask`] loop calls this every period; a test drives it directly so
/// the recovery path is exercised deterministically (no timer wait).
#[cfg(feature = "ext-pubsub-advanced-recovery")]
fn run_periodic_tick<R, T>(
    session: &Session<R, T, Unicast>,
    statesref: &Arc<Mutex<State>>,
    pending: &Arc<PendingGets>,
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
        issue_recovery_query(
            session,
            statesref,
            pending,
            base_keyexpr,
            req,
            dest,
            timeout_ms,
        );
    }
}

/// RAII handle for the subscriber's two timer tasks — the periodic recovery
/// loop (thin glue over [`run_periodic_tick`] / [`State::periodic_requests`])
/// and the R2621 retention sweep (thin glue over
/// [`State::reclaim_expired_sources`]). Dropping it aborts the loop, so an
/// undeclared subscriber stops re-asking and stops sweeping at once (the
/// [`crate::storage_replication_service::DigestPublisher`] teardown shape).
///
/// R2817 — ONE type for both, as upstream holds both in one
/// (`zenoh-ext/src/advanced_subscriber.rs` @ `_gc_task: AbortOnDropHandle<()>,`
/// and `periodic_task: Option<AbortOnDropHandle<()>>,`), and DETACHABLE,
/// because a backgrounded subscriber has no handle left to hold it. What ends
/// a detached loop is the loop itself: each task holds only WEAK references to
/// the state and the session, which is upstream's own shape
/// (`zenoh-ext/src/advanced_subscriber.rs` @ `async fn gc_task(statesref: Weak<Mutex<State>>, retention_period: Duration) {`),
/// and returns on the first tick either is gone. Until R2817 the tasks held
/// both strongly and relied on this abort alone — which is also why a
/// backgrounded subscriber could not be built on them: a detached task
/// holding its session strongly keeps that session alive forever.
#[cfg(feature = "ext-pubsub-advanced-recovery")]
struct AbortOnDropTask {
    /// `Some` until [`Self::detach`] takes it.
    handle: Option<tokio::task::JoinHandle<()>>,
}

#[cfg(feature = "ext-pubsub-advanced-recovery")]
impl AbortOnDropTask {
    fn new(handle: tokio::task::JoinHandle<()>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    /// Let the task run on without this handle; it ends when its weak
    /// references stop upgrading.
    fn detach(mut self) {
        self.handle.take();
    }
}

#[cfg(feature = "ext-pubsub-advanced-recovery")]
impl Drop for AbortOnDropTask {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// RAII teardown for the subscriber's in-flight recovery / history GETs: on
/// drop, unregister every one that has not reached its terminal Final.
///
/// R2816 — it holds the session. It held a boxed cancel closure because
/// [`AdvancedSubscriber`] was generic over `R` alone; the subscriber is
/// `(R, T)` now, and `Session::cancel_pending_query` needs no bound a `Drop`
/// impl could not carry.
///
/// R2817 — and it can be DISARMED, for [`AdvancedSubscriber::background`]: a
/// backgrounded subscriber is still running, so the GETs it has in flight are
/// still its own and must complete rather than be cancelled. They end with
/// the session, whose reply registry holds them.
#[cfg(feature = "ext-pubsub-advanced-recovery")]
struct RecoveryCancel<R: SessionRuntime, T: TimeSource> {
    pending: Arc<PendingGets>,
    session: Session<R, T, Unicast>,
    /// `true` until [`Self::disarm`]; the `Drop` cancels only while armed.
    armed: bool,
}

#[cfg(feature = "ext-pubsub-advanced-recovery")]
impl<R: SessionRuntime, T: TimeSource> RecoveryCancel<R, T> {
    fn disarm(mut self) {
        self.armed = false;
    }
}

#[cfg(feature = "ext-pubsub-advanced-recovery")]
impl<R: SessionRuntime, T: TimeSource> Drop for RecoveryCancel<R, T> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        for rid in self.pending.cancel() {
            self.session.cancel_pending_query(rid);
        }
    }
}

/// A live advanced subscriber bound to a [`Session`]: owns the wrapped
/// plain [`Subscriber`] (RAII: dropping it undeclares) whose callback runs
/// the per-source ordering / de-duplication state machine.
///
/// R2816 — GENERIC OVER THE SESSION'S `T` AND HOLDING THE SESSION, the shape
/// `AdvancedPublisher<R, T>` has had all along and upstream's has too (its
/// `detect_publishers` reaches the session through the wrapped subscriber).
/// It was `R`-only, and three members of this struct had to be type-erased to
/// `Box<dyn Send>` or a boxed closure for exactly that reason; `detect_publishers`
/// could not be written at all, because nothing on the handle could declare.
pub struct AdvancedSubscriber<
    R: SessionRuntime = crate::runtime_impl::TokioRuntime,
    T: TimeSource = crate::runtime_impl::TokioTime,
> {
    // ⚠ THE FIELD ORDER IS THE RETRACTION ORDER, and for the entities it is
    // zenoh-pico's: the subscription, then the late-publisher subscription, then
    // the heartbeat subscription, then the detection token
    // (`vendor/zenoh-pico/src/api/advanced_subscriber.c` @
    // `z_result_t _ze_advanced_subscriber_undeclare(_ze_advanced_subscriber_t *sub) {`
    // undeclares the first three, and the token goes with the state it lives in).
    // Rust drops fields in the order they are declared. Each entity is [`Held`]
    // with the declaration that names it, so a host that declares keys retracts
    // each key right after its entity, which is where a peer sees it.
    _subscriber: Held<Subscriber<R>>,
    /// R2816 — the session this subscriber was declared on; see the type doc.
    session: Session<R, T, Unicast>,
    /// R2815 — the global identity [`Self::id`] reports; see [`global_id_of`].
    id: EntityGlobalId,
    /// The shared ordering state — upstream's `statesref`, and for the same
    /// reason upstream keeps it on the handle: a sample-miss listener is
    /// declared on the SUBSCRIBER after it exists, so the handle must be able
    /// to reach the registry the callbacks fire into.
    ///
    /// R2814 — unconditional. R311y83 kept it only so a test could drive a
    /// recovery tick, and R311y95 then gated it `cfg(test)` because production
    /// never read it; [`Self::sample_miss_listener`] is the production reader
    /// that makes it a real field in every build.
    statesref: Arc<Mutex<State>>,
    /// R311y83 — the periodic recovery task (RAII abort-on-drop), `Some` only
    /// when `RecoveryConfig::periodic_queries` was set.
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    _periodic: Option<AbortOnDropTask>,
    /// R2621 — the retention sweep's RAII handle. Held so a dropped subscriber
    /// stops sweeping; see [`AbortOnDropTask`].
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    _retention: Option<AbortOnDropTask>,
    /// R311y592 — the in-flight recovery / history GET cancellation (RAII
    /// cancel-on-drop), `None` only for the plain [`Self::declare`] form, which
    /// issues no GET at all. Aborting `_periodic` stops the subscriber ASKING;
    /// this is what stops it ANSWERING — the two are separate teardowns because
    /// a GET already on the wire outlives the timer that started it.
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    _recovery_cancel: Option<RecoveryCancel<R, T>>,
    /// R311y100 — the late-publisher-detection LIVELINESS subscriber on
    /// `<ke>/@adv/pub/**` (RAII undeclare-on-drop), `Some` only when
    /// `HistoryConfig::detect_late_publishers` was set.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    _liveliness_sub: Option<Held<crate::session::LivelinessSubscriber<R, T>>>,
    /// R311y84 — the heartbeat subscriber on `<ke>/@adv/pub/**` (RAII
    /// undeclare-on-drop), `Some` only when `RecoveryConfig::heartbeat` was set.
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    _heartbeat_sub: Option<Held<Subscriber<R>>>,
    /// R311y826 — the `@adv/sub` DETECTION liveliness token (RAII
    /// undeclare-on-drop), `Some` only when
    /// [`AdvancedSubscriberOptions::subscriber_detection`] was set.
    ///
    /// The sibling of the publisher's `@adv/pub` token: this is what makes the
    /// subscriber visible to a third party, and dropping the subscriber must
    /// retract it, or an observer keeps seeing a subscriber that is gone.
    ///
    /// R2816 — the token itself rather than R311y826's `DetectionTokenGuard`,
    /// a `Box<dyn Send>` that existed only because this struct had no `T`.
    _detection_token: Option<Held<crate::session::LivelinessToken<R, T>>>,
    /// The host's naming of the entities, kept for [`Self::background`]: a
    /// backgrounded subscriber has no handle left to let go of the declarations
    /// that name its entities, so it hands them back to the host that made them.
    forms: Option<FormsHandle>,
}

#[cfg(feature = "ext-pubsub-advanced-recovery")]
impl<R: SessionRuntime, T: TimeSource> AdvancedSubscriber<R, T> {
    /// Whether the heartbeat-driven retransmission channel is actually LIVE.
    ///
    /// R311y544. `RecoveryConfig::heartbeat` is a REQUEST; this is the
    /// OUTCOME. They can differ: [`declare_with_options`](Self::declare_with_options)
    /// degrades rather than failing when the derived `<base>/@adv/pub/**`
    /// keyexpr is refused by wz's outbound pico-safety gate, because the live
    /// subscription is the contract and the recovery channels are an
    /// enhancement.
    ///
    /// Before this accessor existed the degradation was SILENT, and the only
    /// thing observable about it was an argv flag echoed back into a log line —
    /// which reads as "heartbeat is on" whether or not any heartbeat subscriber
    /// exists. Callers that need the enhancement (and every fixture asserting
    /// it) must read this, not the request.
    pub fn heartbeat_channel_is_live(&self) -> bool {
        self._heartbeat_sub.is_some()
    }

    /// R311y592 — this subscriber's in-flight recovery / history GET registry.
    ///
    /// Test-only, and the companion of the `statesref` field: a
    /// test that drives [`run_periodic_tick`] directly must hand it the SAME
    /// registry the subscriber's own callbacks use, or the tick's GETs land
    /// outside the teardown this type exists to guarantee.
    ///
    /// Panics on the plain [`Self::declare`] form, which issues no GET and so
    /// has no registry — a direct tick against it would be meaningless.
    ///
    /// The gate is the UNION of its two callers' gates — `composed_periodic_
    /// tick_recovers_lost_last_sample` (`all(recovery, cache, allow-loop)`) and
    /// `a_synchronously_answered_history_get_leaves_no_registration_behind`
    /// (`all(history, cache)`) — reduced by the `ext-pubsub-advanced-recovery`
    /// this `impl` block already carries and which `history` implies. Not a bare
    /// `cfg(test)`: see the note on [`PendingGets::sizes`].
    #[cfg(all(
        test,
        feature = "ext-pubsub-advanced-cache",
        any(feature = "pubsub-allow-loop", feature = "ext-pubsub-advanced-history")
    ))]
    fn pending_gets(&self) -> &Arc<PendingGets> {
        &self
            ._recovery_cancel
            .as_ref()
            .expect("declare_with_options subscribers own a recovery registry")
            .pending
    }
}

/// R2815 — refuse a session whose own zid cannot be an identity, BEFORE
/// anything is declared. See [`AdvancedSubscribeError::SessionZid`].
fn require_session_zid(zid: &[u8]) -> Result<(), AdvancedSubscribeError> {
    if (1..=16).contains(&zid.len()) {
        Ok(())
    } else {
        Err(AdvancedSubscribeError::SessionZid { len: zid.len() })
    }
}

/// R2815 — the subscriber's global identity: its session's zid and the id its
/// declaration carries on the wire, which is upstream's
/// `zenoh-ext/src/advanced_subscriber.rs` @ `pub fn id(&self) -> EntityGlobalId {`
/// delegating to the plain subscriber's own id.
///
/// The eid is the plain subscription's id because that IS what the
/// declaration sends (`announce_subscriber`: "the wire subscriber id IS the
/// local SubscriptionId"). `zid` has passed [`require_session_zid`].
fn global_id_of<R: SessionRuntime>(
    zid: &[u8],
    subscriber: &Subscriber<R>,
) -> Result<EntityGlobalId, AdvancedSubscribeError> {
    let id = subscriber.id().as_u64();
    let eid = u32::try_from(id).map_err(|_| AdvancedSubscribeError::EntityIdOutOfRange { id })?;
    EntityGlobalId::new(zid, eid).ok_or(AdvancedSubscribeError::SessionZid { len: zid.len() })
}

/// The identity a subscriber reports: its host's, when the host has one
/// ([`DeclarationForms::entity_id`]), else the plain subscription's own
/// ([`global_id_of`]).
///
/// A host that declares this subscriber once per connection has one identity
/// for it and as many plain subscription ids as it has connections, and the
/// identity is what the detection token is named with.
fn identity_of<R: SessionRuntime>(
    zid: &[u8],
    subscriber: &Subscriber<R>,
    forms: Option<&FormsHandle>,
) -> Result<EntityGlobalId, AdvancedSubscribeError> {
    match forms.and_then(|f| f.forms().entity_id()) {
        Some(eid) => EntityGlobalId::new(zid, eid)
            .ok_or(AdvancedSubscribeError::SessionZid { len: zid.len() }),
        None => global_id_of(zid, subscriber),
    }
}

/// What `forms` says about one entity, the literal form when it says nothing.
fn form_of(
    forms: Option<&FormsHandle>,
    ask: impl FnOnce(&dyn DeclarationForms) -> EntityForm,
) -> EntityForm {
    forms.map(|f| ask(f.forms())).unwrap_or_default()
}

/// Declare a plain subscription on `keyexpr` in `form`: announced literally or
/// on a declared key, retracted the way the form says, and held together with
/// what names it.
fn declare_subscription<R, T>(
    session: &Session<R, T, Unicast>,
    keyexpr: &str,
    form: &EntityForm,
    options: SubscribeOptions,
    callback: impl FnMut(&dyn SampleView) + Send + 'static,
) -> Result<Held<Subscriber<R>>, AdvancedSubscribeError>
where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    let options = options.with_retraction_naming(form.retraction().cloned());
    let subscriber = if form.is_literal() {
        session.declare_subscriber(keyexpr.to_owned(), options, callback)?
    } else {
        session.declare_subscriber_aliased(form.mapping_id(), form.suffix(), options, callback)?
    };
    Ok(Held::new(subscriber, form))
}

/// R2814 — the surface every build has, whatever the recovery feature says:
/// the handle's own accessors and the miss-listener declarations.
impl<R: SessionRuntime, T: TimeSource> AdvancedSubscriber<R, T> {
    /// R2815 — this subscriber's global identity, upstream's
    /// `zenoh-ext/src/advanced_subscriber.rs` @ `pub fn id(&self) -> EntityGlobalId {`.
    ///
    /// The same pair its `@adv/sub` detection token is named with, by
    /// construction: both are read from here.
    pub fn id(&self) -> EntityGlobalId {
        self.id
    }

    /// R2815 — the key expression this subscriber subscribes to, upstream's
    /// `zenoh-ext/src/advanced_subscriber.rs` @ `pub fn key_expr(&self) -> &KeyExpr<'static> {`.
    ///
    /// Spelled `keyexpr` like the plain [`Subscriber::keyexpr`] and
    /// `AdvancedPublisher::keyexpr` (R2619): one concept, one spelling in this
    /// crate.
    pub fn keyexpr(&self) -> &str {
        self._subscriber.entity.keyexpr()
    }

    /// R2815 — undeclare this subscriber, upstream's
    /// `zenoh-ext/src/advanced_subscriber.rs` @ `pub fn undeclare(self) -> SubscriberUndeclaration<()> {`.
    ///
    /// Consuming and infallible, the shape R2619 gave the advanced publisher
    /// for the same reason: every piece of this subscriber's wire and task
    /// state retracts on drop — the plain subscription, the heartbeat and
    /// late-publisher subscribers, the detection token, the recovery and
    /// retention tasks and the in-flight GETs. What the method adds is that the
    /// caller says WHEN, at a point after which the handle no longer exists.
    pub fn undeclare(self) {
        drop(self);
    }

    /// R2817 — run this subscriber in the BACKGROUND until its session is
    /// dropped, with no handle left to retract it: upstream's
    /// `zenoh-ext/src/advanced_subscriber.rs` @ `pub fn background(self) -> AdvancedSubscriberBuilder<'a, 'b, 'c, Callback<Sample>, true> {`.
    ///
    /// Upstream resolves that builder by setting its plain subscribers to the
    /// background (`zenoh-ext/src/advanced_subscriber.rs` @ `fn set_background_impl(&mut self, background: bool) {`)
    /// and keeps everything else in the state their callbacks share, so the
    /// whole subscriber lives exactly as long as those callbacks — until the
    /// session closes. Every piece here reaches that same lifetime: the live,
    /// heartbeat and late-publisher subscriptions stay declared, the detection
    /// token stays asserted, the GETs in flight run to their Final, and the
    /// timer tasks run on until their weak references stop upgrading.
    ///
    /// Nothing left behind holds the session strongly, which is what makes
    /// "until the session is dropped" true rather than "forever": each
    /// callback and task downgrades it (see the private `AbortOnDropTask`).
    ///
    /// A method on the handle rather than a declare flag, as
    /// [`SampleMissListener::background`] and the plain subscriber's are in
    /// this crate; upstream offers it on the builder, which wz does not have.
    pub fn background(self) {
        let Self {
            _subscriber,
            session: _,
            id: _,
            statesref: _,
            #[cfg(feature = "ext-pubsub-advanced-recovery")]
            _periodic,
            #[cfg(feature = "ext-pubsub-advanced-recovery")]
            _retention,
            #[cfg(feature = "ext-pubsub-advanced-recovery")]
            _recovery_cancel,
            #[cfg(feature = "ext-pubsub-advanced-recovery")]
            _heartbeat_sub,
            #[cfg(feature = "ext-pubsub-advanced-history")]
            _liveliness_sub,
            _detection_token,
            forms,
        } = self;
        // What names an entity is handed to the host that made it, since nothing
        // is left to let it go after the entity: the entity stays declared for
        // the session's life, and so must its name.
        let retain = |keeps: Option<Arc<dyn Send + Sync>>| {
            if let (Some(forms), Some(keeps)) = (forms.as_ref(), keeps) {
                forms.forms().retain(keeps);
            }
        };
        // In the order the entities retract, which is the order the host will
        // let their names go in.
        let Held { entity, _keeps } = _subscriber;
        entity.background();
        retain(_keeps);
        #[cfg(feature = "ext-pubsub-advanced-history")]
        if let Some(Held { entity, _keeps }) = _liveliness_sub {
            entity.background();
            retain(_keeps);
        }
        #[cfg(feature = "ext-pubsub-advanced-recovery")]
        {
            for task in [_periodic, _retention].into_iter().flatten() {
                task.detach();
            }
            if let Some(cancel) = _recovery_cancel {
                cancel.disarm();
            }
            if let Some(Held { entity, _keeps }) = _heartbeat_sub {
                entity.background();
                retain(_keeps);
            }
        }
        if let Some(Held { entity, _keeps }) = _detection_token {
            entity.background();
            retain(_keeps);
        }
    }

    /// R2816 — watch the advanced PUBLISHERS of this subscriber's key
    /// expression come and go, upstream's
    /// `zenoh-ext/src/advanced_subscriber.rs` @ `pub fn detect_publishers(&self) -> LivelinessSubscriberBuilder<'_, '_, DefaultHandler> {`.
    ///
    /// A liveliness subscriber on `<keyexpr>/@adv/pub/**`, which is where a
    /// publisher that opts into detection declares its token; `callback` sees
    /// each one appear (`Put`) and go (`Delete`). Upstream returns the plain
    /// liveliness builder, so the caller picks history and handler there;
    /// here `options` carries the same choice, and the returned handle is the
    /// plain one, undeclared on drop.
    pub fn detect_publishers(
        &self,
        options: crate::session::LivelinessSubscriberOptions,
        callback: impl FnMut(crate::declare::LivelinessSample<'_>) + Send + 'static,
    ) -> Result<
        crate::session::LivelinessSubscriber<R, T>,
        crate::session::LivelinessSubscriberAliasError,
    > {
        self.session.declare_liveliness_subscriber(
            crate::advanced_ke::publisher_detection_ke(self.keyexpr()),
            options,
            callback,
        )
    }

    /// R2816 — [`Self::detect_publishers`] with the samples on a channel,
    /// upstream's default-handler form; the counterpart of
    /// `Session::declare_liveliness_subscriber_with_channel`, which it
    /// delegates to.
    #[allow(clippy::type_complexity)]
    pub fn detect_publishers_with_channel(
        &self,
        options: crate::session::LivelinessSubscriberOptions,
    ) -> Result<
        (
            crate::session::LivelinessSubscriber<R, T>,
            tokio::sync::mpsc::UnboundedReceiver<crate::session::OwnedLivelinessSample>,
        ),
        crate::session::LivelinessSubscriberAliasError,
    > {
        self.session.declare_liveliness_subscriber_with_channel(
            crate::advanced_ke::publisher_detection_ke(self.keyexpr()),
            options,
        )
    }

    /// Declare a sample-miss listener: `callback` receives a [`Miss`] for every
    /// forward gap this subscriber detects on a sequenced source from now on.
    /// Upstream's `zenoh-ext/src/advanced_subscriber.rs` @ `pub fn sample_miss_listener(&self) -> SampleMissListenerBuilder<'_, DefaultHandler> {`
    /// in its `.callback(..)` form.
    ///
    /// Any number may be declared, and each is retracted on its own — by
    /// dropping the returned handle or calling [`SampleMissListener::undeclare`];
    /// [`SampleMissListener::background`] keeps one for the subscriber's life.
    ///
    /// A listener hears only misses detected AFTER it is declared, as
    /// upstream's does: a hole already reported to nobody is not replayed.
    pub fn sample_miss_listener<F>(&self, callback: F) -> SampleMissListener
    where
        F: FnMut(Miss) + Send + 'static,
    {
        let id = self
            .statesref
            .lock()
            .expect("advanced subscriber state mutex poisoned")
            .miss_handlers()
            .register(Box::new(callback));
        SampleMissListener::new(id, Arc::downgrade(&self.statesref))
    }

    /// Declare a sample-miss listener whose misses arrive on a channel —
    /// upstream's DEFAULT form, `sample_miss_listener()` resolved with its
    /// `DefaultHandler`, a FIFO the caller receives from.
    ///
    /// Unbounded, as `LivelinessSubscriber`'s channel form is in this crate:
    /// a miss is reported under the subscriber's state lock, so a bounded
    /// channel that blocked on a slow reader would stall sample delivery for
    /// every source — the opposite of what reporting a gap is for.
    pub fn sample_miss_listener_with_channel(
        &self,
    ) -> (
        SampleMissListener,
        tokio::sync::mpsc::UnboundedReceiver<Miss>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let listener = self.sample_miss_listener(move |miss| {
            // A receiver that has gone away is a listener nobody reads; the
            // miss is dropped exactly as it is with no listener at all.
            let _ = tx.send(miss);
        });
        (listener, rx)
    }

    /// R2819 — [`Self::declare`] with the samples handed to a queue instead of
    /// a callback: upstream's handler form, `zenoh-ext/src/advanced_subscriber.rs`
    /// @ `pub fn with<Handler>(self, handler: Handler) -> AdvancedSubscriberBuilder<'a, 'b, 'c, Handler>`,
    /// whose default resolves to a FIFO the caller receives from, through
    /// @ `pub fn handler(&self) -> &Handler {`.
    ///
    /// BOUNDED, AND IT WAITS RATHER THAN DROPS. Upstream's FIFO blocks its
    /// sender when full; this is the crate's same answer for a plain
    /// subscription, [`Session::declare_subscriber_buffered`]: a delivery
    /// stages and returns, and the drive loop awaits capacity at its drain. So
    /// a slow reader slows this session instead of losing samples, and it is
    /// safe that the advanced subscriber delivers under its state lock —
    /// staging never waits. `capacity` sizes the memory a slow reader may pin,
    /// as for the plain form.
    ///
    /// The receiver and drain handle are returned beside the subscriber, as
    /// [`Self::detect_publishers_with_channel`] and the plain form return
    /// theirs; upstream reaches its handler through the subscriber instead.
    ///
    /// # Panics
    ///
    /// If `capacity` is 0: a queue nothing can enter is a subscription the
    /// loop would wait on forever.
    #[allow(clippy::type_complexity)]
    pub fn declare_buffered(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        capacity: usize,
    ) -> Result<
        (
            Self,
            tokio::sync::mpsc::Receiver<Sample>,
            crate::session::BufferedDrainStage,
        ),
        AdvancedSubscribeError,
    >
    where
        T: TimeSource + 'static,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        SessionLinkActions<R, T>: Send + Sync + 'static,
        <R as SessionRuntime>::IterationWork: crate::session::BufferedWork,
    {
        let (deliver, rx, drain_stage) = session.buffered_delivery::<Sample>(capacity);
        let subscriber = Self::declare(session, keyexpr, deliver)?;
        Ok((subscriber, rx, drain_stage))
    }

    /// R2819 — [`Self::declare_with_options`] with the samples on a queue; see
    /// [`Self::declare_buffered`]. Every delivery path the options arm — live,
    /// recovered, history, and a flushed reorder buffer — reaches the queue,
    /// because all of them deliver through the one `on_sample` this stages.
    ///
    /// # Panics
    ///
    /// If `capacity` is 0, as [`Self::declare_buffered`].
    #[allow(clippy::type_complexity)]
    pub fn declare_with_options_buffered(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        options: AdvancedSubscriberOptions,
        capacity: usize,
    ) -> Result<
        (
            Self,
            tokio::sync::mpsc::Receiver<Sample>,
            crate::session::BufferedDrainStage,
        ),
        AdvancedSubscribeError,
    >
    where
        R: 'static,
        T: TimeSource + Send + Sync + 'static,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        SessionLinkActions<R, T>: Send + Sync + 'static,
        Session<R, T, Unicast>: Send + 'static,
        <R as SessionRuntime>::IterationWork: crate::session::BufferedWork,
    {
        let (deliver, rx, drain_stage) = session.buffered_delivery::<Sample>(capacity);
        let subscriber = Self::declare_with_options(session, keyexpr, options, deliver)?;
        Ok((subscriber, rx, drain_stage))
    }
}

#[cfg(not(feature = "ext-pubsub-advanced-recovery"))]
impl<R: SessionRuntime, T: TimeSource> AdvancedSubscriber<R, T> {
    /// Declare an advanced subscriber on `keyexpr`. `on_sample` receives
    /// each in-order / de-duplicated [`Sample`]; a detected forward gap on a
    /// sequenced source is reported to the listeners declared through
    /// [`Self::sample_miss_listener`].
    pub fn declare<OnSample>(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        on_sample: OnSample,
    ) -> Result<Self, AdvancedSubscribeError>
    where
        T: TimeSource + 'static,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        SessionLinkActions<R, T>: Send + Sync + 'static,
        OnSample: FnMut(Sample) + Send + 'static,
    {
        Self::declare_ordering(session, keyexpr, Locality::Any, None, on_sample)
    }

    /// R2819 — declare an advanced subscriber from [`AdvancedSubscriberOptions`]
    /// in a build without recovery, where the options that exist are the two
    /// upstream offers on every advanced subscriber: the live subscription's
    /// origin and subscriber detection.
    ///
    /// Its bounds are the recovery build's `declare_with_options` bounds, not
    /// this build's lighter [`Self::declare`] ones, so compiling recovery in
    /// cannot tighten the signature under a caller (the invariant R311y88
    /// states for `declare`).
    pub fn declare_with_options<OnSample>(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        options: AdvancedSubscriberOptions,
        on_sample: OnSample,
    ) -> Result<Self, AdvancedSubscribeError>
    where
        R: 'static,
        T: TimeSource + Send + Sync + 'static,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        SessionLinkActions<R, T>: Send + Sync + 'static,
        Session<R, T, Unicast>: Send + 'static,
        OnSample: FnMut(Sample) + Send + 'static,
    {
        let mut declared = Self::declare_ordering(
            session,
            keyexpr,
            options.allowed_origin,
            options.forms.clone(),
            on_sample,
        )?;
        // Declared last, as the recovery build declares it: a token that
        // outraces its own subscription tells an observer something untrue.
        // A refusal drops `declared`, which retracts the subscription.
        declared._detection_token =
            declare_detection_token(session, declared.keyexpr(), &options, declared.id)?;
        Ok(declared)
    }

    /// The ordering subscriber both declare forms of this build share.
    fn declare_ordering<OnSample>(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        allowed_origin: Locality,
        forms: Option<FormsHandle>,
        on_sample: OnSample,
    ) -> Result<Self, AdvancedSubscribeError>
    where
        T: TimeSource + 'static,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        SessionLinkActions<R, T>: Send + Sync + 'static,
        OnSample: FnMut(Sample) + Send + 'static,
    {
        require_session_zid(session.zid())?;
        let state = Arc::new(Mutex::new(State::new(
            Box::new(on_sample),
            MissHandlers::default(),
        )));
        let cb_state = Arc::clone(&state);
        let cb_clock = Arc::clone(session.clock());
        let keyexpr: String = keyexpr.into();
        let form = form_of(forms.as_ref(), |f| f.subscriber(&keyexpr));
        let subscriber = declare_subscription(
            session,
            &keyexpr,
            &form,
            SubscribeOptions::default().with_allowed_origin(allowed_origin),
            move |view: &dyn SampleView| {
                cb_state
                    .lock()
                    .expect("advanced subscriber state mutex poisoned")
                    .handle(view, cb_clock.now_monotonic_ms());
            },
        )?;
        let id = identity_of(session.zid(), &subscriber.entity, forms.as_ref())?;
        Ok(Self {
            _subscriber: subscriber,
            session: session.clone(),
            id,
            statesref: state,
            // The option-free `declare()` cannot ask for detection.
            _detection_token: None,
            forms,
        })
    }
}

#[cfg(feature = "ext-pubsub-advanced-recovery")]
impl<R: SessionRuntime, T: TimeSource> AdvancedSubscriber<R, T> {
    /// Declare a plain advanced subscriber (no recovery): a forward gap is
    /// reported to the declared miss listeners and delivers past the hole. See
    /// [`Self::declare_with_options`] for the gap-recovering form.
    ///
    /// R311y88 (review H1) — this form does NOT route through `declare_impl`
    /// (which `tokio::spawn`s + whose callback captures the session): it builds
    /// a non-spawning subscriber whose callback only orders. Its bounds are
    /// therefore IDENTICAL to the recovery-OFF build's `declare` — so toggling
    /// `ext-pubsub-advanced-recovery` (an additive feature) cannot tighten this
    /// signature and break a downstream `declare` caller (the signature-stability
    /// invariant). The spawn-requiring bounds live only on `declare_with_options`.
    pub fn declare<OnSample>(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        on_sample: OnSample,
    ) -> Result<Self, AdvancedSubscribeError>
    where
        T: TimeSource + 'static,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        SessionLinkActions<R, T>: Send + Sync + 'static,
        OnSample: FnMut(Sample) + Send + 'static,
    {
        require_session_zid(session.zid())?;
        let state = Arc::new(Mutex::new(State::new(
            Box::new(on_sample),
            MissHandlers::default(),
        )));
        let cb_state = Arc::clone(&state);
        let cb_clock = Arc::clone(session.clock());
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
                    .handle_live(view, cb_clock.now_monotonic_ms());
            },
        )?;
        let id = global_id_of(session.zid(), &subscriber)?;
        Ok(Self {
            // The option-free form has no host to name anything: literal.
            _subscriber: Held::new(subscriber, &EntityForm::literal()),
            session: session.clone(),
            id,
            statesref: state,
            _periodic: None,
            #[cfg(feature = "ext-pubsub-advanced-recovery")]
            _retention: None,
            // The plain miss-form `declare()` issues no recovery / history GET
            // (its callback only orders), so there is nothing to cancel.
            _recovery_cancel: None,
            _heartbeat_sub: None,
            // The plain miss-form `declare()` never sets history, so no
            // late-publisher liveliness subscriber.
            #[cfg(feature = "ext-pubsub-advanced-history")]
            _liveliness_sub: None,
            // The option-free `declare()` cannot ask for detection.
            _detection_token: None,
            forms: None,
        })
    }

    /// Declare a configured advanced subscriber from [`AdvancedSubscriberOptions`]:
    /// any combination of retransmission (gap recovery), a startup history query,
    /// the GET locality, and the GET timeout. Recovery and history are INDEPENDENT
    /// (zenoh `.recovery()` / `.history()`): `options` with only `history` set is a
    /// history-without-retransmission subscriber. With recovery on, a forward gap is
    /// buffered and a sample-driven `_sn`-range recovery GET refills it from the
    /// publisher's `@adv` cache; a miss listener hears only a hole recovery does
    /// NOT fill. With recovery off, a forward gap reports a [`Miss`] and delivers
    /// past the hole. Misses go to the listeners declared through
    /// [`Self::sample_miss_listener`].
    pub fn declare_with_options<OnSample>(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        options: AdvancedSubscriberOptions,
        on_sample: OnSample,
    ) -> Result<Self, AdvancedSubscribeError>
    where
        R: 'static,
        T: TimeSource + Send + Sync + 'static,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        SessionLinkActions<R, T>: Send + Sync + 'static,
        Session<R, T, Unicast>: Send + 'static,
        OnSample: FnMut(Sample) + Send + 'static,
    {
        Self::declare_impl(
            session,
            keyexpr,
            on_sample,
            MissHandlers::default(),
            options,
        )
    }

    /// R2814 — [`Self::declare_with_options`] with ONE miss listener registered
    /// BEFORE the subscriber can detect anything, kept for the subscriber's
    /// life (the [`SampleMissListener::background`] form).
    ///
    /// # Why this exists beside the upstream-shaped pair
    ///
    /// `declare_with_options` issues its startup history GET inside the call,
    /// and those replies can complete — and flush their holes — before a
    /// listener declared afterwards is registered; in loopback they complete
    /// synchronously, so the window is not theoretical. Upstream has the same
    /// window and its callers live with it. Two kinds of wz host cannot: one
    /// that re-declares ONE logical subscriber on each connection it opens (the
    /// C ABIs' per-face replay, where the C program's listener already exists
    /// when the wz subscriber is made), and one whose reports are graded (the
    /// demo's `ADVANCED MISS` line, which the history legs read). Seeding the
    /// registry before the subscriber exists closes that window rather than
    /// narrowing it. Every other listener is declared on the handle, as
    /// upstream's are.
    pub fn declare_with_options_and_miss_listener<OnSample, OnMiss>(
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
        let mut miss_handlers = MissHandlers::default();
        miss_handlers.register(Box::new(on_miss));
        Self::declare_impl(session, keyexpr, on_sample, miss_handlers, options)
    }

    fn declare_impl<OnSample>(
        session: &Session<R, T, Unicast>,
        keyexpr: impl Into<String>,
        on_sample: OnSample,
        miss_handlers: MissHandlers,
        options: AdvancedSubscriberOptions,
    ) -> Result<Self, AdvancedSubscribeError>
    where
        R: 'static,
        T: TimeSource + Send + Sync + 'static,
        <R as SessionRuntime>::LinkSink: Send + Sync,
        SessionLinkActions<R, T>: Send + Sync + 'static,
        Session<R, T, Unicast>: Send + 'static,
        OnSample: FnMut(Sample) + Send + 'static,
    {
        // R2550 — CHECK CONFIG FIRST, which is both upstream's order and the
        // only order that means anything:
        // `zenoh-ext/src/advanced_subscriber.rs` @ `bail!("max_samples must not be zero")`
        // sits in the block `AdvancedSubscriber::new` opens with, before a
        // single subscriber is declared. Refusing
        // after the base subscriber went out would leave a declaration on the
        // wire for a subscriber the caller never gets.
        //
        // The knob order is upstream's too — `max_samples` then `max_age` — so a
        // caller who zeroed BOTH is told about the same one either reference
        // would name.
        #[cfg(feature = "ext-pubsub-advanced-history")]
        if let Some(history) = options.history.as_ref() {
            if history.sample_depth == Some(0) {
                return Err(AdvancedSubscribeError::HistoryBoundZero {
                    knob: "max_samples",
                });
            }
            if history.max_age == Some(0.0) {
                return Err(AdvancedSubscribeError::HistoryBoundZero { knob: "max_age" });
            }
        }
        // R2815 — after upstream's own config check, before anything is
        // declared: a session with no valid zid gives this subscriber no
        // identity, and every refusal below this line has something to retract.
        require_session_zid(session.zid())?;
        // R311y91 (review M1) — recovery + history are INDEPENDENT (zenoh keeps
        // `.recovery()` / `.history()` separate): `retransmission` is driven by
        // `options.recovery`, `history_pending` by `options.history` — a
        // history-only subscriber (recovery None) is now representable.
        let recovery = options.recovery;
        let retransmission = recovery.is_some();
        // R311y96 (review-arbiter MED) — the GET destination and the sub origin are
        // now INDEPENDENT (zenoh keeps them on separate axes). `dest` = the
        // recovery/history GET locality; `sub_origin` = the live/heartbeat sub origin.
        let dest = options.get_locality;
        let sub_origin = options.allowed_origin;
        let periodic = recovery.and_then(|c| c.periodic_queries());
        // R2621 — retention is configured through `RecoveryConfig` because that
        // is where upstream puts it, so a subscriber with no recovery config
        // runs no sweep: the same scope its `gc_task` has.
        let retention = recovery.map(|c| c.retention_period());
        // R3064 -- there is no off-runtime precondition here, and the one R311y90 put
        // here was false from R2366 on. The periodic task was a bare `tokio::spawn`,
        // which PANICS without a runtime, so a declare off one was refused with a
        // variant of its own; R2366 moved it onto the process's `Application`
        // runtime, as upstream spawns the same task (see the spawn below), and
        // nothing this declare does asks the calling thread for a runtime any more.
        // What survived was a refusal of a declaration that would have worked, and
        // on a C session that is the ordinary case: the in-process plane declares
        // from the C application thread, the refusal was swallowed by the
        // best-effort fan-out, and the subscriber was dead while the declare
        // reported success.
        let heartbeat = recovery.map(|c| c.heartbeat()).unwrap_or(false);
        // R311y89 (review C3) — the recovery + history GET timeout (zenoh's shared
        // builder `query_timeout`), threaded to every GET so the deadline sweep can
        // release a no-answerer query.
        let timeout_ms = recovery_query_timeout_ms(options.query_timeout);
        #[cfg(feature = "ext-pubsub-advanced-history")]
        let history = options.history;
        let base_keyexpr: String = keyexpr.into();

        let state =
            State::new(Box::new(on_sample), miss_handlers).with_retransmission(retransmission);
        // The startup history get is one in flight from the start; the buffer's ceiling is
        // upstream's own derivation, field for field — see the machine's field doc.
        #[cfg(feature = "ext-pubsub-advanced-history")]
        let state = state.with_history(
            usize::from(history.is_some()),
            history
                .as_ref()
                .and_then(|h| h.sample_depth)
                .unwrap_or(usize::MAX),
        );
        let state = Arc::new(Mutex::new(state));
        // R311y592 — the in-flight GET registry every issuing site below shares,
        // and that the returned subscriber cancels through on drop.
        let pending = Arc::new(PendingGets::new());
        let cb_state = Arc::clone(&state);
        let cb_clock = Arc::clone(session.clock());
        let cb_pending = Arc::clone(&pending);
        // R2817 — every callback and task below holds its session WEAKLY,
        // upstream's `conf.session.downgrade()` at each of them. They live in
        // the session's own registries, so a strong clone there is a cycle:
        // harmless while the handle's teardown unregisters them, a session
        // kept alive forever once `background` leaves them registered.
        let q_session = session.downgrade();
        let q_base = base_keyexpr.clone();
        // How the host names each entity on the wire (see [`DeclarationForms`]):
        // asked entity by entity, at the moment each is declared, in the order
        // they are declared.
        let forms = options.forms.clone();
        let subscriber_form = form_of(forms.as_ref(), |f| f.subscriber(&base_keyexpr));
        let subscriber = declare_subscription(
            session,
            &base_keyexpr,
            &subscriber_form,
            // R311y96 (review-arbiter MED) — the live subscription honors its OWN
            // origin knob (`options.allowed_origin`), independent of the GET
            // locality (zenoh's `conf.origin`, faithful; default `Any`).
            SubscribeOptions::default().with_allowed_origin(sub_origin),
            move |view: &dyn SampleView| {
                let request = cb_state
                    .lock()
                    .expect("advanced subscriber state mutex poisoned")
                    .handle_live(view, cb_clock.now_monotonic_ms());
                // Issue the recovery GET OUTSIDE the state lock: Session::query
                // re-enters the session (the loopback fan drains the cache's
                // replies, which lock `cb_state` again). R311lh deferred-fire
                // makes this re-entrant call safe.
                // Upgraded only when there is a GET to issue; a `None` means
                // the session has gone and there is no one to ask.
                if let Some(request) = request {
                    if let Some(q_session) = q_session.upgrade() {
                        issue_recovery_query(
                            &q_session,
                            &cb_state,
                            &cb_pending,
                            &q_base,
                            request,
                            dest,
                            timeout_ms,
                        );
                    }
                }
            },
        )?;
        // R2815 — read off the plain subscription just declared; the detection
        // token below is named with the same pair. A host with ONE identity for
        // a subscriber it declares on every connection supplies it instead.
        let id = identity_of(session.zid(), &subscriber.entity, forms.as_ref())?;

        // R311y83 — the periodic recovery trigger: a background loop that
        // re-asks every known source `_sn=last+1..` every `period`. Spawned
        // here (on the process's `Application` runtime), aborted on drop.
        // The loop is thin glue over `run_periodic_tick` / `periodic_requests`
        // (the deterministically tested core; the storage_replication
        // DigestPublisher pattern).
        // R2621 — the retention sweep. Same glue shape as the periodic task
        // below, and the same clamp: a sub-ms period would truncate to a
        // zero-delay spin.
        //
        // R2817 — both loops hold the state and the session WEAKLY and return
        // on the first tick either is gone; see [`AbortOnDropTask`].
        let retention_task = retention.map(|period| {
            let r_state = Arc::downgrade(&state);
            let clock = Arc::clone(session.clock());
            let period_ms = (period.as_millis() as u64).max(1);
            AbortOnDropTask::new(
                crate::runtime_pool::WzRuntime::Application.spawn(async move {
                    loop {
                        clock.sleep(period_ms).await;
                        let Some(r_state) = r_state.upgrade() else {
                            return;
                        };
                        r_state
                            .lock()
                            .expect("advanced subscriber state mutex poisoned")
                            .reclaim_expired_sources(clock.now_monotonic_ms(), period);
                    }
                }),
            )
        });

        let periodic_task = periodic.map(|period| {
            let p_session = session.downgrade();
            let p_state = Arc::downgrade(&state);
            let p_pending = Arc::clone(&pending);
            let p_base = base_keyexpr.clone();
            let clock = Arc::clone(session.clock());
            // R311y87 (review C4) — clamp to >=1ms: a sub-ms Duration truncates
            // to 0, turning the loop into a zero-delay GET storm / busy spin.
            let period_ms = (period.as_millis() as u64).max(1);
            // The APPLICATION subsystem — upstream's own choice for the same
            // task: `ZRuntime::Application.spawn` wraps `spawn_periodic_queries`
            // (`zenoh-ext/src/advanced_subscriber.rs`
            // @ `AbortOnDropHandle::new(ZRuntime::Application.spawn(`). It issues GETs
            // on the consumer's behalf, so it is application work even though
            // nothing awaits it.
            AbortOnDropTask::new(
                crate::runtime_pool::WzRuntime::Application.spawn(async move {
                    loop {
                        clock.sleep(period_ms).await;
                        let (Some(p_session), Some(p_state)) =
                            (p_session.upgrade(), p_state.upgrade())
                        else {
                            return;
                        };
                        run_periodic_tick(
                            &p_session, &p_state, &p_pending, &p_base, dest, timeout_ms,
                        );
                    }
                }),
            )
        });

        // R311y84 — the heartbeat subscriber: on each `<ke>/@adv/pub/**` beacon,
        // decode the publisher's last sn (`z_deserialize::<u32>`) and issue a
        // bounded `_sn=last+1..hb` recovery GET (zenoh advanced_subscriber.rs:
        // 1053-1145). Callback-driven (no task); the GET re-enters Session::query
        // OUTSIDE the state lock, the sample-driven re-entrancy discipline.
        //
        // R311y543 — and it DEGRADES rather than failing. The derived keyexpr
        // is `<base>/@adv/pub/**`, so a base ending in `**` — which is upstream
        // `z_advanced_sub.c`'s own default, `demo/example/**` — produces the
        // `**` + literal + `*`-shape shape wz's outbound gate refuses because it
        // SIGABRTs a real zenoh-pico peer (R299 bug #3 / R300). Until now that
        // refusal came back through `?` and took the LIVE subscription with it:
        // `SharedSession::declare_advanced_subscriber` swallows a failed declare
        // with `if let Ok(sub)`, so a C program subscribing on `demo/example/**`
        // through either ABI got NO subscriber at all and received nothing,
        // where the real `libzenohc.so` receives every sample. Measured, on the
        // wire, against a real zenoh-pico advanced publisher.
        //
        // R311y544 — "the gate is not the thing to weaken", this comment used to
        // continue, "the keyexpr it refuses really does crash a pico peer". That
        // was the unmeasured half. The gate WAS the thing to fix: only a
        // ONE-byte chunk holds pico's `in_big_wild` window open and `@adv` is
        // four, so the derived form was never in the bug family. Measured
        // against a real `_z_keyexpr_canonize` in a subprocess
        // (`layer3_keyexpr_canon`), and end to end against a live zenoh-pico
        // peer (`apfull_double_star_adv_keyexpr_does_not_crash_a_real_pico_peer`).
        //
        // The evidence was already in the tree: the QUERY emit path carries no
        // pico-safety check, so the history GET for the same base has been
        // sending `<base>/@adv/**` to real picos all along, and their cache
        // queryables have been answering it.
        //
        // The degrade path stays as a guard for a future derivation that reopens
        // the window — but it is no longer SILENT. It warns, and
        // `heartbeat_channel_is_live` reports the outcome so a caller can tell a
        // live channel from an amputated one.
        //
        // ⚠ DEFINED HERE AND RUN LATER, after the history query and the
        // late-publisher subscription. zenoh-pico declares the heartbeat
        // subscription after both (`vendor/zenoh-pico/src/api/advanced_subscriber.c` @
        // `// Heartbeat subscriber`), and a host that declares keys shows the
        // order on the wire. Nothing here depends on it: a beacon waits a whole
        // period, and the GET in flight is gated by its own pending state.
        let declare_heartbeat =
            || -> Result<Option<Held<Subscriber<R>>>, AdvancedSubscribeError> {
                Ok(
                    if heartbeat
                        && crate::advanced_ke::adv_ke_is_outbound_safe(
                            &crate::advanced_ke::publisher_detection_ke(&base_keyexpr),
                        )
                    {
                        let hb_state = Arc::clone(&state);
                        let hb_clock = Arc::clone(session.clock());
                        let hb_pending = Arc::clone(&pending);
                        let hb_session = session.downgrade();
                        let hb_base = base_keyexpr.clone();
                        let hb_keyexpr = crate::advanced_ke::publisher_detection_ke(&base_keyexpr);
                        let hb_form = form_of(forms.as_ref(), |f| f.heartbeat(&hb_keyexpr));
                        Some(declare_subscription(
                            session,
                            &hb_keyexpr,
                            &hb_form,
                            // R311y96 — the heartbeat sub shares the live sub's origin knob.
                            SubscribeOptions::default().with_allowed_origin(sub_origin),
                            move |hb_view: &dyn SampleView| {
                                if hb_view.kind() != SampleKind::Put {
                                    return;
                                }
                                // R2552 — SEQUENCED ONLY, and here that is INHERENT rather
                                // than deferred: a heartbeat's payload IS a sequence number
                                // (`z_deserialize::<u32>` below) and a timestamped
                                // publisher has none to send, so a `uhlc` token on this
                                // path would be a beacon with nothing to beacon.
                                let Some(AdvPublisherSource::Sequenced { zid, eid }) =
                                    parse_heartbeat_source(hb_view.keyexpr())
                                else {
                                    return;
                                };
                                let Ok(hb_sn) = z_deserialize::<u32>(hb_view.payload()) else {
                                    return;
                                };
                                let request = hb_state
                                    .lock()
                                    .expect("advanced subscriber state mutex poisoned")
                                    .handle_heartbeat(zid, eid, hb_sn, hb_clock.now_monotonic_ms());
                                if let Some(request) = request {
                                    if let Some(hb_session) = hb_session.upgrade() {
                                        issue_recovery_query(
                                            &hb_session,
                                            &hb_state,
                                            &hb_pending,
                                            &hb_base,
                                            request,
                                            dest,
                                            timeout_ms,
                                        );
                                    }
                                }
                            },
                        )?)
                    } else {
                        // R311y544 — and it SAYS SO. A degradation nobody can observe is
                        // indistinguishable from a working channel: the demo's declare log
                        // reports the argv flag, so `recovery_heartbeat=true` printed
                        // happily through the whole window in which no heartbeat subscriber
                        // was ever declared. See [`Self::heartbeat_channel_is_live`].
                        if heartbeat {
                            log::warn!(
                                "advanced subscriber on '{base_keyexpr}': heartbeat recovery was \
                     REQUESTED but its derived keyexpr '{}' is refused by the outbound \
                     pico-safety gate, so the channel is DEGRADED — the live \
                     subscription is unaffected, heartbeat-driven retransmission is not \
                     available",
                                crate::advanced_ke::publisher_detection_ke(&base_keyexpr),
                            );
                        }
                        None
                    },
                )
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
                &pending,
                &base_keyexpr,
                history.sample_depth,
                history.max_age,
                dest,
                timeout_ms,
            );
        }

        // R311y100 — the late-publisher LIVELINESS subscriber: a publisher whose
        // `@adv` token appears on `<ke>/@adv/pub/**` (a `Put`) triggers a
        // per-publisher history GET. R311y101 (review MED) — declared
        // `history(true)` (matching zenoh advanced_subscriber.rs:1034), NOT
        // future-only: the startup history GET above is a point-in-time snapshot
        // fired just before this declare, so a publisher present at declare whose
        // cache filled in that window would otherwise be missed; `history(true)`
        // sets the CURRENT bit on the outbound interest so the answerer replays
        // its current tokens, INTENDING to re-trigger that publisher's GET.
        // FIDELITY CAVEAT (R311y102 review): the current-replay path is wired
        // (observer.rs responder) but has NO end-to-end test, and same-session
        // liveliness loopback is omitted in wz, so this races-window closure is
        // verified only by the future-token path (the composed test injects a
        // post-declare DeclToken); the present-at-declare replay is untested. The
        // fix is benign regardless — a replay GET is dedup/reorder-idempotent. The
        // closure is thin glue over [`on_late_publisher_detected`]. `HistoryConfig`
        // is `Copy`, so `history` is readable after the `if let`.
        #[cfg(feature = "ext-pubsub-advanced-history")]
        let liveliness_sub: Option<Held<crate::session::LivelinessSubscriber<R, T>>> =
            if history.is_some_and(|h| h.detect_late_publishers) {
                let lp_state = Arc::clone(&state);
                let lp_pending = Arc::clone(&pending);
                let lp_session = session.downgrade();
                let lp_base = base_keyexpr.clone();
                let lp_keyexpr = crate::advanced_ke::publisher_detection_ke(&base_keyexpr);
                let (lp_depth, lp_age) = history
                    .map(|h| (h.sample_depth, h.max_age))
                    .unwrap_or((None, None));
                let lp_form = form_of(forms.as_ref(), |f| f.late_publishers(&lp_keyexpr));
                let sub = declare_late_publisher_subscription(
                    session,
                    &lp_keyexpr,
                    &lp_form,
                    LivelinessSubscriberOptions::new().with_history(true),
                    move |sample: LivelinessSample<'_>| {
                        let Some(lp_session) = lp_session.upgrade() else {
                            return;
                        };
                        on_late_publisher_detected(
                            &lp_session,
                            &lp_state,
                            &lp_pending,
                            &lp_base,
                            sample.kind,
                            sample.keyexpr,
                            lp_depth,
                            lp_age,
                            dest,
                            timeout_ms,
                        );
                    },
                )?;
                Some(sub)
            } else {
                None
            };

        // The heartbeat subscription, in the place pico declares it (see
        // `declare_heartbeat`'s definition).
        let heartbeat_sub = declare_heartbeat()?;

        // R311y592 — the teardown that stops the subscriber ANSWERING.
        let recovery_cancel = Some(RecoveryCancel {
            pending: Arc::clone(&pending),
            session: session.clone(),
            armed: true,
        });

        // R311y826 — the `@adv/sub` detection token. Declared LAST, after the
        // live subscription and every recovery channel, so a subscriber only
        // advertises itself once it is actually able to receive: a token that
        // outraces its own subscription tells an observer something untrue for
        // the width of the gap.
        let detection_token = declare_detection_token(session, &base_keyexpr, &options, id)?;

        Ok(Self {
            _subscriber: subscriber,
            session: session.clone(),
            id,
            statesref: state,
            _periodic: periodic_task,
            #[cfg(feature = "ext-pubsub-advanced-recovery")]
            _retention: retention_task,
            _recovery_cancel: recovery_cancel,
            _heartbeat_sub: heartbeat_sub,
            #[cfg(feature = "ext-pubsub-advanced-history")]
            _liveliness_sub: liveliness_sub,
            _detection_token: detection_token,
            forms,
        })
    }
}

/// R311y826 — declare the `@adv/sub` detection token when the caller asked for
/// it, else `None`.
///
/// Split out of `declare_with_options` so the KE construction and the
/// opt-in test have one home rather than being inlined into an already long
/// constructor.
///
/// R2819 — in every build: both builds' `declare_with_options` call it.
fn declare_detection_token<R, T>(
    session: &Session<R, T, Unicast>,
    keyexpr: &str,
    options: &AdvancedSubscriberOptions,
    id: EntityGlobalId,
) -> Result<Option<Held<crate::session::LivelinessToken<R, T>>>, AdvancedSubscribeError>
where
    R: SessionRuntime + 'static,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    let Some(detection) = options.subscriber_detection.as_ref() else {
        return Ok(None);
    };

    // R2815 — named with the subscriber's OWN identity, which is what upstream
    // reads here: `zenoh-ext/src/advanced_subscriber.rs` @ `/ &subscriber.id().zid().into_keyexpr()`.
    // Until R2815 the zid was one the CALLER supplied on `SubscriberDetection`
    // and the eid was minted from `alloc_next_entity_id`, so the token named a
    // pair that matched no other id of the same subscriber — and could name a
    // zid that was not this session's at all.
    let ke = crate::advanced_ke::subscriber_adv_ke(
        keyexpr,
        &zid_to_zenoh_hex(id.zid()),
        id.eid(),
        detection.metadata.as_deref(),
    );
    // The host names the token's key where it declares keys; asked only now,
    // because this is the moment the token is declared.
    let form = form_of(options.forms.as_ref(), |f| f.token(&ke));
    let token_options = crate::session::LivelinessOptions::default()
        .with_retraction_naming_the_key(form.names_key_on_retraction());
    let token = if form.is_literal() {
        session.declare_token(ke, token_options)?
    } else {
        session.declare_token_aliased(form.mapping_id(), form.suffix(), token_options)?
    };
    Ok(Some(Held::new(token, &form)))
}

/// Declare the late-publisher liveliness subscription on `keyexpr` in `form`,
/// held together with what names it.
#[cfg(feature = "ext-pubsub-advanced-history")]
fn declare_late_publisher_subscription<R, T>(
    session: &Session<R, T, Unicast>,
    keyexpr: &str,
    form: &EntityForm,
    options: LivelinessSubscriberOptions,
    sink: impl FnMut(LivelinessSample<'_>) + Send + 'static,
) -> Result<Held<crate::session::LivelinessSubscriber<R, T>>, AdvancedSubscribeError>
where
    R: SessionRuntime,
    T: TimeSource + 'static,
    <R as SessionRuntime>::LinkSink: Send + Sync,
    SessionLinkActions<R, T>: Send + Sync + 'static,
{
    let subscription = if form.is_literal() {
        session.declare_liveliness_subscriber(keyexpr.to_owned(), options, sink)?
    } else {
        session.declare_liveliness_subscriber_aliased(
            form.mapping_id(),
            form.suffix(),
            options,
            sink,
        )?
    };
    Ok(Held::new(subscription, form))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::observer::ApplicationLayerObserver;
    use crate::runtime_impl::TokioTime;
    use crate::session::{PublishOptions, TokioSession};
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    use std::time::Duration;
    use wz_session_core::locality::Locality;
    use wz_session_core::sample::SourceInfo;

    /// The [`Miss`] a source of `zid`/`eid` reports for `nb` skipped samples.
    fn miss_of(zid: &[u8], eid: u32, nb: u32) -> Miss {
        Miss::for_test(
            EntityGlobalId::new(zid, eid).expect("a 1..=16-byte test zid"),
            nb,
        )
    }

    /// An inbound `DeclToken` for `ke`, as a peer's liveliness token arrives.
    /// R2816 hoisted it from the two tests that each carried a nested copy.
    fn make_decl_token(id: u64, ke: &str) -> wz_codecs::declare::DeclareOwnedVariant {
        use wz_codecs::decl_token::DeclToken;
        use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
        use wz_codecs::wireexpr_local::WireexprLocal;
        let keyexpr = Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: 0,
                suffix_len: Some(ke.len() as u64),
                suffix: Some(ke),
            }),
        };
        wz_codecs::declare::DeclareVariant::CodecZenohDeclToken(DeclToken {
            id,
            keyexpr,
            ..DeclToken::default()
        })
        .try_into_owned()
        .unwrap()
    }

    /// R2816 — `detect_publishers` sees an advanced publisher's token arrive
    /// on this subscriber's key expression, and only there.
    ///
    /// Two tokens are injected: one under `demo/data/@adv/pub/...` (a
    /// publisher of THIS key expression) and one under `demo/other/@adv/pub/...`
    /// (a publisher of another). The first must reach the callback and the
    /// second must not, so a detector declared on the wrong key expression — or
    /// on `**` — cannot pass, and one that hears nothing cannot either.
    ///
    /// Control: declaring the detector on the subscriber's bare key expression
    /// instead of `publisher_detection_ke` reds the first assertion.
    #[test]
    fn detect_publishers_hears_this_keyexprs_publishers_only() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);
        let sub = AdvancedSubscriber::declare(&session, "demo/data", |_s: Sample| {})
            .expect("advanced subscriber declares");

        let heard = Arc::new(Mutex::new(Vec::<String>::new()));
        let h = Arc::clone(&heard);
        let _detector = sub
            .detect_publishers(
                crate::session::LivelinessSubscriberOptions::new(),
                move |sample: crate::declare::LivelinessSample<'_>| {
                    h.lock().unwrap().push(sample.keyexpr.to_string());
                },
            )
            .expect("the detector declares");

        let ours = "demo/data/@adv/pub/b0a/7/_";
        let theirs = "demo/other/@adv/pub/b0a/8/_";
        for (id, ke) in [(41u64, ours), (42u64, theirs)] {
            session
                .observer()
                .lock()
                .unwrap()
                .liveliness_subscribers
                .dispatch_declare(&make_decl_token(id, ke), &hashbrown::HashMap::new());
        }
        session.drain_deferred_fires();

        assert_eq!(
            *heard.lock().unwrap(),
            vec![ours.to_owned()],
            "the detector hears this key expression's publisher and no other"
        );
    }

    /// R2814 — THE REGISTRY'S CLAIM, graded on the declared surface: two
    /// listeners on one subscriber each hear every miss, and retracting one
    /// leaves the other hearing.
    ///
    /// # Why this fixture and not "one listener fires"
    ///
    /// One listener firing is what the single `on_miss` closure this replaced
    /// already did, so it grades nothing about a registry. The defect the old
    /// shape generated — in both C ABIs, which adapted to it with one slot —
    /// was that a second listener REPLACED the first and dropping the first
    /// then silenced the second. Each half of that is an arm here: after the
    /// first gap BOTH must have heard it, and after `first` is retracted the
    /// second gap must reach `second` and NOT `first`.
    ///
    /// # Control
    ///
    /// Making [`MissHandlers::register`] clear the map before inserting (a
    /// one-slot registry) reds the first arm — `first` hears nothing — and
    /// making [`MissHandlers::unregister`] clear the whole map reds the last,
    /// `second` going deaf when `first` leaves.
    #[test]
    fn two_miss_listeners_each_hear_and_retract_independently() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let sub = AdvancedSubscriber::declare(&session, "demo/data", |_s: Sample| {})
            .expect("advanced subscriber declares against the test link");
        let heard_first = Arc::new(Mutex::new(Vec::<Miss>::new()));
        let heard_second = Arc::new(Mutex::new(Vec::<Miss>::new()));
        let (f, s) = (Arc::clone(&heard_first), Arc::clone(&heard_second));
        let first = sub.sample_miss_listener(move |miss| f.lock().unwrap().push(miss));
        let _second = sub.sample_miss_listener(move |miss| s.lock().unwrap().push(miss));

        put_sequenced(&session, 0);
        put_sequenced(&session, 2); // skips 1
        assert_eq!(
            (
                heard_first.lock().unwrap().clone(),
                heard_second.lock().unwrap().clone()
            ),
            (vec![miss_of(&[0x02], 7, 1)], vec![miss_of(&[0x02], 7, 1)]),
            "both declared listeners hear the one gap"
        );

        first.undeclare();
        put_sequenced(&session, 5); // skips 3 and 4
        assert_eq!(
            heard_first.lock().unwrap().clone(),
            vec![miss_of(&[0x02], 7, 1)],
            "a retracted listener hears nothing more"
        );
        assert_eq!(
            heard_second.lock().unwrap().clone(),
            vec![miss_of(&[0x02], 7, 1), miss_of(&[0x02], 7, 2)],
            "retracting one listener leaves the other hearing"
        );
    }

    /// R2814 — the two ways a listener outlives its handle or its subscriber,
    /// each of which the registry must answer without surprise.
    ///
    /// * [`SampleMissListener::background`] keeps the listener registered with
    ///   no handle left to retract it — upstream's `.background()`.
    /// * A listener handle dropped AFTER its subscriber is a no-op: it holds
    ///   the state weakly, so there is nothing to unregister from and nothing
    ///   it kept alive.
    ///
    /// Control: making `background` leave `undeclare_on_drop` set reds the
    /// first arm, because the handle's own drop then retracts it.
    #[test]
    fn a_background_listener_stays_and_a_late_drop_is_harmless() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let sub = AdvancedSubscriber::declare(&session, "demo/data", |_s: Sample| {})
            .expect("advanced subscriber declares against the test link");
        let heard = Arc::new(Mutex::new(0u32));
        let h = Arc::clone(&heard);
        sub.sample_miss_listener(move |miss| *h.lock().unwrap() += miss.nb())
            .background();
        let (late, mut rx) = sub.sample_miss_listener_with_channel();

        put_sequenced(&session, 0);
        put_sequenced(&session, 3); // skips 1 and 2
        assert_eq!(
            *heard.lock().unwrap(),
            2,
            "the background listener is still registered after its handle is gone"
        );
        assert_eq!(
            rx.try_recv().ok(),
            Some(miss_of(&[0x02], 7, 2)),
            "the channel form delivers the same miss"
        );

        drop(sub);
        // The subscriber, and with it the registry, is gone; retracting now
        // must neither panic nor find anything to hold.
        late.undeclare();
    }

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

    /// Publish `payload` under a TIMESTAMP and no source_info — the shape a
    /// Timestamp-mode publisher emits.
    ///
    /// `zid` is the timestamp's own id, which is what upstream keys the
    /// timestamped state on (`*timestamp.get_id()`), NOT a source_info zid:
    /// these samples carry no source_info at all, which is the whole point.
    fn put_timestamped(session: &TokioSession, payload: u8, time: u64, zid: &[u8]) -> usize {
        session
            .publish(
                "demo/data",
                &[payload],
                PublishOptions::put()
                    .with_locality(Locality::SessionLocal)
                    .with_timestamp(wz_session_core::sample::TimestampHint {
                        time,
                        zid: zid.to_vec(),
                    }),
            )
            .expect("loopback timestamped publish")
    }

    /// R2522 — TIMESTAMP-mode de-duplication: upstream's middle
    /// `handle_sample` arm, which this subscriber now has.
    ///
    /// # What it grades
    ///
    /// Upstream's `handle_sample` has THREE arms, not two: sequenced (a
    /// source_info sn), then TIMESTAMPED (`else if let Some(timestamp) =
    /// sample.timestamp()`, keyed on `*timestamp.get_id()` and ordered by the
    /// uhlc `(time, id)` Ord), then a bare deliver for a sample carrying
    /// neither. wz had the first and the third; the middle one was the standing
    /// residual of `ext-pubsub-advanced-subscriber` and the reason
    /// `ext-pubsub-advanced-history`'s clause (5) was open — one build answers
    /// both atoms, and this is the guard on it.
    ///
    /// # Why the fixture is a REPEATED timestamp
    ///
    /// It is the smallest observable difference. Upstream admits a sample only
    /// when `state.last_delivered.map(|t| t < *timestamp).unwrap_or(true)`, so
    /// the second arrival at an EQUAL timestamp is dropped — strictly, not
    /// `<=`. Before R2522 wz delivered both, because nothing was recorded to
    /// compare against; the RED this was written against read
    /// `left: [[160], [161], [162], [163]]` / `right: [[160], [161]]`. The
    /// trailing older-150 sample grades the other half of the claim: "ordered
    /// by its own clock", not "de-duplicated by identity" — an identity-keyed
    /// implementation would drop the repeat and still deliver the 150. The
    /// final sample carries a SECOND timestamp-id at an instant older than
    /// every one before it and must still deliver, which is what separates
    /// "per-id state" from "one global newest instant"; the latter passes every
    /// other assertion here.
    ///
    /// # The control
    ///
    /// Deleting the `if let Some(ts) = view.timestamp()` arm from
    /// [`State::deliver_unsequenced`] must red THIS test and nothing else:
    /// every other sample in this module carries a `source_info`, so it never
    /// reaches the arm.
    ///
    /// The ordering primitive is NOT behind the storage gate, which the
    /// residual's own text doubted:
    /// `wz_session_core::sample::timestamp_strictly_newer` is `pub`, `alloc`-
    /// gated, and implements uhlc's `(time, 16-byte LE id)` comparison.
    #[test]
    fn timestamped_samples_are_deduplicated_by_their_own_clock() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let delivered = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let d = Arc::clone(&delivered);
        let _sub = AdvancedSubscriber::declare(&session, "demo/data", move |sample: Sample| {
            d.lock().unwrap().push(sample.payload.to_vec())
        })
        .expect("advanced subscriber declares against the test link");

        let source = &[0xC3u8, 0xC3];
        put_timestamped(&session, 0xA0, 100, source);
        put_timestamped(&session, 0xA1, 200, source);
        // The SAME instant from the SAME source: a retransmission, which the
        // timestamped arm must drop because 200 is not strictly newer than 200.
        put_timestamped(&session, 0xA2, 200, source);
        // And an OLDER one, which is the other half of "ordered by its own
        // clock" rather than "deduplicated by identity".
        put_timestamped(&session, 0xA3, 150, source);
        // A DIFFERENT clock, at an instant older than everything above. It must
        // deliver: the state is keyed PER timestamp-id (upstream's
        // `*timestamp.get_id()`), so one source's clock never suppresses
        // another's. A single global "newest instant" would drop this, and
        // would pass every assertion above.
        put_timestamped(&session, 0xB0, 50, &[0xD4u8, 0xD4]);

        // ANTI-VACUITY FIRST: the loopback really delivered something, so a
        // dropped-everything build cannot satisfy the claim below.
        let got = delivered.lock().unwrap().clone();
        assert!(
            !got.is_empty(),
            "the SessionLocal loopback delivered nothing, so nothing below is \
             being measured"
        );
        assert_eq!(
            got,
            vec![vec![0xA0u8], vec![0xA1u8], vec![0xB0u8]],
            "a Timestamp-mode source is ordered by its OWN clock: the repeat at \
             200 and the older 150 are both DROPPED, while the second source's \
             older 50 still delivers because the state is keyed per timestamp-id"
        );
    }

    /// State-machine unit test (synthetic source, controlled sns): a source
    /// feeds 0,1, then 3 (a gap at 2), then a duplicate 1. The plain advanced
    /// subscriber must deliver 0,1,3 in order, fire one Miss(nb=1) on the
    /// 1->3 gap, and DROP the duplicate.
    #[test]
    fn sequenced_in_order_gap_miss_and_dedup() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let delivered = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let misses = Arc::new(Mutex::new(Vec::<Miss>::new()));
        let d = Arc::clone(&delivered);
        let m = Arc::clone(&misses);
        let sub = AdvancedSubscriber::declare(&session, "demo/data", move |sample: Sample| {
            d.lock().unwrap().push(sample.payload.to_vec())
        })
        .expect("advanced subscriber declares against the test link");
        let _listener = sub.sample_miss_listener(move |miss: Miss| m.lock().unwrap().push(miss));

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
            vec![miss_of(&[0x02], 7, 1)],
            "one miss reported for the single skipped sample (sn 2)"
        );
    }

    /// A NEW source's first sample always delivers (no last marker yet),
    /// and a second source is tracked independently.
    #[test]
    fn distinct_sources_track_independently() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let delivered = Arc::new(Mutex::new(Vec::<(u32, u8)>::new()));
        let d = Arc::clone(&delivered);
        let _sub = AdvancedSubscriber::declare(&session, "demo/data", move |sample: Sample| {
            let eid = sample.source_info.as_ref().map(|s| s.eid).unwrap_or(0);
            d.lock().unwrap().push((eid, sample.payload[0]));
        })
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
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let misses = Arc::new(Mutex::new(0usize));
        let d = Arc::clone(&delivered);
        let m = Arc::clone(&misses);
        let sub = AdvancedSubscriber::declare(&session, "demo/data", move |sample: Sample| {
            d.lock().unwrap().push(sample.payload[0])
        })
        .expect("advanced subscriber declares");
        let _listener = sub.sample_miss_listener(move |_miss: Miss| *m.lock().unwrap() += 1);

        // A REAL publisher with its OWN zid (its genuine identity) +
        // SequenceNumber sequencing; default Locality::Any -> the loopback
        // leg fires the local subscriber (own-zid loopback delivers — no
        // self-echo dedup on the loopback path).
        let publisher = AdvancedPublisher::declare(
            &session,
            "demo/data",
            {
                // `#[non_exhaustive]` and another crate's: no struct literal can name it here.
                let mut options = AdvancedPublisherOptions::default();
                options.sequencing = Sequencing::SequenceNumber;
                options.cache = Some(CacheConfig {
                    max_samples: 8,
                    ..CacheConfig::default()
                });
                options.publisher_detection = true;
                options.sample_miss_detection = MissDetectionConfig::default();
                options
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
    /// R2550 — a ZERO history bound is REFUSED at construction, both knobs,
    /// as upstream refuses it:
    /// `zenoh-ext/src/advanced_subscriber.rs` @ `bail!("max_age must not be zero")`
    /// is the second of the two arms it refuses with.
    ///
    /// Found by sweeping this atom's surface at the pin rather than by reading
    /// its reason: the reason never carried a validation clause at all, because
    /// no round had compared the two builders' `// Check config` blocks.
    ///
    /// The assertions name the knob, so a refusal that fires for the WRONG one
    /// is a failure rather than a pass — and the both-zero case pins upstream's
    /// ORDER (`max_samples` first), which is the only observable that tells the
    /// two checks apart when a caller zeroes both.
    #[cfg(all(
        feature = "ext-pubsub-advanced-history",
        feature = "ext-pubsub-advanced-recovery"
    ))]
    #[test]
    fn history_bounds_of_zero_are_refused_at_construction() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let declare = |history: HistoryConfig| {
            AdvancedSubscriber::declare_with_options(
                &session,
                "demo/data",
                AdvancedSubscriberOptions::new().with_history(history),
                |_s: Sample| {},
            )
            .map(|_| ())
        };

        match declare(HistoryConfig::default().max_samples(0)) {
            Err(AdvancedSubscribeError::HistoryBoundZero { knob }) => {
                assert_eq!(knob, "max_samples")
            }
            other => panic!("max_samples(0) must be refused, got {other:?}"),
        }
        match declare(HistoryConfig::default().max_age(0.0)) {
            Err(AdvancedSubscribeError::HistoryBoundZero { knob }) => {
                assert_eq!(knob, "max_age")
            }
            other => panic!("max_age(0.0) must be refused, got {other:?}"),
        }
        // BOTH zero: upstream checks max_samples first, so that is the knob a
        // caller is told about. Pinning the order is what keeps the two arms
        // from being interchangeable.
        match declare(HistoryConfig::default().max_samples(0).max_age(0.0)) {
            Err(AdvancedSubscribeError::HistoryBoundZero { knob }) => {
                assert_eq!(knob, "max_samples", "upstream's order: max_samples first")
            }
            other => panic!("both-zero must be refused, got {other:?}"),
        }
        // ANTI-VACUITY: a NON-zero bound must still declare, or the three
        // assertions above would pass on a subscriber that refuses everything.
        declare(HistoryConfig::default().max_samples(1).max_age(1.0))
            .expect("a non-zero history bound still declares");
    }

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
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
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
        let cache = AdvancedCache::declare(
            &session,
            cache_ke,
            CacheConfig {
                max_samples: 8,
                ..CacheConfig::default()
            },
        )
        .expect("advanced cache declares");
        for sn in 0u8..5 {
            cache.cache_sample(CachedSample::new(
                "demo/data",
                vec![sn],
                Some(SourceInfo::new(&pub_zid, pub_eid, sn as u32)),
                TimestampHint {
                    time: 100 + sn as u64,
                    zid: pub_zid.clone(),
                },
                crate::sample::SampleKind::Put,
            ));
        }

        // The recovering subscriber; recovery GET pinned to SessionLocal (the
        // loopback cache is the only answerer — the test has no remote peer).
        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let misses = Arc::new(Mutex::new(0usize));
        let d = Arc::clone(&delivered);
        let m = Arc::clone(&misses);
        let _sub = AdvancedSubscriber::declare_with_options_and_miss_listener(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_recovery(RecoveryConfig::new())
                .with_get_locality(Locality::SessionLocal),
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

    /// R311y561 — the same composed loopback recovery, but the sample in the
    /// hole is a **DELETE**, and it must arrive as a Del.
    ///
    /// This is the end-to-end half of the divergence R311y559 shipped and y561
    /// closes. Before y561 the publisher never cached a Del at all, precisely
    /// because the ring could only replay it as a Put — and a Put replayed in
    /// place of a retraction RESURRECTS the deleted key on the recovering
    /// subscriber, which is worse than losing the retraction. The chain proven
    /// here is every link of that fix at once: the ring retains the kind, the
    /// cache answers on the Del arm
    /// ([`wz_session_core::query_sink::ReplyOut::reply_keyed_del_sourced`]), the
    /// reply survives the loopback as a Del, `recovered_sample_from_reply`
    /// rebuilds a Del `Sample` instead of discarding it, and the reorder buffer
    /// drains it in sn order between the live Puts around it.
    ///
    /// The assertion is on `(kind, payload)` pairs, not payloads: a Del rebuilt
    /// as an empty Put has the same payload and only the kind discriminates.
    /// The recovered TIMESTAMP is asserted separately — it is the second thing
    /// y561 restored, after a doc comment claimed for rounds that `ReplyView`
    /// had no timestamp accessor when R311y321 had already added one.
    #[cfg(all(
        feature = "ext-pubsub-advanced-recovery",
        feature = "ext-pubsub-advanced-cache",
        feature = "pubsub-allow-loop"
    ))]
    #[test]
    fn composed_recovery_replays_a_cached_delete_as_a_delete() {
        use crate::advanced_cache::{AdvancedCache, CacheConfig, CachedSample};
        use crate::sample::SampleKind;
        use wz_session_core::sample::TimestampHint;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let pub_zid = vec![0x0Au8];
        let pub_eid = 6u32;
        let zid_hex = zid_to_zenoh_hex(&pub_zid);

        // The cache holds the full stream 0..=4 where sn 3 is a DELETE.
        let cache_ke = format!("demo/data/@adv/pub/{zid_hex}/{pub_eid}/_");
        let cache = AdvancedCache::declare(
            &session,
            cache_ke,
            CacheConfig {
                max_samples: 8,
                ..CacheConfig::default()
            },
        )
        .expect("advanced cache declares");
        for sn in 0u8..5 {
            let kind = if sn == 3 {
                SampleKind::Del
            } else {
                SampleKind::Put
            };
            cache.cache_sample(CachedSample::new(
                "demo/data",
                if kind == SampleKind::Del {
                    Vec::new()
                } else {
                    vec![sn]
                },
                Some(SourceInfo::new(&pub_zid, pub_eid, sn as u32)),
                TimestampHint {
                    time: 100 + sn as u64,
                    zid: pub_zid.clone(),
                },
                kind,
            ));
        }

        // Record (kind, payload) — a Del rebuilt as an empty Put would be
        // indistinguishable on payload alone — plus the delivered timestamps.
        type Delivered = Vec<(SampleKind, Vec<u8>)>;
        let delivered: Arc<Mutex<Delivered>> = Arc::new(Mutex::new(Vec::new()));
        let stamps = Arc::new(Mutex::new(Vec::<Option<u64>>::new()));
        let misses = Arc::new(Mutex::new(0usize));
        let d = Arc::clone(&delivered);
        let ts = Arc::clone(&stamps);
        let m = Arc::clone(&misses);
        let _sub = AdvancedSubscriber::declare_with_options_and_miss_listener(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_recovery(RecoveryConfig::new())
                .with_get_locality(Locality::SessionLocal),
            move |sample: Sample| {
                d.lock()
                    .unwrap()
                    .push((sample.kind, sample.payload.to_vec()));
                ts.lock().unwrap().push(sample.timestamp.map(|t| t.time));
            },
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
        live(2, 0xA2);
        // sn 3 missing -> buffer the live sn 4, GET _sn=3.. -> the cache replies
        // the DEL at sn 3 (and the Put at sn 4, a dup that is dropped).
        live(4, 0xA4);

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![
                (SampleKind::Put, vec![0xA0]),
                (SampleKind::Put, vec![0xA1]),
                (SampleKind::Put, vec![0xA2]),
                (SampleKind::Del, Vec::new()),
                (SampleKind::Put, vec![0xA4]),
            ],
            "the recovered sn 3 arrives as a DELETE with an empty payload, in \
             sn order between the live Puts — not as an empty Put, which would \
             leave the subscriber believing the key still holds a value"
        );
        assert_eq!(
            *misses.lock().unwrap(),
            0,
            "the recovery filled the hole with the retraction -> no Miss"
        );
        assert_eq!(
            stamps.lock().unwrap()[3],
            Some(103),
            "the recovered sample carries the timestamp the cache retained \
             (100 + sn) — ReplyView::timestamp has existed since R311y321 and \
             the recovery path now reads it"
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
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let pub_zid = vec![0x09u8];
        let pub_eid = 4u32;
        let zid_hex = zid_to_zenoh_hex(&pub_zid);
        let cache_ke = format!("demo/data/@adv/pub/{zid_hex}/{pub_eid}/_");
        let cache = AdvancedCache::declare(
            &session,
            cache_ke,
            CacheConfig {
                max_samples: 8,
                ..CacheConfig::default()
            },
        )
        .expect("advanced cache declares");
        for sn in 0u8..3 {
            cache.cache_sample(CachedSample::new(
                "demo/data",
                vec![sn],
                Some(SourceInfo::new(&pub_zid, pub_eid, sn as u32)),
                TimestampHint {
                    time: 100 + sn as u64,
                    zid: pub_zid.clone(),
                },
                crate::sample::SampleKind::Put,
            ));
        }

        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let misses = Arc::new(Mutex::new(0usize));
        let d = Arc::clone(&delivered);
        let m = Arc::clone(&misses);
        let sub = AdvancedSubscriber::declare_with_options_and_miss_listener(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_recovery(RecoveryConfig::new())
                .with_get_locality(Locality::SessionLocal),
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
            &sub.statesref,
            // The subscriber's OWN registry, not a throwaway: driving the tick
            // through a second one would exercise a code path production never
            // takes and would leave the real registry unobserved.
            sub.pending_gets(),
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
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let pub_zid = vec![0x09u8];
        let pub_eid = 4u32;
        let zid_hex = zid_to_zenoh_hex(&pub_zid);
        let adv_ke = format!("demo/data/@adv/pub/{zid_hex}/{pub_eid}/_");

        let cache = AdvancedCache::declare(
            &session,
            adv_ke.clone(),
            CacheConfig {
                max_samples: 8,
                ..CacheConfig::default()
            },
        )
        .expect("advanced cache declares");
        for sn in 0u8..3 {
            cache.cache_sample(CachedSample::new(
                "demo/data",
                vec![sn],
                Some(SourceInfo::new(&pub_zid, pub_eid, sn as u32)),
                TimestampHint {
                    time: 100 + sn as u64,
                    zid: pub_zid.clone(),
                },
                crate::sample::SampleKind::Put,
            ));
        }

        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let misses = Arc::new(Mutex::new(0usize));
        let d = Arc::clone(&delivered);
        let m = Arc::clone(&misses);
        let _sub = AdvancedSubscriber::declare_with_options_and_miss_listener(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_recovery(RecoveryConfig::new().with_heartbeat())
                .with_get_locality(Locality::SessionLocal),
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

    /// R2555 — the THIRD liveliness arm, end to end through the real closure:
    /// a publisher whose `@adv` token carries an UNREADABLE zid still has its
    /// cache recovered.
    ///
    /// This is upstream's `} else if s.kind() == SampleKind::Put {` arm, which
    /// wz had folded into the same `None` as "not a token at all" — so the
    /// publisher announced itself, wz could not key a state for it, and wz
    /// therefore recovered nothing rather than falling back to a global query.
    ///
    /// The token KE uses `zz` for the zid chunk: not hex, so it fails
    /// `zenoh_hex_to_zid` exactly where upstream's `ZenohId::from_str` fails.
    /// Everything else mirrors the sequenced and timestamped composed tests, so
    /// the arm is what differs.
    #[cfg(all(
        feature = "ext-pubsub-advanced-history",
        feature = "ext-pubsub-advanced-publisher",
        feature = "pubsub-allow-loop"
    ))]
    #[test]
    fn detect_unidentified_late_publisher_recovers_its_cache_globally() {
        use hashbrown::HashMap;

        use crate::advanced_cache::{AdvancedCache, CacheConfig, CachedSample};
        use wz_session_core::sample::TimestampHint;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        // `zz` is not hex: the zid chunk does not decode.
        let pub_adv_ke = "demo/data/@adv/pub/zz/7/_".to_string();
        let cache = AdvancedCache::declare(
            &session,
            pub_adv_ke.clone(),
            CacheConfig {
                max_samples: 8,
                ..CacheConfig::default()
            },
        )
        .expect("advanced cache declares");

        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let d = Arc::clone(&delivered);
        let _sub = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_history(HistoryConfig::new().detect_late_publishers())
                .with_get_locality(Locality::SessionLocal),
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
        )
        .expect("late-publisher-detecting subscriber declares");
        assert!(delivered.lock().unwrap().is_empty());

        for i in 0u8..3 {
            cache.cache_sample(CachedSample::new(
                "demo/data",
                vec![i],
                None,
                TimestampHint {
                    time: 100 + i as u64,
                    zid: vec![0xEEu8],
                },
                crate::sample::SampleKind::Put,
            ));
        }

        session
            .observer()
            .lock()
            .unwrap()
            .liveliness_subscribers
            .dispatch_declare(&make_decl_token(93u64, &pub_adv_ke), &HashMap::new());
        session.drain_deferred_fires();

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0, 1, 2],
            "a publisher wz cannot identify still has its cache recovered, via \
             the GLOBAL history slot upstream uses for exactly this case"
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
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let pub_zid = vec![0x09u8];
        let pub_eid = 4u32;
        let zid_hex = zid_to_zenoh_hex(&pub_zid);
        let cache_ke = format!("demo/data/@adv/pub/{zid_hex}/{pub_eid}/_");
        let cache = AdvancedCache::declare(
            &session,
            cache_ke,
            CacheConfig {
                max_samples: 8,
                ..CacheConfig::default()
            },
        )
        .expect("advanced cache declares");
        for sn in 0u8..3 {
            cache.cache_sample(CachedSample::new(
                "demo/data",
                vec![sn],
                Some(SourceInfo::new(&pub_zid, pub_eid, sn as u32)),
                TimestampHint {
                    time: 100 + sn as u64,
                    zid: pub_zid.clone(),
                },
                crate::sample::SampleKind::Put,
            ));
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
                .with_get_locality(Locality::SessionLocal),
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
        )
        .expect("history-enabled advanced subscriber declares");

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0, 1, 2],
            "the late joiner recovered the publisher's cached history (0,1,2) on declare"
        );
    }

    /// R311y89 (review C3) regression: a startup history GET with NO `@adv` answerer
    /// must not wedge the subscriber forever. `Locality::Any` emits a wire Query
    /// (expecting a peer `Final` that never arrives) and fans loopback; with no cache
    /// declared the loopback yields only its synthetic `Final` (1 of the 2 expected),
    /// so `history_pending` stays set and a live sample buffers undelivered. The C3
    /// timeout registers the GET with a live deadline, so the reply registry's
    /// deadline sweep fires the synthetic terminal `Final` -> `finish_history` clears
    /// the gate and flushes the buffer. R311y326 — the failing arm this test guards
    /// against is now the EXPLICIT-clamp path: recovery threads
    /// `recovery_query_timeout_ms` (>= 1 ms), which is what arms the deadline. A raw
    /// `timeout_ms == 0` no longer produces `deadline_ms == None` on this build
    /// (`ext-pubsub-advanced-history` composes `query-timeout`, so `0` resolves to
    /// the platform default); pre-y326 it did, and the sweep skipped it forever.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    #[test]
    fn history_get_with_no_answerer_is_rescued_by_the_timeout_sweep() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
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
                .with_get_locality(Locality::Any)
                .with_query_timeout(timeout),
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
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

    /// R3064 (it replaces R311y90's review-C5 regression, which asserted the opposite):
    /// declaring a recovering subscriber with periodic_queries OFF a tokio runtime
    /// DECLARES. This `#[test]` runs outside any runtime. The refusal it used to pin was
    /// true while the task was a bare `tokio::spawn` and false from R2366, when it moved
    /// onto the process's `Application` runtime; on a C session it is the ordinary case
    /// (the in-process plane declares from the C application thread), where the refusal
    /// was swallowed and the subscriber was dead.
    ///
    /// What this does NOT show is the task asking: it sends nothing until a source is
    /// known, which takes a sample from one. That behaviour is the deterministic core's
    /// (`run_periodic_tick`, tested on its own), and its end-to-end form on a C session is
    /// the same-session differential, where the periodic subscriber hears the puts.
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    #[test]
    fn declare_with_periodic_off_runtime_declares() {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let declared = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new().with_recovery(
                RecoveryConfig::new().with_periodic_queries(Duration::from_millis(100)),
            ),
            |_sample: Sample| {},
        );
        assert!(
            declared.is_ok(),
            "a periodic recovery asks the calling thread for no runtime: {:?}",
            declared.err()
        );
    }

    /// R311y91 (review M1) — history-WITHOUT-retransmission is now representable
    /// (zenoh keeps `.recovery()` / `.history()` separate). An
    /// `AdvancedSubscriberOptions` with history set but NO recovery (retransmission
    /// off) still recovers a late joiner's cached history on declare. Before the
    /// split, history rode `RecoveryConfig`, so `retransmission = recovery.is_some()`
    /// was forced ON whenever history was set -- this config was unrepresentable.
    ///
    /// R2818 — gated on the cache too: this and the two `history_max_*` tests
    /// below stand up an `AdvancedCache` as the answerer, which history does not
    /// imply, so a `-history` build without the cache failed to compile them.
    #[cfg(all(
        feature = "ext-pubsub-advanced-history",
        feature = "ext-pubsub-advanced-cache"
    ))]
    #[test]
    fn history_only_without_recovery_recovers_late_joiner_cache() {
        use crate::advanced_cache::{AdvancedCache, CacheConfig, CachedSample};
        use wz_session_core::sample::TimestampHint;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let pub_zid = vec![0x09u8];
        let pub_eid = 4u32;
        let zid_hex = zid_to_zenoh_hex(&pub_zid);
        let cache_ke = format!("demo/data/@adv/pub/{zid_hex}/{pub_eid}/_");
        let cache = AdvancedCache::declare(
            &session,
            cache_ke,
            CacheConfig {
                max_samples: 8,
                ..CacheConfig::default()
            },
        )
        .expect("advanced cache declares");
        for sn in 0u8..3 {
            cache.cache_sample(CachedSample::new(
                "demo/data",
                vec![sn],
                Some(SourceInfo::new(&pub_zid, pub_eid, sn as u32)),
                TimestampHint {
                    time: 100 + sn as u64,
                    zid: pub_zid.clone(),
                },
                crate::sample::SampleKind::Put,
            ));
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
                .with_get_locality(Locality::SessionLocal),
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
        )
        .expect("history-only (no recovery) advanced subscriber declares");

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0, 1, 2],
            "history-only (retransmission off) still recovered the cache (0,1,2) on declare"
        );
    }

    /// R311y94 (review V2) — the `_max` history cap composed end-to-end. A cache
    /// retaining 0..5 answered by a history GET with `HistoryConfig::max_samples(2)`
    /// (the `_max=2` selector) delivers only the NEWEST 2 (3,4), oldest-first. This
    /// exercises the R311y94 loopback-selector fix: the SessionLocal GET now carries
    /// `_max=2` to the cache's `answer_from_ring` (before the fix the loopback Query
    /// dropped the selector and the cache over-returned 0..5).
    #[cfg(all(
        feature = "ext-pubsub-advanced-history",
        feature = "ext-pubsub-advanced-cache"
    ))]
    #[test]
    fn history_max_samples_caps_to_newest_n() {
        use crate::advanced_cache::{AdvancedCache, CacheConfig, CachedSample};
        use wz_session_core::sample::TimestampHint;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let pub_zid = vec![0x09u8];
        let pub_eid = 4u32;
        let zid_hex = zid_to_zenoh_hex(&pub_zid);
        let cache_ke = format!("demo/data/@adv/pub/{zid_hex}/{pub_eid}/_");
        // A cache deep enough to retain all 5 samples (so the cap, not eviction,
        // bounds the result).
        let cache = AdvancedCache::declare(
            &session,
            cache_ke,
            CacheConfig {
                max_samples: 8,
                ..CacheConfig::default()
            },
        )
        .expect("advanced cache declares");
        for sn in 0u8..5 {
            cache.cache_sample(CachedSample::new(
                "demo/data",
                vec![sn],
                Some(SourceInfo::new(&pub_zid, pub_eid, sn as u32)),
                TimestampHint {
                    time: 100 + sn as u64,
                    zid: pub_zid.clone(),
                },
                crate::sample::SampleKind::Put,
            ));
        }

        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let d = Arc::clone(&delivered);
        let _sub = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_history(HistoryConfig::new().max_samples(2))
                .with_get_locality(Locality::SessionLocal),
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
        )
        .expect("capped-history advanced subscriber declares");

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![3, 4],
            "_max=2 delivered only the newest 2 cached samples (3,4), oldest-first"
        );
    }

    /// R311y98 composed `_time` age filter: a `max_age(3600s)` history
    /// subscriber recovers a publisher's cache, but the cache drops the sample
    /// older than the age bound. The samples carry REAL wall-clock NTP64
    /// timestamps (the cache resolves `now(-age)` against `wall_clock_ntp64()`);
    /// a 2-hour-old sample falls outside the 1-hour window while two ~now
    /// samples pass — deterministic because the 1-hour window dwarfs the test's
    /// runtime.
    #[cfg(all(
        feature = "ext-pubsub-advanced-history",
        feature = "ext-pubsub-advanced-cache"
    ))]
    #[test]
    fn history_max_age_drops_samples_older_than_the_window() {
        use crate::advanced_cache::{AdvancedCache, CacheConfig, CachedSample};
        use crate::timestamp_source::wall_clock_ntp64;
        use wz_session_core::sample::TimestampHint;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let pub_zid = vec![0x09u8];
        let pub_eid = 4u32;
        let zid_hex = zid_to_zenoh_hex(&pub_zid);
        let cache_ke = format!("demo/data/@adv/pub/{zid_hex}/{pub_eid}/_");
        let cache = AdvancedCache::declare(
            &session,
            cache_ke,
            CacheConfig {
                max_samples: 8,
                ..CacheConfig::default()
            },
        )
        .expect("advanced cache declares");

        let now = wall_clock_ntp64();
        let two_hours = 2 * (3600u64 << 32);
        // sn 0 is 2h old (outside a 1h window); sn 1,2 are ~now (inside).
        let times = [now.saturating_sub(two_hours), now, now];
        for (sn, &t) in times.iter().enumerate() {
            cache.cache_sample(CachedSample::new(
                "demo/data",
                vec![sn as u8],
                Some(SourceInfo::new(&pub_zid, pub_eid, sn as u32)),
                TimestampHint {
                    time: t,
                    zid: pub_zid.clone(),
                },
                crate::sample::SampleKind::Put,
            ));
        }

        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let d = Arc::clone(&delivered);
        let _sub = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_history(HistoryConfig::new().max_age(3600.0))
                .with_get_locality(Locality::SessionLocal),
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
        )
        .expect("age-bounded history advanced subscriber declares");

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![1, 2],
            "max_age=3600s dropped the 2h-old sample, kept the two recent ones"
        );
    }

    /// R311y100/y101 composed late-publisher recovery, driving the REAL
    /// liveliness subscriber closure end-to-end (R311y101 review MED): a
    /// publisher that appears AFTER the subscriber joined has its cache
    /// recovered. The cache is EMPTY at subscriber-declare (so the startup
    /// history GET delivers nothing), then filled via `cache_sample` (NOT
    /// publish — no live delivery, so the subscriber genuinely missed them).
    /// An inbound `DeclToken` on the publisher's `@adv` KE is injected through
    /// the liveliness registry (`dispatch_declare` + `drain_deferred_fires`,
    /// the wire liveliness path the same-session token loopback omits) so the
    /// ACTUAL closure (`sample.kind` / `sample.keyexpr` extraction + the
    /// captured `lp_base` / `lp_depth` / `lp_age` / `dest` / `timeout` args)
    /// runs — not just the [`on_late_publisher_detected`] SSOT. A subsequent
    /// `UndeclToken` (a Delete) issues no recovery.
    #[cfg(all(
        feature = "ext-pubsub-advanced-history",
        feature = "ext-pubsub-advanced-publisher",
        feature = "pubsub-allow-loop"
    ))]
    #[test]
    fn detect_late_publisher_recovers_a_post_join_publisher_cache() {
        use hashbrown::HashMap;

        use crate::advanced_cache::{AdvancedCache, CacheConfig, CachedSample};
        use wz_session_core::sample::TimestampHint;

        // Replicas of the session-test liveliness injection helpers (session/
        // tests.rs:5874): build an inbound Decl/Undecl token wire frame whose
        // inline-literal keyexpr resolves with no peer table.
        fn make_undecl_token(id: u64) -> wz_codecs::declare::DeclareOwnedVariant {
            use wz_codecs::undecl_token::UndeclToken;
            wz_codecs::declare::DeclareVariant::CodecZenohUndeclToken(UndeclToken {
                id,
                ..UndeclToken::default()
            })
            .try_into_owned()
            .unwrap()
        }

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let pub_zid = vec![0x09u8];
        let pub_eid = 4u32;
        let zid_hex = zid_to_zenoh_hex(&pub_zid);
        let pub_adv_ke = format!("demo/data/@adv/pub/{zid_hex}/{pub_eid}/_");

        // The publisher's cache queryable exists but is EMPTY at declare time.
        let cache = AdvancedCache::declare(
            &session,
            pub_adv_ke.clone(),
            CacheConfig {
                max_samples: 8,
                ..CacheConfig::default()
            },
        )
        .expect("advanced cache declares");

        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let d = Arc::clone(&delivered);
        let _sub = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_history(HistoryConfig::new().detect_late_publishers())
                .with_get_locality(Locality::SessionLocal),
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
        )
        .expect("late-publisher-detecting subscriber declares");
        assert!(
            delivered.lock().unwrap().is_empty(),
            "empty cache at declare -> the startup history GET recovers nothing"
        );

        // The LATE publisher caches samples (cache_sample, not publish -> the
        // subscriber's live subscription never sees them).
        for sn in 0u8..3 {
            cache.cache_sample(CachedSample::new(
                "demo/data",
                vec![sn],
                Some(SourceInfo::new(&pub_zid, pub_eid, sn as u32)),
                TimestampHint {
                    time: 100 + sn as u64,
                    zid: pub_zid.clone(),
                },
                crate::sample::SampleKind::Put,
            ));
        }

        // Inject the publisher's `@adv` liveliness token (a Put) -> the REAL
        // liveliness closure fires -> the per-publisher history GET recovers the
        // whole cache. The dispatch only STAGES; `drain_deferred_fires` runs it.
        let token_id = 77u64;
        session
            .observer()
            .lock()
            .unwrap()
            .liveliness_subscribers
            .dispatch_declare(&make_decl_token(token_id, &pub_adv_ke), &HashMap::new());
        session.drain_deferred_fires();

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0, 1, 2],
            "the late publisher's cached history was recovered via the real liveliness closure"
        );

        // The token is retracted (a Delete) -> the closure's kind!=Put guard
        // issues no recovery (no new deliveries).
        let before = delivered.lock().unwrap().len();
        session
            .observer()
            .lock()
            .unwrap()
            .liveliness_subscribers
            .dispatch_declare(&make_undecl_token(token_id), &HashMap::new());
        session.drain_deferred_fires();
        assert_eq!(
            delivered.lock().unwrap().len(),
            before,
            "a Delete liveliness sample issues no recovery GET"
        );
    }

    /// R2553 — the same end-to-end path for a TIMESTAMPED publisher, which is
    /// the whole of this round and the arm that was silently dead.
    ///
    /// # Why this is a wz↔wz witness and needs no foreign oracle
    ///
    /// The atom's reason carried the `uhlc` shape as a "faithful-subset
    /// deferral" against upstream. It is also a gap between wz's OWN two
    /// halves, and that is cheaper to prove: `AdvancedPublisher` emits the
    /// `uhlc` discriminator for `Sequencing::Timestamp` AND `Sequencing::None`
    /// — two of its three modes, the second being the plainest configuration
    /// there is — while the subscriber declined the token and dropped every
    /// reply the cache would have sent. So a late-joining wz publisher was
    /// invisible to a wz subscriber, with no second implementation involved.
    ///
    /// # The two independent defects this covers, and why one test can
    ///
    /// The token must be RECOGNISED (`on_late_publisher_detected`'s timestamped
    /// arm, which did not exist) and the replies must be INGESTED
    /// (`recovered_sample_from_reply`, which opened with `source_info()?` and
    /// discarded exactly the samples a timestamped cache returns). Either alone
    /// still delivers nothing, so a single delivered-payload assertion is
    /// witness to both — and the control probes below damage them separately.
    ///
    /// Mirrors [`detect_late_publisher_recovers_a_post_join_publisher_cache`]
    /// chunk for chunk, changing only what the shape changes: the token's `eid`
    /// chunk is `uhlc`, and the cached samples carry NO `SourceInfo` and are
    /// ordered by their timestamps alone.
    #[cfg(all(
        feature = "ext-pubsub-advanced-history",
        feature = "ext-pubsub-advanced-publisher",
        feature = "pubsub-allow-loop"
    ))]
    #[test]
    fn detect_late_timestamped_publisher_recovers_a_post_join_publisher_cache() {
        use hashbrown::HashMap;

        use crate::advanced_cache::{AdvancedCache, CacheConfig, CachedSample};
        use wz_session_core::sample::TimestampHint;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let pub_zid = vec![0x11u8, 0x22];
        let zid_hex = zid_to_zenoh_hex(&pub_zid);
        // The KE a `Sequencing::Timestamp` / `Sequencing::None` publisher
        // declares, built through the `@adv` SSOT so the test cannot drift from
        // what `AdvancedPublisher::declare` emits.
        let pub_adv_ke = crate::advanced_ke::publisher_adv_ke(
            "demo/data",
            &zid_hex,
            crate::advanced_ke::KE_ADV_UHLC,
            None,
        );

        let cache = AdvancedCache::declare(
            &session,
            pub_adv_ke.clone(),
            CacheConfig {
                max_samples: 8,
                ..CacheConfig::default()
            },
        )
        .expect("advanced cache declares");

        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let d = Arc::clone(&delivered);
        let _sub = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_history(HistoryConfig::new().detect_late_publishers())
                .with_get_locality(Locality::SessionLocal),
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
        )
        .expect("late-publisher-detecting subscriber declares");
        assert!(
            delivered.lock().unwrap().is_empty(),
            "empty cache at declare -> the startup history GET recovers nothing"
        );

        // The LATE publisher caches samples with NO source_info — the shape
        // that makes them timestamped — ordered only by their own clock.
        for i in 0u8..3 {
            cache.cache_sample(CachedSample::new(
                "demo/data",
                vec![i],
                None,
                TimestampHint {
                    time: 100 + i as u64,
                    zid: pub_zid.clone(),
                },
                crate::sample::SampleKind::Put,
            ));
        }

        session
            .observer()
            .lock()
            .unwrap()
            .liveliness_subscribers
            .dispatch_declare(&make_decl_token(91u64, &pub_adv_ke), &HashMap::new());
        session.drain_deferred_fires();

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0, 1, 2],
            "a late TIMESTAMPED publisher's cached history was recovered through \
             the real liveliness closure"
        );

        // The slot the trigger opened was closed by the GET's terminal Final,
        // so the source is queryable again rather than wedged at one in flight.
        // Asserted through the public surface the subscriber owns: a second
        // token Put for the same publisher must re-issue, and re-issuing
        // re-delivers nothing (the instants are no longer strictly newer),
        // which is itself the timestamped ordering holding across a re-query.
        session
            .observer()
            .lock()
            .unwrap()
            .liveliness_subscribers
            .dispatch_declare(&make_decl_token(92u64, &pub_adv_ke), &HashMap::new());
        session.drain_deferred_fires();
        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0, 1, 2],
            "a re-detection re-queries but delivers no duplicate: the timestamped \
             ordering drops an instant that is not strictly newer"
        );
    }

    /// R311y592 — the TEARDOWN CANCELLATION contract, and the CALIBRATION arm
    /// for the test below it.
    ///
    /// This arm holds the subscriber ALIVE and drives the exact same two
    /// injections, so it establishes that (a) the rid this test computes really
    /// is the history GET's, (b) `deliver_local_reply` + `deliver_local_final`
    /// really do reach `on_sample` through it. Without it the negative arm below
    /// would pass on a mistyped rid, an un-intersecting keyexpr, or a
    /// `source_info: None` that `recovered_sample_from_reply` silently refuses —
    /// a proof that passes on absence rather than on the fix.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    #[test]
    fn a_late_history_reply_reaches_a_live_subscribers_callback() {
        let (delivered, session, sub, rid) = history_pending_fixture();

        deliver_history_reply(&session, rid);
        assert!(
            delivered.lock().unwrap().is_empty(),
            "a recovered sample BUFFERS while the history GET is still pending"
        );
        deliver_history_final(&session, rid);

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0x42],
            "the terminal Final flushed the buffer into the live subscriber's callback"
        );
        drop(sub);
    }

    /// R311y592 — dropping an advanced subscriber must CANCEL its in-flight
    /// recovery / history GETs, so that nothing arriving afterwards reaches the
    /// user's `on_sample`.
    ///
    /// This is pico's `_ze_advanced_subscriber_state_t::_cancellation_token`:
    /// one token per subscriber state, cloned onto every recovery / history
    /// `z_get` (`vendor/zenoh-pico/src/api/advanced_subscriber.c:924-928`) and
    /// cancelled in the subscriber's drop handler
    /// (`advanced_subscriber.c:1230-1231`) so that "all advanced subscriber
    /// resources are released by the time `z_close()`/undeclare returns"
    /// (the comment at `advanced_subscriber.c:1216-1219`).
    ///
    /// Before R311y592 wz had no such path: `PeriodicTask` aborted the re-ask
    /// timer, but every GET already in flight kept its own `Arc<Mutex<State>>`
    /// alive, and `State` owns `on_sample`. At the C ABI that callback is a C
    /// function pointer plus a context the application is entitled to free the
    /// moment `ze_undeclare_advanced_subscriber` returns — so a reply landing
    /// one instant later called into freed memory. The calibration arm above
    /// proves the injection reaches a LIVE subscriber; this arm proves it
    /// reaches a dropped one's callback no longer.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    #[test]
    fn dropping_an_advanced_subscriber_cancels_its_in_flight_history_get() {
        let (delivered, session, sub, rid) = history_pending_fixture();

        assert_eq!(
            session.observer().lock().unwrap().replies.len(),
            1,
            "the startup history GET is in flight before the drop"
        );

        drop(sub);

        assert_eq!(
            session.observer().lock().unwrap().replies.len(),
            0,
            "dropping the subscriber unregistered its in-flight history GET"
        );

        // ...and the same two injections the calibration arm delivers now reach
        // nobody: the pending entry (which owned the only remaining handle on
        // `State`, hence on `on_sample`) is gone.
        deliver_history_reply(&session, rid);
        deliver_history_final(&session, rid);
        assert!(
            delivered.lock().unwrap().is_empty(),
            "no sample was delivered into a dropped subscriber's callback"
        );
    }

    /// R311y592 — the OTHER ordering `PendingGets` has to survive: a GET the
    /// LOOPBACK answers inside [`Session::query`], so its terminal Final runs
    /// BEFORE the call returns the rid there is to record.
    ///
    /// A registry that only ever removed on `finish` would end this test holding
    /// one rid that is already dead — harmless per GET, unbounded over a
    /// long-lived subscriber re-asking on every heartbeat, and invisible to
    /// every other test here because a stale rid changes no delivery. Both
    /// counters are asserted: `live` empty is the claim, `finished_early` empty
    /// is what stops the fix from being a leak in the other set.
    #[cfg(all(
        feature = "ext-pubsub-advanced-history",
        feature = "ext-pubsub-advanced-cache"
    ))]
    #[test]
    fn a_synchronously_answered_history_get_leaves_no_registration_behind() {
        use crate::advanced_cache::{AdvancedCache, CacheConfig, CachedSample};
        use wz_session_core::sample::TimestampHint;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let pub_zid = vec![0x09u8];
        let zid_hex = zid_to_zenoh_hex(&pub_zid);
        let cache = AdvancedCache::declare(
            &session,
            format!("demo/data/@adv/pub/{zid_hex}/4/_"),
            CacheConfig {
                max_samples: 8,
                ..CacheConfig::default()
            },
        )
        .expect("advanced cache declares");
        cache.cache_sample(CachedSample::new(
            "demo/data",
            vec![0x11],
            Some(SourceInfo::new(&pub_zid, 4, 0)),
            TimestampHint {
                time: 100,
                zid: pub_zid.clone(),
            },
            crate::sample::SampleKind::Put,
        ));

        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let d = Arc::clone(&delivered);
        let sub = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_history(HistoryConfig::new())
                .with_get_locality(Locality::SessionLocal),
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
        )
        .expect("history-enabled advanced subscriber declares");

        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0x11],
            "the loopback answered the history GET synchronously, inside the declare"
        );
        assert_eq!(
            sub.pending_gets().sizes(),
            (0, 0),
            "a synchronously-completed GET leaves NEITHER a live registration nor \
             an early-finish marker behind"
        );
        assert_eq!(
            session.observer().lock().unwrap().replies.len(),
            0,
            "and the session agrees: no pending query outlived the loopback answer"
        );
    }

    /// Shared setup for the two arms above: a session with NO `@adv` answerer,
    /// a history-enabled advanced subscriber (so exactly one GET — the startup
    /// history query — is issued and stays pending), and that GET's rid.
    ///
    /// The rid is COMPUTED, not guessed: `alloc_next_request_id` is a plain
    /// monotonic counter, so consuming one before the declare fixes the next
    /// one, and `HistoryConfig::new()` (no `detect_late_publishers`) issues
    /// exactly that one query. The calibration arm is what proves the
    /// computation right.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    #[allow(clippy::type_complexity)]
    fn history_pending_fixture() -> (
        Arc<Mutex<Vec<u8>>>,
        TokioSession,
        AdvancedSubscriber<crate::runtime_impl::TokioRuntime>,
        u64,
    ) {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);
        // `_driver` is dropped here deliberately: these arms drive the reply
        // registry directly and never read the recorded link traffic.

        let probe = session.actions().alloc_next_request_id();
        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let d = Arc::clone(&delivered);
        let sub = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_history(HistoryConfig::new())
                // Remote-only: no local `@adv` cache exists, and SessionLocal
                // would synthesise a terminal Final at declare time and close
                // the GET before either arm could inject anything.
                .with_get_locality(Locality::Remote)
                .with_query_timeout(Duration::from_secs(3600)),
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
        )
        .expect("history-enabled advanced subscriber declares");
        (delivered, session, sub, probe + 1)
    }

    /// Inject one recovered Put reply for `rid`, keyed so it intersects the
    /// subscriber's `demo/data` and carrying the `source_info` the recovered-
    /// sample re-keying requires.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    fn deliver_history_reply(session: &TokioSession, rid: u64) {
        use wz_session_core::reply::{InboundReply, InboundReplyBody};

        let inbound = InboundReply {
            rid,
            keyexpr_literal: "demo/data".to_string(),
            body: InboundReplyBody::Put {
                payload: vec![0x42].into(),
                attachment: None,
                encoding: None,
                source_info: Some(SourceInfo::new(&[0x02], 7, 0)),
                timestamp: None,
            },
            responder: None,
            qos: None,
            stamp: Default::default(),
        };
        session
            .observer()
            .lock()
            .unwrap()
            .replies
            .deliver_local_reply(&inbound);
        session.drain_deferred_fires();
    }

    /// Inject the terminal Final for `rid` (what runs `finish_history` and
    /// flushes the reorder buffer into `on_sample`).
    #[cfg(feature = "ext-pubsub-advanced-history")]
    fn deliver_history_final(session: &TokioSession, rid: u64) {
        session
            .observer()
            .lock()
            .unwrap()
            .replies
            .deliver_local_final(rid);
        session.drain_deferred_fires();
    }

    /// How many recorded outbound frames carry `needle` in their bytes. A
    /// keyexpr travels the wire as its literal string, so a substring scan
    /// over the recorded frames answers "did this key expression go out"
    /// without decoding every frame shape.
    fn frames_carrying(driver: &crate::test_fixtures::RecordingLinkDriver, needle: &str) -> usize {
        let n = needle.as_bytes();
        (0..driver.frame_count())
            .filter(|&i| {
                let bytes = driver.frame_bytes(i);
                bytes.windows(n.len()).any(|w| w == n)
            })
            .count()
    }

    /// The option-free [`AdvancedSubscriber::declare`] declares no detection
    /// token, and the publisher in the same test declares one.
    ///
    /// This began as the MEASUREMENT of the atom's `subscriber_detection`
    /// residual — before R311y826 no wz form declared the token at all — and
    /// it is kept, retargeted at the form that still declares none. The
    /// publisher half is the CONTROL and it is what makes the subject
    /// assertion mean anything: `@adv/pub` bytes DO appear, so the recorder
    /// sees liveliness tokens, and "no `@adv/sub` frames" is a fact about this
    /// declare form rather than about an observation window that catches
    /// nothing.
    ///
    /// zenoh builds the suffix as `KE_ADV_PREFIX / KE_SUB / zid / eid /
    /// [meta | KE_EMPTY]` (advanced_subscriber.rs:1151-1160, constants at
    /// zenoh/src/api/admin.rs:48-58) and zenoh-pico spells the identical
    /// suffix (advanced_subscriber.c:1651-1655).
    #[cfg(all(
        feature = "ext-pubsub-advanced-publisher",
        feature = "pubsub-allow-loop"
    ))]
    #[test]
    fn option_free_declare_emits_no_detection_token_while_the_publisher_does() {
        use crate::advanced_publisher::{AdvancedPublisher, AdvancedPublisherOptions};

        let (actions, driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let _pub = AdvancedPublisher::declare(
            &session,
            "demo/data",
            AdvancedPublisherOptions::default(),
            vec![0x09],
        )
        .expect("advanced publisher declares");

        let _sub = AdvancedSubscriber::declare(&session, "demo/data", |_sample: Sample| {})
            .expect("advanced subscriber declares");

        assert!(
            frames_carrying(&driver, "demo/data/@adv/pub/") > 0,
            "CONTROL: the publisher's detection token must reach the wire, or \
             this test observes nothing"
        );
        assert_eq!(
            frames_carrying(&driver, "demo/data/@adv/sub/"),
            0,
            "the option-free declare form asks for no detection, so it must \
             declare no @adv/sub token"
        );
    }

    /// Detection is OPT-IN: default options declare no token, matching zenoh's
    /// builder default (`liveliness: false`, advanced_subscriber.rs:164). The
    /// publisher control is present for the same reason as above.
    #[cfg(all(
        feature = "ext-pubsub-advanced-publisher",
        feature = "pubsub-allow-loop"
    ))]
    #[test]
    fn detection_is_off_by_default() {
        let (driver, _declared) = declare_with_detection(None);
        assert!(
            frames_carrying(&driver, "demo/data/@adv/pub/") > 0,
            "CONTROL: liveliness tokens do reach this recorder"
        );
        assert_eq!(
            frames_carrying(&driver, "demo/data/@adv/sub/"),
            0,
            "default options must not declare a detection token"
        );
    }

    /// Opting in declares the token, and its key expression is the suffix BOTH
    /// references build: `<ke>/@adv/sub/<zid_hex>/<eid>/_`. The trailing `_` is
    /// asserted explicitly — it is the routing-matching chunk zenoh's own
    /// comment calls out, and an observer's wildcard-tailed query stops
    /// matching if it is dropped.
    #[cfg(all(
        feature = "ext-pubsub-advanced-publisher",
        feature = "pubsub-allow-loop"
    ))]
    #[test]
    fn subscriber_detection_declares_the_adv_sub_token() {
        let (driver, declared) = declare_with_detection(Some(SubscriberDetection::new()));
        // The hex RENDERING is `zid_hex`'s contract and is tested there; this
        // test asserts the KE is keyed by THIS subscriber's identity, so it
        // renders through the same SSOT rather than restating a spelling.
        let id = declared.subscriber.id();
        let prefix = format!("demo/data/@adv/sub/{}/", zid_to_zenoh_hex(id.zid()));
        assert_eq!(
            frames_carrying(&driver, &prefix),
            1,
            "exactly one detection token, keyed by this node's zid ({prefix})"
        );
        // R2815 — and by this subscriber's OWN eid: the token names the same
        // pair `id()` reports, which is upstream's `subscriber.id()` read at
        // the same place. Control: minting the eid from the session's entity
        // counter again (the pre-R2815 shape) reds this, because that counter
        // is not the one the subscription's declaration id comes from.
        let exact = format!("{prefix}{}/_", id.eid());
        assert_eq!(
            frames_carrying(&driver, &exact),
            1,
            "the token's eid is the subscriber's own ({exact})"
        );
        let ke_tail_present = (0..driver.frame_count()).any(|i| {
            let bytes = driver.frame_bytes(i);
            let needle = prefix.as_bytes();
            bytes
                .windows(needle.len())
                .position(|w| w == needle)
                .map(|at| {
                    // ... <eid digits> '/' '_'
                    let rest = &bytes[at + needle.len()..];
                    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
                    rest.get(digits) == Some(&b'/') && rest.get(digits + 1) == Some(&b'_')
                })
                .unwrap_or(false)
        });
        assert!(
            ke_tail_present,
            "with no metadata the token's last chunk is the concrete `_`, not \
             an empty chunk (zenoh KE_EMPTY, admin.rs:58)"
        );
    }

    /// Metadata SUBSTITUTES for the `_` chunk rather than being appended after
    /// it — zenoh picks one or the other (advanced_subscriber.rs:1156-1160).
    #[cfg(all(
        feature = "ext-pubsub-advanced-publisher",
        feature = "pubsub-allow-loop"
    ))]
    #[test]
    fn detection_metadata_replaces_the_empty_chunk() {
        let (driver, declared) = declare_with_detection(Some(
            SubscriberDetection::new().with_metadata("room/kitchen"),
        ));
        let prefix = format!(
            "demo/data/@adv/sub/{}/",
            zid_to_zenoh_hex(declared.subscriber.id().zid())
        );
        assert_eq!(frames_carrying(&driver, &prefix), 1, "one detection token");

        // Read the chunk that FOLLOWS `<eid>/` rather than searching the whole
        // frame for the metadata string: a probe that appended the metadata
        // after `_` instead of substituting for it left every substring
        // assertion true, so the position is the whole claim.
        let tail = token_tail_after_eid(&driver, &prefix).expect("the token KE is on the wire");
        assert_eq!(
            tail, "room/kitchen",
            "metadata REPLACES the empty chunk; the token's tail must be the \
             metadata alone, with no `_` on either side of it"
        );
    }

    /// The remainder of a token key expression after `<prefix><eid>/`, i.e.
    /// the meta-or-`_` tail, read out of the recorded frame that carries
    /// `prefix`.
    ///
    /// Stops at the first byte that cannot appear in a key expression chunk
    /// path, which is how the tail is delimited from whatever the frame
    /// encodes next.
    #[cfg(all(
        feature = "ext-pubsub-advanced-publisher",
        feature = "pubsub-allow-loop"
    ))]
    fn token_tail_after_eid(
        driver: &crate::test_fixtures::RecordingLinkDriver,
        prefix: &str,
    ) -> Option<String> {
        let needle = prefix.as_bytes();
        (0..driver.frame_count()).find_map(|i| {
            let bytes = driver.frame_bytes(i);
            let at = bytes.windows(needle.len()).position(|w| w == needle)?;
            let rest = &bytes[at + needle.len()..];
            let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
            if digits == 0 || rest.get(digits) != Some(&b'/') {
                return None;
            }
            let tail: Vec<u8> = rest[digits + 1..]
                .iter()
                .copied()
                .take_while(|b| b.is_ascii_alphanumeric() || *b == b'/' || *b == b'_' || *b == b'-')
                .collect();
            String::from_utf8(tail).ok()
        })
    }

    /// R2815 — a SESSION whose zid is not 1..=16 bytes gives its subscribers no
    /// identity, so both declare forms REFUSE before declaring anything. This
    /// replaces R311y826's test of a caller-supplied detection zid: the caller
    /// no longer supplies one, and the zid that matters is the session's.
    ///
    /// The refusal must leave nothing on the wire. The recorder is read for
    /// that, with a CONTROL session holding a valid zid on the same fixture, so
    /// "nothing on the wire" cannot be satisfied by a recorder that never sees
    /// a declaration at all.
    #[test]
    fn a_session_without_a_zid_gives_no_subscriber_an_identity() {
        let session_with = |zid: Vec<u8>| {
            let mut params = wz_runtime_tokio_test_support::fixture_session_init_params();
            params.zid = zid;
            let (actions, driver) = crate::test_fixtures::recording_actions_with_params(params);
            let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
            let clock = Arc::new(TokioTime::new());
            (TokioSession::new(actions, observer, clock), driver)
        };

        let (control, control_driver) = session_with(vec![0x0a, 0x0b]);
        let declared = AdvancedSubscriber::declare(&control, "demo/data", |_s: Sample| {})
            .expect("CONTROL: a session with a valid zid declares");
        assert_eq!(
            declared.id().zid(),
            &[0x0a, 0x0b],
            "id() reads the session's zid"
        );
        assert_eq!(declared.keyexpr(), "demo/data");
        assert!(
            frames_carrying(&control_driver, "demo/data") > 0,
            "CONTROL: a declaration reaches this recorder"
        );

        for bad in [vec![], vec![0u8; 17]] {
            let len = bad.len();
            let (session, driver) = session_with(bad);
            // `expect_err` would need AdvancedSubscriber: Debug; match instead.
            let Err(err) = AdvancedSubscriber::declare(&session, "demo/data", |_s: Sample| {})
            else {
                panic!("a session without a zid must be refused, not accepted");
            };
            assert!(
                matches!(err, AdvancedSubscribeError::SessionZid { len: got } if got == len),
                "refusal names the session zid's length, got {err:?}"
            );
            assert_eq!(
                frames_carrying(&driver, "demo/data"),
                0,
                "a refused declare leaves nothing on the wire"
            );
        }
    }

    /// Dropping the subscriber retracts its detection token. An observer that
    /// keeps seeing a subscriber which is gone is the failure this guards.
    ///
    /// The assertion is a DIFFERENCE between a detectable subscriber's
    /// teardown and a plain one's, not "something went out". The first version
    /// of this test asserted the latter and a damage probe that removed the
    /// token entirely still passed it: the subscriber's own undeclare already
    /// emits a frame, so "more frames after drop" is true either way. What
    /// only a token can add is one MORE frame than the same teardown without
    /// one.
    #[cfg(all(
        feature = "ext-pubsub-advanced-publisher",
        feature = "pubsub-allow-loop"
    ))]
    #[test]
    fn dropping_a_detectable_subscriber_retracts_its_token() {
        let teardown_frames = |detection: Option<SubscriberDetection>| {
            let (driver, declared) = declare_with_detection(detection);
            let before = driver.frame_count();
            drop(declared.subscriber);
            driver.frame_count() - before
        };

        let plain = teardown_frames(None);
        let detectable = teardown_frames(Some(SubscriberDetection::new()));
        assert_eq!(
            detectable,
            plain + 1,
            "a detectable subscriber's teardown must carry exactly one extra \
             frame — the token's undeclare; plain teardown emitted {plain}, \
             detectable emitted {detectable}"
        );
    }

    /// Declare a publisher (the liveliness CONTROL) plus an advanced
    /// subscriber carrying `detection`, over one recording session.
    #[cfg(all(
        feature = "ext-pubsub-advanced-publisher",
        feature = "pubsub-allow-loop"
    ))]
    fn declare_with_detection(
        detection: Option<SubscriberDetection>,
    ) -> (Arc<crate::test_fixtures::RecordingLinkDriver>, Declared) {
        use crate::advanced_publisher::{AdvancedPublisher, AdvancedPublisherOptions};

        let (actions, driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        // The publisher is the liveliness CONTROL and is returned to the
        // caller, not dropped here: the teardown test drops the SUBSCRIBER and
        // counts frames, so the publisher must still be alive at that point
        // and must not contribute a teardown of its own.
        let publisher = AdvancedPublisher::declare(
            &session,
            "demo/data",
            AdvancedPublisherOptions::default(),
            vec![0x09],
        )
        .expect("advanced publisher declares");

        // R2815 — an UNRELATED plain subscription first, kept alive. It moves
        // the subscription-id counter and not the session's entity counter, so
        // the subscriber under test gets an id the entity counter would NOT
        // hand out next. Without it the two counters agreed on this fixture
        // and a token named with a freshly minted eid passed the "own eid"
        // assertion — the control for that claim came back green.
        let unrelated = session
            .declare_subscriber("demo/unrelated", SubscribeOptions::default(), |_| {})
            .expect("unrelated plain subscriber declares");

        let mut options = AdvancedSubscriberOptions::new();
        if let Some(detection) = detection {
            options = options.with_subscriber_detection(detection);
        }
        let sub = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            options,
            |_s: Sample| {},
        )
        .expect("advanced subscriber declares");
        (
            driver,
            Declared {
                subscriber: sub,
                _publisher: publisher,
                _unrelated: unrelated,
            },
        )
    }

    /// What [`declare_with_detection`] hands back: the subscriber under test
    /// plus the control publisher, kept alive alongside it.
    #[cfg(all(
        feature = "ext-pubsub-advanced-publisher",
        feature = "pubsub-allow-loop"
    ))]
    struct Declared {
        subscriber: AdvancedSubscriber,
        _publisher: crate::advanced_publisher::AdvancedPublisher<
            crate::runtime_impl::TokioRuntime,
            TokioTime,
        >,
        _unrelated: crate::session::Subscriber,
    }

    /// The `QueryTarget` every recorded outbound Request carries, read back with
    /// session-core's OWN `ext_target` reader rather than a byte scan: the
    /// target ext is a zint whose bytes could occur anywhere in a frame, so
    /// "the bytes are in there" is not the same claim as "the Request carries
    /// this target".
    ///
    /// A `None` entry is a Request whose Q_T ext is ABSENT, which is exactly
    /// what a lost target pin looks like on the wire -- `read_request_target`
    /// maps absence onto the never-transmitted `0 = BEST_MATCHING` default.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    fn recorded_request_targets(
        driver: &crate::test_fixtures::RecordingLinkDriver,
    ) -> Vec<Option<wz_session_core::query_mode::QueryTarget>> {
        use wz_session_core::inbound::{parse_inbound, InboundFrame};
        use wz_session_core::network_message::{parse_frame_payload, NetworkMessage};
        use wz_session_core::request_routing_context::read_request_target;

        let mut targets = Vec::new();
        for idx in 0..driver.frame_count() {
            let bytes = driver.frame_bytes(idx);
            // This session's OWN bytes, so a parse failure is a defect rather
            // than a frame shape this helper may walk past.
            let InboundFrame::Frame { payload, .. } =
                parse_inbound(&bytes).expect("the session's own frame parses")
            else {
                continue;
            };
            for record in parse_frame_payload(&payload).expect("the session's own batch parses") {
                if let NetworkMessage::Request(request) = record {
                    targets.push(read_request_target(&request));
                }
            }
        }
        targets
    }

    /// R2507 — the WIRE half of R2505's `QueryTarget::All` pin. R2505 put the
    /// pin in [`issue_recovery_get`] and graded it at the BUILDER, which cannot
    /// tell a pin that reaches the peer from one that does not: `with_target` is
    /// a documented silent no-op without `query-target`, and the field then
    /// stays at the `None` sentinel that ELIDES Q_T from the frame. So the
    /// subject here is the recorded frame, decoded.
    ///
    /// The discriminator is session-core's reader answering `None` for an absent
    /// ext (`request_routing_context.rs` @ `pub fn read_request_target`): EVERY
    /// way of losing the pin lands there -- the `with_target` call deleted, the
    /// `"query-target"` line dropped from `ext-pubsub-advanced-recovery`'s
    /// closure in `Cargo.toml`, or the emit path ceasing to thread the target
    /// ([`crate::session::querier`] @ `pub(super) fn effective_target`).
    ///
    /// The SET is pinned, not a count: `vec![Some(All)]` also says this declare
    /// emits exactly ONE Request, so a second GET appearing (or the history GET
    /// disappearing) fails here instead of passing as "at least one was right".
    /// An empty recording fails the same equality, which is the anti-vacuity
    /// arm -- there is no filter for a zero population to slip through.
    ///
    /// ⛔ The cfg names ONLY `ext-pubsub-advanced-history`. Adding
    /// `feature = "query-target"` would cfg this guard OUT of precisely the
    /// build whose regression it exists to catch; the feature is implied here
    /// anyway (history -> recovery -> query-target), so naming it would buy
    /// nothing and cost the grading.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    #[test]
    fn the_history_get_puts_query_target_all_on_the_wire() {
        use wz_session_core::query_mode::QueryTarget;

        let (actions, driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let _sub = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_history(HistoryConfig::new())
                // Remote: the GET has to reach the LINK to be graded at all.
                // SessionLocal is answered inside the declare and emits no
                // Request, which is why the history arms that drive the reply
                // registry directly drop their driver.
                .with_get_locality(Locality::Remote),
            |_s: Sample| {},
        )
        .expect("history-enabled advanced subscriber declares");

        assert_eq!(
            recorded_request_targets(&driver),
            vec![Some(QueryTarget::All)],
            "the startup history GET must put Q_T = All on the wire. An absent \
             target reads back as BEST_MATCHING, which a peer answers from ONE \
             queryable -- a history GET answered by one queryable returns a \
             strictly smaller history, so this is a delivery difference and not \
             a cosmetic one"
        );
    }

    /// R2817 — `background()` on the option-free form: the subscriber keeps
    /// ORDERING and DELIVERING after its handle is gone, emits no retraction,
    /// and leaves nothing behind that holds its session.
    ///
    /// Delivery is the discriminator, as for the plain liveliness form: a
    /// `background` that dropped the handle without disarming it would
    /// unregister the subscription and this log would stop at the two samples
    /// sent before it. The duplicate `1` after the handle is gone is what
    /// shows the ORDERING state survived too, not just a bare subscription.
    ///
    /// Controls: making [`Subscriber::background`] a plain drop reds the
    /// frame and delivery assertions; the strong count is the CONTROL for
    /// the leak claim, and it is asserted to have MOVED at declare so that
    /// "back to base" cannot be a count that never rose.
    #[test]
    fn a_background_advanced_subscriber_keeps_ordering_after_its_handle_is_gone() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);
        let base = session.strong_count();

        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let d = Arc::clone(&delivered);
        let sub = AdvancedSubscriber::declare(&session, "demo/data", move |sample: Sample| {
            d.lock().unwrap().push(sample.payload[0])
        })
        .expect("advanced subscriber declares");
        put_sequenced(&session, 0);
        put_sequenced(&session, 1);
        assert!(
            session.strong_count() > base,
            "CONTROL: the live handle holds its session, so the count must have \
             risen at declare or the assertion below measures nothing"
        );

        let frames = driver.frame_count();
        sub.background();
        assert_eq!(
            driver.frame_count(),
            frames,
            "background() must emit no retraction"
        );
        assert_eq!(
            session.strong_count(),
            base,
            "nothing a backgrounded subscriber leaves behind may hold its session"
        );

        put_sequenced(&session, 1); // duplicate: the ordering state must drop it
        put_sequenced(&session, 2);
        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0, 1, 2],
            "after background() the subscriber still delivers in order and still \
             drops the duplicate"
        );
    }

    /// R2819 — `declare_with_options` honours `allowed_origin` in EVERY build,
    /// with or without recovery: upstream's `allowed_origin` is a knob of every
    /// advanced subscriber, and until R2819 a recovery-off build had no options
    /// form to set it through.
    ///
    /// The samples are SessionLocal loopback, so a `Remote`-only subscriber
    /// must deliver none. The default options are the CONTROL on the same
    /// fixture: they deliver both, so "nothing arrived" is a fact about the
    /// origin knob rather than about a publish that never loops back.
    #[test]
    fn declare_with_options_honours_the_allowed_origin() {
        let delivered_with = |origin: Option<Locality>| {
            let (actions, _driver) = crate::test_fixtures::recording_actions();
            let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
            let clock = Arc::new(TokioTime::new());
            let session = TokioSession::new(actions, observer, clock);
            let mut options = AdvancedSubscriberOptions::new();
            if let Some(origin) = origin {
                options = options.with_allowed_origin(origin);
            }
            let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
            let d = Arc::clone(&delivered);
            let _sub = AdvancedSubscriber::declare_with_options(
                &session,
                "demo/data",
                options,
                move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
            )
            .expect("advanced subscriber declares");
            put_sequenced(&session, 0);
            put_sequenced(&session, 1);
            let out = delivered.lock().unwrap().clone();
            out
        };

        assert_eq!(
            delivered_with(None),
            vec![0, 1],
            "CONTROL: the default origin (Any) delivers loopback samples"
        );
        assert_eq!(
            delivered_with(Some(Locality::Remote)),
            Vec::<u8>::new(),
            "a Remote-only subscriber must not deliver SessionLocal samples"
        );
    }

    /// Drain `session`'s buffered stages while a reader collects the first
    /// payload byte of up to `want` samples from `rx`.
    ///
    /// Every `recv` is BOUNDED: the sender lives as long as the subscriber, so
    /// a lost sample never closes the channel, and an unbounded wait would turn
    /// a control into a hang (the plain buffered test measured exactly that).
    async fn drain_payloads(
        session: &TokioSession,
        mut rx: tokio::sync::mpsc::Receiver<Sample>,
        want: usize,
    ) -> Vec<u8> {
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            while got.len() < want {
                match tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await {
                    Ok(Some(sample)) => got.push(sample.payload[0]),
                    Ok(None) | Err(_) => break,
                }
                tokio::task::yield_now().await;
            }
            got
        });
        session.drain_buffered().await;
        reader.await.expect("reader task panicked")
    }

    /// R2819 — the buffered form delivers every sample, in order and
    /// de-duplicated, through a queue SMALLER than the burst.
    ///
    /// Anti-vacuity is the plain buffered test's: capacity 2 against five
    /// distinct samples, all staged before anything reads, so a delivery that
    /// dropped on a full queue instead of waiting loses the tail. The repeated
    /// `1` is what shows the samples went through the advanced subscriber's
    /// ORDERING state rather than around it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_buffered_advanced_subscriber_waits_and_keeps_its_ordering() {
        const CAPACITY: usize = 2;
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let (_sub, rx, _drain_stage) =
            AdvancedSubscriber::declare_buffered(&session, "demo/data", CAPACITY)
                .expect("buffered advanced subscriber declares");
        for sn in [0, 1, 1, 2, 3, 4] {
            put_sequenced(&session, sn);
        }

        assert_eq!(
            drain_payloads(&session, rx, 5).await,
            vec![0, 1, 2, 3, 4],
            "every sample must reach the queue once and in order -- a queue of \
             {CAPACITY} against five samples is over capacity by construction"
        );
    }

    /// R2819 — the options form's queue receives what the HISTORY GET
    /// recovers, not only live samples: history is delivered by a reply
    /// flush, a different path from the live callback, and both must stage.
    ///
    /// The history completes synchronously inside the declare (loopback), so
    /// all three samples are staged before the reader starts; capacity 1
    /// makes the drain wait twice.
    #[cfg(all(
        feature = "ext-pubsub-advanced-history",
        feature = "ext-pubsub-advanced-cache"
    ))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_buffered_advanced_subscriber_queues_its_recovered_history() {
        use crate::advanced_cache::{AdvancedCache, CacheConfig, CachedSample};
        use wz_session_core::sample::TimestampHint;

        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);

        let pub_zid = vec![0x09u8];
        let pub_eid = 4u32;
        let zid_hex = zid_to_zenoh_hex(&pub_zid);
        let cache = AdvancedCache::declare(
            &session,
            format!("demo/data/@adv/pub/{zid_hex}/{pub_eid}/_"),
            CacheConfig {
                max_samples: 8,
                ..CacheConfig::default()
            },
        )
        .expect("advanced cache declares");
        for sn in 0u8..3 {
            cache.cache_sample(CachedSample::new(
                "demo/data",
                vec![sn],
                Some(SourceInfo::new(&pub_zid, pub_eid, sn as u32)),
                TimestampHint {
                    time: 100 + sn as u64,
                    zid: pub_zid.clone(),
                },
                crate::sample::SampleKind::Put,
            ));
        }

        let (_sub, rx, _drain_stage) = AdvancedSubscriber::declare_with_options_buffered(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_history(HistoryConfig::new())
                .with_get_locality(Locality::SessionLocal),
            1,
        )
        .expect("buffered advanced subscriber with history declares");

        assert_eq!(
            drain_payloads(&session, rx, 3).await,
            vec![0, 1, 2],
            "the recovered history must reach the queue, oldest first"
        );
    }

    /// R2817 — `background()` on the fully configured form, where every piece
    /// `declare_with_options` can build is present: heartbeat and
    /// late-publisher subscriptions, the retention task, the recovery GET
    /// registry and the detection token.
    ///
    /// The strong count is the claim this adds over the option-free test. Each
    /// of those callbacks and tasks used to hold a STRONG session clone; left
    /// registered by `background`, any one of them keeps the session alive
    /// for good. Control, run: restoring ONE strong capture — in the live
    /// callback alone — reds this with `left: 2` / `right: 1`, so the count
    /// sees a single leaked clone, not only the sum of all of them. The frame
    /// count covers the retractions a
    /// plain drop would emit here — `UndeclSubscriber` ×2, the liveliness
    /// `Interest(Final)` and the token's `UndeclToken`.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    #[test]
    fn a_fully_configured_background_subscriber_holds_no_session_and_retracts_nothing() {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);
        let base = session.strong_count();

        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let d = Arc::clone(&delivered);
        let sub = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_recovery(RecoveryConfig::new().with_heartbeat())
                .with_history(HistoryConfig::new().detect_late_publishers())
                .with_subscriber_detection(SubscriberDetection::new())
                .with_get_locality(Locality::SessionLocal),
            move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
        )
        .expect("fully configured advanced subscriber declares");
        assert!(
            sub.heartbeat_channel_is_live(),
            "CONTROL: the heartbeat subscription exists, so its callback is in \
             the population this test grades"
        );
        let token_prefix = format!("demo/data/@adv/sub/{}/", zid_to_zenoh_hex(sub.id().zid()));
        assert_eq!(
            frames_carrying(&driver, &token_prefix),
            1,
            "CONTROL: the detection token was declared"
        );

        let frames = driver.frame_count();
        sub.background();
        assert_eq!(
            driver.frame_count(),
            frames,
            "background() must emit no retraction: no UndeclSubscriber, no \
             liveliness Interest(Final), no UndeclToken"
        );
        assert_eq!(
            session.strong_count(),
            base,
            "every callback and task a backgrounded subscriber leaves registered \
             must hold its session weakly"
        );

        put_sequenced(&session, 0);
        put_sequenced(&session, 1);
        assert_eq!(
            *delivered.lock().unwrap(),
            vec![0, 1],
            "the backgrounded subscriber still delivers"
        );
    }

    /// What a host's answer keeps alive, recording the moment it is let go of:
    /// its label and how many frames the session had sent by then.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    struct Witness {
        label: &'static str,
        log: Arc<Mutex<Vec<(&'static str, usize)>>>,
        driver: Arc<crate::test_fixtures::RecordingLinkDriver>,
    }

    #[cfg(feature = "ext-pubsub-advanced-history")]
    impl Drop for Witness {
        fn drop(&mut self) {
            self.log
                .lock()
                .unwrap()
                .push((self.label, self.driver.frame_count()));
        }
    }

    /// A host that names nothing — every answer is the literal form — but
    /// records what it is asked, in order, and what its answers keep alive.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    struct RecordingForms {
        identity: Option<u32>,
        asked: Mutex<Vec<String>>,
        released: Arc<Mutex<Vec<(&'static str, usize)>>>,
        driver: Arc<crate::test_fixtures::RecordingLinkDriver>,
        retained: Mutex<Vec<Arc<dyn Send + Sync>>>,
    }

    #[cfg(feature = "ext-pubsub-advanced-history")]
    impl RecordingForms {
        fn new(
            identity: Option<u32>,
            driver: &Arc<crate::test_fixtures::RecordingLinkDriver>,
        ) -> Arc<Self> {
            Arc::new(Self {
                identity,
                asked: Mutex::new(Vec::new()),
                released: Arc::new(Mutex::new(Vec::new())),
                driver: Arc::clone(driver),
                retained: Mutex::new(Vec::new()),
            })
        }

        fn answer(&self, label: &'static str, keyexpr: &str) -> EntityForm {
            self.asked
                .lock()
                .unwrap()
                .push(format!("{label} {keyexpr}"));
            EntityForm::literal().keeping(Arc::new(Witness {
                label,
                log: Arc::clone(&self.released),
                driver: Arc::clone(&self.driver),
            }))
        }
    }

    #[cfg(feature = "ext-pubsub-advanced-history")]
    impl DeclarationForms for RecordingForms {
        fn entity_id(&self) -> Option<u32> {
            self.identity
        }
        fn subscriber(&self, keyexpr: &str) -> EntityForm {
            self.answer("subscriber", keyexpr)
        }
        fn late_publishers(&self, keyexpr: &str) -> EntityForm {
            self.answer("late_publishers", keyexpr)
        }
        fn heartbeat(&self, keyexpr: &str) -> EntityForm {
            self.answer("heartbeat", keyexpr)
        }
        fn token(&self, keyexpr: &str) -> EntityForm {
            self.answer("token", keyexpr)
        }
        fn retain(&self, anchor: Arc<dyn Send + Sync>) {
            self.retained.lock().unwrap().push(anchor);
        }
    }

    /// A subscriber with every entity that makes a host declare a key — the live
    /// subscription, the late-publisher subscription, the heartbeat subscription
    /// and the detection token — declared with `forms`.
    ///
    /// The subscriber holds its session, so returning it keeps the session alive.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    fn declare_with_forms(
        identity: Option<u32>,
    ) -> (
        Arc<crate::test_fixtures::RecordingLinkDriver>,
        Arc<RecordingForms>,
        AdvancedSubscriber,
    ) {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        let forms = RecordingForms::new(identity, &driver);
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        let session = TokioSession::new(actions, observer, clock);
        let sub = AdvancedSubscriber::declare_with_options(
            &session,
            "demo/data",
            AdvancedSubscriberOptions::new()
                .with_recovery(RecoveryConfig::new().with_heartbeat())
                .with_history(HistoryConfig::new().detect_late_publishers())
                .with_subscriber_detection(SubscriberDetection::new())
                .with_get_locality(Locality::SessionLocal)
                .with_declaration_forms(forms.clone()),
            |_s: Sample| {},
        )
        .expect("a fully configured advanced subscriber declares");
        (driver, forms, sub)
    }

    /// The forms are asked about each entity at the moment it is declared and in
    /// zenoh-pico's order — the subscription, the late-publisher subscription,
    /// the heartbeat subscription, the detection token — and the token is named
    /// with the identity the host gives, which is also the one the handle
    /// reports.
    ///
    /// The order is what a host that declares keys shows a peer: its keys go out
    /// as it is asked. The heartbeat subscription comes AFTER the late-publisher
    /// one because pico declares it after the history query and that
    /// subscription (`vendor/zenoh-pico/src/api/advanced_subscriber.c` @
    /// `// Heartbeat subscriber`).
    ///
    /// # Controls
    ///
    /// Declaring the heartbeat subscription before the late-publisher one reds
    /// the order; ignoring [`DeclarationForms::entity_id`] reds the identity,
    /// which then names the plain subscription's own id.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    #[test]
    fn the_forms_are_asked_in_pico_order_and_the_hosts_identity_names_the_token() {
        let (driver, forms, sub) = declare_with_forms(Some(77));

        assert_eq!(sub.id().eid(), 77, "the handle reports the host's identity");
        let zid = zid_to_zenoh_hex(sub.id().zid());
        assert_eq!(
            *forms.asked.lock().unwrap(),
            vec![
                String::from("subscriber demo/data"),
                String::from("late_publishers demo/data/@adv/pub/**"),
                String::from("heartbeat demo/data/@adv/pub/**"),
                format!("token demo/data/@adv/sub/{zid}/77/_"),
            ],
            "the host is asked about each entity as it is declared, in pico's order, and \
             the token is named with the host's identity"
        );
        assert_eq!(
            frames_carrying(&driver, &format!("demo/data/@adv/sub/{zid}/77/_")),
            1,
            "CONTROL: the token reached the wire under that name"
        );
    }

    /// Each entity lets go of what names it right after itself, in pico's
    /// retraction order: the subscription, the late-publisher subscription, the
    /// heartbeat subscription, then the token.
    ///
    /// Read from the frame count at the moment each answer is released: every
    /// entity's own retraction is one frame, so an answer released right after
    /// its entity sees exactly one more frame than the one before it.
    ///
    /// # Control
    ///
    /// Declaring the answer BEFORE the entity in [`Held`] — so a key goes before
    /// the entity that named it — reds the first count, because the answer is
    /// then released ahead of its entity's frame.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    #[test]
    fn each_entity_lets_go_of_its_name_right_after_itself_in_pico_order() {
        let (driver, forms, sub) = declare_with_forms(None);
        assert!(
            forms.released.lock().unwrap().is_empty(),
            "CONTROL: nothing is released while the subscriber stands"
        );

        let before = driver.frame_count();
        drop(sub);
        let released = forms.released.lock().unwrap().clone();
        assert_eq!(
            released.iter().map(|(label, _)| *label).collect::<Vec<_>>(),
            vec!["subscriber", "late_publishers", "heartbeat", "token"],
            "the answers are released entity by entity in pico's retraction order"
        );
        // The first three entities' retractions are frames the session has sent
        // by the time their answer goes. The token's is queued in the same order
        // but recorded a moment later, so its answer is held only to the count
        // before it.
        assert_eq!(
            released[..3],
            [
                ("subscriber", before + 1),
                ("late_publishers", before + 2),
                ("heartbeat", before + 3),
            ],
            "each answer is released right AFTER its entity's own retraction"
        );
        assert!(
            released[3].1 > before + 2,
            "the token's answer is released after the three before it: {released:?}"
        );
    }

    /// A backgrounded subscriber hands what names its entities to the host, which
    /// keeps them until its own end; nothing is released at the call.
    ///
    /// # Control
    ///
    /// Dropping the answers in `background()` instead of handing them over
    /// releases all four at the call, which reds the first assertion.
    #[cfg(feature = "ext-pubsub-advanced-history")]
    #[test]
    fn a_backgrounded_subscriber_hands_its_names_to_the_host() {
        let (_driver, forms, sub) = declare_with_forms(None);

        sub.background();
        assert!(
            forms.released.lock().unwrap().is_empty(),
            "a backgrounded subscriber's names must outlive the call: released {:?}",
            forms.released.lock().unwrap()
        );
        assert_eq!(
            forms.retained.lock().unwrap().len(),
            4,
            "the host was handed one answer per entity"
        );

        forms.retained.lock().unwrap().clear();
        let released: Vec<&str> = forms
            .released
            .lock()
            .unwrap()
            .iter()
            .map(|(label, _)| *label)
            .collect();
        assert_eq!(
            released,
            vec!["subscriber", "late_publishers", "heartbeat", "token"],
            "the host lets them go when it chooses"
        );
    }
}
