// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `LivelinessGetRegistry` — REQUESTER-side registry for the liveliness
//! GET (snapshot query). The application asks "which liveliness tokens
//! matching keyexpr K are currently alive?"; wz emits one CURRENT
//! liveliness `Interest`, the peer replies with an `interest_id`-tagged
//! `Declare(DeclToken)` per matching live token, terminated by an
//! `interest_id`-tagged `Declare(DeclFinal)`. This mirrors zenoh-pico's
//! `z_liveliness_get` / `_z_liveliness_query`
//! (`vendor/zenoh-pico/src/net/liveliness.c:314-366`) and the symmetric
//! responder side already wz-resident in
//! [`crate::declare::local_token::LocalTokenRegistry`].
//!
//! ## Why this is NOT built on the query (Request/Response) plane
//!
//! The application *surface* of a liveliness get looks like a query —
//! it delivers a stream of replies terminated by a final, so it reuses
//! the response-plane [`crate::reply_sink::ReplySink`] / [`ReplyView`]
//! delivery seam (one SSOT for "get → replies → final"). But the *wire*
//! is the **Interest / declaration** plane, not the Request / Query
//! plane: the request leg is a CURRENT liveliness `Interest`, and the
//! replies arrive as `Declare(DeclToken)` records, terminated by a
//! `Declare(DeclFinal)` — never a `Request(Query)` / `Response(Reply)` /
//! `ResponseFinal`. That is what real zenoh peers speak, so a query-plane
//! model would be unable to interoperate. Consequently this registry
//! correlates on the outer [`wz_codecs::declare::DeclareOwned::interest_id`]
//! (declaration plane) rather than a `Response.request_id`, and it is a
//! sibling of [`crate::reply::ReplyRegistry`] — same *pattern* (a bounded
//! pending table keyed by a correlation id, each entry carrying a
//! [`ReplySink`] + an optional deadline), never the same *type*. The
//! split matches both zenoh-pico (its `_z_liveliness_pending_query` map is
//! distinct from the query pending map) and wz's own structural separation
//! of the liveliness registries from the pub/sub + query registries.
//!
//! ## Position alongside the other liveliness registries
//!
//! | Registry                         | Role                                    | Correlation        |
//! |----------------------------------|-----------------------------------------|--------------------|
//! | [`crate::declare::LivelinessRegistry`]            | observe EVERY peer `Decl*Token`         | none (callback)    |
//! | [`crate::declare::liveliness_subscriber::LivelinessSubscriberRegistry`] | subscribe to peer tokens matching my keyexpr | per-subscriber slot |
//! | [`crate::declare::local_token::LocalTokenRegistry`] | DECLARER side + inbound-Interest responder | local token table  |
//! | [`LivelinessGetRegistry`]                          | one-shot CURRENT snapshot of peer tokens | per-get `interest_id` |
//!
//! An inbound `Declare(DeclToken)` carrying `interest_id = None` is an
//! *unsolicited* (proactive) token declaration and is the observer /
//! subscriber registries' concern; this registry ignores it. Only a
//! `Declare` whose outer envelope carries `interest_id = Some(id)` —
//! the peer's solicited reply to one of our outstanding gets — routes
//! here, fanning to the single pending get with the matching id.
//!
//! ## no-heap split (mirror of the sibling registries)
//!
//! 1. **Storage + fire (no-heap)** — the pending table is a
//!    [`crate::bounded::BoundedVec`] of [`PendingGet`] rows; the
//!    [`LivelinessGetRegistry::dispatch_reply_borrowed`] /
//!    [`LivelinessGetRegistry::dispatch_final`] /
//!    [`LivelinessGetRegistry::sweep_timed_out`] fire entries take only
//!    `Copy` scalars + a borrowed keyexpr, so they compile + run on the
//!    MCU no-alloc profile.
//! 2. **Owned inbound parse (alloc)** —
//!    [`LivelinessGetRegistry::dispatch_declare`] /
//!    [`LivelinessGetRegistry::dispatch_messages`] consume an owned
//!    [`wz_codecs::declare::DeclareOwned`] + resolve its keyexpr through
//!    the shared peer table, then funnel through the no-heap SSOT.

use crate::bounded::BoundedVec;
use crate::caps;
use crate::registry_error::RegisterError;
use crate::reply_sink::{BorrowedReply, ReplyKind, ReplySink};

#[cfg(feature = "alloc")]
pub use crate::reply_sink::BoxedReplySink;

// R311y739 -- `String` / `HashMap` were here for the wire-dispatch params
// alone, which now take `impl Into<MappingSpaces>`. The suite below imports
// both for itself.

#[cfg(feature = "alloc")]
use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant};

#[cfg(feature = "alloc")]
use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
#[cfg(feature = "alloc")]
use crate::network_message::NetworkMessage;
#[cfg(feature = "alloc")]
use crate::wireexpr_resolve::{resolve_wireexpr_in, MappingSpaces};

/// One outstanding liveliness get. Private to this module; consumers
/// interact through [`LivelinessGetRegistry::register`] /
/// [`LivelinessGetRegistry::unregister`] and the higher-level
/// `Session::liveliness().get()` surface.
struct PendingGet<C: ReplySink> {
    /// The `interest_id` allocated for the outbound CURRENT Interest;
    /// the correlation key every inbound reply `Declare` echoes in its
    /// outer envelope.
    interest_id: u64,
    /// The reply-delivery sink (DIP seam). `C = BoxedReplySink` on AP
    /// (heap `on_reply` + `on_final` closures), a consumer-supplied
    /// closed `enum` on MCU.
    sink: C,
    /// Absolute monotonic-ms deadline (snapshot taken at register time
    /// as `clock.now_monotonic_ms() + timeout_ms`). `None` means the
    /// get never times out (it stays pending until the peer's
    /// `Declare(DeclFinal)` arrives). A `Some(d)` entry is swept by
    /// [`LivelinessGetRegistry::sweep_timed_out`] when `now_ms >= d` so an
    /// unanswered get cannot leak its slot. R311y323 — this said the sweep fires
    /// `on_final` "exactly as a real terminator would", which was the whole point
    /// and is now false: the sweep fires `on_timeout`, so a swept get is
    /// DISTINGUISHABLE from a real terminator (it carries a synthetic
    /// `Err("Timeout")` first). The slot still cannot leak — `on_timeout` ends in
    /// the same final. Mirrors
    /// [`crate::reply::ReplyRegistry`]'s per-pending deadline.
    deadline_ms: Option<u64>,
}

/// Requester-side registry tracking the liveliness GET (snapshot)
/// queries wz has outstanding on this session, routing each inbound
/// solicited `Declare(DeclToken)` reply to the matching get's
/// [`ReplySink::on_reply`] and the terminating `Declare(DeclFinal)` to
/// its [`ReplySink::on_final`] (after which the pending entry is
/// removed). See module-level docs for why this is a declaration-plane
/// sibling of [`crate::reply::ReplyRegistry`] rather than a reuse of it.
pub struct LivelinessGetRegistry<C: ReplySink> {
    pending: BoundedVec<PendingGet<C>, { caps::MAX_PENDING_LIVELINESS_GETS }>,
    /// F3 — interest ids whose get terminated since the last
    /// [`take_finalized`](Self::take_finalized) drain (inbound
    /// `DeclFinal` or local timeout sweep). The observer's
    /// `flush_pending` drains these through
    /// `ResponseSink::prune_liveliness_get_interest` so the
    /// session-reconnect declaration cache drops the one-shot CURRENT
    /// Interest — the requester never emits an interest-FINAL for a get
    /// (the peer's `DeclFinal` terminates the protocol), so without this
    /// the cache entry would replay a finished snapshot on every
    /// reconnect (zenoh-pico shares the leak — its `_z_liveliness_query`
    /// routes through the caching `_z_send_declare`, `liveliness.c:355`,
    /// with no prune; wz closes it). Capacity contract (R311ka): every
    /// staging site drains within its own lock window — the dispatch
    /// path via `flush_pending` in the same `observer.dispatch` call,
    /// the sweep path at its caller right after `sweep_timed_out` — so
    /// one staged batch is bounded by the pending table and the shared
    /// capacity cannot overflow (a dropped marker would be a PERMANENT
    /// replay-leak: this drain is the entry's only prune).
    finalized: BoundedVec<u64, { caps::MAX_PENDING_LIVELINESS_GETS }>,
}

impl<C: ReplySink> Default for LivelinessGetRegistry<C> {
    fn default() -> Self {
        Self::with_sink_backing()
    }
}

impl<C: ReplySink> LivelinessGetRegistry<C> {
    /// New empty registry over an explicit sink backing `C` (the
    /// no-`alloc` / MCU entry point, paired with
    /// [`register`](Self::register)). AP callers use the inferring
    /// [`new`](LivelinessGetRegistry::new) shorthand, which fixes
    /// `C = BoxedReplySink`.
    pub fn with_sink_backing() -> Self {
        Self {
            pending: BoundedVec::new(),
            finalized: BoundedVec::new(),
        }
    }

    /// F3 — drain the interest ids whose gets terminated since the last
    /// call (inbound `DeclFinal` or timeout sweep). The caller routes
    /// each through
    /// `ResponseSink::prune_liveliness_get_interest` so the
    /// session-reconnect declaration cache drops the finished one-shot
    /// Interest (see the `finalized` field docs). Returns the staged ids
    /// by value, leaving the staging empty.
    pub fn take_finalized(&mut self) -> BoundedVec<u64, { caps::MAX_PENDING_LIVELINESS_GETS }> {
        core::mem::take(&mut self.finalized)
    }

    /// Register a pending get keyed by `interest_id`. Fresh ids come
    /// from
    /// [`crate::session_glue::SessionLinkActions::alloc_next_interest_id`],
    /// so a collision is a programming error rather than a runtime
    /// condition; a duplicate `interest_id` is rejected with `Ok(false)`
    /// (no-op). `deadline_ms` is the absolute monotonic-ms timeout
    /// snapshot (`None` = never expires). Returns `Ok(true)` on a fresh
    /// registration, `Err(TableFull)` when the pending table is at
    /// [`caps::MAX_PENDING_LIVELINESS_GETS`] (fail-fast on the no-alloc
    /// backing; never returned on the `alloc` backing).
    pub fn register(
        &mut self,
        interest_id: u64,
        deadline_ms: Option<u64>,
        sink: C,
    ) -> Result<bool, RegisterError> {
        if self.pending.iter().any(|p| p.interest_id == interest_id) {
            return Ok(false);
        }
        self.pending
            .push(PendingGet {
                interest_id,
                sink,
                deadline_ms,
            })
            .map_err(|_| RegisterError::TableFull)?;
        Ok(true)
    }

    /// Remove a pending get by `interest_id` without firing `on_final`.
    /// Returns `true` when an entry was removed, `false` when none
    /// matched (idempotent). Used by the RAII / explicit-cancel path
    /// when the application drops the get handle before the snapshot
    /// completes.
    pub fn unregister(&mut self, interest_id: u64) -> bool {
        let before = self.pending.len();
        self.pending.retain(|p| p.interest_id != interest_id);
        before != self.pending.len()
    }

    /// Number of currently-outstanding pending gets.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether the registry holds any pending get.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// no-heap fire entry: deliver one alive-token reply to the pending
    /// get whose `interest_id` matches. The reply is synthesised as a
    /// [`ReplyKind::Put`] [`BorrowedReply`] whose `rid` is the
    /// `interest_id` (the correlation id the get caller holds) and whose
    /// keyexpr is the resolved token keyexpr — a liveliness reply is
    /// "this keyexpr is currently alive", so it carries no payload. The
    /// pending entry stays in the table; only a `DeclFinal`
    /// ([`Self::dispatch_final`]) or a timeout ([`Self::sweep_timed_out`])
    /// removes it. Borrow-driven (the caller supplies the resolved
    /// keyexpr), so it is the MCU no-heap reply path; the `alloc` wire
    /// path ([`dispatch_declare`](Self::dispatch_declare)) resolves the
    /// keyexpr through the peer table and funnels through here. Returns
    /// the count of sinks fired (0 if no get matches, else 1).
    pub fn dispatch_reply_borrowed(&mut self, interest_id: u64, keyexpr: &str) -> usize {
        let reply = BorrowedReply {
            rid: interest_id,
            keyexpr,
            kind: ReplyKind::Put,
            payload: &[],
            err_encoding: None,
            // A liveliness reply carries no value side-bands (Put-token only).
            attachment: None,
            put_encoding: None,
        };
        let mut fired: usize = 0;
        for pending in self.pending.iter_mut() {
            if pending.interest_id == interest_id {
                pending.sink.on_reply(&reply);
                fired = fired.saturating_add(1);
            }
        }
        fired
    }

    /// no-heap fire entry: signal the terminating `Declare(DeclFinal)`
    /// for `interest_id`. Fires the matching get's `on_final` once and
    /// removes the pending entry. Returns `true` when a pending get was
    /// terminated, `false` for an unknown id (the peer may emit a
    /// `DeclFinal` for an id whose get was already cancelled locally —
    /// dropping it silently is correct). Mirrors
    /// [`crate::reply::ReplyRegistry::deliver_local_final`]'s
    /// fire-then-remove contract; a liveliness get expects exactly one
    /// terminator (one CURRENT Interest to one peer), so there is no
    /// `remaining_finals` counter.
    pub fn dispatch_final(&mut self, interest_id: u64) -> bool {
        self.fire_final_for(interest_id)
    }

    /// Fire [`ReplySink::on_timeout`] + drop every pending get whose
    /// `deadline_ms` is at or before `now_ms`. Returns the number of gets swept
    /// (zero in the common case where nothing has timed out). Entries with
    /// `deadline_ms == None` never expire. `now_ms` is caller-supplied
    /// (typically `clock.now_monotonic_ms()`) so the test surface stays
    /// deterministic.
    ///
    /// Mirror of [`crate::reply::ReplyRegistry::sweep_timed_out`], including
    /// R311y323's reversal of the opaque-cause pick the two registries shared.
    /// This doc read "the fired `on_final` carries the entry's `interest_id`
    /// only, so a callback cannot distinguish 'timed out' from a normal
    /// terminator". It can now: an expired get announces itself with a synthetic
    /// `Err("Timeout")` before its final. zenoh does the same for a liveliness
    /// query off its own `liveliness_queries` table (api/session.rs) — this leg
    /// is upstream parity, not a z_get nicety spilling over.
    ///
    /// It takes `on_timeout`'s DEFAULT (synthesize, then final), which is the
    /// faithful shape here: a liveliness get has no consolidation, so there is
    /// no cache to flush first — exactly why zenoh's liveliness timeout arm has
    /// no flush while its z_get arm does.
    /// When the earliest pending snapshot get is due, or `None` when no pending
    /// entry carries a deadline.
    ///
    /// The wake-arm companion to [`Self::sweep_timed_out`], and the exact mirror
    /// of `ReplyRegistry::next_deadline_ms`. A sweep only runs when something
    /// calls it, so a registry with a deadline and no wake is a registry whose
    /// deadline is decorative — which is what this plane was under the C ABI
    /// until R311y533: `z_liveliness_get` armed a 10 s default and the host had
    /// no way to ask when to come back, so a peer that never sent `DeclFinal`
    /// left the C caller blocked in `z_recv` indefinitely.
    ///
    /// Entries with `deadline_ms == None` are skipped, exactly as the sweep
    /// skips them: they impose no wake. `O(n)` over a table bounded by
    /// [`caps::MAX_PENDING_LIVELINESS_GETS`], read once per wake-arm.
    pub fn next_deadline_ms(&self) -> Option<u64> {
        self.pending
            .iter()
            .filter_map(|entry| entry.deadline_ms)
            .min()
    }

    pub fn sweep_timed_out(&mut self, now_ms: u64) -> usize {
        // R311ig — no-alloc drain-partition via the shared
        // `BoundedVec::drain_partition` seam (mirror of
        // ReplyRegistry::sweep_timed_out): extract the expired entries, then
        // fire after the borrow releases so a panicking `on_final` cannot
        // leave half-swept entries behind.
        let fired = self
            .pending
            .drain_partition(|entry| matches!(entry.deadline_ms, Some(d) if d <= now_ms));
        let swept = fired.len();
        for mut entry in fired {
            let id = entry.interest_id;
            // F3/R311ka — a timed-out get is as terminated as a
            // DeclFinal'd one: stage it for the reconnect-cache prune
            // drain. The sweep CALLER must drain (`take_finalized` ->
            // `prune_liveliness_get_interest`) in the same lock window —
            // see `fire_final_for` for the airtight-capacity contract.
            let staged = self.finalized.push(id);
            debug_assert!(
                staged.is_ok(),
                "finalized staging overflow: sweep caller is not draining \
                 within its lock window (permanent replay-leak hazard)"
            );
            // R311y323 — `on_timeout`, NOT a bare `on_final`, mirroring
            // `ReplyRegistry::sweep_timed_out`. zenoh synthesizes the SAME
            // `Err(ReplyError::new("Timeout", ..))` for an expired LIVELINESS
            // query as for an expired z_get — its `liveliness_queries` table has
            // its own timeout task doing exactly that (`api/session.rs`). Two
            // registries, one contract: an expired get says so.
            //
            // This leg takes `ReplySink::on_timeout`'s DEFAULT (synthesize, then
            // final) and that is the faithful shape here, not a shortcut: a
            // liveliness get has no consolidation, so there is no cache to flush
            // first — which is why zenoh's liveliness timeout arm has no flush
            // either, while its z_get arm does.
            entry.sink.on_timeout(id);
        }
        swept
    }

    /// Shared final fan body: take ownership of the (at most one) pending
    /// entry matching `interest_id`, leave the rest, then fire `on_final`
    /// after the partition releases the `&mut self.pending` borrow.
    /// Returns `true` when an entry was fired + removed. Order-preserving
    /// (a `BoundedVec` partition) though only a single entry can match a
    /// fresh-allocated id.
    fn fire_final_for(&mut self, interest_id: u64) -> bool {
        // R311ig — no-alloc drain-partition via the shared
        // `BoundedVec::drain_partition` seam (see `sweep_timed_out`).
        let fired = self
            .pending
            .drain_partition(|entry| entry.interest_id == interest_id);
        let any = !fired.is_empty();
        for mut entry in fired {
            let id = entry.interest_id;
            // F3/R311ka — stage the terminated id for the reconnect-cache
            // prune drain. This drain is the cache entry's ONLY prune (a
            // get never emits an interest-FINAL), so a dropped marker
            // would be a permanent replay-leak — the capacity argument
            // must therefore be airtight, not best-effort: every staging
            // site drains within its own lock window (the dispatch path
            // through `flush_pending` in the same `observer.dispatch`
            // call; the sweep path at its caller, right after
            // `sweep_timed_out`), so one staged batch is bounded by the
            // pending table the ids came from, and `finalized` shares
            // that table's capacity. The debug_assert pins the invariant.
            let staged = self.finalized.push(id);
            debug_assert!(
                staged.is_ok(),
                "finalized staging overflow: a staging site is not draining \
                 within its lock window (permanent replay-leak hazard)"
            );
            entry.sink.on_final(id);
        }
        any
    }

    /// `alloc`-gated inbound-parse path: route an inbound `Declare`
    /// envelope through the pending table. Only a Declare carrying an
    /// outer `interest_id` is a solicited reply to one of our gets; an
    /// unsolicited token declaration (`interest_id == None`) is dropped
    /// (it is the observer / subscriber registries' concern). A
    /// `DeclToken` fires the matching get's `on_reply` with the resolved
    /// keyexpr; a `DeclFinal` fires `on_final` + removes the get. A
    /// `DeclToken` whose keyexpr references an undeclared peer mapping
    /// drops silently (mirror of the sibling registries' "no resolved
    /// keyexpr → no fire" contract). Other inner variants are ignored.
    #[cfg(feature = "alloc")]
    pub fn dispatch_declare<'a>(
        &mut self,
        declare: &DeclareOwned,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        let interest_id = match declare.interest_id {
            Some(id) => id,
            // Unsolicited (proactive) declaration — not a get reply.
            None => return,
        };
        match &declare.body {
            DeclareOwnedVariant::CodecZenohDeclToken(decl) => {
                let resolved = match resolve_wireexpr_in(&decl.keyexpr.body, peer_keyexpr_table) {
                    Some(s) => s,
                    None => return,
                };
                self.dispatch_reply_borrowed(interest_id, &resolved);
            }
            DeclareOwnedVariant::CodecZenohDeclFinal(_) => {
                self.fire_final_for(interest_id);
            }
            // Other Declare sub-variants are not the liveliness-get
            // requester's concern.
            _ => {}
        }
    }

    /// Drain a `&[NetworkMessage]` through [`Self::dispatch_declare`] for
    /// every `Declare` arm. Mirror of the sibling registries'
    /// `dispatch_messages`; `alloc`-gated (consumes owned messages +
    /// resolves keyexprs). Non-`Declare` variants are no-ops here — the
    /// liveliness-get reply path lives entirely in the `Declare` MID.
    #[cfg(feature = "alloc")]
    pub fn dispatch_messages<'a>(
        &mut self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        for message in messages {
            if let NetworkMessage::Declare(declare) = message {
                self.dispatch_declare(declare, peer_keyexpr_table);
            }
        }
    }

    /// [`IterationEvent`] adapter; mirror of the sibling registries.
    /// Routes `FramePayload` events through [`Self::dispatch_messages`];
    /// other variants (Lease branch, non-poll outcomes) are no-ops.
    /// `alloc`-gated (consumes owned messages).
    #[cfg(feature = "alloc")]
    pub fn dispatch_iteration_event<'a>(
        &mut self,
        event: IterationEvent<'_>,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event {
            self.dispatch_messages(messages, peer_keyexpr_table);
        }
    }
}

/// AP / `alloc`-profile convenience surface (the `BoxedReplySink`
/// instantiation only). The no-`alloc` profile uses
/// [`with_sink_backing`](LivelinessGetRegistry::with_sink_backing) + a
/// consumer-supplied sink.
#[cfg(feature = "alloc")]
impl LivelinessGetRegistry<BoxedReplySink> {
    /// New empty AP registry backed by heap-boxed closures. Inferring
    /// shorthand for
    /// [`with_sink_backing`](LivelinessGetRegistry::with_sink_backing):
    /// fixes `C = BoxedReplySink`.
    pub fn new() -> Self {
        Self::with_sink_backing()
    }

    /// Register a pending get from the `on_reply` + `on_final` capturing
    /// closures (the dynamic-opt-in AP surface). Wraps them in a
    /// [`BoxedReplySink`] and funnels through
    /// [`register`](LivelinessGetRegistry::register); on the `alloc`
    /// backing the table never overflows, so the `TableFull` arm is
    /// unreachable and the result is `Ok(true)` for a fresh id /
    /// `Ok(false)` for a duplicate.
    pub fn register_get(
        &mut self,
        interest_id: u64,
        deadline_ms: Option<u64>,
        on_reply: impl FnMut(&dyn crate::reply_sink::ReplyView) + Send + 'static,
        on_final: impl FnMut(u64) + Send + 'static,
    ) -> Result<bool, RegisterError> {
        self.register(
            interest_id,
            deadline_ms,
            BoxedReplySink::new(on_reply, on_final),
        )
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    //! Behavioural tests for `LivelinessGetRegistry`. `Arc<Mutex<…>>`
    //! capture cells use `std` under `#[cfg(test)]` per the wz-codecs
    //! sibling-crate convention; the production artifact stays no_std.

    use super::*;
    use alloc::string::{String, ToString};
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use hashbrown::HashMap;
    use wz_session_core_test_support::*;

    use crate::reply_sink::ReplyView;

    type Captured = Arc<Mutex<Vec<(u64, String)>>>;

    fn make_get(replies: Captured, finals: Arc<Mutex<Vec<u64>>>) -> BoxedReplySink {
        let replies_cb = replies;
        let finals_cb = finals;
        BoxedReplySink::new(
            move |reply: &dyn ReplyView| {
                replies_cb
                    .lock()
                    .unwrap()
                    .push((reply.rid(), reply.keyexpr().to_string()));
            },
            move |id: u64| {
                finals_cb.lock().unwrap().push(id);
            },
        )
    }

    #[test]
    fn new_registry_starts_empty() {
        let reg = LivelinessGetRegistry::new();
        assert_eq!(reg.len(), 0);
        assert!(reg.is_empty());
    }

    #[test]
    fn register_then_unregister_clears_pending() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        assert!(reg
            .register(7, None, make_get(r.clone(), f.clone()))
            .unwrap());
        assert_eq!(reg.len(), 1);
        assert!(reg.unregister(7));
        assert_eq!(reg.len(), 0);
        assert!(!reg.unregister(7), "double-unregister is idempotent");
    }

    /// R311y740 (N37) — the own-space WITNESS for the liveliness-GET reply
    /// plane. This registry ingests a SOLICITED `Declare(DeclToken)`
    /// correlated by `interest_id`, so it is a separate entry point from the
    /// declarer / subscriber planes even though the record type is shared.
    ///
    /// THE DISCRIMINATOR is the collision: id 7 is in BOTH spaces under
    /// different literals, so a wrong-space read delivers a confident wrong
    /// keyexpr to the requester rather than dropping the reply.
    #[cfg(feature = "alloc")]
    #[test]
    fn an_own_space_alias_resolves_in_our_space_on_the_liveliness_get_plane() {
        let mut reg = LivelinessGetRegistry::new();
        let replies: Captured = Arc::new(Mutex::new(Vec::new()));
        let finals: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(9, None, make_get(replies.clone(), finals.clone()))
            .unwrap();

        let mut peer = HashMap::new();
        peer.insert(7u64, "theirs/token".to_string());
        let mut own = HashMap::new();
        own.insert(7u64, "ours/token".to_string());

        let declare = declare_envelope_decl_token_with_interest(decl_token_nonlocal(1, 7, None), 9);
        reg.dispatch_declare(&declare, MappingSpaces::with_own(&peer, &own));

        assert_eq!(
            *replies.lock().unwrap(),
            vec![(9u64, "ours/token".to_string())],
            "an M=0 alias names OUR space; reading the peer's would have \
             delivered `theirs/token` to the requester",
        );
    }

    /// ANTI-VACUITY twin: with only the peer's space the same reply refuses.
    #[cfg(feature = "alloc")]
    #[test]
    fn without_an_own_space_the_liveliness_get_plane_refuses_the_same_alias() {
        let mut reg = LivelinessGetRegistry::new();
        let replies: Captured = Arc::new(Mutex::new(Vec::new()));
        let finals: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(9, None, make_get(replies.clone(), finals.clone()))
            .unwrap();

        let mut peer = HashMap::new();
        peer.insert(7u64, "theirs/token".to_string());

        let declare = declare_envelope_decl_token_with_interest(decl_token_nonlocal(1, 7, None), 9);
        reg.dispatch_declare(&declare, &peer);

        assert!(
            replies.lock().unwrap().is_empty(),
            "with no own space an M=0 alias must refuse -- never fall back to \
             the peer's table",
        );
    }

    #[test]
    fn duplicate_register_rejected() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        assert!(reg
            .register(7, None, make_get(r.clone(), f.clone()))
            .unwrap());
        assert!(
            !reg.register(7, None, make_get(r.clone(), f.clone()))
                .unwrap(),
            "second register on same interest_id must reject"
        );
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn decl_token_reply_fires_on_reply_with_interest_id_as_rid() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(42, None, make_get(r.clone(), f.clone()))
            .unwrap();

        // Solicited reply: outer Declare carries interest_id=42.
        let declare = declare_envelope_decl_token_with_interest(
            decl_token(11, 0, Some("liveliness/dev11")),
            42,
        );
        reg.dispatch_declare(&declare, &HashMap::new());

        let got = r.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, 42, "rid echoes the get's interest_id");
        assert_eq!(got[0].1, "liveliness/dev11");
        assert!(f.lock().unwrap().is_empty(), "no final yet");
        assert_eq!(reg.len(), 1, "pending entry retained until DeclFinal");
    }

    #[test]
    fn decl_final_fires_on_final_and_removes_pending() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(42, None, make_get(r.clone(), f.clone()))
            .unwrap();

        let token = declare_envelope_decl_token_with_interest(
            decl_token(11, 0, Some("liveliness/dev11")),
            42,
        );
        let fin = declare_envelope_decl_final_with_interest(42);
        reg.dispatch_messages(
            &[
                NetworkMessage::Declare(alloc::boxed::Box::new(token)),
                NetworkMessage::Declare(alloc::boxed::Box::new(fin)),
            ],
            &HashMap::new(),
        );

        assert_eq!(r.lock().unwrap().len(), 1, "one alive token");
        assert_eq!(*f.lock().unwrap(), vec![42], "final fired once");
        assert_eq!(reg.len(), 0, "DeclFinal removes the pending get");
    }

    #[test]
    fn unsolicited_token_without_interest_id_is_ignored() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(42, None, make_get(r.clone(), f.clone()))
            .unwrap();

        // Proactive declaration: no outer interest_id (the un-tagged
        // envelope helper sets interest_id = None). Must not route here
        // (the observer / subscriber registries own it).
        let declare = declare_envelope_decl_token(decl_token(11, 0, Some("liveliness/dev11")));
        reg.dispatch_declare(&declare, &HashMap::new());

        assert!(
            r.lock().unwrap().is_empty(),
            "unsolicited token (interest_id=None) must not fire a get reply"
        );
        assert_eq!(reg.len(), 1, "pending get untouched");
    }

    #[test]
    fn reply_for_unknown_interest_id_fires_nothing() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(42, None, make_get(r.clone(), f.clone()))
            .unwrap();

        let declare = declare_envelope_decl_token_with_interest(
            decl_token(11, 0, Some("liveliness/dev11")),
            99, // no pending get with id 99
        );
        reg.dispatch_declare(&declare, &HashMap::new());
        assert!(r.lock().unwrap().is_empty());
        assert!(!reg.dispatch_final(99), "unknown final id removes nothing");
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn unresolvable_mapping_id_drops_reply() {
        let mut reg = LivelinessGetRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_cb = fired.clone();
        reg.register(
            42,
            None,
            BoxedReplySink::new(
                move |_r: &dyn ReplyView| {
                    fired_cb.fetch_add(1, Ordering::SeqCst);
                },
                |_| {},
            ),
        )
        .unwrap();

        // mapping_id=55 with no peer-keyexpr table entry → resolve None.
        let declare = declare_envelope_decl_token_with_interest(decl_token(11, 55, None), 42);
        reg.dispatch_declare(&declare, &HashMap::new());
        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "unresolvable keyexpr drops"
        );
    }

    #[test]
    fn aliased_keyexpr_resolves_through_peer_table() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(42, None, make_get(r.clone(), f.clone()))
            .unwrap();

        let mut table = HashMap::new();
        table.insert(10u64, "liveliness".to_string());
        let declare =
            declare_envelope_decl_token_with_interest(decl_token(99, 10, Some("/dev42")), 42);
        reg.dispatch_declare(&declare, &table);

        let got = r.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, "liveliness/dev42");
    }

    #[test]
    fn sweep_times_out_pending_get() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(42, Some(1000), make_get(r.clone(), f.clone()))
            .unwrap();
        reg.register(43, None, make_get(r.clone(), f.clone()))
            .unwrap();

        assert_eq!(reg.sweep_timed_out(999), 0, "before deadline: nothing");
        assert_eq!(reg.sweep_timed_out(1000), 1, "at deadline: id 42 swept");
        assert_eq!(*f.lock().unwrap(), vec![42], "swept get fires on_final");
        assert_eq!(reg.len(), 1, "never-expiring get 43 retained");
        assert_eq!(reg.sweep_timed_out(5000), 0, "idempotent; 43 never expires");
    }

    /// R311y323 — the SIBLING leg. zenoh synthesizes the same
    /// `Err(ReplyError::new("Timeout", ..))` for an expired LIVELINESS query as
    /// for an expired z_get: its `liveliness_queries` table has its own timeout
    /// task doing exactly that. Two registries, one contract.
    ///
    /// Why this test and not just `sweep_times_out_pending_get` above: that one
    /// asserts only `on_final`, so it stayed GREEN through the whole y323 change
    /// and would stay green if this leg were reverted. A sibling that cannot
    /// fail is not coverage — the same shape as the y321 Err bug.
    ///
    /// This leg takes `ReplySink::on_timeout`'s DEFAULT, and that is faithful:
    /// a liveliness get has no consolidation, so there is no cache to flush
    /// first — which is why zenoh's liveliness timeout arm has no flush either
    /// while its z_get arm does.
    #[test]
    fn sweep_synthesizes_the_timeout_error_on_the_liveliness_leg() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(42, Some(1000), make_get(r.clone(), f.clone()))
            .unwrap();

        assert_eq!(reg.sweep_timed_out(1500), 1);
        assert_eq!(
            *r.lock().unwrap(),
            vec![(42, String::new())],
            "an expired liveliness get must announce itself with a synthetic \
             reply carrying its id and no keyexpr, exactly as the z_get leg does"
        );
        assert_eq!(*f.lock().unwrap(), vec![42], "the final still fires, after");
    }

    #[test]
    fn no_codec_borrowed_path_fires_reply_and_final() {
        // MCU no-heap path: register + fire without any codec / Declare.
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(7, None, make_get(r.clone(), f.clone()))
            .unwrap();

        assert_eq!(reg.dispatch_reply_borrowed(7, "live/a"), 1);
        assert_eq!(reg.dispatch_reply_borrowed(7, "live/b"), 1);
        assert_eq!(reg.dispatch_reply_borrowed(8, "live/c"), 0, "no get id 8");
        assert!(reg.dispatch_final(7));

        let got = r.lock().unwrap().clone();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].1, "live/a");
        assert_eq!(got[1].1, "live/b");
        assert_eq!(*f.lock().unwrap(), vec![7]);
        assert_eq!(reg.len(), 0);
    }

    /// F3 — every termination path (DeclFinal + timeout sweep) stages the
    /// interest id for the reconnect-cache prune drain; `take_finalized`
    /// returns the staged ids and empties the staging. Replies and
    /// unknown-id finals stage nothing.
    #[test]
    fn terminations_stage_finalized_ids_for_prune_drain() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(7, None, make_get(r.clone(), f.clone()))
            .unwrap();
        reg.register(8, Some(1000), make_get(r.clone(), f.clone()))
            .unwrap();

        // A reply is not a termination: nothing staged.
        assert_eq!(reg.dispatch_reply_borrowed(7, "live/a"), 1);
        assert!(reg.take_finalized().is_empty());

        // DeclFinal terminates get 7; an unknown id stages nothing.
        assert!(reg.dispatch_final(7));
        assert!(!reg.dispatch_final(99));
        let staged: Vec<u64> = reg.take_finalized().into_iter().collect();
        assert_eq!(staged, vec![7]);
        assert!(
            reg.take_finalized().is_empty(),
            "take_finalized drains the staging"
        );

        // A timeout sweep is as terminal as a DeclFinal.
        assert_eq!(reg.sweep_timed_out(1000), 1);
        let staged: Vec<u64> = reg.take_finalized().into_iter().collect();
        assert_eq!(staged, vec![8]);
    }
}
