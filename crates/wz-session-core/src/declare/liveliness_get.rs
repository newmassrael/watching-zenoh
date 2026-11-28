// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
//! the response-plane [`crate::reply_sink::ReplySink`] / [`crate::reply_sink::ReplyView`]
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
//! | [`crate::declare::liveliness::LivelinessRegistry`] | observe EVERY peer `Decl*Token`         | none (callback)    |
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
//!    [`crate::bounded::BoundedVec`] of `PendingGet` rows; the
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

use crate::bounded::{BoundedVec, Profile, Storage};
use crate::caps;
use crate::registry_error::RegisterError;
use crate::reply_sink::{BorrowedReply, ReplyKind, ReplySink};

#[cfg(feature = "alloc")]
pub use crate::reply_sink::BoxedReplySink;

// R311y739 -- `String` / `HashMap` were here for the wire-dispatch params
// alone, which now take `impl Into<MappingSpaces>`. The suite below imports
// both for itself.

#[cfg(feature = "alloc")]
use crate::transport_profile::owned::{DeclareOwned, DeclareOwnedVariant};

#[cfg(feature = "alloc")]
use crate::driver_loop::DriverLoopOutcome;
#[cfg(feature = "storage-profile")]
use crate::driver_loop::IterationEvent;
#[cfg(feature = "alloc")]
use crate::network_message::NetworkMessage;
#[cfg(feature = "alloc")]
use crate::wireexpr_resolve::resolve_wireexpr_in;
#[cfg(feature = "storage-profile")]
use crate::wireexpr_resolve::MappingSpaces;

/// The reply a pending liveliness get is handed for an alive token at `keyexpr` answering
/// `interest_id`: a Put whose request id is the interest id the get holds, carrying no value, a
/// token saying only that its key is alive.
pub fn token_reply(interest_id: u64, keyexpr: &str) -> BorrowedReply<'_> {
    BorrowedReply {
        rid: crate::wire_id::interest_id_as_read(interest_id),
        keyexpr,
        kind: ReplyKind::Put,
        payload: &[],
        err_encoding: None,
        // A liveliness reply carries no value side-bands (Put-token only).
        attachment: None,
        put_encoding: None,
    }
}

/// The pending snapshot `declare`, a record of a frame the copying receive decoded, ends: the
/// interest id of a DeclFinal answering an Interest, `None` for any other declaration.
#[cfg(feature = "alloc")]
pub fn snapshot_final(declare: &DeclareOwned) -> Option<u64> {
    match (declare.interest_id, &declare.body) {
        (Some(interest_id), DeclareOwnedVariant::CodecZenohDeclFinal(_)) => Some(interest_id),
        _ => None,
    }
}

/// [`snapshot_final`] for a `Declare` the in-place receive path lends.
#[cfg(all(
    feature = "storage-profile",
    feature = "codec-declare",
    feature = "rx-lent-control"
))]
pub fn snapshot_final_view(declare: &wz_codecs::lent::Declare<'_>) -> Option<u64> {
    match (declare.interest_id, &declare.body) {
        (Some(interest_id), wz_codecs::lent::DeclareVariant::CodecZenohDeclFinal(_)) => {
            Some(interest_id)
        }
        _ => None,
    }
}

/// The alive token `declare`, a record of a frame the copying receive decoded, answers with the
/// pending snapshot its interest id names, for a caller that keeps its snapshots itself and says
/// which ids are pending (`pending`): its key, resolved over `peer_keyexpr_table`, written into
/// `room`, and that interest id. `None` for a declaration that answers no pending snapshot or is
/// no token, and for one whose key does not resolve or does not fit `room`, which the second
/// counts in `oversize`.
#[cfg(feature = "alloc")]
pub fn claim_answering_token<'a, PS: Storage, OS: Storage>(
    declare: &DeclareOwned,
    pending: impl FnOnce(u64) -> bool,
    peer_keyexpr_table: impl Into<MappingSpaces<'a, PS, OS>>,
    room: &mut dyn crate::wireexpr_resolve::KeyexprOut,
    oversize: &mut u32,
) -> Option<u64> {
    let interest_id = declare.interest_id.filter(|&id| pending(id))?;
    let DeclareOwnedVariant::CodecZenohDeclToken(decl) = &declare.body else {
        return None;
    };
    let resolved = resolve_wireexpr_in(&decl.keyexpr.body, peer_keyexpr_table.into())?;
    claim_into(interest_id, &resolved, room, oversize)
}

/// [`claim_answering_token`] for a `Declare` the in-place receive path lends, its key composed
/// where its frame lies, so the claim takes no heap.
#[cfg(all(
    feature = "storage-profile",
    feature = "codec-declare",
    feature = "rx-lent-control"
))]
pub fn claim_answering_token_view<'a, 'f, PS: Storage, OS: Storage>(
    declare: &wz_codecs::lent::Declare<'f>,
    pending: impl FnOnce(u64) -> bool,
    peer_keyexpr_table: impl Into<MappingSpaces<'a, PS, OS>>,
    room: &mut dyn crate::wireexpr_resolve::KeyexprOut,
    oversize: &mut u32,
) -> Option<u64> {
    use wz_codecs::lent::DeclareVariant;
    let interest_id = declare.interest_id.filter(|&id| pending(id))?;
    let DeclareVariant::CodecZenohDeclToken(decl) = &declare.body else {
        return None;
    };
    let mut composed = crate::wireexpr_resolve::KeyexprRow::new_static();
    let resolved = match crate::wireexpr_resolve::resolve_wireexpr_view(
        &decl.keyexpr.body,
        peer_keyexpr_table.into(),
        &mut composed,
    ) {
        Ok(resolved) => resolved?,
        Err(_) => {
            *oversize = oversize.saturating_add(1);
            return None;
        }
    };
    claim_into(interest_id, resolved, room, oversize)
}

/// `keyexpr`, the key of an alive token answering the pending snapshot `interest_id`, written
/// into `room`, where the caller reads it while the frame it was read off is let go of; `None`,
/// counted in `oversize`, for a key past `room`. The caller picks the room's policy: one of the
/// static policy (`KeyexprRow`) takes no heap whatever the build's profile.
#[cfg(any(
    feature = "alloc",
    all(
        feature = "storage-profile",
        feature = "codec-declare",
        feature = "rx-lent-control"
    )
))]
fn claim_into(
    interest_id: u64,
    keyexpr: &str,
    room: &mut dyn crate::wireexpr_resolve::KeyexprOut,
    oversize: &mut u32,
) -> Option<u64> {
    room.clear();
    if room.push_str(keyexpr).is_err() {
        *oversize = oversize.saturating_add(1);
        return None;
    }
    Some(interest_id)
}

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
///
/// The storage policy `P` is the build's [`Profile`] unless a caller names another;
/// the pending table and the finalized markers are [`BoundedVec`]s of that policy.
pub struct LivelinessGetRegistry<C: ReplySink, P: Storage = Profile> {
    pending: BoundedVec<PendingGet<C>, { caps::MAX_PENDING_LIVELINESS_GETS }, P>,
    /// The earliest deadline of a pending get ([`Self::due_ms`]), `u64::MAX` with none: lowered as
    /// a get with a deadline is registered, and worked out again only when the get that leaves
    /// the table held it, so a holder reads it without a walk of the gets.
    due_ms: u64,
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
    finalized: BoundedVec<u64, { caps::MAX_PENDING_LIVELINESS_GETS }, P>,
    /// The most gets the registry holds pending (`MAX_PENDING_LIVELINESS_GETS`): what the
    /// creator of the registry resolved ([`Self::limit_to`]), the build's value until it does. A
    /// growable table refuses nothing by its storage, so this is what bounds it; where the build
    /// fixes the bound to the storage's capacity it is held in no byte and the storage refuses
    /// alone.
    quota: crate::limits::MaxPendingLivelinessGetsHeld,
    /// How many token replies were NOT delivered because their keyexpr is longer
    /// than the bounded buffer the slot profile's receive path resolves into
    /// ([`Self::oversize`]). Stays zero on every build that reads the owned
    /// message, whose keyexpr is a `String`.
    oversize: u32,
}

impl<C: ReplySink, P: Storage> Default for LivelinessGetRegistry<C, P> {
    fn default() -> Self {
        Self {
            pending: BoundedVec::default(),
            due_ms: u64::MAX,
            finalized: BoundedVec::default(),
            quota: Default::default(),
            oversize: 0,
        }
    }
}

impl<C: ReplySink> LivelinessGetRegistry<C, Profile> {
    /// New empty registry over an explicit sink backing `C` (the
    /// no-`alloc` / MCU entry point, paired with
    /// [`register`](Self::register)). AP callers use the inferring
    /// [`new`](LivelinessGetRegistry::new) shorthand, which fixes
    /// `C = BoxedReplySink`.
    pub fn with_sink_backing() -> Self {
        Self::default()
    }
}

#[cfg(feature = "alloc")]
impl<C: ReplySink> LivelinessGetRegistry<C, crate::bounded::OnUse> {
    /// An empty registry of at most `rows` pending gets and as many markers they leave when they
    /// end, under `MAX_PENDING_LIVELINESS_GETS`, each table taken at its first row: the snapshots a
    /// session holds pending on one face, at its open.
    pub fn counted(rows: usize) -> Self {
        Self {
            pending: BoundedVec::counted(rows),
            finalized: BoundedVec::counted(rows),
            ..Self::default()
        }
    }
}

/// The rows of a [`LivelinessGetRegistry`] of the region policy, which a region lays out beside
/// it: its pending gets' and the markers they leave, each at the build's bound.
pub struct LivelinessGetRows<C: ReplySink> {
    pending: [core::mem::MaybeUninit<PendingGet<C>>; caps::MAX_PENDING_LIVELINESS_GETS],
    finalized: [core::mem::MaybeUninit<u64>; caps::MAX_PENDING_LIVELINESS_GETS],
}

// SAFETY: both tables' rows are `MaybeUninit`, valid as any bytes, holding no value until placed.
unsafe impl<C: ReplySink> crate::bounded::ZeroEmpty for LivelinessGetRows<C> {}

/// The lines a description holds for one [`LivelinessGetRegistry`]: its two tables' rows.
pub const LIVELINESS_GET_LINES: usize = 2;

impl<C: ReplySink, P: crate::bounded::LaidOut> LivelinessGetRegistry<C, P> {
    /// The description of a registry at `at` and, in a region, its [`LivelinessGetRows`] at `rows`:
    /// the lines of its pending gets' rows and of their markers', each lent a face's
    /// `MAX_PENDING_LIVELINESS_GETS`.
    pub const fn places(
        at: usize,
        rows: usize,
    ) -> crate::bounded::RegionLines<LIVELINESS_GET_LINES> {
        crate::bounded::RegionLines::EMPTY
            .seq(
                crate::bounded::SeqPlace::of_room::<
                    PendingGet<C>,
                    { caps::MAX_PENDING_LIVELINESS_GETS },
                >(
                    at.wrapping_add(core::mem::offset_of!(Self, pending)),
                    rows.wrapping_add(core::mem::offset_of!(LivelinessGetRows<C>, pending)),
                )
                .counted(crate::bounded::RowCount::LivelinessGets),
            )
            .seq(
                crate::bounded::SeqPlace::of_room::<u64, { caps::MAX_PENDING_LIVELINESS_GETS }>(
                    at.wrapping_add(core::mem::offset_of!(Self, finalized)),
                    rows.wrapping_add(core::mem::offset_of!(LivelinessGetRows<C>, finalized)),
                )
                .counted(crate::bounded::RowCount::LivelinessGets),
            )
    }
}

impl<C: ReplySink, P: Storage> LivelinessGetRegistry<C, P> {
    /// The bytes one pending get takes in the registry's storage: its row, and the marker it leaves
    /// in the finalized ids when it ends, which the same count bounds.
    pub const ROW_BYTES: usize =
        core::mem::size_of::<PendingGet<C>>() + core::mem::size_of::<u64>();

    /// Hold the registry to the `MAX_PENDING_LIVELINESS_GETS` its creator resolved: a
    /// registration that would leave more gets pending than `quota` admits is refused
    /// ([`RegisterError::TableFull`]), and the gets already pending are kept, as a lowered soft
    /// limit keeps what it holds.
    pub fn limit_to(&mut self, quota: crate::limits::MaxPendingLivelinessGetsHeld) {
        self.quota = quota;
    }

    /// How many token replies were refused for a keyexpr past the bounded buffer
    /// ([`crate::wireexpr_resolve::KeyexprBuf`]) and so not delivered. Only the slot
    /// profile's receive path, which resolves into that buffer, can refuse; a
    /// refusal is counted, never a truncated keyexpr delivered.
    pub fn oversize(&self) -> u32 {
        self.oversize
    }

    /// F3 — drain the interest ids whose gets terminated since the last
    /// call (inbound `DeclFinal` or timeout sweep). The caller routes
    /// each through
    /// `ResponseSink::prune_liveliness_get_interest` so the
    /// session-reconnect declaration cache drops the finished one-shot
    /// Interest (see the `finalized` field docs). Returns the staged ids
    /// by value, leaving the staging empty and keeping its storage: a table lent its rows at open
    /// has no others to be given, so the ids are copied out into a working buffer of the policy's
    /// scratch and the staging is cleared in place.
    pub fn take_finalized(
        &mut self,
    ) -> BoundedVec<u64, { caps::MAX_PENDING_LIVELINESS_GETS }, P::Scratch> {
        let mut taken = BoundedVec::default();
        for &interest_id in self.finalized.iter() {
            // The staging and the buffer share one ceiling, so every id fits.
            let kept = taken.push(interest_id).is_ok();
            debug_assert!(kept, "a finalized id fits a buffer of the same ceiling");
        }
        self.finalized.clear();
        taken
    }

    /// Whether a terminated get is staged for [`Self::take_finalized`], asked without taking it.
    pub fn has_finalized(&self) -> bool {
        !self.finalized.is_empty()
    }

    /// Register a pending get keyed by `interest_id`. Fresh ids come
    /// from
    /// `crate::session_glue::SessionLinkActions::alloc_next_interest_id`,
    /// so a collision is a programming error rather than a runtime
    /// condition; a duplicate `interest_id` is rejected with `Ok(false)`
    /// (no-op). `deadline_ms` is the absolute monotonic-ms timeout
    /// snapshot (`None` = never expires). Returns `Ok(true)` on a fresh
    /// registration, `Err(TableFull)` when the pending table is at
    /// [`caps::MAX_PENDING_LIVELINESS_GETS`] (fail-fast on the fixed
    /// backing) or at the quota the creator stated ([`Self::limit_to`],
    /// on every backing).
    ///
    /// On the fixed backing a terminated get's `finalized` marker still
    /// occupies its slot until [`take_finalized`](Self::take_finalized)
    /// drains it, so the table is full when `pending + finalized` reaches
    /// the capacity. That keeps `pending.len() <= finalized.free_slots()`
    /// as an invariant of the TYPE rather than of every caller's draining
    /// discipline: each termination moves one entry from `pending` to
    /// `finalized`, so the marker push in `fire_final_for` /
    /// `sweep_timed_out` can never be the one refused (a refused marker
    /// would be a permanent replay leak). On the growable backing
    /// `free_slots` is unbounded and this check never refuses.
    pub fn register(
        &mut self,
        interest_id: u64,
        deadline_ms: Option<u64>,
        sink: C,
    ) -> Result<bool, RegisterError> {
        if self.pending.iter().any(|p| p.interest_id == interest_id) {
            return Ok(false);
        }
        if !self.has_room() {
            return Err(RegisterError::TableFull);
        }
        self.pending
            .push(PendingGet {
                interest_id,
                sink,
                deadline_ms,
            })
            .map_err(|_| RegisterError::TableFull)?;
        if let Some(deadline_ms) = deadline_ms {
            self.due_ms = self.due_ms.min(deadline_ms);
        }
        Ok(true)
    }

    /// Whether one more get may be held pending: inside the quota its creator stated, and with a
    /// marker row free for its final, which [`Self::register`] keeps for each get it holds. A
    /// caller asks before it makes what a registration would hold, so a get it cannot hold costs
    /// nothing.
    pub fn has_room(&self) -> bool {
        self.pending.len() < self.finalized.free_slots()
            && self.quota.admits(self.pending.len().saturating_add(1))
    }

    /// Drop every pending get and every staged marker without firing anything: what the loss of
    /// the face the gets were asked of does to them, each sink's drop being its end. The rows stay
    /// the tables'.
    pub fn clear(&mut self) {
        self.pending.clear();
        self.finalized.clear();
        self.due_ms = u64::MAX;
    }

    /// Remove a pending get by `interest_id` without firing `on_final`.
    /// Returns `true` when an entry was removed, `false` when none
    /// matched (idempotent). Used by the RAII / explicit-cancel path
    /// when the application drops the get handle before the snapshot
    /// completes.
    pub fn unregister(&mut self, interest_id: u64) -> bool {
        let before = self.pending.len();
        let due_ms = self.due_ms;
        let mut held_due = false;
        self.pending.retain(|p| {
            let keep = p.interest_id != interest_id;
            held_due |= !keep && p.deadline_ms == Some(due_ms);
            keep
        });
        if held_due {
            self.rearm_due();
        }
        before != self.pending.len()
    }

    /// Remove the first pending get whose sink `pick` names without firing `on_final`: what the
    /// cancellation of the get the sink is a leg of does to it, the sink's drop being the leg's end.
    /// Whether one was removed.
    pub fn unregister_first(&mut self, mut pick: impl FnMut(&C) -> bool) -> bool {
        let Some(at) = self.pending.iter().position(|entry| pick(&entry.sink)) else {
            return false;
        };
        if self.pending.remove(at).deadline_ms == Some(self.due_ms) {
            self.rearm_due();
        }
        true
    }

    /// Number of currently-outstanding pending gets.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether the registry holds any pending get.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Whether `interest_id` names a get this registry is still waiting on.
    ///
    /// THE ROUTING PREDICATE, and the reason it is public: zenoh decides who
    /// owns an inbound solicited `Declare(DeclToken)` by asking exactly this
    /// question of its `liveliness_queries` table, and answers the query and
    /// nothing else when it is `true` (`zenoh/src/api/session.rs:2609-2632` —
    /// the `return` is placed before the `remote_tokens` insert and before
    /// `execute_subscriber_callbacks`). wz's observer fans one message into
    /// every registry in sequence rather than running a chain of early
    /// returns, so the same rule is expressed as a filter the liveliness
    /// OBSERVER planes apply, reading this registry under a disjoint borrow.
    ///
    /// It is deliberately not `contains` or `is_pending`: what the caller
    /// needs to know is whether a GET has a CLAIM on the declare, and an entry
    /// that has already been finalized or swept no longer does.
    pub fn has_pending(&self, interest_id: u64) -> bool {
        self.pending.iter().any(|p| p.interest_id == interest_id)
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
        let reply = token_reply(interest_id, keyexpr);
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
        // R311ig — no-alloc take-then-fire via the shared
        // `BoundedVec::take_next_where` seam (mirror of
        // ReplyRegistry::sweep_timed_out): take one expired entry out, then
        // fire it after the borrow releases so a panicking `on_final` cannot
        // leave a half-swept entry behind.
        let mut swept = 0usize;
        let mut at = 0;
        while let Some(mut entry) = self.pending.take_next_where(
            &mut at,
            |entry| matches!(entry.deadline_ms, Some(d) if d <= now_ms),
        ) {
            swept = swept.saturating_add(1);
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
            entry
                .sink
                .on_timeout(crate::wire_id::interest_id_as_read(id));
        }
        self.rearm_due();
        swept
    }

    /// The earliest deadline of a pending get, `u64::MAX` when none has one: a sweep before it
    /// ends nothing ([`Self::sweep_timed_out`]). Kept as the gets come and go, so it is
    /// [`Self::next_deadline_ms`] read without a walk.
    pub fn due_ms(&self) -> u64 {
        self.due_ms
    }

    /// Work [`Self::due_ms`] out again from the gets left, after one that held it left.
    fn rearm_due(&mut self) {
        self.due_ms = self.next_deadline_ms().unwrap_or(u64::MAX);
    }

    /// Shared final fan body: take ownership of the (at most one) pending
    /// entry matching `interest_id`, leave the rest, then fire `on_final`
    /// after the partition releases the `&mut self.pending` borrow.
    /// Returns `true` when an entry was fired + removed. Order-preserving
    /// (a `BoundedVec` partition) though only a single entry can match a
    /// fresh-allocated id.
    fn fire_final_for(&mut self, interest_id: u64) -> bool {
        // R311ig — no-alloc take-then-fire via the shared
        // `BoundedVec::take_next_where` seam (see `sweep_timed_out`).
        let mut any = false;
        let due_ms = self.due_ms;
        let mut held_due = false;
        let mut at = 0;
        while let Some(mut entry) = self
            .pending
            .take_next_where(&mut at, |entry| entry.interest_id == interest_id)
        {
            any = true;
            held_due |= entry.deadline_ms == Some(due_ms);
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
            entry.sink.on_final(crate::wire_id::interest_id_as_read(id));
        }
        if held_due {
            self.rearm_due();
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
    pub fn dispatch_declare<'a, PS: Storage, OS: Storage>(
        &mut self,
        declare: &DeclareOwned,
        peer_keyexpr_table: impl Into<MappingSpaces<'a, PS, OS>>,
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

    /// The alive token `declare`, a record of a frame the copying receive decoded, answers a
    /// pending get of this table with, for a caller that hands the reply to the get itself: its
    /// key, resolved as [`Self::dispatch_declare`] resolves it, written into `room`, and the
    /// interest id it answers, both of which the caller hands the get
    /// ([`Self::dispatch_reply_borrowed`]) and its callback ([`token_reply`]). `None` for a
    /// declaration that answers no pending get here, and one whose key does not resolve or does
    /// not fit `room` (counted, [`Self::oversize`]): the get is handed nothing of it.
    #[cfg(feature = "alloc")]
    pub fn claim_token<'a, PS: Storage, OS: Storage>(
        &mut self,
        declare: &DeclareOwned,
        peer_keyexpr_table: impl Into<MappingSpaces<'a, PS, OS>>,
        room: &mut dyn crate::wireexpr_resolve::KeyexprOut,
    ) -> Option<u64> {
        let pending = declare.interest_id.is_some_and(|id| self.has_pending(id));
        claim_answering_token(
            declare,
            |_| pending,
            peer_keyexpr_table,
            room,
            &mut self.oversize,
        )
    }

    /// [`Self::claim_token`] for a `Declare` the in-place receive path lends, its key resolved as
    /// [`Self::dispatch_declare_view`] resolves it.
    #[cfg(all(
        feature = "storage-profile",
        feature = "codec-declare",
        feature = "rx-lent-control"
    ))]
    pub fn claim_token_view<'a, 'f, PS: Storage, OS: Storage>(
        &mut self,
        declare: &wz_codecs::lent::Declare<'f>,
        peer_keyexpr_table: impl Into<MappingSpaces<'a, PS, OS>>,
        room: &mut dyn crate::wireexpr_resolve::KeyexprOut,
    ) -> Option<u64> {
        let pending = declare.interest_id.is_some_and(|id| self.has_pending(id));
        claim_answering_token_view(
            declare,
            |_| pending,
            peer_keyexpr_table,
            room,
            &mut self.oversize,
        )
    }

    /// [`Self::dispatch_iteration_event`] to the `DeclFinal`s of a frame the copying receive
    /// decoded alone, for a caller that took each alive token of it answering a pending get
    /// itself ([`Self::claim_token`]), in their order, before this: a `DeclFinal` then ends its
    /// get after every token the frame carried. Any other event is a no-op.
    #[cfg(feature = "storage-profile")]
    pub fn dispatch_finals_of(&mut self, event: IterationEvent<'_, '_>) {
        #[cfg(feature = "alloc")]
        if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event {
            for message in crate::driver_loop::owned_records(messages).unwrap_or_default() {
                if let NetworkMessage::Declare(declare) = message {
                    if let (Some(interest_id), DeclareOwnedVariant::CodecZenohDeclFinal(_)) =
                        (declare.interest_id, &declare.body)
                    {
                        self.fire_final_for(interest_id);
                    }
                }
            }
        }
        #[cfg(not(feature = "alloc"))]
        let _ = event;
    }

    /// [`Self::dispatch_declare`] for a `Declare` the in-place receive path lends
    /// ([`IterationEvent::InPlace`]): the same two arms over the declaration as it
    /// is decoded where its frame lies. The keyexpr is resolved by
    /// [`resolve_wireexpr_view`](crate::wireexpr_resolve::resolve_wireexpr_view)
    /// into a bounded buffer; a reply past it is counted
    /// ([`Self::oversize`]) and not delivered.
    #[cfg(all(
        feature = "storage-profile",
        feature = "codec-declare",
        feature = "rx-lent-control"
    ))]
    pub fn dispatch_declare_view<'a, 'f, PS: Storage, OS: Storage>(
        &mut self,
        declare: &wz_codecs::lent::Declare<'f>,
        peer_keyexpr_table: impl Into<MappingSpaces<'a, PS, OS>>,
    ) {
        use wz_codecs::lent::DeclareVariant;
        let peer_keyexpr_table = peer_keyexpr_table.into();
        let Some(interest_id) = declare.interest_id else {
            // Unsolicited (proactive) declaration — not a get reply.
            return;
        };
        match &declare.body {
            DeclareVariant::CodecZenohDeclToken(decl) => {
                let mut composed = crate::wireexpr_resolve::KeyexprBuf::new();
                let resolved = match crate::wireexpr_resolve::resolve_wireexpr_view(
                    &decl.keyexpr.body,
                    peer_keyexpr_table,
                    &mut composed,
                ) {
                    Ok(Some(s)) => s,
                    Ok(None) => return,
                    Err(_) => {
                        self.oversize = self.oversize.saturating_add(1);
                        return;
                    }
                };
                self.dispatch_reply_borrowed(interest_id, resolved);
            }
            DeclareVariant::CodecZenohDeclFinal(_) => {
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
    pub fn dispatch_messages<'a, PS: Storage, OS: Storage>(
        &mut self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: impl Into<MappingSpaces<'a, PS, OS>>,
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
    // Out of line, for the stack: the observer's fan (`SlotObserverOf::dispatch_event_among`)
    // calls each plane in turn, and each plane's temporaries stay in a frame of its own.
    #[inline(never)]
    #[cfg(feature = "storage-profile")]
    pub fn dispatch_iteration_event<'a, PS: Storage, OS: Storage>(
        &mut self,
        event: IterationEvent<'_, '_>,
        peer_keyexpr_table: impl Into<MappingSpaces<'a, PS, OS>>,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        match event {
            #[cfg(feature = "alloc")]
            IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) => {
                if let Some(messages) = crate::driver_loop::owned_records(messages) {
                    self.dispatch_messages(messages, peer_keyexpr_table);
                }
            }
            // A Declare the in-place receive path lends where its frame lies.
            #[cfg(all(feature = "codec-declare", feature = "rx-lent-control"))]
            IterationEvent::InPlace(record) => {
                if let Some(declare) = record.declare() {
                    self.dispatch_declare_view(
                        declare,
                        MappingSpaces::from_sender(peer_keyexpr_table, record.sender()),
                    );
                }
            }
            _ => {}
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
    /// [`register`](LivelinessGetRegistry::register), and refuses as it does:
    /// `TableFull` past the stated quota on every backing, and past the
    /// capacity on the fixed one.
    pub fn register_get(
        &mut self,
        interest_id: u64,
        deadline_ms: Option<u64>,
        on_reply: impl FnMut(&dyn crate::reply_sink::ReplyView) + Send + 'static,
        on_final: impl FnMut(crate::wire_id::RequestId) + Send + 'static,
    ) -> Result<bool, RegisterError> {
        self.register(
            interest_id,
            deadline_ms,
            BoxedReplySink::new(on_reply, on_final),
        )
    }
}

#[cfg(all(test, feature = "storage-profile"))]
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

    type Captured = Arc<Mutex<Vec<(crate::wire_id::RequestId, String)>>>;

    fn make_get(
        replies: Captured,
        finals: Arc<Mutex<Vec<crate::wire_id::RequestId>>>,
    ) -> BoxedReplySink {
        let replies_cb = replies;
        let finals_cb = finals;
        BoxedReplySink::new(
            move |reply: &dyn ReplyView| {
                replies_cb
                    .lock()
                    .unwrap()
                    .push((reply.rid(), reply.keyexpr().to_string()));
            },
            move |id: crate::wire_id::RequestId| {
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
        let f: Arc<Mutex<Vec<crate::wire_id::RequestId>>> = Arc::new(Mutex::new(Vec::new()));
        assert!(reg
            .register(7, None, make_get(r.clone(), f.clone()))
            .unwrap());
        assert_eq!(reg.len(), 1);
        assert!(reg.unregister(7));
        assert_eq!(reg.len(), 0);
        assert!(!reg.unregister(7), "double-unregister is idempotent");
    }

    /// A sink that names itself, for a test that finds a get by its sink.
    struct Tagged(u8);

    impl ReplySink for Tagged {
        fn on_reply(&mut self, _reply: &dyn ReplyView) {}

        fn on_final(&mut self, _rid: crate::wire_id::RequestId) {
            panic!("a get removed by its sink fires no final");
        }
    }

    /// The first get whose sink the pick names is removed, its final not fired, and the earliest
    /// deadline is worked out again from the gets left; a pick that names none removes nothing.
    /// Turned red by a removal that keeps the deadline of the get gone, or one that takes every
    /// get the pick names.
    #[test]
    fn the_first_get_its_sink_names_is_removed_and_the_deadline_moves_on() {
        let mut reg = LivelinessGetRegistry::<Tagged>::with_sink_backing();
        for (interest_id, tag, due) in [(1, 1, 100), (2, 2, 300), (3, 1, 500)] {
            assert!(reg
                .register(interest_id, Some(due), Tagged(tag))
                .expect("a row is free"));
        }
        assert_eq!(reg.due_ms(), 100);
        assert!(reg.unregister_first(|sink| sink.0 == 1));
        assert_eq!(reg.len(), 2, "the first the pick names, and no other");
        assert_eq!(
            reg.due_ms(),
            300,
            "the deadline of the get gone is not kept"
        );
        assert!(!reg.unregister_first(|sink| sink.0 == 9));
        assert!(reg.unregister_first(|sink| sink.0 == 1));
        assert!(reg.unregister_first(|sink| sink.0 == 2));
        assert!(reg.is_empty());
    }

    /// R311y740 (N37) — the own-space WITNESS for the liveliness-GET reply
    /// plane. This registry ingests a SOLICITED `Declare(DeclToken)`
    /// correlated by `interest_id`, so it is a separate entry point from the
    /// declarer / subscriber planes even though the record type is shared.
    ///
    /// THE DISCRIMINATOR is the collision: id 7 is in BOTH spaces under
    /// different literals, so a wrong-space read delivers a confident wrong
    /// keyexpr to the requester rather than dropping the reply.
    #[cfg(feature = "storage-profile")]
    #[test]
    fn an_own_space_alias_resolves_in_our_space_on_the_liveliness_get_plane() {
        let mut reg = LivelinessGetRegistry::new();
        let replies: Captured = Arc::new(Mutex::new(Vec::new()));
        let finals: Arc<Mutex<Vec<crate::wire_id::RequestId>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(9, None, make_get(replies.clone(), finals.clone()))
            .unwrap();

        let mut peer = HashMap::new();
        peer.insert(7u64, "theirs/token".to_string());
        let mut own: HashMap<crate::wire_id::ExprId, String> = HashMap::new();
        own.insert(7, "ours/token".to_string());

        let declare = declare_envelope_decl_token_with_interest(decl_token_nonlocal(1, 7, None), 9);
        reg.dispatch_declare(&declare, MappingSpaces::with_own(&peer, &own));

        assert_eq!(
            *replies.lock().unwrap(),
            vec![(9, "ours/token".to_string())],
            "an M=0 alias names OUR space; reading the peer's would have \
             delivered `theirs/token` to the requester",
        );
    }

    /// ANTI-VACUITY twin: with only the peer's space the same reply refuses.
    #[cfg(feature = "storage-profile")]
    #[test]
    fn without_an_own_space_the_liveliness_get_plane_refuses_the_same_alias() {
        let mut reg = LivelinessGetRegistry::new();
        let replies: Captured = Arc::new(Mutex::new(Vec::new()));
        let finals: Arc<Mutex<Vec<crate::wire_id::RequestId>>> = Arc::new(Mutex::new(Vec::new()));
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
        let f: Arc<Mutex<Vec<crate::wire_id::RequestId>>> = Arc::new(Mutex::new(Vec::new()));
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
        let f: Arc<Mutex<Vec<crate::wire_id::RequestId>>> = Arc::new(Mutex::new(Vec::new()));
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
        let f: Arc<Mutex<Vec<crate::wire_id::RequestId>>> = Arc::new(Mutex::new(Vec::new()));
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

    /// A frame whose alive tokens a caller claimed and handed itself, one at a time, is told its
    /// `DeclFinal`s alone after them: the token reaches the get once, by the key the claim wrote
    /// into the caller's room, and the Final ends the get after it. A token that answers no
    /// pending get, and a Final, are claimed by none. Turned red by a claim that hands the get the
    /// token itself, one that claims a stranger's token or a Final, or a dispatch of the frame's
    /// Finals that hands the token a second time or drops the Final.
    #[cfg(feature = "storage-profile")]
    #[test]
    fn a_frame_whose_tokens_were_claimed_ends_its_get_after_them() {
        if !crate::driver_loop::OWNED_RECORDS {
            return;
        }
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<crate::wire_id::RequestId>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(42, None, make_get(r.clone(), f.clone()))
            .unwrap();
        let token = declare_envelope_decl_token_with_interest(
            decl_token(11, 0, Some("liveliness/dev11")),
            42,
        );
        let stranger = declare_envelope_decl_token_with_interest(
            decl_token(12, 0, Some("liveliness/dev12")),
            43,
        );
        let fin = declare_envelope_decl_final_with_interest(42);
        let mut room = crate::wireexpr_resolve::KeyexprBuf::new();
        assert_eq!(
            reg.claim_token(&stranger, &HashMap::new(), &mut room),
            None,
            "a token answering no pending get was claimed"
        );
        assert_eq!(
            reg.claim_token(&fin, &HashMap::new(), &mut room),
            None,
            "a Final was claimed as a token"
        );
        assert_eq!(
            reg.claim_token(&token, &HashMap::new(), &mut room),
            Some(42)
        );
        assert!(
            r.lock().unwrap().is_empty(),
            "the claim handed the get the token itself"
        );
        let key = crate::wireexpr_resolve::KeyexprOut::as_str(&room);
        assert_eq!(key, "liveliness/dev11");
        assert_eq!(reg.dispatch_reply_borrowed(42, key), 1);

        let outcome = DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: crate::driver_loop::frame_records(vec![
                NetworkMessage::Declare(alloc::boxed::Box::new(token)),
                NetworkMessage::Declare(alloc::boxed::Box::new(fin)),
            ]),
            has_ext: false,
            extensions: Vec::new(),
            priority: crate::qos::Priority::DEFAULT,
        };
        reg.dispatch_finals_of(IterationEvent::Poll(&outcome));
        assert_eq!(
            *r.lock().unwrap(),
            vec![(42, "liveliness/dev11".to_string())],
            "the frame's token was handed again"
        );
        assert_eq!(*f.lock().unwrap(), vec![42], "the Final was dropped");
        assert_eq!(reg.len(), 0, "the Final left its get pending");
    }

    /// The sink is handed the interest id at the width upstream reads it,
    /// while the table still matches on the session's 64-bit id.
    #[test]
    fn a_get_correlates_its_sink_by_the_interest_id_as_the_wire_reads_it() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<crate::wire_id::RequestId>>> = Arc::new(Mutex::new(Vec::new()));
        let wide = (1u64 << 32) | 9;
        reg.register(wide, None, make_get(r.clone(), f.clone()))
            .unwrap();

        assert_eq!(reg.dispatch_reply_borrowed(9, "liveliness/a"), 0);
        assert_eq!(reg.dispatch_reply_borrowed(wide, "liveliness/a"), 1);
        assert!(reg.dispatch_final(wide));

        assert_eq!(*r.lock().unwrap(), vec![(9, "liveliness/a".to_string())]);
        assert_eq!(*f.lock().unwrap(), vec![9]);
    }

    #[test]
    fn unsolicited_token_without_interest_id_is_ignored() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<crate::wire_id::RequestId>>> = Arc::new(Mutex::new(Vec::new()));
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
        let f: Arc<Mutex<Vec<crate::wire_id::RequestId>>> = Arc::new(Mutex::new(Vec::new()));
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
        let f: Arc<Mutex<Vec<crate::wire_id::RequestId>>> = Arc::new(Mutex::new(Vec::new()));
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
        let f: Arc<Mutex<Vec<crate::wire_id::RequestId>>> = Arc::new(Mutex::new(Vec::new()));
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

    /// The earliest deadline is kept as gets end by every road: a DeclFinal, an unregistration,
    /// a sweep and the drop of the table, each leaving the earliest of the gets left, as a walk of
    /// them reads it, and none once none is left. Turned red by a registration that does not
    /// lower it, or a road that leaves the deadline of a get gone.
    #[test]
    fn due_ms_is_the_earliest_left_after_every_end_of_a_get() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<crate::wire_id::RequestId>>> = Arc::new(Mutex::new(Vec::new()));
        assert_eq!(reg.due_ms(), u64::MAX, "an empty table is due never");
        for (id, deadline_ms) in [(1, Some(300)), (2, Some(100)), (3, None), (4, Some(200))] {
            reg.register(id, deadline_ms, make_get(r.clone(), f.clone()))
                .unwrap();
        }
        assert_eq!(reg.due_ms(), 100, "the earliest deadline registered");
        assert!(reg.dispatch_final(2));
        assert_eq!(reg.due_ms(), 200, "the earliest left after the DeclFinal");
        assert_eq!(Some(reg.due_ms()), reg.next_deadline_ms());
        assert!(reg.unregister(1));
        assert_eq!(reg.due_ms(), 200, "a later get's end moved it");
        assert_eq!(reg.sweep_timed_out(200), 1);
        assert_eq!(
            reg.due_ms(),
            u64::MAX,
            "only a get that never expires is left"
        );
        assert_eq!(reg.next_deadline_ms(), None);
        drop(reg.take_finalized());
        reg.register(5, Some(50), make_get(r, f)).unwrap();
        assert_eq!(reg.due_ms(), 50);
        reg.clear();
        assert_eq!(reg.due_ms(), u64::MAX, "the table's drop left a deadline");
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
        let f: Arc<Mutex<Vec<crate::wire_id::RequestId>>> = Arc::new(Mutex::new(Vec::new()));
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
        let f: Arc<Mutex<Vec<crate::wire_id::RequestId>>> = Arc::new(Mutex::new(Vec::new()));
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
        let f: Arc<Mutex<Vec<crate::wire_id::RequestId>>> = Arc::new(Mutex::new(Vec::new()));
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

    /// On the fixed backing a terminated get's `finalized` marker holds its
    /// slot until the prune drain takes it. Without that, a registration made
    /// before the drain could fill `pending` back to the capacity `finalized`
    /// shares, and the next termination's marker push would be the refused one
    /// — a permanent replay leak that only a `debug_assert` stood between.
    #[cfg(feature = "bounded-heapless")]
    #[test]
    fn an_undrained_final_marker_holds_its_slot_on_the_fixed_backing() {
        let mut reg = LivelinessGetRegistry::new();
        let r: Captured = Arc::new(Mutex::new(Vec::new()));
        let f: Arc<Mutex<Vec<crate::wire_id::RequestId>>> = Arc::new(Mutex::new(Vec::new()));
        for id in 0..caps::MAX_PENDING_LIVELINESS_GETS as u64 {
            assert_eq!(
                reg.register(id, None, make_get(r.clone(), f.clone())),
                Ok(true)
            );
        }
        assert!(
            reg.dispatch_final(0),
            "get 0 terminates; its marker is staged"
        );
        assert!(
            !reg.has_room(),
            "a caller asking first is told there is no room"
        );
        assert_eq!(
            reg.register(100, None, make_get(r.clone(), f.clone())),
            Err(RegisterError::TableFull),
            "the undrained marker still occupies its slot"
        );
        let staged: Vec<u64> = reg.take_finalized().into_iter().collect();
        assert_eq!(staged, vec![0]);
        assert!(reg.has_room(), "CONTROL: the drain gives the room back");
        assert_eq!(
            reg.register(100, None, make_get(r.clone(), f.clone())),
            Ok(true),
            "the drain frees the slot"
        );
    }
}
