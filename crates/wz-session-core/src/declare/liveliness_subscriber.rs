// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `LivelinessSubscriberRegistry` — application-layer registry that
//! tracks the local liveliness subscribers wz has declared on this
//! session and routes inbound `Declare(DeclToken|UndeclToken)` records
//! to their keyexpr-matched callbacks. The application surface
//! mirrors zenoh-pico's `z_liveliness_declare_subscriber` /
//! `z_liveliness_undeclare_subscriber` pair
//! (`vendor/zenoh-pico/src/net/liveliness.c:220-235`).
//!
//! ## Position in the dispatch stack
//!
//! This registry sits alongside [`crate::declare::LivelinessRegistry`]
//! but plays a distinct role:
//!
//! | Registry                         | What it observes                | Lifetime model              |
//! |----------------------------------|---------------------------------|-----------------------------|
//! | [`LivelinessRegistry`]           | EVERY peer `Decl*Token` record  | callback-only (no slot id)  |
//! | [`LivelinessSubscriberRegistry`] | peer `Decl*Token` matching MY   | per-subscriber slot + RAII  |
//! |                                  | declared keyexpr pattern        |                             |
//!
//! Both registries receive the same inbound dispatch (an
//! [`crate::observer::ApplicationLayerObserver::dispatch_event`] call
//! fans the `IterationEvent` into each). They are not chained —
//! installing a subscriber here does NOT install an
//! `on_token_declared` on the sibling [`LivelinessRegistry`].
//! Applications that want "every peer's liveliness signal regardless
//! of keyexpr" register on [`LivelinessRegistry`]; applications that
//! want "the peer's tokens that match keyexpr X" register here.
//!
//! ## Lifetime: keyexpr → callback per subscriber
//!
//! Unlike [`LivelinessRegistry`] (callback-only, no per-callback
//! state), each subscriber here owns a slot keyed by the
//! `interest_id` allocated through
//! [`crate::session_glue::SessionLinkActions::alloc_next_interest_id`].
//! The slot carries:
//!
//! * the subscriber's keyexpr `pattern` (R311gb Track 2 — one
//!   [`crate::bounded::BoundedString`]; matching splits it into a stack
//!   chunk view at dispatch with no heap, and the same buffer serves the
//!   introspection / debug `keyexpr` accessor);
//! * the user-supplied [`LivelinessSampleSink`];
//! * `history` flag — `true` when the subscriber requested current +
//!   future replay (CURRENT bit on the outbound Interest); the
//!   responder's inbound `Declare(DeclFinal)` (carrying our
//!   `interest_id`) flips `history_complete` to `true` (R311xx);
//! * `history_complete` — observable via
//!   [`Self::history_complete`] so an integration test can await
//!   replay completion.
//!
//! The RAII handle (R280 [`crate::session::LivelinessSubscriber`])
//! holds the `interest_id` and on `Drop` triggers
//! [`Self::unregister`] + an outbound `InterestFinal`.
//!
//! ## peer_token_table — UndeclToken keyexpr resolution
//!
//! `Declare(DeclToken)` carries `(token_id, keyexpr)`; the inbound
//! dispatch resolves the keyexpr via the shared peer keyexpr table
//! and matches it against every subscriber slot. The registry
//! remembers the `(token_id → resolved keyexpr)` pair locally so a
//! subsequent `Declare(UndeclToken)` — which carries only `token_id`,
//! per zenoh-pico's `_z_undecl_encode` shape at
//! `vendor/zenoh-pico/src/protocol/codec/declarations.c:128-130` — can
//! be projected back into the same keyexpr and fanned to the same
//! set of matching subscribers as a `LivelinessSampleKind::Delete`
//! sample.
//!
//! This table is registry-local because the peer's declaration set
//! is not held anywhere else in wz (the existing
//! [`LivelinessRegistry`] is callback-only with no state); maintaining
//! it here keeps the cross-registry coupling at zero and matches
//! zenoh-pico's `_z_session_t._remote_tokens` table sized per session.

// R311gb (Track 2) — String / HashMap back the `alloc` wire side (the
// `peer_token_table` token→keyexpr table + dispatch params); the no-alloc
// control plane stores slots in a `BoundedVec` (each slot's pattern in a
// `BoundedString`) and fires the borrowed `LivelinessSample` view.
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use hashbrown::HashMap;

#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use wz_codecs::declare::DeclareOwnedVariant;

use crate::bounded::{BoundedString, BoundedVec};
use crate::caps;
#[cfg(feature = "alloc")]
use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
use crate::keyexpr_match::{keyexpr_pattern_matches, MAX_KEYEXPR_CHUNKS};
#[cfg(feature = "alloc")]
use crate::network_message::NetworkMessage;
use crate::registry_error::RegisterError;
#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use crate::wireexpr_resolve::resolve_wireexpr;

// R311ek / R311gb — the pure-data sample types are codec-agnostic +
// no_std; `BoxedLivelinessSampleSink` (the heap adapter) is `alloc`-gated.
#[cfg(feature = "alloc")]
pub use crate::declare::liveliness_sample::BoxedLivelinessSampleSink;
pub use crate::declare::liveliness_sample::{
    LivelinessSample, LivelinessSampleKind, LivelinessSampleSink,
};

/// Per-subscriber slot. Private to this module; consumers interact
/// through [`LivelinessSubscriberRegistry::register`] /
/// [`LivelinessSubscriberRegistry::unregister`] and the RAII handle
/// at the [`crate::session::LivelinessSubscriber`] layer.
struct LivelinessSubscriberSlot<C: LivelinessSampleSink> {
    /// R311gb (Track 2) — the slot's interest id (was the `HashMap` key;
    /// now carried in-row since the slot table is a linear `BoundedVec`).
    interest_id: u64,
    /// R311gb (Track 2) — the subscriber's keyexpr pattern, stored as one
    /// [`BoundedString`] (no-alloc backing on MCU). Matching splits it on
    /// `/` at dispatch time into a stack chunk view (the pre-split owned
    /// `Vec<String>` + duplicate `keyexpr` `String` are folded into this
    /// single buffer). Empty literal chunks are preserved so `a//b` is
    /// distinguishable from `a/b`; the registry's `keyexpr` accessor
    /// returns this verbatim.
    pattern: BoundedString<{ caps::MAX_KEYEXPR_BYTES }>,
    /// R311gb-3d — the delivery sink (DIP seam). Fired in registration
    /// order if multiple subscribers are declared on overlapping
    /// patterns. `C = BoxedLivelinessSampleSink` on AP, a consumer-
    /// supplied closed `enum` on MCU.
    sink: C,
    /// `true` when the subscriber requested CURRENT replay (the
    /// `history` flag on the outbound Interest sets the C bit).
    history: bool,
    /// `true` once the responder's `Declare(DeclFinal)` for this
    /// subscriber's `interest_id` has been observed inbound — i.e. the
    /// peer has finished replaying the historical token set. Stays
    /// `false` when `history == false` (no replay was requested; the flag
    /// is only meaningful for history-enabled subscribers).
    ///
    /// R311xx sets this from the `Declare(DeclFinal)` arm of
    /// [`Self::dispatch_messages`] (NOT an `Interest(Final)`, which the
    /// responder never sends — that was the pre-R311xx bug).
    history_complete: bool,
}

/// Application-layer registry tracking the LOCAL liveliness
/// subscribers wz has declared on this session, routing inbound
/// `Decl*Token` records to their keyexpr-matched callbacks. See
/// module-level docs for the dispatch contract and the
/// `peer_token_table` keyexpr-resolution mechanism.
pub struct LivelinessSubscriberRegistry<C: LivelinessSampleSink> {
    /// R311gb (Track 2) — bounded slot table (was a `HashMap` keyed by
    /// `interest_id`; now a linear `BoundedVec` with the id carried
    /// in-row, scanned on register / unregister / accessor lookup —
    /// `caps::MAX_LIVELINESS_SUBSCRIPTIONS` is small so the linear scan is
    /// cheaper than a no-alloc map).
    slots: BoundedVec<LivelinessSubscriberSlot<C>, { caps::MAX_LIVELINESS_SUBSCRIPTIONS }>,
    /// Peer-side token table: maps a `DeclToken.id` to the keyexpr it
    /// resolved to at `DeclToken` arrival time. Populated by
    /// [`Self::dispatch_declare`] on `DeclToken` reception and
    /// consumed on the matching `UndeclToken` reception so the
    /// `Delete` sample can carry the same keyexpr as the prior `Put`.
    /// Cleared on `UndeclToken` reception (R280); a `DeclToken` whose
    /// id was never seen is treated as a no-op.
    ///
    /// R311gb (Track 2) — wire-side resolution state (populated by
    /// `dispatch_declare` consuming owned `Declare` records);
    /// `alloc`-gated per the borrow boundary. The no-alloc control plane
    /// (slot table + matching + fan) does not depend on it; an MCU caller
    /// supplies the keyexpr to [`Self::dispatch_sample_borrowed`] directly.
    #[cfg(feature = "alloc")]
    peer_token_table: HashMap<u64, String>,
}

impl<C: LivelinessSampleSink> Default for LivelinessSubscriberRegistry<C> {
    fn default() -> Self {
        Self::with_sink_backing()
    }
}

impl<C: LivelinessSampleSink> LivelinessSubscriberRegistry<C> {
    /// New empty registry over an explicit sink backing `C`. No slots,
    /// empty peer-token table.
    ///
    /// R311gb-3d — the generic constructor (no-`alloc` / MCU entry point,
    /// paired with [`register`](Self::register) taking an explicit sink).
    /// AP callers use the inferring [`new`](LivelinessSubscriberRegistry::new)
    /// shorthand, which fixes `C = BoxedLivelinessSampleSink`.
    pub fn with_sink_backing() -> Self {
        Self {
            slots: BoundedVec::new(),
            #[cfg(feature = "alloc")]
            peer_token_table: HashMap::new(),
        }
    }

    /// Register a subscriber slot keyed by `interest_id`. Returns
    /// `false` if `interest_id` is already registered — callers
    /// allocate fresh ids through
    /// [`crate::session_glue::SessionLinkActions::alloc_next_interest_id`]
    /// so collision is a programming error, not a runtime condition.
    ///
    /// `keyexpr` is the subscriber's pattern (zenoh-pico semantics:
    /// `*` matches one chunk, `**` matches zero or more chunks);
    /// every matching inbound `DeclToken` / `UndeclToken` fires the
    /// callback with the resolved keyexpr literal. `history = true`
    /// records the subscriber's request for CURRENT replay (the C
    /// bit on the outbound Interest); the flag is consumed by
    /// [`Self::history_complete`] queries and by the R311xx
    /// `Declare(DeclFinal)` arm of [`Self::dispatch_messages`].
    ///
    /// R311gb-3d — takes an explicit [`LivelinessSampleSink`] (the DIP
    /// seam; `C = BoxedLivelinessSampleSink` on AP, a consumer-supplied
    /// closed `enum` on MCU). The `Session::declare_liveliness_subscriber`
    /// surface keeps its `impl FnMut(LivelinessSample)` closure shape and
    /// wraps it in a [`BoxedLivelinessSampleSink`] before calling here.
    ///
    /// R311gb (Track 2) — takes the keyexpr by `&str` (stored in the slot's
    /// [`BoundedString`]) and is fallible on the no-alloc backing:
    /// `Ok(true)` = newly registered, `Ok(false)` = duplicate
    /// `interest_id` (no-op), `Err(TableFull)` = slot table at capacity,
    /// `Err(KeyexprTooLong)` = keyexpr exceeds [`caps::MAX_KEYEXPR_BYTES`].
    /// On the `alloc` backing the two `Err` arms are never returned.
    pub fn register(
        &mut self,
        interest_id: u64,
        keyexpr: &str,
        history: bool,
        sink: C,
    ) -> Result<bool, RegisterError> {
        // Duplicate check by linear scan (the slot table is a `BoundedVec`
        // now, not a keyed map). Fresh ids come from
        // `alloc_next_interest_id`, so a collision is a programming error.
        if self.slots.iter().any(|s| s.interest_id == interest_id) {
            return Ok(false);
        }
        let mut pattern: BoundedString<{ caps::MAX_KEYEXPR_BYTES }> = BoundedString::new();
        pattern
            .push_str(keyexpr)
            .map_err(|_| RegisterError::KeyexprTooLong)?;
        self.slots
            .push(LivelinessSubscriberSlot {
                interest_id,
                pattern,
                sink,
                history,
                history_complete: false,
            })
            .map_err(|_| RegisterError::TableFull)?;
        Ok(true)
    }

    /// Remove a subscriber slot. Returns `true` when a slot was
    /// removed, `false` when no slot matched (idempotent on a
    /// double-unregister). The RAII handle's `Drop` calls this; an
    /// explicit `LivelinessSubscriber::undeclare` ahead of the drop
    /// covers the same call site.
    pub fn unregister(&mut self, interest_id: u64) -> bool {
        let before = self.slots.len();
        self.slots.retain(|s| s.interest_id != interest_id);
        before != self.slots.len()
    }

    /// Mark the subscriber with `interest_id` as history-complete.
    /// Called from the R311xx `Declare(DeclFinal)` inbound arm. No-op
    /// when the id is unknown (the peer may emit a `DeclFinal` for an
    /// id whose subscriber was already unregistered locally; dropping
    /// the signal silently is the correct response).
    pub fn mark_history_complete(&mut self, interest_id: u64) {
        if let Some(slot) = self.slots.iter_mut().find(|s| s.interest_id == interest_id) {
            slot.history_complete = true;
        }
    }

    /// Number of currently-registered subscriber slots. Useful for
    /// diagnostic surfaces and unit tests.
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Borrow the keyexpr string a subscriber was declared on.
    /// Returns `None` for an unknown `interest_id`. Carried for
    /// debug logging — the matching engine uses `pattern_chunks`,
    /// not this view.
    pub fn keyexpr(&self, interest_id: u64) -> Option<&str> {
        self.slots
            .iter()
            .find(|s| s.interest_id == interest_id)
            .map(|slot| slot.pattern.as_str())
    }

    /// `true` when the subscriber requested CURRENT replay AND the
    /// peer has signaled history-complete via its `Declare(DeclFinal)`.
    /// Returns `false` for an unknown id, for a `history = false`
    /// subscriber (no replay requested → flag never flips), or
    /// before the peer's `Declare(DeclFinal)` arrives.
    pub fn history_complete(&self, interest_id: u64) -> bool {
        self.slots
            .iter()
            .find(|s| s.interest_id == interest_id)
            .map(|slot| slot.history && slot.history_complete)
            .unwrap_or(false)
    }

    /// Snapshot of how many peer-side `DeclToken` records are
    /// currently tracked. Equal to the number of `DeclToken` arrivals
    /// minus matching `UndeclToken` arrivals; bounded by the peer's
    /// declared token set. Test / diagnostic surface only.
    #[cfg(feature = "alloc")]
    pub fn peer_token_count(&self) -> usize {
        self.peer_token_table.len()
    }

    /// Route an inbound `Declare` envelope's inner body through the
    /// matching subscriber slots. Updates `peer_token_table` on
    /// `DeclToken` arrival (so a later `UndeclToken` can resolve back
    /// to the same keyexpr) and removes the entry on `UndeclToken`
    /// arrival.
    ///
    /// `peer_keyexpr_table` is the shared mapping table populated by
    /// [`crate::pubsub::SubscriberRegistry`] from inbound
    /// `Declare(DeclKexpr)` records. A `DeclToken` whose keyexpr
    /// references an undeclared peer mapping silently drops (mirror
    /// of [`crate::declare::LivelinessRegistry::dispatch_declare`]'s
    /// "no resolved keyexpr → no fire" contract — recording the slot
    /// match without the resolved keyexpr would surface a half-truth
    /// to the callback).
    /// R311gb (Track 2) — no-heap fire entry: fan a borrowed liveliness
    /// sample `(kind, keyexpr, token_id)` to every slot whose pattern
    /// matches `keyexpr`, delivering the `LivelinessSample` view to each
    /// matching sink. Borrow-driven (the caller supplies the resolved
    /// keyexpr), so it is the MCU no-heap fan-out; the `alloc` wire path
    /// ([`dispatch_declare`](Self::dispatch_declare)) resolves the keyexpr
    /// through the peer table + `peer_token_table` and funnels through
    /// here. Returns the count of slots fired.
    pub fn dispatch_sample_borrowed(
        &mut self,
        kind: LivelinessSampleKind,
        keyexpr: &str,
        token_id: u64,
    ) -> usize {
        self.fan_to_matching_slots(kind, keyexpr, token_id)
    }

    /// Route an inbound `Declare` envelope's inner body through the
    /// matching subscriber slots. Updates `peer_token_table` on
    /// `DeclToken` arrival (so a later `UndeclToken` can resolve back
    /// to the same keyexpr) and removes the entry on `UndeclToken`
    /// arrival.
    ///
    /// `peer_keyexpr_table` is the shared mapping table populated by
    /// [`crate::pubsub::SubscriberRegistry`] from inbound
    /// `Declare(DeclKexpr)` records. A `DeclToken` whose keyexpr
    /// references an undeclared peer mapping silently drops (mirror
    /// of [`crate::declare::LivelinessRegistry::dispatch_declare`]'s
    /// "no resolved keyexpr → no fire" contract — recording the slot
    /// match without the resolved keyexpr would surface a half-truth
    /// to the callback).
    ///
    /// R311gb (Track 2) — `all(codec-declare, alloc)`-gated: consumes the
    /// owned `DeclareOwnedVariant` (codec) + the `alloc` `peer_token_table`
    /// resolution, then funnels through the no-heap
    /// [`dispatch_sample_borrowed`](Self::dispatch_sample_borrowed) SSOT.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_declare(
        &mut self,
        body: &DeclareOwnedVariant,
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        match body {
            DeclareOwnedVariant::CodecZenohDeclToken(decl) => {
                let resolved = match resolve_wireexpr(&decl.keyexpr.body, peer_keyexpr_table) {
                    Some(s) => s,
                    None => return,
                };
                self.peer_token_table.insert(decl.id, resolved.clone());
                self.fan_to_matching_slots(LivelinessSampleKind::Put, &resolved, decl.id);
            }
            DeclareOwnedVariant::CodecZenohUndeclToken(undecl) => {
                let resolved = match self.peer_token_table.remove(&undecl.id) {
                    Some(s) => s,
                    None => return,
                };
                self.fan_to_matching_slots(LivelinessSampleKind::Delete, &resolved, undecl.id);
            }
            // Other DeclareOwnedVariant arms are not the liveliness layer's
            // concern.
            _ => {}
        }
    }

    /// R311y521 — flush EVERY remote token, firing a `Delete` to each matching
    /// subscriber slot. Returns how many tokens were flushed.
    ///
    /// This is the link-loss path, and it is a direct transcription of
    /// zenoh-pico's `_z_liveliness_subscription_undeclare_all`
    /// (`src/session/liveliness.c:99-120`), which pico calls from
    /// `_zp_unicast_failed_result` (`src/transport/unicast/lease.c:74-78`) the
    /// moment a unicast transport fails.
    ///
    /// Without it a remote token outlives the link that announced it: the peer
    /// is gone, no `UndeclToken` will ever arrive for it (the link that would
    /// have carried it is what died), and every liveliness subscriber goes on
    /// believing the token is alive. wz's `reset_for_reopen` rebuilds link and
    /// handshake state and touches no registry, so before this the stale entry
    /// also survived the RE-open — and a re-declared token then fired a second
    /// `Put` for something the application was never told had gone.
    ///
    /// The table is DRAINED BEFORE any sink runs, mirroring pico's own move
    /// ("it is safe to just move the data" — `liveliness.c:103-106`): a sink
    /// that re-declares during the fan-out then lands in the fresh table
    /// instead of an entry being iterated. Here the drain is also what makes
    /// the `&mut self` fan-out borrow legal, so the two reasons agree.
    ///
    /// Delete order is by token id, which is a TEST-determinism choice and not
    /// a wire property — pico's intmap order is its own, and no correct
    /// consumer may depend on either.
    /// R311y536 — the BODY is `alloc`-gated, not the function, and the
    /// asymmetry is the defect this closes. `peer_token_table` is itself
    /// `#[cfg(feature = "alloc")]` (it is the wire-side resolution state; the
    /// no-alloc control plane takes the keyexpr directly through
    /// `dispatch_sample_borrowed`), and this method reached that field, plus
    /// `alloc::vec::Vec` and `String`, with no gate at all. So every no-alloc
    /// build of this crate failed with four errors — E0433 on `alloc`, E0425
    /// on `String`, and E0609 twice on the absent field — which is why the
    /// hosted `no_std` cross-compile (Layer G) and the `wz-runtime-coop` arm of
    /// Layer C1l were both red while every host lane stayed green.
    ///
    /// Gating the BODY rather than the function keeps the signature stable
    /// (`feedback_signature_stability`), mirroring the sole caller
    /// `Observer::flush_liveliness_on_link_loss`, which has the identical
    /// shape one level up: a body-level cfg with a `0` fallback. `0` is the
    /// honest answer without `alloc` — there is no peer-token table, so
    /// nothing was flushed.
    pub fn flush_peer_tokens_on_link_loss(&mut self) -> usize {
        #[cfg(feature = "alloc")]
        {
            if self.peer_token_table.is_empty() {
                return 0;
            }
            let mut drained: alloc::vec::Vec<(u64, String)> =
                self.peer_token_table.drain().collect();
            drained.sort_by_key(|(id, _)| *id);
            for (id, keyexpr) in &drained {
                self.fan_to_matching_slots(LivelinessSampleKind::Delete, keyexpr, *id);
            }
            drained.len()
        }
        #[cfg(not(feature = "alloc"))]
        {
            0
        }
    }

    /// Internal fan-out helper (the no-heap match SSOT). Walks every slot
    /// and invokes its sink when the slot's pattern matches the resolved
    /// keyexpr. R311gb (Track 2) — splits the slot's [`BoundedString`]
    /// pattern into a stack chunk view (no heap); a pattern exceeding
    /// [`MAX_KEYEXPR_CHUNKS`] chunks (cannot happen for a registered
    /// pattern) is skipped rather than matched truncated. Returns the
    /// count of slots fired.
    fn fan_to_matching_slots(
        &mut self,
        kind: LivelinessSampleKind,
        resolved: &str,
        token_id: u64,
    ) -> usize {
        let mut fired: usize = 0;
        for slot in self.slots.iter_mut() {
            let mut chunks: BoundedVec<&str, MAX_KEYEXPR_CHUNKS> = BoundedVec::new();
            let mut overflow = false;
            for c in slot.pattern.split('/') {
                if chunks.push(c).is_err() {
                    overflow = true;
                    break;
                }
            }
            if overflow {
                continue;
            }
            if keyexpr_pattern_matches(&chunks, resolved) {
                // R311gb-3d — deliver through the LivelinessSampleSink seam.
                slot.sink.on_sample(LivelinessSample {
                    kind,
                    keyexpr: resolved,
                    token_id,
                });
                fired = fired.saturating_add(1);
            }
        }
        fired
    }

    /// Drain a `&[NetworkMessage]` through [`Self::dispatch_declare`]
    /// (the `Decl*Token` sample fan) and flip
    /// [`Self::mark_history_complete`] on the responder's
    /// `Declare(DeclFinal)` terminator — the message that ENDS a CURRENT
    /// replay, carrying our `interest_id` (pico
    /// `_z_interest_process_declare_final`,
    /// `vendor/zenoh-pico/src/session/interest.c:508`; mirror of the
    /// liveliness-GET registry's `fire_final_for`). An inbound `Interest`
    /// is the responder's concern (`LocalTokenRegistry`), not the
    /// subscriber's — pico's `_z_interest_process_interest_final`
    /// (interest.c:524) is a TODO no-op — so `Interest` messages are
    /// ignored here. (R311xx: the prior R281 wire-up flipped
    /// history-complete on an `Interest(Final)` the responder never
    /// sends, so the snapshot-complete signal never fired on a real
    /// wz<->wz / wz<->pico exchange.)
    #[cfg(feature = "alloc")]
    pub fn dispatch_messages(
        &mut self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        // R311q — `peer_keyexpr_table` is only consumed inside the
        // cfg-gated `NetworkMessage::Declare` arm below; the
        // explicit `let _ = ...` on the codec-declare-OFF build
        // silences the unused-variable lint without changing the
        // signature (signature-stability principle: dispatch_messages
        // keeps the same shape across builds so caller-side glue
        // need not feature-detect).
        #[cfg(not(feature = "codec-declare"))]
        let _ = peer_keyexpr_table;
        for message in messages {
            match message {
                // R311q — `NetworkMessage::Declare` is cfg-gated on
                // `codec-declare` (the variant disappears entirely when
                // the feature is off); the inner-codec dispatch arm
                // here gates on the same feature so a feature-OFF
                // build elides the Declare path while still handling
                // `Interest` for history-complete marking. When
                // codec-declare is OFF no peer-side declarations can
                // be decoded into NetworkMessage::Declare, so dropping
                // the arm matches the wire reality.
                #[cfg(feature = "codec-declare")]
                NetworkMessage::Declare(decl) => {
                    // R311y1 — `dispatch_declare` is the keyexpr-matched
                    // token FAN (DeclToken/UndeclToken -> Put/Delete, matched
                    // by the subscriber's keyexpr pattern). The DeclFinal
                    // completion below is a DISTINCT correlation model —
                    // matched by `interest_id`, not keyexpr — so it stays in
                    // this message demux rather than folding into
                    // `dispatch_declare`. This is a deliberate NON-mirror of
                    // the liveliness-get registry's single-key envelope
                    // dispatch (get is interest_id-only); conflating the two
                    // correlation models here would lose separation, not gain
                    // symmetry.
                    self.dispatch_declare(&decl.body, peer_keyexpr_table);
                    // R311xx — the responder terminates a CURRENT replay
                    // with `Declare(DeclFinal)` carrying our `interest_id`
                    // (the declarer-side `LocalTokenRegistry` stages it via
                    // `build_final_reply`; pico
                    // `_z_interest_process_declare_final`, interest.c:508),
                    // NOT an `Interest(Final)`. Flip history-complete for
                    // the matching history-subscriber slot — the
                    // `slot.history` guard in `history_complete` keeps the
                    // flag meaningful only for history-enabled subscribers.
                    if let Some(interest_id) = decl.interest_id {
                        if matches!(decl.body, DeclareOwnedVariant::CodecZenohDeclFinal(_)) {
                            self.mark_history_complete(interest_id);
                        }
                    }
                }
                // R311xx — an inbound `Interest` is the responder's
                // concern (`LocalTokenRegistry::respond_to_interest`), not
                // the subscriber's; the CURRENT-replay completion arrives
                // as the `Declare(DeclFinal)` handled above. Ignored here.
                _ => {}
            }
        }
    }

    /// [`IterationEvent`] adapter; mirror of the other
    /// application-layer registries. Routes `FramePayload` events
    /// through [`Self::dispatch_messages`]; other variants are
    /// no-ops here (the liveliness signal path lives entirely in the
    /// `Declare` / `Interest` MIDs).
    #[cfg(feature = "alloc")]
    pub fn dispatch_iteration_event(
        &mut self,
        event: IterationEvent<'_>,
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event {
            self.dispatch_messages(messages, peer_keyexpr_table);
        }
    }
}

/// R311gb-3d — AP / `alloc`-profile convenience constructor (the
/// `BoxedLivelinessSampleSink` instantiation only). The no-`alloc`
/// profile uses [`with_sink_backing`](LivelinessSubscriberRegistry::with_sink_backing)
/// + a consumer-supplied sink.
#[cfg(feature = "alloc")]
impl LivelinessSubscriberRegistry<BoxedLivelinessSampleSink> {
    /// New empty AP registry backed by heap-boxed closures. The inferring
    /// shorthand for
    /// [`with_sink_backing`](LivelinessSubscriberRegistry::with_sink_backing):
    /// `LivelinessSubscriberRegistry::new()` fixes
    /// `C = BoxedLivelinessSampleSink`.
    pub fn new() -> Self {
        Self::with_sink_backing()
    }
}

// R311gb (Track 2) — test gate now explicit (was inherited from the
// module's `codec-declare` gate); exercises `dispatch_declare` (owned
// `DeclareOwnedVariant`), now `all(codec-declare, alloc)`-gated.
#[cfg(all(test, feature = "codec-declare"))]
mod tests {
    //! R311ds — behavioural tests migrated here from the
    //! wz-runtime-tokio `declare/liveliness_subscriber.rs` shell
    //! (R311dr-wider-tests carry closure). The shell gated on
    //! `liveliness-subscriber + codec-declare`; here the whole module
    //! is `codec-declare`-gated, so a plain `#[cfg(test)]` suffices.
    //! `Arc<Mutex<…>>` sample-sink capture uses `std` under
    //! `#[cfg(test)]` per the wz-codecs sibling-crate convention;
    //! production stays no_std.

    use super::*;
    use alloc::boxed::Box;
    use alloc::string::{String, ToString};
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use hashbrown::HashMap;
    use wz_codecs::declare::DeclareOwnedVariant;
    use wz_codecs::interest::Interest;
    use wz_codecs::interest_body::InterestBody;
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_local::WireexprLocal;
    use wz_session_core_test_support::*;

    use crate::network_message::NetworkMessage;

    fn make_subscriber(
        capture: Arc<Mutex<Vec<(LivelinessSampleKind, String, u64)>>>,
    ) -> BoxedLivelinessSampleSink {
        BoxedLivelinessSampleSink::new(move |sample: LivelinessSample<'_>| {
            capture.lock().unwrap().push((
                sample.kind,
                sample.keyexpr.to_string(),
                sample.token_id,
            ));
        })
    }

    #[test]
    fn new_registry_starts_empty() {
        let reg = LivelinessSubscriberRegistry::new();
        assert_eq!(reg.slot_count(), 0);
        assert_eq!(reg.peer_token_count(), 0);
        assert!(reg.keyexpr(0).is_none());
        assert!(!reg.history_complete(0));
    }

    #[test]
    fn register_then_unregister_clears_slot() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        assert!(reg
            .register(7, "liveliness/dev", false, make_subscriber(sink.clone()))
            .unwrap());
        assert_eq!(reg.slot_count(), 1);
        assert_eq!(reg.keyexpr(7), Some("liveliness/dev"));
        assert!(reg.unregister(7));
        assert_eq!(reg.slot_count(), 0);
        assert!(!reg.unregister(7), "double-unregister is idempotent");
    }

    #[test]
    fn duplicate_register_rejected() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        assert!(reg
            .register(7, "a", false, make_subscriber(sink.clone()))
            .unwrap());
        assert!(
            !reg.register(7, "b", false, make_subscriber(sink.clone()))
                .unwrap(),
            "second register on same interest_id must reject"
        );
        assert_eq!(reg.keyexpr(7), Some("a"), "first registration retained");
    }

    #[test]
    fn decl_token_dispatches_put_sample_on_pattern_match() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "liveliness/*", false, make_subscriber(sink.clone()))
            .unwrap();

        let body =
            DeclareOwnedVariant::CodecZenohDeclToken(decl_token(42, 0, Some("liveliness/dev42")));
        reg.dispatch_declare(&body, &HashMap::new());

        let captured = sink.lock().unwrap().clone();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].0, LivelinessSampleKind::Put);
        assert_eq!(captured[0].1, "liveliness/dev42");
        assert_eq!(captured[0].2, 42);
        assert_eq!(reg.peer_token_count(), 1);
    }

    /// R311y521 — link loss fires a Delete for EVERY remote token and empties
    /// the table, as pico's `_z_liveliness_subscription_undeclare_all` does.
    ///
    /// The keyexprs are asserted by NAME, not just counted: a flush that fired
    /// the right number of Deletes with a wrong or empty keyexpr would tell a
    /// subscriber the wrong token died.
    #[test]
    fn link_loss_flushes_every_remote_token_as_a_delete() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "liveliness/**", false, make_subscriber(sink.clone()))
            .unwrap();
        for (id, ke) in [
            (7u64, "liveliness/a"),
            (3, "liveliness/b"),
            (9, "liveliness/c"),
        ] {
            reg.dispatch_declare(
                &DeclareOwnedVariant::CodecZenohDeclToken(decl_token(id, 0, Some(ke))),
                &HashMap::new(),
            );
        }
        assert_eq!(reg.peer_token_count(), 3);
        sink.lock().unwrap().clear();

        assert_eq!(reg.flush_peer_tokens_on_link_loss(), 3);

        let captured = sink.lock().unwrap().clone();
        assert_eq!(captured.len(), 3, "one Delete per remote token");
        assert!(
            captured.iter().all(|c| c.0 == LivelinessSampleKind::Delete),
            "link loss produces Deletes, never Puts: {captured:?}"
        );
        // Ordered by token id, which is this impl's determinism choice.
        assert_eq!(
            captured.iter().map(|c| c.1.as_str()).collect::<Vec<_>>(),
            vec!["liveliness/b", "liveliness/a", "liveliness/c"],
            "each Delete must name the token that actually died"
        );
        assert_eq!(
            reg.peer_token_count(),
            0,
            "the table is emptied, so a re-declare after reopen is a fresh Put \
             rather than a second one for a token the app was never told died"
        );
    }

    /// The negative arm: a flush with nothing registered is a no-op that fires
    /// no sample. Without it, "3 Deletes" above could be satisfied by a flush
    /// that fabricates one per SLOT rather than per TOKEN.
    #[test]
    fn link_loss_with_no_remote_tokens_fires_nothing() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "liveliness/**", false, make_subscriber(sink.clone()))
            .unwrap();
        assert_eq!(reg.flush_peer_tokens_on_link_loss(), 0);
        assert!(sink.lock().unwrap().is_empty());
    }

    /// A token the subscriber's pattern does NOT match is still flushed from
    /// the table, but fires no sample — the same asymmetry `dispatch_declare`
    /// already has, kept explicit so a future "fan to every slot" shortcut
    /// cannot pass silently.
    #[test]
    fn link_loss_flushes_an_unmatched_token_without_firing_it() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "liveliness/**", false, make_subscriber(sink.clone()))
            .unwrap();
        reg.dispatch_declare(
            &DeclareOwnedVariant::CodecZenohDeclToken(decl_token(4, 0, Some("other/thing"))),
            &HashMap::new(),
        );
        sink.lock().unwrap().clear();

        assert_eq!(reg.flush_peer_tokens_on_link_loss(), 1);
        assert!(sink.lock().unwrap().is_empty());
        assert_eq!(reg.peer_token_count(), 0);
    }

    #[test]
    fn undecl_token_dispatches_delete_sample_using_remembered_keyexpr() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "liveliness/**", false, make_subscriber(sink.clone()))
            .unwrap();

        let decl =
            DeclareOwnedVariant::CodecZenohDeclToken(decl_token(7, 0, Some("liveliness/svc/api")));
        reg.dispatch_declare(&decl, &HashMap::new());

        let undecl = DeclareOwnedVariant::CodecZenohUndeclToken(undecl_token(7));
        reg.dispatch_declare(&undecl, &HashMap::new());

        let captured = sink.lock().unwrap().clone();
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[1].0, LivelinessSampleKind::Delete);
        assert_eq!(
            captured[1].1, "liveliness/svc/api",
            "Delete keyexpr resolved from remembered DeclToken arrival",
        );
        assert_eq!(captured[1].2, 7);
        assert_eq!(
            reg.peer_token_count(),
            0,
            "UndeclToken arrival removes the (id, keyexpr) entry",
        );
    }

    #[test]
    fn non_matching_keyexpr_does_not_fire_callback() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "alpha/*", false, make_subscriber(sink.clone()))
            .unwrap();

        let body =
            DeclareOwnedVariant::CodecZenohDeclToken(decl_token(5, 0, Some("beta/instance")));
        reg.dispatch_declare(&body, &HashMap::new());

        assert!(
            sink.lock().unwrap().is_empty(),
            "DeclToken on a non-matching keyexpr must not fan",
        );
        assert_eq!(
            reg.peer_token_count(),
            1,
            "peer-token table still records the arrival; only the subscriber fan was filtered",
        );
    }

    #[test]
    fn unresolvable_mapping_id_drops_dispatch() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_for_cb = fired.clone();
        reg.register(
            1,
            "**",
            false,
            BoxedLivelinessSampleSink::new(move |_| {
                fired_for_cb.fetch_add(1, Ordering::SeqCst);
            }),
        )
        .unwrap();
        // mapping_id=55 with no peer-keyexpr table entry → resolve_wireexpr returns None.
        let body = DeclareOwnedVariant::CodecZenohDeclToken(decl_token(1, 55, None));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "unresolvable mapping_id must drop dispatch; no fire, no peer-token entry",
        );
        assert_eq!(reg.peer_token_count(), 0);
    }

    #[test]
    fn aliased_keyexpr_resolves_through_peer_table() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "liveliness/*", false, make_subscriber(sink.clone()))
            .unwrap();

        // Peer declared mapping_id=10 → "liveliness".
        let mut table = HashMap::new();
        table.insert(10u64, "liveliness".to_string());

        // DeclToken with mapping_id=10 + suffix="/dev42" composes to
        // "liveliness/dev42" through resolve_wireexpr.
        let body = DeclareOwnedVariant::CodecZenohDeclToken(decl_token(99, 10, Some("/dev42")));
        reg.dispatch_declare(&body, &table);

        let captured = sink.lock().unwrap().clone();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].1, "liveliness/dev42");
        assert_eq!(captured[0].2, 99);
    }

    #[test]
    fn multiple_subscribers_fire_in_registration_order_on_overlap() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink1: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        let sink2: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "**", false, make_subscriber(sink1.clone()))
            .unwrap();
        reg.register(2, "alpha/*", false, make_subscriber(sink2.clone()))
            .unwrap();

        let body = DeclareOwnedVariant::CodecZenohDeclToken(decl_token(3, 0, Some("alpha/one")));
        reg.dispatch_declare(&body, &HashMap::new());

        assert_eq!(sink1.lock().unwrap().len(), 1, "** catches all");
        assert_eq!(sink2.lock().unwrap().len(), 1, "alpha/* catches alpha/one");
    }

    /// R311xx — history_complete flips on the responder's
    /// `Declare(DeclFinal)` (echoing the subscriber's interest_id), and
    /// the `slot.history` guard keeps it meaningful only for
    /// history-enabled subscribers (a `history=false` slot stays `false`
    /// even if a DeclFinal echoes its id). Replaces the pre-R311xx test
    /// that wrongly drove completion from an `Interest(Final)` the
    /// responder never sends.
    #[test]
    fn declare_final_marks_history_complete_only_for_history_subscribers() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "a", true, make_subscriber(sink.clone()))
            .unwrap();
        reg.register(2, "b", false, make_subscriber(sink.clone()))
            .unwrap();

        // The responder's CURRENT-replay terminator: one Declare(DeclFinal)
        // per subscriber id, echoing that subscriber's interest_id.
        let messages = vec![
            NetworkMessage::Declare(Box::new(declare_envelope_decl_final_with_interest(1))),
            NetworkMessage::Declare(Box::new(declare_envelope_decl_final_with_interest(2))),
        ];
        reg.dispatch_messages(&messages, &HashMap::new());

        assert!(
            reg.history_complete(1),
            "history-enabled subscriber observes history_complete after Declare(DeclFinal)",
        );
        assert!(
            !reg.history_complete(2),
            "history=false subscriber stays false even if a DeclFinal echoes its id \
             (the slot.history guard — replay was not requested)",
        );
    }

    /// R311xx — an inbound `Interest` is the responder's concern
    /// (`LocalTokenRegistry`), never the subscriber's: it must not touch
    /// `history_complete` regardless of mode. (Pre-R311xx an
    /// `Interest(Final)` wrongly flipped completion; the real terminator
    /// is the `Declare(DeclFinal)` covered above.)
    #[test]
    fn inbound_interest_is_ignored_by_subscriber_registry() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "x", true, make_subscriber(sink.clone()))
            .unwrap();

        let interest = Interest {
            header: 0x19 | 0x40, // FUTURE
            interest_id: 1,
            body: Some(InterestBody {
                header: 0x01 | 0x08 | 0x10 | 0x40,
                keyexpr: Some(Wireexpr {
                    body: WireexprVariant::WireexprLocal(WireexprLocal {
                        id: 0,
                        suffix_len: Some(1),
                        suffix: Some("x"),
                    }),
                }),
            }),
            extensions: None,
        }
        .try_into_owned()
        .unwrap();
        let messages = vec![NetworkMessage::Interest(interest)];
        reg.dispatch_messages(&messages, &HashMap::new());

        assert!(
            !reg.history_complete(1),
            "an inbound Interest must not flip history_complete (responder's concern)",
        );
    }

    /// R311xx (diagnose-first) — the RESPONDER terminates a CURRENT
    /// replay with `Declare(DeclareFinal){interest_id}`, NOT
    /// `Interest(Final)`: see [`crate::declare::local_token`]'s
    /// `build_final_reply` and pico `_z_interest_process_declare_final`
    /// (`vendor/zenoh-pico/src/session/interest.c:508`); the sibling
    /// `_z_interest_process_interest_final` (interest.c:524) is a TODO
    /// no-op. A history-subscriber must flip `history_complete` on that
    /// inbound `Declare(DeclFinal)` whose `interest_id` echoes its own,
    /// exactly as the liveliness-GET registry fires its final
    /// ([`crate::declare::liveliness_get`] `fire_final_for`).
    #[test]
    fn history_complete_fires_on_responder_declare_final() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "live/**", true, make_subscriber(sink.clone()))
            .unwrap();

        // The responder's terminator: Declare(DeclFinal) carrying our
        // interest_id (build_final_reply -> interest_id = Some(1)).
        let decl_final = declare_envelope_decl_final_with_interest(1);
        let messages = vec![NetworkMessage::Declare(Box::new(decl_final))];
        reg.dispatch_messages(&messages, &HashMap::new());

        assert!(
            reg.history_complete(1),
            "history-subscriber must flip history_complete on the responder's \
             Declare(DeclFinal), not on an Interest(Final) the responder never sends",
        );
    }

    #[test]
    fn other_declare_arms_are_noops() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "**", false, make_subscriber(sink.clone()))
            .unwrap();

        // DeclSubscriber + DeclQueryable arms must not route into the
        // liveliness-subscriber registry.
        let messages =
            vec![
                NetworkMessage::Declare(Box::new(declare_envelope_decl_subscriber(
                    decl_subscriber(2, 0, Some("anything")),
                ))),
                NetworkMessage::Declare(Box::new(declare_envelope_decl_queryable(decl_queryable(
                    3,
                    0,
                    Some("anything"),
                )))),
            ];
        reg.dispatch_messages(&messages, &HashMap::new());

        assert!(
            sink.lock().unwrap().is_empty(),
            "non-token Declare arms must not fan into LivelinessSubscriberRegistry",
        );
    }

    /// R311gb (Track 2) — direct exercise of the no-heap fire entry
    /// `dispatch_sample_borrowed`: the MCU path delivers a borrowed
    /// `LivelinessSample` to matching slots with no codec / no
    /// `peer_token_table` (the caller supplies the resolved keyexpr).
    #[test]
    fn dispatch_sample_borrowed_fans_to_matching_slot_no_codec() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let cap: Arc<Mutex<Vec<(LivelinessSampleKind, String, u64)>>> =
            Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "live/**", false, make_subscriber(cap.clone()))
            .unwrap();

        let fired = reg.dispatch_sample_borrowed(LivelinessSampleKind::Put, "live/dev/3", 77);
        assert_eq!(fired, 1);
        let got = cap.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, LivelinessSampleKind::Put);
        assert_eq!(got[0].1, "live/dev/3");
        assert_eq!(got[0].2, 77);
    }

    /// R311xx — integrated responder->subscriber proof across BOTH
    /// liveliness registries (the wiring the isolated unit tests +
    /// [`history_complete_fires_on_responder_declare_final`] could not
    /// give): a [`LocalTokenRegistry`] holding a token receives the
    /// history-subscriber's CurrentFuture Interest, stages the
    /// current-token replay, and that replay — reified into the wire
    /// `Declare(DeclToken)`+`Declare(DeclFinal)` the sink emits — drives
    /// the subscriber to (a) fire the current token as a PUT sample AND
    /// (b) flip `history_complete` on the terminating `DeclFinal`. This
    /// exercises both R311xx fixes together: the responder gates the
    /// replay on the CURRENT bit, and the subscriber completes the
    /// snapshot on the `DeclFinal` (not an `Interest(Final)`).
    #[cfg(all(feature = "alloc", feature = "liveliness-token"))]
    #[test]
    fn responder_replay_drives_subscriber_put_and_history_complete() {
        use crate::bounded::BoundedVec;
        use crate::caps;
        use crate::declare::local_token::{DeclResponseItem, LocalTokenRegistry};
        use wz_codecs::interest::InterestOwned;
        use wz_codecs::interest_body::InterestBodyOwned;
        use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};
        use wz_codecs::wireexpr_local::WireexprLocalOwned;

        // Responder: holds one token, receives the subscriber's
        // CurrentFuture (C|F) tokens Interest, stages the replay.
        let mut responder = LocalTokenRegistry::new();
        responder.register(9, "live/dev1").unwrap();

        let sub_interest_id = 3u64;
        let interest = InterestOwned {
            header: 0x19 | 0x20 | 0x40, // CurrentFuture: CURRENT + FUTURE
            interest_id: sub_interest_id,
            body: Some(InterestBodyOwned {
                header: 0x08, // tokens
                keyexpr: Some(WireexprOwned {
                    body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                        id: 0,
                        suffix_len: Some(7),
                        suffix: Some(crate::codec_owned::owned_string("live/**").unwrap()),
                    }),
                }),
            }),
            extensions: None,
        };
        let mut pending: BoundedVec<DeclResponseItem, { caps::MAX_PENDING_DECLARES }> =
            BoundedVec::new();
        responder.respond_to_interest(&interest, &HashMap::new(), &mut pending);

        // Reify the staged replay into the wire Declares the sink emits:
        // one Declare(DeclToken{interest_id}) per match + the terminating
        // Declare(DeclFinal{interest_id}) (build_token_reply /
        // build_final_reply shape — interest_id echoed, inline keyexpr).
        let mut wire: Vec<NetworkMessage> = Vec::new();
        for item in pending.iter() {
            match item {
                DeclResponseItem::Token {
                    token_id,
                    interest_id,
                } => {
                    let ke = responder.keyexpr_for(*token_id).unwrap();
                    wire.push(NetworkMessage::Declare(Box::new(
                        declare_envelope_decl_token_with_interest(
                            decl_token(*token_id, 0, Some(ke)),
                            *interest_id,
                        ),
                    )));
                }
                DeclResponseItem::Final { interest_id } => {
                    wire.push(NetworkMessage::Declare(Box::new(
                        declare_envelope_decl_final_with_interest(*interest_id),
                    )));
                }
            }
        }

        // Subscriber: history=true on live/**, consumes the replay.
        let mut sub = LivelinessSubscriberRegistry::new();
        let cap: Arc<Mutex<Vec<(LivelinessSampleKind, String, u64)>>> =
            Arc::new(Mutex::new(Vec::new()));
        sub.register(
            sub_interest_id,
            "live/**",
            true,
            make_subscriber(cap.clone()),
        )
        .unwrap();
        sub.dispatch_messages(&wire, &HashMap::new());

        // (a) the current token surfaced as a PUT sample...
        let got = cap.lock().unwrap().clone();
        assert_eq!(got.len(), 1, "exactly the one current token replayed");
        assert_eq!(got[0].0, LivelinessSampleKind::Put);
        assert_eq!(got[0].1, "live/dev1");
        assert_eq!(got[0].2, 9);
        // (b) ...and the DeclFinal terminator completed the snapshot.
        assert!(
            sub.history_complete(sub_interest_id),
            "the responder's Declare(DeclFinal) must complete the history snapshot",
        );
    }
}
