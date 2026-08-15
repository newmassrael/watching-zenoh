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
use crate::wireexpr_resolve::resolve_wireexpr_in;
// R311y739 — the two-space PAIR is `alloc`-only: `dispatch_messages` /
// `dispatch_iteration_event` name it in their signatures under that gate alone,
// while only the `Declare` arm inside them resolves and so carries `codec-declare`.
#[cfg(feature = "alloc")]
use crate::wireexpr_resolve::MappingSpaces;

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
        // R311y790 — a history subscriber is owed the tokens THIS session
        // already knows before the peer's CURRENT reply adds any. Both
        // upstreams do the replay inside their register function
        // (zenoh-pico `_z_register_liveliness_subscriber` calls
        // `_z_liveliness_subscription_trigger_history` between the register
        // and the Interest emit, `src/net/liveliness.c:196-209`; zenoh runs
        // it in `declare_liveliness_subscriber_inner` before
        // `send_interest`, `zenoh/src/api/session.rs:1768-1815`), and so
        // does this — folding it in is what makes both wz declare paths
        // (literal and aliased) correct with one rule instead of two
        // call-site copies that can drift.
        if history {
            self.replay_known_tokens(interest_id);
        }
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
    pub fn dispatch_declare<'a>(
        &mut self,
        body: &DeclareOwnedVariant,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        match body {
            DeclareOwnedVariant::CodecZenohDeclToken(decl) => {
                let resolved = match resolve_wireexpr_in(&decl.keyexpr.body, peer_keyexpr_table) {
                    Some(s) => s,
                    None => return,
                };
                // R311y769 — the FIRST declaration of an id wins, and a repeat
                // is silent. zenoh wraps this whole arm in
                // `if let Entry::Vacant(e) = state.remote_tokens.entry(m.id)`
                // (`zenoh/src/api/session.rs:2633`), so an OCCUPIED id neither
                // re-inserts nor calls the subscriber back.
                //
                // Both halves matter and they are one decision, not two. Firing
                // again would tell an application that counts presence that the
                // same token appeared twice; re-inserting would rebind the id to
                // the newer keyexpr, and the eventual `UndeclToken` — which
                // carries only the id — would then name a keyexpr the token was
                // never declared on. Skipping the arm entirely is what keeps the
                // retraction truthful.
                if self.peer_token_table.contains_key(&decl.id) {
                    return;
                }
                self.peer_token_table.insert(decl.id, resolved.clone());
                self.fan_to_matching_slots(LivelinessSampleKind::Put, &resolved, decl.id);
            }
            DeclareOwnedVariant::CodecZenohUndeclToken(undecl) => {
                let resolved = match self.peer_token_table.remove(&undecl.id) {
                    Some(s) => s,
                    // R311y769 — the id is unknown, so FALL BACK to the keyexpr
                    // the retraction carries itself. zenoh reaches its
                    // `else if m.ext_wire_expr.wire_expr != WireExpr::empty()`
                    // branch here (`api/session.rs:2679-2708`) and delivers the
                    // Delete all the same.
                    //
                    // This is what a SOURCED retraction always looks like: zenoh
                    // identifies a sourced token by its KEYEXPR, not an id (the
                    // id is 0 — see
                    // [`build_undeclare_token_with_keyexpr`](crate::declare_build::build_undeclare_token_with_keyexpr)),
                    // so the table can never hold it and dropping on a table miss
                    // discarded every one of them.
                    //
                    // [`resolve_ext_keyexpr`](crate::declare_ext_keyexpr::resolve_ext_keyexpr)
                    // rather than the literal-only `read_ext_keyexpr`, because
                    // the ext may name an alias; and the PEER half of the pair
                    // because upstream pins this resolution to the remote space
                    // (`wireexpr_to_keyexpr(.., false)`) regardless of what the
                    // ext's own mapping bit says. An ext that is absent or names
                    // an alias the peer never declared resolves to `None`, and
                    // then nothing fires — a Delete for a keyexpr nobody named
                    // would be worse than the drop this replaces.
                    None => match crate::declare_ext_keyexpr::resolve_ext_keyexpr(
                        undecl.extensions.as_ref(),
                        peer_keyexpr_table.peer(),
                    ) {
                        Some(s) => s,
                        None => return,
                    },
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

    /// R311y790 — replay the peer tokens this session ALREADY knows to the one
    /// subscriber `interest_id` names, as `Put` samples. Returns how many were
    /// replayed. Called by [`register`](Self::register) for a `history = true`
    /// slot; both upstreams do exactly this at declare time — zenoh collects
    /// `state.remote_tokens` intersecting the new subscriber's keyexpr and
    /// calls its callback with an empty-payload `Put`
    /// (`zenoh/src/api/session.rs:1768-1801`), and zenoh-pico's
    /// `_z_liveliness_subscription_trigger_history` walks `zn->_remote_tokens`
    /// and does the same (`vendor/zenoh-pico/src/net/liveliness.c:133-166`).
    ///
    /// The peer's CURRENT reply is NOT a substitute for this, which is why it
    /// is not merely a latency optimisation: a zenoh router suppresses
    /// re-declaring a token it has already declared to that face
    /// (`net/routing/hat/router/token.rs:127`), so a SECOND history subscriber
    /// on one wz session received an EMPTY history where both upstreams give
    /// it the full set — silently, since the responder still terminates the
    /// replay with its `Declare(DeclFinal)` and `history_complete` flips true.
    ///
    /// ONLY the named slot fires; this is deliberately not
    /// `fan_to_matching_slots` (a code span, not a link: that helper is
    /// private and a doc link to it is a broken one). The replay is
    /// owed to the subscriber that just declared — every other matching slot
    /// was already told about these tokens when they arrived live, and firing
    /// them again would report the same token appearing twice to an
    /// application that counts presence.
    ///
    /// The replay cannot double-fire against the peer's own CURRENT reply
    /// either: an inbound `DeclToken` for an id already in `peer_token_table`
    /// is dropped by the R311y769 first-declaration-wins guard in
    /// `dispatch_declare` (a code span, not a link: that method is gated on
    /// `all(codec-declare, alloc)` and the link breaks in builds without it).
    ///
    /// Replay order is by token id. That is a TEST-determinism choice and not
    /// a wire property — the same call the sibling
    /// [`flush_peer_tokens_on_link_loss`](Self::flush_peer_tokens_on_link_loss)
    /// records, and neither upstream's map order is defined.
    ///
    /// The BODY is `alloc`-gated, not the function (signature stability, the
    /// same shape as the sibling flush): `peer_token_table` is the wire-side
    /// resolution state and does not exist on the no-alloc control plane, so
    /// `0` is the honest answer there — nothing is known to replay.
    pub fn replay_known_tokens(&mut self, interest_id: u64) -> usize {
        #[cfg(feature = "alloc")]
        {
            let Self {
                slots,
                peer_token_table,
            } = self;
            if peer_token_table.is_empty() {
                return 0;
            }
            let slot = match slots.iter_mut().find(|s| s.interest_id == interest_id) {
                Some(s) => s,
                None => return 0,
            };
            let mut matched: alloc::vec::Vec<(u64, &str)> = alloc::vec::Vec::new();
            {
                // Same chunk view the live fan builds, hoisted out of the scan
                // because one pattern is being matched against many keyexprs
                // here rather than one keyexpr against many patterns. An
                // over-long pattern is skipped rather than matched truncated,
                // the same refusal `fan_to_matching_slots` makes.
                let mut chunks: BoundedVec<&str, MAX_KEYEXPR_CHUNKS> = BoundedVec::new();
                for c in slot.pattern.split('/') {
                    if chunks.push(c).is_err() {
                        return 0;
                    }
                }
                for (token_id, keyexpr) in peer_token_table.iter() {
                    if keyexpr_pattern_matches(&chunks, keyexpr) {
                        matched.push((*token_id, keyexpr.as_str()));
                    }
                }
            }
            matched.sort_by_key(|(token_id, _)| *token_id);
            for (token_id, keyexpr) in &matched {
                slot.sink.on_sample(LivelinessSample {
                    kind: LivelinessSampleKind::Put,
                    keyexpr,
                    token_id: *token_id,
                });
            }
            matched.len()
        }
        #[cfg(not(feature = "alloc"))]
        {
            let _ = interest_id;
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
    pub fn dispatch_messages<'a>(
        &mut self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        self.dispatch_messages_unclaimed(messages, peer_keyexpr_table, &|_| false);
    }

    /// [`Self::dispatch_messages`], skipping any `Declare` whose outer
    /// `interest_id` a caller CLAIMS.
    ///
    /// A liveliness GET's replies are interest_id-tagged and match this
    /// registry's keyexpr patterns just as an unsolicited declaration does, so
    /// without this filter a snapshot fires every matching subscription: the
    /// application is told a token "came alive" at the instant of its own
    /// unrelated query, and the token enters the peer table as if it had been
    /// announced. zenoh routes such a declare to the query and `return`s
    /// before both (`zenoh/src/api/session.rs:2609-2632`).
    ///
    /// THE CLAIM IS PER-ID, NOT PER-SOLICITATION, and that distinction is the
    /// whole of the rule: a HISTORY subscriber's own CURRENT replay is
    /// interest_id-tagged too, and it must arrive. Only an id a pending GET
    /// still owns is skipped.
    ///
    /// The two entry points share ONE body: `dispatch_messages` is this with a
    /// closure that claims nothing.
    #[cfg(feature = "alloc")]
    pub fn dispatch_messages_unclaimed<'a>(
        &mut self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
        claimed: &dyn Fn(u64) -> bool,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        // R311q — `peer_keyexpr_table` is only consumed inside the
        // cfg-gated `NetworkMessage::Declare` arm below; the
        // explicit `let _ = ...` on the codec-declare-OFF build
        // silences the unused-variable lint without changing the
        // signature (signature-stability principle: dispatch_messages
        // keeps the same shape across builds so caller-side glue
        // need not feature-detect).
        //
        // `claimed` is in the same position and gets the same treatment
        // rather than an `#[allow(unused_variables)]` on the parameter: a
        // per-parameter allow would keep silencing the lint if a later
        // change stopped reading it in the codec-declare build too.
        #[cfg(not(feature = "codec-declare"))]
        let _ = (peer_keyexpr_table, claimed);
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
                    // The GET's claim: this declare answers a pending
                    // liveliness snapshot, so it is not this registry's — not
                    // its Put fan, and not its history-complete marker either
                    // (a GET's DeclFinal terminates the GET, not a
                    // subscriber's replay).
                    if decl.interest_id.is_some_and(claimed) {
                        continue;
                    }
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
    pub fn dispatch_iteration_event<'a>(
        &mut self,
        event: IterationEvent<'_>,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        self.dispatch_iteration_event_unclaimed(event, peer_keyexpr_table, &|_| false);
    }

    /// [`Self::dispatch_iteration_event`] with the claim filter of
    /// [`Self::dispatch_messages_unclaimed`].
    #[cfg(feature = "alloc")]
    pub fn dispatch_iteration_event_unclaimed<'a>(
        &mut self,
        event: IterationEvent<'_>,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
        claimed: &dyn Fn(u64) -> bool,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event {
            self.dispatch_messages_unclaimed(messages, peer_keyexpr_table, claimed);
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

    /// R311y740 (N37) — the own-space WITNESS for the liveliness-SUBSCRIBER
    /// plane. Distinct from the declarer plane's witness even though both
    /// ingest `DeclToken`: this registry resolves the keyexpr and then MATCHES
    /// it against registered patterns, so a wrong-space read changes which
    /// slot fires, not merely what string it carries.
    ///
    /// THE DISCRIMINATOR is the collision plus two disjoint patterns: id 7
    /// resolves `ours/dev` in our space and `theirs/dev` in the peer's, and a
    /// slot is registered for each. Reading the wrong space fires the OTHER
    /// subscriber.
    #[test]
    fn an_own_space_alias_resolves_in_our_space_on_the_liveliness_subscriber_plane() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let ours: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        let theirs: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "ours/*", false, make_subscriber(ours.clone()))
            .unwrap();
        reg.register(2, "theirs/*", false, make_subscriber(theirs.clone()))
            .unwrap();

        let mut peer = HashMap::new();
        peer.insert(7u64, "theirs/dev".to_string());
        let mut own = HashMap::new();
        own.insert(7u64, "ours/dev".to_string());

        let body = DeclareOwnedVariant::CodecZenohDeclToken(decl_token_nonlocal(42, 7, None));
        reg.dispatch_declare(&body, MappingSpaces::with_own(&peer, &own));

        assert_eq!(
            ours.lock().unwrap().len(),
            1,
            "an M=0 alias names OUR space; id 7 is `ours/dev` there",
        );
        assert_eq!(
            theirs.lock().unwrap().len(),
            0,
            "reading the peer's space for an M=0 alias would have fired this \
             subscriber instead",
        );
    }

    /// ANTI-VACUITY twin: with only the peer's space the same record fires
    /// NEITHER slot — so the witness above measures the installed own space,
    /// not merely that some table held id 7.
    #[test]
    fn without_an_own_space_the_liveliness_subscriber_plane_refuses_the_same_alias() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let ours: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        let theirs: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "ours/*", false, make_subscriber(ours.clone()))
            .unwrap();
        reg.register(2, "theirs/*", false, make_subscriber(theirs.clone()))
            .unwrap();

        let mut peer = HashMap::new();
        peer.insert(7u64, "theirs/dev".to_string());

        let body = DeclareOwnedVariant::CodecZenohDeclToken(decl_token_nonlocal(42, 7, None));
        reg.dispatch_declare(&body, &peer);

        assert_eq!(ours.lock().unwrap().len(), 0);
        assert_eq!(
            theirs.lock().unwrap().len(),
            0,
            "with no own space an M=0 alias must refuse -- never fall back to \
             the peer's table",
        );
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

    /// R311y790 — THE HEADLINE WITNESS. A history subscriber declared while
    /// the session already knows remote tokens is replayed them as `Put`s at
    /// declare time, as both upstreams do (zenoh `api/session.rs:1768-1801`,
    /// pico `net/liveliness.c:133-166`).
    ///
    /// The SECOND subscriber is the shape that actually broke: a zenoh router
    /// suppresses re-declaring a token it has already declared to that face
    /// (`hat/router/token.rs:127`), so waiting for the peer's CURRENT reply
    /// hands it an empty history while the first subscriber has the full set.
    ///
    /// THE DISCRIMINATOR is the untouched first subscriber. Replaying through
    /// the shared `fan_to_matching_slots` would satisfy every count below
    /// except that one — subscriber A would be told a second time about
    /// tokens it was told about live.
    #[test]
    fn a_second_history_subscriber_is_replayed_the_tokens_already_known() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let first: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "liveliness/**", false, make_subscriber(first.clone()))
            .unwrap();
        // Ids deliberately out of ascending order: the replay is id-ordered.
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
        assert_eq!(first.lock().unwrap().len(), 3, "live arrivals fired A");

        let second: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(2, "liveliness/**", true, make_subscriber(second.clone()))
            .unwrap();

        let replayed = second.lock().unwrap().clone();
        assert_eq!(
            replayed,
            vec![
                (LivelinessSampleKind::Put, "liveliness/b".to_string(), 3),
                (LivelinessSampleKind::Put, "liveliness/a".to_string(), 7),
                (LivelinessSampleKind::Put, "liveliness/c".to_string(), 9),
            ],
            "a history subscriber is owed every already-known token as a Put, \
             id-ordered",
        );
        assert_eq!(
            first.lock().unwrap().len(),
            3,
            "the replay is owed to the DECLARING slot only -- subscriber A was \
             already told about these tokens when they arrived live",
        );
    }

    /// The `history` flag is what gates the replay, exactly as it gates the
    /// CURRENT bit on the wire (pico `net/liveliness.c:196`, zenoh's
    /// `if history { .. } else { vec![] }` at `api/session.rs:1768-1777`). A
    /// future-only subscriber asked for no snapshot and must be given none.
    #[test]
    fn a_non_history_subscriber_is_replayed_nothing() {
        let mut reg = LivelinessSubscriberRegistry::new();
        reg.dispatch_declare(
            &DeclareOwnedVariant::CodecZenohDeclToken(decl_token(7, 0, Some("liveliness/a"))),
            &HashMap::new(),
        );

        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "liveliness/**", false, make_subscriber(sink.clone()))
            .unwrap();

        assert_eq!(
            sink.lock().unwrap().len(),
            0,
            "future-only asked for no snapshot; replaying anyway would deliver \
             a Put for a token that arrived before the subscriber existed",
        );
    }

    /// The replay is keyexpr-matched by the DECLARING subscriber's own
    /// pattern, the same intersection both upstreams filter on
    /// (`key_expr.intersects(token)` / `_z_keyexpr_intersects`) — a known
    /// token outside the pattern is not owed to it.
    #[test]
    fn the_replay_is_filtered_by_the_declaring_subscribers_pattern() {
        let mut reg = LivelinessSubscriberRegistry::new();
        for (id, ke) in [(7u64, "liveliness/a"), (8, "other/b")] {
            reg.dispatch_declare(
                &DeclareOwnedVariant::CodecZenohDeclToken(decl_token(id, 0, Some(ke))),
                &HashMap::new(),
            );
        }
        assert_eq!(reg.peer_token_count(), 2);

        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "liveliness/*", true, make_subscriber(sink.clone()))
            .unwrap();

        let replayed = sink.lock().unwrap().clone();
        assert_eq!(
            replayed,
            vec![(LivelinessSampleKind::Put, "liveliness/a".to_string(), 7)],
            "only the tokens the subscriber's pattern matches are replayed",
        );
    }

    /// R311y790 + R311y769 COMPOSE: after the local replay, the peer's own
    /// CURRENT reply for the same token id fires nothing, because
    /// `dispatch_declare` drops a `DeclToken` whose id the table already
    /// holds (first-declaration-wins, zenoh's `Entry::Vacant` arm at
    /// `api/session.rs:2633`). Without that guard the replay would DOUBLE the
    /// history it exists to supply, which is why this pin lives beside it.
    #[test]
    fn the_replay_and_the_peers_current_reply_do_not_double_fire() {
        let mut reg = LivelinessSubscriberRegistry::new();
        reg.dispatch_declare(
            &DeclareOwnedVariant::CodecZenohDeclToken(decl_token(7, 0, Some("liveliness/a"))),
            &HashMap::new(),
        );

        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "liveliness/**", true, make_subscriber(sink.clone()))
            .unwrap();
        assert_eq!(sink.lock().unwrap().len(), 1, "replayed once at declare");

        // The peer answers the CURRENT interest with the token it already
        // declared before this subscriber existed.
        reg.dispatch_declare(
            &DeclareOwnedVariant::CodecZenohDeclToken(decl_token(7, 0, Some("liveliness/a"))),
            &HashMap::new(),
        );
        assert_eq!(
            sink.lock().unwrap().len(),
            1,
            "the peer's CURRENT reply for an already-known id must not fire a \
             second Put on top of the replay",
        );
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

    /// R311y769 (`liveliness-subscriber`) — a REPEATED `DeclToken` naming an id
    /// the peer already declared fires NOTHING. zenoh wraps the entire arm in
    /// `if let Entry::Vacant(e) = state.remote_tokens.entry(m.id)`
    /// (`zenoh/src/api/session.rs:2633`), so an OCCUPIED id neither re-inserts
    /// nor calls the subscriber back: an application counting presence is never
    /// told the same token appeared twice.
    ///
    /// DISCRIMINATING ON THE KEYEXPR, not only the count. The second declare
    /// names a DIFFERENT keyexpr, and the later Delete must still carry the
    /// FIRST one — an implementation that suppressed the callback but still
    /// overwrote the table would satisfy a count-only assertion and then name
    /// the wrong keyexpr as dead. `Entry::Vacant` suppresses both.
    #[test]
    fn a_repeated_decl_token_for_a_known_id_fires_no_second_put() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "liveliness/**", false, make_subscriber(sink.clone()))
            .unwrap();

        reg.dispatch_declare(
            &DeclareOwnedVariant::CodecZenohDeclToken(decl_token(7, 0, Some("liveliness/first"))),
            &HashMap::new(),
        );
        assert_eq!(
            sink.lock().unwrap().len(),
            1,
            "precondition: the first declare fires"
        );

        reg.dispatch_declare(
            &DeclareOwnedVariant::CodecZenohDeclToken(decl_token(7, 0, Some("liveliness/second"))),
            &HashMap::new(),
        );
        assert_eq!(
            sink.lock().unwrap().len(),
            1,
            "a DeclToken for an already-known id fires no second Put",
        );
        assert_eq!(
            reg.peer_token_count(),
            1,
            "and it adds no second table entry",
        );

        reg.dispatch_declare(
            &DeclareOwnedVariant::CodecZenohUndeclToken(undecl_token(7)),
            &HashMap::new(),
        );
        let captured = sink.lock().unwrap().clone();
        assert_eq!(captured.len(), 2);
        assert_eq!(
            (captured[1].0, captured[1].1.as_str()),
            (LivelinessSampleKind::Delete, "liveliness/first"),
            "the occupied entry was NOT overwritten, so the Delete names the \
             keyexpr the token was actually declared on",
        );
    }

    /// The ANTI-VACUITY twin of the gate above: a DISTINCT id declared after the
    /// first still fires. Without it, "no second Put" would be satisfied by a
    /// registry that had stopped firing Puts altogether.
    #[test]
    fn a_second_distinct_token_id_still_fires_its_own_put() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "liveliness/**", false, make_subscriber(sink.clone()))
            .unwrap();

        for (id, ke) in [(7u64, "liveliness/first"), (8, "liveliness/second")] {
            reg.dispatch_declare(
                &DeclareOwnedVariant::CodecZenohDeclToken(decl_token(id, 0, Some(ke))),
                &HashMap::new(),
            );
        }
        let captured = sink.lock().unwrap().clone();
        assert_eq!(captured.len(), 2, "two distinct ids are two Puts");
        assert_eq!(captured[1].1, "liveliness/second");
        assert_eq!(reg.peer_token_count(), 2);
    }

    /// R311y769 (`liveliness-subscriber`) — an `UndeclToken` for an id this
    /// registry never saw falls back to the keyexpr its OWN `ext_wire_expr`
    /// carries and still delivers the Delete. zenoh's `else if
    /// m.ext_wire_expr.wire_expr != WireExpr::empty()` branch
    /// (`zenoh/src/api/session.rs:2679-2708`) is the whole of this: a retraction
    /// that names its keyexpr does not need the declaration to have been
    /// observed, which is what a SOURCED token (`id == 0`, keyexpr IS the
    /// identity) always looks like.
    ///
    /// The message is built by the PRODUCTION builder
    /// [`build_undeclare_token_with_keyexpr`](crate::declare_build::build_undeclare_token_with_keyexpr),
    /// not a hand-rolled fixture, so what the reader accepts is what wz emits.
    #[test]
    fn an_undecl_token_for_an_unknown_id_falls_back_to_its_ext_keyexpr() {
        use crate::declare_build::build_undeclare_token_with_keyexpr;

        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "liveliness/**", false, make_subscriber(sink.clone()))
            .unwrap();

        let body = build_undeclare_token_with_keyexpr("liveliness/svc/api")
            .expect("build sourced undeclare")
            .body;
        let DeclareOwnedVariant::CodecZenohUndeclToken(ref undecl) = body else {
            unreachable!("the builder emits an UndeclToken")
        };
        assert_eq!(
            undecl.id, 0,
            "precondition: a sourced retraction carries no id, so the table \
             lookup CANNOT be what resolves it",
        );
        assert_eq!(
            reg.peer_token_count(),
            0,
            "precondition: no declaration was ever observed for it",
        );

        reg.dispatch_declare(&body, &HashMap::new());

        let captured = sink.lock().unwrap().clone();
        assert_eq!(
            captured.len(),
            1,
            "the retraction is delivered, not dropped"
        );
        assert_eq!(
            (captured[0].0, captured[0].1.as_str()),
            (LivelinessSampleKind::Delete, "liveliness/svc/api"),
            "the Delete names the keyexpr the ext_wire_expr carried",
        );
    }

    /// The negative arm that keeps the fallback honest: an id-only `UndeclToken`
    /// for an unknown id has NO ext to fall back to and still fires nothing.
    /// zenoh's `else if` guards on a non-empty `ext_wire_expr` for exactly this
    /// reason — without the guard the fallback would fabricate a Delete for a
    /// keyexpr nobody named.
    #[test]
    fn an_undecl_token_for_an_unknown_id_with_no_ext_still_fires_nothing() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "liveliness/**", false, make_subscriber(sink.clone()))
            .unwrap();

        reg.dispatch_declare(
            &DeclareOwnedVariant::CodecZenohUndeclToken(undecl_token(99)),
            &HashMap::new(),
        );
        assert!(
            sink.lock().unwrap().is_empty(),
            "an unknown id with no ext_wire_expr names nothing to retract",
        );
    }

    /// The PRECEDENCE leg: when the id IS known, the REMEMBERED keyexpr wins and
    /// the ext is not consulted. zenoh reaches the ext only in the `else` of the
    /// successful `remote_tokens.remove` (`api/session.rs:2665-2679`), so a
    /// retraction whose ext disagrees with the observed declaration retracts what
    /// was actually declared.
    #[test]
    fn a_known_id_retracts_by_its_remembered_keyexpr_not_the_ext() {
        use crate::declare_build::build_undeclare_token_with_keyexpr;

        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "liveliness/**", false, make_subscriber(sink.clone()))
            .unwrap();

        reg.dispatch_declare(
            &DeclareOwnedVariant::CodecZenohDeclToken(decl_token(
                7,
                0,
                Some("liveliness/declared"),
            )),
            &HashMap::new(),
        );
        sink.lock().unwrap().clear();

        let mut body = build_undeclare_token_with_keyexpr("liveliness/from-the-ext")
            .expect("build sourced undeclare")
            .body;
        let DeclareOwnedVariant::CodecZenohUndeclToken(ref mut undecl) = body else {
            unreachable!("the builder emits an UndeclToken")
        };
        undecl.id = 7;

        reg.dispatch_declare(&body, &HashMap::new());

        let captured = sink.lock().unwrap().clone();
        assert_eq!(captured.len(), 1);
        assert_eq!(
            (captured[0].0, captured[0].1.as_str()),
            (LivelinessSampleKind::Delete, "liveliness/declared"),
            "the observed declaration wins; the ext is the FALLBACK, not an \
             override",
        );
    }

    /// The fallback resolves an ALIASED ext through the peer table, which is why
    /// it funnels through
    /// [`resolve_ext_keyexpr`](crate::declare_ext_keyexpr::resolve_ext_keyexpr)
    /// (alias-capable) rather than the literal-only `read_ext_keyexpr`. zenoh's
    /// fallback calls `wireexpr_to_keyexpr(.., false)`, whose `false` pins the
    /// REMOTE space — the peer's declarations — so this passes the peer half of
    /// the pair and nothing else.
    ///
    /// The second leg is the anti-vacuity one: the SAME message against an EMPTY
    /// table fires nothing, so the first leg measures the table rather than the
    /// suffix bytes.
    #[test]
    fn the_fallback_resolves_an_aliased_ext_through_the_peer_table() {
        use crate::declare_ext_keyexpr::KEYEXPR_EXT_HEADER;
        use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
        use wz_codecs::ext_zbuf::ExtZbufOwned;

        // inner_header 0x03 (local + suffix), VLE id 0x07, suffix "dev".
        let aliased = || ExtEntryOwned {
            header: KEYEXPR_EXT_HEADER,
            body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
                value_len: 5,
                value: crate::codec_owned::owned_bytes(&[0x03, 0x07, b'd', b'e', b'v']).unwrap(),
            }),
        };
        let msg = || {
            let mut u = undecl_token(0);
            u.header |= 0x80; // Z: the inner declaration carries an ext chain
            u.extensions = Some(vec![aliased()]);
            DeclareOwnedVariant::CodecZenohUndeclToken(u)
        };

        let mut peer = HashMap::new();
        peer.insert(7u64, "liveliness/".to_string());

        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "liveliness/**", false, make_subscriber(sink.clone()))
            .unwrap();
        reg.dispatch_declare(&msg(), &peer);
        let captured = sink.lock().unwrap().clone();
        assert_eq!(captured.len(), 1);
        assert_eq!(
            (captured[0].0, captured[0].1.as_str()),
            (LivelinessSampleKind::Delete, "liveliness/dev"),
            "the aliased ext composes the peer's mapping with the suffix",
        );

        let mut bare = LivelinessSubscriberRegistry::new();
        let unresolved: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        bare.register(
            1,
            "liveliness/**",
            false,
            make_subscriber(unresolved.clone()),
        )
        .unwrap();
        bare.dispatch_declare(&msg(), &HashMap::new());
        assert!(
            unresolved.lock().unwrap().is_empty(),
            "an alias the peer never declared resolves to nothing, so no Delete \
             is fabricated",
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
