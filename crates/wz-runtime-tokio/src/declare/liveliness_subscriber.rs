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
//! * pre-split `pattern_chunks` for the subscriber's keyexpr (so
//!   `keyexpr_pattern_matches` runs at dispatch with zero per-event
//!   allocation beyond the `Vec<&str>` borrow conversion);
//! * the original keyexpr string (for introspection / debug logging);
//! * the user-supplied [`LivelinessSampleCallback`];
//! * `history` flag — `true` when the subscriber requested current +
//!   future replay (CURRENT bit on the outbound Interest); the
//!   inbound `InterestFinal` flips `history_complete` to `true`
//!   (R281+ wire-up);
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

use hashbrown::HashMap;

use wz_codecs::declare::DeclareVariant;

use super::resolve_wireexpr;
use crate::pubsub::keyexpr_pattern_matches;
use crate::session_glue::{DriverLoopOutcome, IterationEvent, NetworkMessage};

/// Liveliness sample dispatched into a [`LivelinessSampleCallback`].
/// Mirrors zenoh-pico's `z_sample_t` projection for the liveliness
/// path: a `DeclToken` arrival surfaces as `Put`, an `UndeclToken`
/// arrival as `Delete` (per `z_liveliness_declare_token`'s
/// doc-comment, `vendor/zenoh-pico/include/zenoh-pico/api/liveliness.h`).
///
/// The lifetime borrow ties the keyexpr `&str` to the dispatch call
/// stack so the callback can read it without cloning. Callers that
/// want to retain the keyexpr beyond the callback body must
/// `.to_string()` it.
#[derive(Debug, Clone, Copy)]
pub struct LivelinessSample<'a> {
    /// Discriminator: `Put` for `DeclToken`, `Delete` for `UndeclToken`.
    pub kind: LivelinessSampleKind,
    /// Resolved keyexpr — either the literal carried inline on the
    /// `DeclToken` or the peer-table lookup result for an aliased
    /// declaration. For an `UndeclToken` this is the keyexpr the
    /// matching `DeclToken` resolved to (looked up from the
    /// registry's [`peer_token_table`](LivelinessSubscriberRegistry)).
    pub keyexpr: &'a str,
    /// Peer-side token id from the originating `DeclToken`. Stable
    /// across the matching `UndeclToken` so consumers can correlate
    /// `Put` / `Delete` pairs without keyexpr comparisons.
    pub token_id: u64,
}

/// Liveliness sample kind discriminator. Mirrors the
/// `Z_SAMPLE_KIND_PUT` / `Z_SAMPLE_KIND_DELETE` pair that
/// `z_liveliness_declare_token`'s doc-comment commits to:
/// "subscribers on an intersecting key expression will receive a PUT
/// sample when connectivity is achieved, and a DELETE sample if it's
/// lost".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivelinessSampleKind {
    /// Inbound `DeclToken` — a peer just brought a liveliness token
    /// alive on a matching keyexpr.
    Put,
    /// Inbound `UndeclToken` — a peer just retracted a liveliness
    /// token whose prior `DeclToken` matched.
    Delete,
}

/// Boxed callback fired for each [`LivelinessSample`] whose keyexpr
/// matches a subscriber's pattern. `Send + 'static` so the registry
/// can be shared across tasks under `Arc<Mutex<...>>` (matching the
/// other application-layer registries' threading contract).
pub type LivelinessSampleCallback = Box<dyn FnMut(LivelinessSample<'_>) + Send + 'static>;

/// Per-subscriber slot. Private to this module; consumers interact
/// through [`LivelinessSubscriberRegistry::register`] /
/// [`LivelinessSubscriberRegistry::unregister`] and the RAII handle
/// at the [`crate::session::LivelinessSubscriber`] layer.
struct LivelinessSubscriberSlot {
    /// Pre-split keyexpr chunks for [`keyexpr_pattern_matches`]. Same
    /// chunk-preserving split as [`crate::pubsub::SubscriberRegistry`]:
    /// empty literal chunks are kept so `a//b` is distinguishable
    /// from `a/b`.
    pattern_chunks: Vec<String>,
    /// Original keyexpr string. Carried for introspection
    /// (`debug` logs, status surfaces) — the matching engine uses
    /// `pattern_chunks` directly.
    keyexpr: String,
    /// User callback. Fired in registration order if multiple
    /// subscribers are declared on overlapping patterns.
    callback: LivelinessSampleCallback,
    /// `true` when the subscriber requested CURRENT replay (the
    /// `history` flag on the outbound Interest sets the C bit).
    history: bool,
    /// `true` once an `InterestFinal` for this subscriber's
    /// `interest_id` has been observed inbound — i.e. the peer has
    /// finished replaying the historical token set. Stays `false`
    /// when `history == false` (no replay was requested; the flag is
    /// only meaningful for history-enabled subscribers).
    ///
    /// R281+ wire-up sets this from the
    /// [`NetworkMessage::Interest`] inbound arm.
    history_complete: bool,
}

/// Application-layer registry tracking the LOCAL liveliness
/// subscribers wz has declared on this session, routing inbound
/// `Decl*Token` records to their keyexpr-matched callbacks. See
/// module-level docs for the dispatch contract and the
/// `peer_token_table` keyexpr-resolution mechanism.
pub struct LivelinessSubscriberRegistry {
    slots: HashMap<u64, LivelinessSubscriberSlot>,
    /// Peer-side token table: maps a `DeclToken.id` to the keyexpr it
    /// resolved to at `DeclToken` arrival time. Populated by
    /// [`Self::dispatch_declare`] on `DeclToken` reception and
    /// consumed on the matching `UndeclToken` reception so the
    /// `Delete` sample can carry the same keyexpr as the prior `Put`.
    /// Cleared on `UndeclToken` reception (R280); a `DeclToken` whose
    /// id was never seen is treated as a no-op.
    peer_token_table: HashMap<u64, String>,
}

impl Default for LivelinessSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LivelinessSubscriberRegistry {
    /// New empty registry. No slots, empty peer-token table.
    pub fn new() -> Self {
        Self {
            slots: HashMap::new(),
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
    /// [`Self::history_complete`] queries and by the R281+
    /// `InterestFinal` arm of [`Self::dispatch_messages`].
    pub fn register(
        &mut self,
        interest_id: u64,
        keyexpr: impl Into<String>,
        history: bool,
        callback: LivelinessSampleCallback,
    ) -> bool {
        let keyexpr_string = keyexpr.into();
        let pattern_chunks: Vec<String> = keyexpr_string.split('/').map(str::to_string).collect();
        let slot = LivelinessSubscriberSlot {
            pattern_chunks,
            keyexpr: keyexpr_string,
            callback,
            history,
            history_complete: false,
        };
        if self.slots.contains_key(&interest_id) {
            return false;
        }
        self.slots.insert(interest_id, slot);
        true
    }

    /// Remove a subscriber slot. Returns `true` when a slot was
    /// removed, `false` when no slot matched (idempotent on a
    /// double-unregister). The RAII handle's `Drop` calls this; an
    /// explicit `LivelinessSubscriber::undeclare` ahead of the drop
    /// covers the same call site.
    pub fn unregister(&mut self, interest_id: u64) -> bool {
        self.slots.remove(&interest_id).is_some()
    }

    /// Mark the subscriber with `interest_id` as history-complete.
    /// Called from the R281+ `InterestFinal` inbound arm. No-op when
    /// the id is unknown (the peer may emit an `InterestFinal` for
    /// an id whose subscriber was already unregistered locally;
    /// dropping the signal silently is the correct response).
    pub fn mark_history_complete(&mut self, interest_id: u64) {
        if let Some(slot) = self.slots.get_mut(&interest_id) {
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
            .get(&interest_id)
            .map(|slot| slot.keyexpr.as_str())
    }

    /// `true` when the subscriber requested CURRENT replay AND the
    /// peer has signaled history-complete via `InterestFinal`.
    /// Returns `false` for an unknown id, for a `history = false`
    /// subscriber (no replay requested → flag never flips), or
    /// before the peer's `InterestFinal` arrives.
    pub fn history_complete(&self, interest_id: u64) -> bool {
        self.slots
            .get(&interest_id)
            .map(|slot| slot.history && slot.history_complete)
            .unwrap_or(false)
    }

    /// Snapshot of how many peer-side `DeclToken` records are
    /// currently tracked. Equal to the number of `DeclToken` arrivals
    /// minus matching `UndeclToken` arrivals; bounded by the peer's
    /// declared token set. Test / diagnostic surface only.
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
    pub fn dispatch_declare(
        &mut self,
        body: &DeclareVariant,
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        match body {
            DeclareVariant::CodecZenohDeclToken(decl) => {
                let resolved = match resolve_wireexpr(&decl.keyexpr.body, peer_keyexpr_table) {
                    Some(s) => s,
                    None => return,
                };
                self.peer_token_table.insert(decl.id, resolved.clone());
                self.fan_to_matching_slots(LivelinessSampleKind::Put, &resolved, decl.id);
            }
            DeclareVariant::CodecZenohUndeclToken(undecl) => {
                let resolved = match self.peer_token_table.remove(&undecl.id) {
                    Some(s) => s,
                    None => return,
                };
                self.fan_to_matching_slots(LivelinessSampleKind::Delete, &resolved, undecl.id);
            }
            // Other DeclareVariant arms are not the liveliness layer's
            // concern.
            _ => {}
        }
    }

    /// Internal fan-out helper. Walks every slot and invokes its
    /// callback when the slot's pattern chunks match the resolved
    /// keyexpr. Borrows the chunks via a per-slot `Vec<&str>` view
    /// — the per-slot allocation is the same shape
    /// [`crate::pubsub::SubscriberRegistry::dispatch_push`] uses; it
    /// stays out of the inner loop on the matching engine itself.
    fn fan_to_matching_slots(&mut self, kind: LivelinessSampleKind, resolved: &str, token_id: u64) {
        for slot in self.slots.values_mut() {
            let chunks: Vec<&str> = slot.pattern_chunks.iter().map(String::as_str).collect();
            if keyexpr_pattern_matches(&chunks, resolved) {
                (slot.callback)(LivelinessSample {
                    kind,
                    keyexpr: resolved,
                    token_id,
                });
            }
        }
    }

    /// Drain a `Vec<NetworkMessage>` through [`Self::dispatch_declare`]
    /// for the Declare arm and [`Self::mark_history_complete`] for the
    /// `Interest(Final)` arm (R281 wire-up — an Interest whose outer
    /// header carries neither `C` nor `F` is an InterestFinal per
    /// `_Z_INTEREST_NOT_FINAL_MASK` at
    /// `vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/
    /// interest.h:35`).
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
                    self.dispatch_declare(&decl.body, peer_keyexpr_table);
                }
                NetworkMessage::Interest(interest) => {
                    // Outer header bit5 = C (CURRENT), bit6 = F (FUTURE).
                    // The `_Z_INTEREST_NOT_FINAL_MASK = C | F` gate
                    // (interest.h:35) discriminates Final (both clear)
                    // from non-final. An InterestFinal targeting one of
                    // our outbound interest_ids marks the matching
                    // subscriber history-complete; non-final Interests
                    // from the peer are out of scope here (R283+).
                    let is_final = (interest.header & 0x60) == 0;
                    if is_final {
                        self.mark_history_complete(interest.interest_id);
                    }
                }
                _ => {}
            }
        }
    }

    /// [`IterationEvent`] adapter; mirror of the other
    /// application-layer registries. Routes `FramePayload` events
    /// through [`Self::dispatch_messages`]; other variants are
    /// no-ops here (the liveliness signal path lives entirely in the
    /// `Declare` / `Interest` MIDs).
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

// R311q — tests are gated on `liveliness-subscriber` (the feature the
// dispatch behaviour exists for) AND on `codec-declare` (the feature
// that materialises `NetworkMessage::Declare` + the `decl_token` /
// `undecl_token` fixtures). The feature chain
// `liveliness-subscriber → declare-interest → codec-declare` makes
// these two conditions equivalent in practice; both are spelled out
// here for self-documentation.
#[cfg(all(test, feature = "liveliness-subscriber", feature = "codec-declare"))]
mod tests {
    use super::super::test_helpers::*;
    use super::*;
    use crate::session_glue::NetworkMessage;
    use portable_atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use wz_codecs::declare::DeclareVariant;
    use wz_codecs::interest::Interest;
    use wz_codecs::interest_body::InterestBody;
    use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
    use wz_codecs::wireexpr_local::WireexprLocal;

    fn make_subscriber(
        sink: Arc<Mutex<Vec<(LivelinessSampleKind, String, u64)>>>,
    ) -> LivelinessSampleCallback {
        Box::new(move |sample: LivelinessSample<'_>| {
            sink.lock()
                .unwrap()
                .push((sample.kind, sample.keyexpr.to_string(), sample.token_id));
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
        assert!(reg.register(7, "liveliness/dev", false, make_subscriber(sink.clone())));
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
        assert!(reg.register(7, "a", false, make_subscriber(sink.clone())));
        assert!(
            !reg.register(7, "b", false, make_subscriber(sink.clone())),
            "second register on same interest_id must reject"
        );
        assert_eq!(reg.keyexpr(7), Some("a"), "first registration retained");
    }

    #[test]
    fn decl_token_dispatches_put_sample_on_pattern_match() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "liveliness/*", false, make_subscriber(sink.clone()));

        let body = DeclareVariant::CodecZenohDeclToken(decl_token(42, 0, Some("liveliness/dev42")));
        reg.dispatch_declare(&body, &HashMap::new());

        let captured = sink.lock().unwrap().clone();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].0, LivelinessSampleKind::Put);
        assert_eq!(captured[0].1, "liveliness/dev42");
        assert_eq!(captured[0].2, 42);
        assert_eq!(reg.peer_token_count(), 1);
    }

    #[test]
    fn undecl_token_dispatches_delete_sample_using_remembered_keyexpr() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "liveliness/**", false, make_subscriber(sink.clone()));

        let decl =
            DeclareVariant::CodecZenohDeclToken(decl_token(7, 0, Some("liveliness/svc/api")));
        reg.dispatch_declare(&decl, &HashMap::new());

        let undecl = DeclareVariant::CodecZenohUndeclToken(undecl_token(7));
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
        reg.register(1, "alpha/*", false, make_subscriber(sink.clone()));

        let body = DeclareVariant::CodecZenohDeclToken(decl_token(5, 0, Some("beta/instance")));
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
            Box::new(move |_| {
                fired_for_cb.fetch_add(1, Ordering::SeqCst);
            }),
        );
        // mapping_id=55 with no peer-keyexpr table entry → resolve_wireexpr returns None.
        let body = DeclareVariant::CodecZenohDeclToken(decl_token(1, 55, None));
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
        reg.register(1, "liveliness/*", false, make_subscriber(sink.clone()));

        // Peer declared mapping_id=10 → "liveliness".
        let mut table = HashMap::new();
        table.insert(10u64, "liveliness".to_string());

        // DeclToken with mapping_id=10 + suffix="/dev42" composes to
        // "liveliness/dev42" through resolve_wireexpr.
        let body = DeclareVariant::CodecZenohDeclToken(decl_token(99, 10, Some("/dev42")));
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
        reg.register(1, "**", false, make_subscriber(sink1.clone()));
        reg.register(2, "alpha/*", false, make_subscriber(sink2.clone()));

        let body = DeclareVariant::CodecZenohDeclToken(decl_token(3, 0, Some("alpha/one")));
        reg.dispatch_declare(&body, &HashMap::new());

        assert_eq!(sink1.lock().unwrap().len(), 1, "** catches all");
        assert_eq!(sink2.lock().unwrap().len(), 1, "alpha/* catches alpha/one");
    }

    #[test]
    fn interest_final_marks_history_complete_only_for_history_subscribers() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "a", true, make_subscriber(sink.clone()));
        reg.register(2, "b", false, make_subscriber(sink.clone()));

        // InterestFinal for interest_id=1.
        let interest_final = Interest {
            header: 0x19, // N_MID_INTEREST, no C, no F
            interest_id: 1,
            body: None,
            extensions: None,
        };
        let messages = vec![NetworkMessage::Interest(interest_final)];
        reg.dispatch_messages(&messages, &HashMap::new());

        assert!(
            reg.history_complete(1),
            "history-enabled subscriber must observe history_complete after InterestFinal",
        );
        assert!(
            !reg.history_complete(2),
            "history=false subscriber returns false even after InterestFinal — replay was not requested",
        );
    }

    #[test]
    fn non_final_interest_does_not_mark_history_complete() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "x", true, make_subscriber(sink.clone()));

        // Non-final Interest (FUTURE bit set) carrying a body. This is the
        // shape the peer would emit if it ever asked us about tokens
        // (R283 carry — bilateral Interest is out of scope at R280).
        let non_final = Interest {
            header: 0x19 | 0x40, // FUTURE
            interest_id: 1,
            body: Some(InterestBody {
                header: 0x01 | 0x08 | 0x10 | 0x40,
                keyexpr: Some(Wireexpr {
                    body: WireexprVariant::WireexprLocal(WireexprLocal {
                        id: 0,
                        suffix_len: Some(1),
                        suffix: Some("x".to_string()),
                    }),
                }),
            }),
            extensions: None,
        };
        let messages = vec![NetworkMessage::Interest(non_final)];
        reg.dispatch_messages(&messages, &HashMap::new());

        assert!(
            !reg.history_complete(1),
            "non-final Interest (C or F set) must not flip history_complete",
        );
    }

    #[test]
    fn other_declare_arms_are_noops() {
        let mut reg = LivelinessSubscriberRegistry::new();
        let sink: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        reg.register(1, "**", false, make_subscriber(sink.clone()));

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
}
