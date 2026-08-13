// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `RemoteSubscriberRegistry` — application-layer registry tracking
//! the peer's outbound `DeclSubscriber` / `UndeclSubscriber` records.
//! See [`crate::declare`] module docs for the cross-registry rationale
//! and callback contract.
//!
//! R311do / di-15 — migrated to wz-session-core (was
//! `wz-runtime-tokio::declare::subscriber`). AP-side test fixtures
//! stay in the wz-runtime-tokio shell because they exercise
//! Tokio-bound sync primitives. `has_matching` is an inherent method
//! on the registry calling [`crate::keyexpr_match::keyexpr_intersect_patterns`]
//! directly — no extension-trait split (R311dn-pre lift made this
//! possible).

// R311gb (Track 2) — String / Vec / HashMap back the `alloc` wire side
// (the peer `declared` membership table + `has_matching` chunking + the
// dispatch params); the no-alloc control plane stores observers in a
// `BoundedVec` and fires through the borrowed `DeclView` seam.
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use hashbrown::HashMap;

#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use wz_codecs::declare::DeclareOwnedVariant;

// The shared [`DeclObserverPair`] holds the bounded observer lists +
// install/fire SSOT; `DeclSink` / `UndeclSink` (bounds) + `DeclView`
// (no-heap fire currency) are unconditional; the `BorrowedDecl` builder +
// `Boxed*` adapters + the wire-codec / envelope imports carry the
// narrower gates.
#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use crate::decl_sink::BorrowedDecl;
#[cfg(feature = "alloc")]
use crate::decl_sink::{BoxedDeclSink, BoxedUndeclSink};
use crate::decl_sink::{DeclObserverPair, DeclSink, DeclView, UndeclSink};
#[cfg(feature = "alloc")]
use crate::declare::declared_intersects;
#[cfg(all(feature = "session-matching", feature = "alloc"))]
use crate::declare::matching::{BoxedMatchingSink, MatchingWatchList};
#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use crate::network_message::NetworkMessage;
use crate::registry_error::RegisterError;
#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use crate::wireexpr_resolve::{resolve_wireexpr_in, MappingSpaces};

/// Application-layer registry tracking the peer's outbound
/// `DeclSubscriber` / `UndeclSubscriber` records. `!Sync` by
/// construction; cross-task sharing goes through `Arc<Mutex<…>>`.
///
/// `register` and `unregister` are not provided here because the
/// registry is callback-only — there is no per-subscription state to
/// track on the consumer side. The application installs an
/// `on_subscriber_declared` and / or `on_subscriber_undeclared`
/// callback once at startup; every matching inbound declare fires
/// every installed callback in registration order.
pub struct RemoteSubscriberRegistry<D: DeclSink, U: UndeclSink> {
    /// R311gb (Track 2) — the shared 2-list observer machinery
    /// (`on_decl` + `on_undecl`, install + fire), composed from
    /// [`crate::decl_sink::DeclObserverPair`] so the fan-out logic lives
    /// once across the three `DeclSink` registries. `D = BoxedDeclSink` /
    /// `U = BoxedUndeclSink` on AP (heap closures), consumer-supplied
    /// closed `enum`s on MCU.
    observers: DeclObserverPair<D, U>,
    /// R290 — peer-declared subscribers tracked by `{id -> resolved
    /// keyexpr}`. Pub-side analogue of the `declared` map landed on
    /// [`crate::declare::queryable::RemoteQueryableRegistry`] in R288.
    /// Populated on every inbound `DeclSubscriber` whose keyexpr
    /// resolves through `peer_keyexpr_table`, and entries removed on
    /// the matching `UndeclSubscriber`. Backbone for the publisher-
    /// side `get_matching_status` consult which iterates this map at
    /// query time to decide whether any currently-declared peer
    /// subscriber's keyexpr intersects the publisher's keyexpr.
    ///
    /// Same HashMap rationale as the Q-side: by-id membership
    /// invariant, by-id Undecl removal, no ordering dependency on
    /// the rare full-iteration consult path.
    ///
    /// R311gb (Track 2) — wire-side membership state (populated by
    /// `dispatch_declare` consuming owned `Declare` records, read by
    /// `has_matching`); `alloc`-gated per the borrow boundary. The
    /// no-alloc control plane (observer lists + fan-out) does not depend
    /// on it.
    #[cfg(feature = "alloc")]
    declared: HashMap<u64, String>,
    /// R311kh — matching-listener watches (pico `Z_FEATURE_MATCHING`):
    /// re-evaluated against the `declared` table on every membership
    /// mutation, firing each watch's sink on a verdict flip. The
    /// listener form of the polling `has_matching` consult.
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    matching_watches: MatchingWatchList<BoxedMatchingSink>,
}

impl<D: DeclSink, U: UndeclSink> Default for RemoteSubscriberRegistry<D, U> {
    fn default() -> Self {
        Self::with_sink_backing()
    }
}

impl<D: DeclSink, U: UndeclSink> RemoteSubscriberRegistry<D, U> {
    /// New empty registry over explicit sink backings `D` / `U`. Both
    /// observer lists start empty; an empty registry processes inbound
    /// `Declare(Decl*)` records as no-ops.
    ///
    /// R311gb-3d — the generic constructor (the no-`alloc` / MCU entry
    /// point, paired with [`on_subscriber_declared_sink`](Self::on_subscriber_declared_sink)
    /// / [`on_subscriber_undeclared_sink`](Self::on_subscriber_undeclared_sink)).
    /// AP callers use the inferring [`new`](RemoteSubscriberRegistry::new)
    /// shorthand, which fixes `D = BoxedDeclSink` / `U = BoxedUndeclSink`.
    pub fn with_sink_backing() -> Self {
        Self {
            observers: DeclObserverPair::new(),
            #[cfg(feature = "alloc")]
            declared: HashMap::new(),
            #[cfg(all(feature = "session-matching", feature = "alloc"))]
            matching_watches: MatchingWatchList::new(),
        }
    }

    /// R311gb-3d — install an explicit [`DeclSink`] observer (the
    /// seam-native entry point; works on every profile). The `alloc`-only
    /// [`on_subscriber_declared`](RemoteSubscriberRegistry::on_subscriber_declared)
    /// convenience wrapper funnels through here after wrapping a closure
    /// in a [`BoxedDeclSink`]. Duplicate sinks are explicitly allowed;
    /// dispatch fires them in registration order. R311lb — returns the
    /// registry-local observer id for
    /// [`remove_subscriber_declared_sink`](Self::remove_subscriber_declared_sink).
    pub fn on_subscriber_declared_sink(&mut self, sink: D) -> Result<u64, RegisterError> {
        self.observers.install_decl(sink)
    }

    /// R311gb-3d — install an explicit [`UndeclSink`] observer. The
    /// `alloc`-only
    /// [`on_subscriber_undeclared`](RemoteSubscriberRegistry::on_subscriber_undeclared)
    /// convenience wrapper funnels through here. R311lb — returns the
    /// registry-local observer id for
    /// [`remove_subscriber_undeclared_sink`](Self::remove_subscriber_undeclared_sink).
    pub fn on_subscriber_undeclared_sink(&mut self, sink: U) -> Result<u64, RegisterError> {
        self.observers.install_undecl(sink)
    }

    /// R311lb — remove the declaration observer keyed by `id` (the
    /// return of
    /// [`on_subscriber_declared_sink`](Self::on_subscriber_declared_sink)).
    /// Returns whether one was removed; double removal is a `false`
    /// no-op. The removal half of the Session-tier decl-listener
    /// surface (R311lc).
    pub fn remove_subscriber_declared_sink(&mut self, id: u64) -> bool {
        self.observers.uninstall_decl(id)
    }

    /// R311lb — remove the undeclaration observer keyed by `id`. Same
    /// contract as
    /// [`remove_subscriber_declared_sink`](Self::remove_subscriber_declared_sink).
    pub fn remove_subscriber_undeclared_sink(&mut self, id: u64) -> bool {
        self.observers.uninstall_undecl(id)
    }

    /// Number of installed `on_subscriber_declared` callbacks.
    pub fn on_decl_len(&self) -> usize {
        self.observers.decl_len()
    }

    /// Number of installed `on_subscriber_undeclared` callbacks.
    pub fn on_undecl_len(&self) -> usize {
        self.observers.undecl_len()
    }

    /// R290 — count of currently-declared peer subscribers (those
    /// whose inbound `DeclSubscriber` has been dispatched and whose
    /// `UndeclSubscriber` has not). Pub-side mirror of the Q-side
    /// `declared_count`.
    #[cfg(feature = "alloc")]
    pub fn declared_count(&self) -> usize {
        self.declared.len()
    }

    /// R290 — iterate over currently-declared peer subscribers as
    /// `(id, resolved_keyexpr)` pairs. Pub-side mirror of the Q-side
    /// `iter_declared`. Ordering is unspecified (HashMap iteration).
    #[cfg(feature = "alloc")]
    pub fn iter_declared(&self) -> impl Iterator<Item = (u64, &str)> + '_ {
        self.declared.iter().map(|(id, ke)| (*id, ke.as_str()))
    }

    /// Backbone for `Publisher::get_matching_status` (R290 surfaced
    /// the API; R293 lifted the underlying matcher to honest
    /// wildcard-vs-wildcard intersection). Pub-side mirror of the
    /// Q-side `has_matching`; returns `true` iff at least one
    /// currently-declared peer subscriber's keyexpr intersects
    /// `publish_keyexpr` under
    /// [`crate::keyexpr_match::keyexpr_intersect_patterns`] — i.e.
    /// there exists at least one literal `/`-separated keyexpr that
    /// both sides match. The Q-side has_matching doc-comment carries
    /// the per-case textbook expansion (literal-literal byte-equal,
    /// one-side wildcard, two-side wildcard overlap); the semantic
    /// is symmetric across Pub-side and Q-side because the matcher
    /// itself is symmetric.
    #[cfg(feature = "alloc")]
    pub fn has_matching(&self, publish_keyexpr: &str) -> bool {
        declared_intersects(&self.declared, publish_keyexpr)
    }

    /// R311kh — register a matching-listener watch over `keyexpr` (pico
    /// `Z_FEATURE_MATCHING`): the sink fires on every VERDICT FLIP of
    /// [`Self::has_matching`]`(keyexpr)` caused by an inbound
    /// `DeclSubscriber` / `UndeclSubscriber`, seeded with the CURRENT
    /// verdict so registration itself never fires (pico transition-only
    /// semantics; `get_matching_status` remains the poll for the current
    /// value). Returns the watch id for
    /// [`Self::undeclare_matching_listener`].
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn declare_matching_listener(&mut self, keyexpr: &str, sink: BoxedMatchingSink) -> u64 {
        self.declare_matching_listener_seeded(keyexpr, false, sink)
    }

    /// R311y788 — [`Self::declare_matching_listener`] with the
    /// session-local half of the current verdict supplied by the caller.
    ///
    /// The seed decides whether registration fires (pico fires `true` at
    /// registration when already matching,
    /// `vendor/zenoh-pico/src/net/filtering.c:341-357`), so it has to be
    /// the SAME verdict the poll reports or the two disagree about the
    /// instant the listener was created — a publisher whose only match is
    /// a subscriber on its own session would poll `true` and then be told
    /// `true` again by a spurious registration fire.
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn declare_matching_listener_seeded(
        &mut self,
        keyexpr: &str,
        local_matching: bool,
        sink: BoxedMatchingSink,
    ) -> u64 {
        let initial = self.has_matching(keyexpr) || local_matching;
        self.matching_watches
            .register(String::from(keyexpr), initial, sink)
    }

    /// R311y788 — re-evaluate every matching watch after a change this
    /// registry cannot see: a subscriber declared or undeclared on THIS
    /// session. The remote half is read from this registry's own
    /// membership; `local_matching` supplies the local half. Returns the
    /// number of watches whose verdict flipped (and therefore fired).
    ///
    /// The remote counterpart needs no such entry point — an inbound
    /// declaration already arrives through
    /// [`Self::dispatch_declare_with_local`], which re-evaluates.
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn reevaluate_matching(&mut self, local_matching: &dyn Fn(&str) -> bool) -> usize {
        self.matching_watches
            .reevaluate(|k| declared_intersects(&self.declared, k) || local_matching(k))
    }

    /// R311kh — remove a matching-listener watch. Returns whether one
    /// was removed (pico `_z_matching_listener_undeclare`).
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn undeclare_matching_listener(&mut self, id: u64) -> bool {
        self.matching_watches.unregister(id)
    }

    /// Number of registered matching-listener watches (observability /
    /// test helper).
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn matching_listener_len(&self) -> usize {
        self.matching_watches.len()
    }

    /// R311gb (Track 2) — no-heap declaration fire: hand each installed
    /// `on_decl` observer the borrowed [`DeclView`]. Borrow-driven (the
    /// caller owns the view), so it is the MCU no-heap fan-out; the wire
    /// path ([`dispatch_declare`](Self::dispatch_declare)) builds a
    /// [`BorrowedDecl`] from the resolved keyexpr and funnels through here
    /// after updating the `declared` membership table. Returns the count
    /// of observers fired.
    pub fn dispatch_declared_borrowed(&mut self, view: &dyn DeclView) -> usize {
        self.observers.fire_declared(view)
    }

    /// R311gb (Track 2) — no-heap undeclaration fire: hand each installed
    /// `on_undecl` observer the bare `id` (the undeclaration carries no
    /// keyexpr). Returns the count of observers fired.
    pub fn dispatch_undeclared(&mut self, id: u64) -> usize {
        self.observers.fire_undeclared(id)
    }

    /// Route an inbound `Declare` envelope's inner body through the
    /// remote-subscriber callbacks. `DeclareOwnedVariant` arms other than
    /// `DeclSubscriber` / `UndeclSubscriber` are no-ops here — the
    /// queryable / token / kexpr / final arms route through their own
    /// dedicated registries.
    ///
    /// `peer_keyexpr_table` is the same table maintained by the
    /// session-level `SubscriberRegistry` from inbound
    /// `Declare(DeclKexpr)` records. Unresolvable keyexprs (mapping
    /// id not yet declared) drop the dispatch silently rather than
    /// firing on a partial keyexpr.
    ///
    /// R311gb (Track 2) — `all(codec-declare, alloc)`-gated: it consumes
    /// the owned `DeclareOwnedVariant` (codec) and updates the `alloc`
    /// `declared` table, then funnels the fan-out through the no-heap
    /// [`dispatch_declared_borrowed`](Self::dispatch_declared_borrowed) /
    /// [`dispatch_undeclared`](Self::dispatch_undeclared) SSOT.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_declare<'a>(
        &mut self,
        body: &DeclareOwnedVariant,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        self.dispatch_declare_with_local(body, peer_keyexpr_table, &|_| false)
    }

    /// R311y788 — [`Self::dispatch_declare`] with the SESSION-LOCAL half
    /// of the matching verdict supplied by the caller.
    ///
    /// A matching watch is a predicate over "does anything match", and
    /// this registry only knows the REMOTE half; the local subscriptions
    /// live on the sibling
    /// [`SubscriberRegistry`](crate::pubsub::SubscriberRegistry). Passing
    /// the local half in rather than mirroring it here keeps one copy of
    /// that fact — and it has to be passed on THIS path, not only at
    /// registration, because a watch held `true` by a local subscriber
    /// must not be flipped to `false` by an unrelated remote undeclare.
    ///
    /// [`Self::dispatch_declare`] delegates here with a `false` local
    /// half, which is the honest answer for a caller that has no local
    /// subscriber table in reach. The production fan
    /// ([`crate::observer::SessionObserver`]) passes the real one.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_declare_with_local<'a>(
        &mut self,
        body: &DeclareOwnedVariant,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
        local_matching: &dyn Fn(&str) -> bool,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        let _ = &local_matching;
        match body {
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl) => {
                let resolved = match resolve_wireexpr_in(&decl.keyexpr.body, peer_keyexpr_table) {
                    Some(s) => s,
                    None => return,
                };
                // R290 — same membership-tracking pattern as the
                // Q-side registry: same-id-replaces semantic, no
                // explicit conflict surfacing.
                self.declared.insert(decl.id, resolved.clone());
                // R311gb-3d / Track 2 — fan through the DeclSink seam via
                // the no-heap SSOT: build the `(id, resolved-keyexpr)`
                // view once and hand each observer `&dyn DeclView`.
                let view = BorrowedDecl {
                    id: decl.id,
                    keyexpr: &resolved,
                };
                self.dispatch_declared_borrowed(&view);
                // R311kh — membership changed: re-evaluate the matching
                // watches (flip-fire only). Disjoint field borrows: the
                // watch list is &mut, the membership table is read
                // through the free-fn consult.
                #[cfg(feature = "session-matching")]
                self.matching_watches
                    .reevaluate(|k| declared_intersects(&self.declared, k) || local_matching(k));
            }
            DeclareOwnedVariant::CodecZenohUndeclSubscriber(undecl) => {
                // R290 — drop the membership entry first so a
                // get_matching_status fired from inside the
                // on_undecl callback chain observes the post-
                // undeclare state.
                self.declared.remove(&undecl.id);
                self.dispatch_undeclared(undecl.id);
                // R311kh — see the DeclSubscriber arm.
                #[cfg(feature = "session-matching")]
                self.matching_watches
                    .reevaluate(|k| declared_intersects(&self.declared, k) || local_matching(k));
            }
            // Other sub-variants do not reach this registry.
            _ => {}
        }
    }

    /// Drain a `Vec<NetworkMessage>` (typically the
    /// `FramePayload.messages` field surfaced by the production
    /// driver loop) through [`Self::dispatch_declare`]. Mirrors the
    /// sibling registries so the observer in production code can fan
    /// one event into every registry uniformly.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_messages<'a>(
        &mut self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        self.dispatch_messages_with_local(messages, peer_keyexpr_table, &|_| false)
    }

    /// R311y788 — [`Self::dispatch_messages`] carrying the session-local
    /// half of the matching verdict; see
    /// [`Self::dispatch_declare_with_local`].
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_messages_with_local<'a>(
        &mut self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
        local_matching: &dyn Fn(&str) -> bool,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        for message in messages {
            if let NetworkMessage::Declare(decl) = message {
                self.dispatch_declare_with_local(&decl.body, peer_keyexpr_table, local_matching);
            }
        }
    }

    /// Convenience adapter that pulls the `FramePayload.messages` out
    /// of an `IterationEvent::Poll(DriverLoopOutcome::FramePayload)`
    /// and forwards to [`Self::dispatch_messages`]. Mirror of the
    /// sibling registries. Other `IterationEvent` variants (`Lease`,
    /// non-FramePayload `Poll` outcomes) are no-ops.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_iteration_event<'a>(
        &mut self,
        event: IterationEvent<'_>,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        self.dispatch_iteration_event_with_local(event, peer_keyexpr_table, &|_| false)
    }

    /// R311y788 — [`Self::dispatch_iteration_event`] carrying the
    /// session-local half of the matching verdict; see
    /// [`Self::dispatch_declare_with_local`]. This is the entry point the
    /// production observer fan uses, so both runtime profiles get the
    /// local half without either of them mirroring the local table.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_iteration_event_with_local<'a>(
        &mut self,
        event: IterationEvent<'_>,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
        local_matching: &dyn Fn(&str) -> bool,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) = event {
            self.dispatch_messages_with_local(messages, peer_keyexpr_table, local_matching);
        }
    }
}

/// R311gb-3d — AP / `alloc`-profile convenience constructors. The
/// closure-taking `on_subscriber_declared` / `on_subscriber_undeclared`
/// wrappers live here (on the `BoxedDeclSink` / `BoxedUndeclSink`
/// instantiation only) because they heap-box the closures; the no-`alloc`
/// profile installs consumer-supplied sinks through the generic
/// [`on_subscriber_declared_sink`](RemoteSubscriberRegistry::on_subscriber_declared_sink)
/// / [`on_subscriber_undeclared_sink`](RemoteSubscriberRegistry::on_subscriber_undeclared_sink)
/// instead.
///
/// R311gb (Track 2) — gated on `alloc` only (not `codec-declare`): the
/// closure installers funnel through the un-gated `on_*_declared_sink`, so
/// the AP observer-install surface composes in any `alloc` subset
/// (`BoxedDeclSink` / `BoxedUndeclSink` are themselves `alloc`-gated).
#[cfg(feature = "alloc")]
impl RemoteSubscriberRegistry<BoxedDeclSink, BoxedUndeclSink> {
    /// New empty AP registry backed by heap-boxed closures. The inferring
    /// shorthand for
    /// [`with_sink_backing`](RemoteSubscriberRegistry::with_sink_backing):
    /// `RemoteSubscriberRegistry::new()` fixes `D = BoxedDeclSink` /
    /// `U = BoxedUndeclSink` so the closure-taking wrappers are in reach
    /// without a turbofish.
    pub fn new() -> Self {
        Self::with_sink_backing()
    }

    /// Install a closure fired on every inbound `Declare(DeclSubscriber)`
    /// whose keyexpr resolves through the peer keyexpr table. The closure
    /// receives `&dyn DeclView` (the peer-declared `id` + resolved
    /// keyexpr) — the R311gb-3d seam contract replaces the prior
    /// `(&DeclSubscriberOwned, &str)`; this is the
    /// [`feedback_signature_stability`] wire-data principled exemption.
    /// Duplicate callbacks are allowed; dispatch fires them in
    /// registration order. The closure is heap-boxed via [`BoxedDeclSink`].
    /// R311lb — returns the registry-local observer id (see
    /// [`Self::remove_subscriber_declared_sink`]); existing callers that
    /// never remove may ignore it.
    pub fn on_subscriber_declared(
        &mut self,
        callback: impl FnMut(&dyn crate::decl_sink::DeclView) + Send + 'static,
    ) -> u64 {
        // AP backing: the observer `BoundedVec` grows past the advisory
        // `N`, so installing never fails here.
        self.on_subscriber_declared_sink(BoxedDeclSink::new(callback))
            .expect("observer install on the alloc backing never exceeds declared capacity")
    }

    /// Install a closure fired on every inbound
    /// `Declare(UndeclSubscriber)`. The closure receives the bare `id`
    /// (`u64`) — the undeclaration carries no keyexpr. Same registration-
    /// order + duplicates-allowed contract as
    /// [`Self::on_subscriber_declared`]. The closure is heap-boxed via
    /// [`BoxedUndeclSink`]. R311lb — returns the registry-local observer
    /// id (see [`Self::remove_subscriber_undeclared_sink`]).
    pub fn on_subscriber_undeclared(&mut self, callback: impl FnMut(u64) + Send + 'static) -> u64 {
        self.on_subscriber_undeclared_sink(BoxedUndeclSink::new(callback))
            .expect("observer install on the alloc backing never exceeds declared capacity")
    }
}

// R311gb (Track 2) — the behavioural tests exercise `dispatch_declare`
// (owned `DeclareOwnedVariant`) + `has_matching`, now
// `all(codec-declare, alloc)`-gated; the module un-gated from
// `codec-declare`, so the test gate is now explicit (was inherited).
#[cfg(all(test, feature = "codec-declare"))]
mod tests {
    //! R311ds — wider behavioural tests migrated here from the
    //! wz-runtime-tokio `declare/subscriber.rs` shell (R311dr-wider-tests
    //! carry closure). They exercise the callback fan-out value capture
    //! through `Arc<Mutex<Vec<…>>>`; the `Mutex` comes from `std` under
    //! `#[cfg(test)]` per the wz-codecs sibling-crate convention (see
    //! `crate` root `extern crate std`). Production stays no_std.

    use super::*;
    use alloc::boxed::Box;
    use alloc::string::{String, ToString};
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use hashbrown::HashMap;
    use wz_codecs::declare::DeclareOwnedVariant;
    use wz_session_core_test_support::*;

    use crate::network_message::NetworkMessage;

    #[test]
    fn empty_registry_dispatch_is_noop() {
        let mut reg = RemoteSubscriberRegistry::new();
        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(7, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(reg.on_decl_len(), 0);
        assert_eq!(reg.on_undecl_len(), 0);
    }

    #[test]
    fn declare_callback_fires_on_literal_keyexpr() {
        let mut reg = RemoteSubscriberRegistry::new();
        let captured: Arc<Mutex<Vec<(u64, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_subscriber_declared(move |decl| {
            captured_for_cb
                .lock()
                .unwrap()
                .push((decl.id(), decl.keyexpr().to_string()));
        });

        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(7, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0], (7, "home/temp".to_string()));
    }

    #[test]
    fn declare_callback_resolves_mapping_id_against_peer_table() {
        let mut reg = RemoteSubscriberRegistry::new();
        let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_subscriber_declared(move |decl| {
            captured_for_cb
                .lock()
                .unwrap()
                .push(decl.keyexpr().to_string());
        });

        let mut peer_table = HashMap::new();
        peer_table.insert(11u64, "sensors/temp".to_string());

        // mapping_id=11, no suffix -> table lookup -> "sensors/temp"
        let body = DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(1, 11, None));
        reg.dispatch_declare(&body, &peer_table);
        // mapping_id=11, suffix="/extra" -> concat
        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(2, 11, Some("/extra")));
        reg.dispatch_declare(&body, &peer_table);

        let captured = captured.lock().unwrap();
        assert_eq!(
            *captured,
            vec!["sensors/temp".to_string(), "sensors/temp/extra".to_string()]
        );
    }

    #[test]
    fn declare_callback_skipped_on_unresolvable_mapping_id() {
        let mut reg = RemoteSubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_for_cb = fired.clone();
        reg.on_subscriber_declared(move |_decl| {
            fired_for_cb.fetch_add(1, Ordering::SeqCst);
        });

        // mapping_id=99 not in (empty) peer table -> skip.
        let body = DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(1, 99, None));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "unresolvable mapping id must skip the callback (no partial keyexpr fire)"
        );
    }

    /// R311y740 (N37) — the own-space WITNESS for this plane.
    ///
    /// R311y739 wired both id spaces into the observer fan and proved the
    /// resolution end-to-end on the Push plane only; every other plane was
    /// *argued* correct from sharing `resolve_wireexpr_in` rather than
    /// measured. This is that measurement for the peer-DECLARE(Subscriber)
    /// plane, and it is not redundant with the shared-resolver tests: what it
    /// rules out is this registry reaching for the peer table by some other
    /// route, which no test of the resolver in isolation can see.
    ///
    /// R311y750 (carry N38) — the route this named, `SubscriberRegistry`'s bare
    /// `peer_keyexpr_table()`, is gone; the raw peer half is now reachable only
    /// through the pair. That narrows what this test has to watch for without
    /// retiring it: a registry can still read the peer half through
    /// `MappingSpaces::peer` after being handed both.
    ///
    /// THE DISCRIMINATOR is the collision: id 7 exists in BOTH spaces under
    /// different literals, so reading the wrong one is a confident WRONG
    /// keyexpr rather than a silent `None`. Both upstreams number their
    /// mappings from 1, so that is the realistic failure.
    #[test]
    fn an_own_space_alias_resolves_in_our_space_on_the_declare_subscriber_plane() {
        let mut reg = RemoteSubscriberRegistry::new();
        let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_subscriber_declared(move |decl| {
            captured_for_cb
                .lock()
                .unwrap()
                .push(decl.keyexpr().to_string());
        });

        let mut peer = HashMap::new();
        peer.insert(7u64, "theirs/sub".to_string());
        let mut own = HashMap::new();
        own.insert(7u64, "ours/sub".to_string());

        // M=0 (`WireexprNonlocal`) names OUR space.
        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber_nonlocal(1, 7, None));
        reg.dispatch_declare(&body, MappingSpaces::with_own(&peer, &own));

        assert_eq!(
            *captured.lock().unwrap(),
            vec!["ours/sub".to_string()],
            "an M=0 alias names OUR space; reading the peer's would have \
             resolved `theirs/sub`",
        );
    }

    /// ANTI-VACUITY twin of
    /// [`an_own_space_alias_resolves_in_our_space_on_the_declare_subscriber_plane`].
    /// With only the peer's space the SAME record resolves nothing, so the
    /// witness above is measuring the installed own space rather than any
    /// table happening to hold id 7.
    #[test]
    fn without_an_own_space_the_declare_subscriber_plane_refuses_the_same_alias() {
        let mut reg = RemoteSubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_for_cb = fired.clone();
        reg.on_subscriber_declared(move |_decl| {
            fired_for_cb.fetch_add(1, Ordering::SeqCst);
        });

        let mut peer = HashMap::new();
        peer.insert(7u64, "theirs/sub".to_string());

        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber_nonlocal(1, 7, None));
        reg.dispatch_declare(&body, &peer);

        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "with no own space an M=0 alias must refuse -- never fall back to \
             the peer's table",
        );
    }

    #[test]
    fn undeclare_callback_fires_on_undecl_subscriber() {
        let mut reg = RemoteSubscriberRegistry::new();
        let captured: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_subscriber_undeclared(move |id| {
            captured_for_cb.lock().unwrap().push(id);
        });

        let body = DeclareOwnedVariant::CodecZenohUndeclSubscriber(undecl_subscriber(42));
        reg.dispatch_declare(&body, &HashMap::new());

        let captured = captured.lock().unwrap();
        assert_eq!(*captured, vec![42]);
    }

    /// R311kh — matching listener flip-fires through the production
    /// dispatch: a matching DeclSubscriber flips false->true, the
    /// matching UndeclSubscriber flips back true->false, a NON-matching
    /// declare never fires, and registration itself is silent (pico
    /// transition-only semantics).
    #[cfg(feature = "session-matching")]
    #[test]
    fn matching_listener_flips_on_membership_mutation() {
        use crate::declare::matching::BoxedMatchingSink;

        let mut reg = RemoteSubscriberRegistry::new();
        let log: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
        let log_cb = log.clone();
        let id = reg.declare_matching_listener(
            "home/temp",
            BoxedMatchingSink::new(move |m| log_cb.lock().unwrap().push(m)),
        );
        assert_eq!(reg.matching_listener_len(), 1);
        assert!(log.lock().unwrap().is_empty(), "registration never fires");

        // Non-matching peer subscriber: membership changes, verdict does not.
        let body = DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(
            1,
            0,
            Some("garage/door"),
        ));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(
            log.lock().unwrap().is_empty(),
            "non-matching declare is silent"
        );

        // Matching peer subscriber (literal-literal byte-equal — no
        // wildcard feature dependency): false -> true fires once.
        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(2, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(*log.lock().unwrap(), vec![true]);

        // Its undeclare: true -> false fires once more.
        let body = DeclareOwnedVariant::CodecZenohUndeclSubscriber(undecl_subscriber(2));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(*log.lock().unwrap(), vec![true, false]);

        // After undeclare-listener, further mutations are silent.
        assert!(reg.undeclare_matching_listener(id));
        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(3, 0, Some("home/x")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(*log.lock().unwrap(), vec![true, false]);
    }

    #[test]
    fn multiple_decl_callbacks_fire_in_registration_order() {
        let mut reg = RemoteSubscriberRegistry::new();
        let order: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let order_a = order.clone();
        let order_b = order.clone();
        reg.on_subscriber_declared(move |_d| order_a.lock().unwrap().push(1));
        reg.on_subscriber_declared(move |_d| order_b.lock().unwrap().push(2));
        assert_eq!(reg.on_decl_len(), 2);

        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(3, 0, Some("a/b")));
        reg.dispatch_declare(&body, &HashMap::new());

        assert_eq!(*order.lock().unwrap(), vec![1, 2]);
    }

    #[test]
    fn nonlocal_keyexpr_arm_resolves_identically_to_local_arm() {
        let mut reg = RemoteSubscriberRegistry::new();
        let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_subscriber_declared(move |d| {
            captured_for_cb
                .lock()
                .unwrap()
                .push(d.keyexpr().to_string())
        });

        let body = DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber_nonlocal(
            9,
            0,
            Some("zone/1"),
        ));
        reg.dispatch_declare(&body, &HashMap::new());

        let captured = captured.lock().unwrap();
        assert_eq!(*captured, vec!["zone/1".to_string()]);
    }

    #[test]
    fn other_declare_arms_are_silently_dropped_here() {
        let mut reg = RemoteSubscriberRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_for_cb = fired.clone();
        reg.on_subscriber_declared(move |_d| {
            fired_for_cb.fetch_add(1, Ordering::SeqCst);
        });

        // A DeclFinal envelope must not fire the subscriber callback
        // — it lives in the SubscriberRegistry's path (DeclKexpr /
        // UndeclKexpr) or the future RemoteQueryableRegistry path
        // (DeclQueryable).
        let body =
            DeclareOwnedVariant::CodecZenohDeclFinal(wz_codecs::decl_final::DeclFinal::default());
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "Subscriber callback must not fire on DeclFinal body"
        );
    }

    #[test]
    fn dispatch_messages_routes_only_declare_variants() {
        let mut reg = RemoteSubscriberRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_cb = counter.clone();
        reg.on_subscriber_declared(move |_d| {
            counter_for_cb.fetch_add(1, Ordering::SeqCst);
        });

        let messages =
            vec![
                NetworkMessage::Declare(Box::new(declare_envelope_decl_subscriber(
                    decl_subscriber(1, 0, Some("home/a")),
                ))),
                NetworkMessage::Declare(Box::new(declare_envelope_decl_subscriber(
                    decl_subscriber(2, 0, Some("home/b")),
                ))),
            ];
        reg.dispatch_messages(&messages, &HashMap::new());
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn dispatch_messages_undecl_and_decl_route_independently() {
        let mut reg = RemoteSubscriberRegistry::new();
        let decl_count = Arc::new(AtomicUsize::new(0));
        let undecl_count = Arc::new(AtomicUsize::new(0));
        let d = decl_count.clone();
        let u = undecl_count.clone();
        reg.on_subscriber_declared(move |_d| {
            d.fetch_add(1, Ordering::SeqCst);
        });
        reg.on_subscriber_undeclared(move |_u| {
            u.fetch_add(1, Ordering::SeqCst);
        });

        let messages =
            vec![
                NetworkMessage::Declare(Box::new(declare_envelope_decl_subscriber(
                    decl_subscriber(1, 0, Some("a")),
                ))),
                NetworkMessage::Declare(Box::new(declare_envelope_undecl_subscriber(
                    undecl_subscriber(1),
                ))),
                NetworkMessage::Declare(Box::new(declare_envelope_decl_subscriber(
                    decl_subscriber(2, 0, Some("b")),
                ))),
            ];
        reg.dispatch_messages(&messages, &HashMap::new());
        assert_eq!(decl_count.load(Ordering::SeqCst), 2);
        assert_eq!(undecl_count.load(Ordering::SeqCst), 1);
    }

    // ── R290 declared / has_matching membership surface ──

    #[test]
    fn subscriber_declared_count_starts_at_zero_and_tracks_decl_undecl_lifecycle() {
        let mut reg = RemoteSubscriberRegistry::new();
        assert_eq!(reg.declared_count(), 0);

        let decl1 = DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(
            10,
            0,
            Some("home/temp"),
        ));
        reg.dispatch_declare(&decl1, &HashMap::new());
        assert_eq!(reg.declared_count(), 1);

        let decl2 = DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(
            11,
            0,
            Some("home/door"),
        ));
        reg.dispatch_declare(&decl2, &HashMap::new());
        assert_eq!(reg.declared_count(), 2);

        let undecl1 = DeclareOwnedVariant::CodecZenohUndeclSubscriber(undecl_subscriber(10));
        reg.dispatch_declare(&undecl1, &HashMap::new());
        assert_eq!(reg.declared_count(), 1);
        let remaining: Vec<(u64, &str)> = reg.iter_declared().collect();
        assert_eq!(remaining, vec![(11, "home/door")]);

        let undecl2 = DeclareOwnedVariant::CodecZenohUndeclSubscriber(undecl_subscriber(11));
        reg.dispatch_declare(&undecl2, &HashMap::new());
        assert_eq!(reg.declared_count(), 0);
    }

    #[test]
    fn subscriber_has_matching_false_on_empty_registry() {
        let reg = RemoteSubscriberRegistry::new();
        assert!(!reg.has_matching("home/temp"));
        assert!(!reg.has_matching("anything"));
    }

    #[test]
    fn subscriber_has_matching_true_on_literal_keyexpr_equality() {
        let mut reg = RemoteSubscriberRegistry::new();
        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(7, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/temp"));
        assert!(!reg.has_matching("home/door"));
    }

    #[test]
    fn subscriber_has_matching_true_when_peer_pattern_covers_publish_literal() {
        let mut reg = RemoteSubscriberRegistry::new();
        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(8, 0, Some("home/**")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/temp"));
        assert!(reg.has_matching("home/door/inner"));
        assert!(!reg.has_matching("other/x"));
    }

    #[test]
    fn subscriber_has_matching_false_on_a_malformed_published_key() {
        // The LOCAL delivery membership check (zenoh compute_data_route parity):
        // a `home/**` subscriber must NOT match a malformed published key (an
        // empty `/`-delimited chunk). This is the local-delivery twin of the
        // mesh-forward drop — both route through the matcher's
        // `target_chunks_well_formed` invariant, so a stray `home/temp/` /
        // `home//temp` / `/home/temp` / `""` reaches no subscriber on any path.
        let mut reg = RemoteSubscriberRegistry::new();
        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(13, 0, Some("home/**")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/temp"), "well-formed key matches");
        for malformed in ["home/temp/", "home//temp", "/home/temp", ""] {
            assert!(
                !reg.has_matching(malformed),
                "`home/**` must not match malformed `{malformed}`"
            );
        }
    }

    #[test]
    fn subscriber_has_matching_true_when_publish_pattern_covers_peer_literal() {
        let mut reg = RemoteSubscriberRegistry::new();
        let body =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(9, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/**"));
        assert!(reg.has_matching("**"));
        assert!(!reg.has_matching("other/**"));
    }

    #[test]
    fn subscriber_has_matching_false_after_undeclare() {
        let mut reg = RemoteSubscriberRegistry::new();
        let decl = DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(
            12,
            0,
            Some("home/temp"),
        ));
        reg.dispatch_declare(&decl, &HashMap::new());
        assert!(reg.has_matching("home/temp"));
        let undecl = DeclareOwnedVariant::CodecZenohUndeclSubscriber(undecl_subscriber(12));
        reg.dispatch_declare(&undecl, &HashMap::new());
        assert!(!reg.has_matching("home/temp"));
    }

    // ── R293 — honest two-pattern overlap (Pub-side mirror) ──

    #[test]
    fn subscriber_has_matching_true_when_two_patterns_share_literal_via_mid_star() {
        // Pub-side mirror of the Q-side test
        // `queryable_has_matching_true_when_two_patterns_share_literal_via_mid_star`.
        // `home/*/temp` peer subscriber + `*/sensor/temp` publish
        // keyexpr share `home/sensor/temp` — pre-R293 the matcher
        // missed this; R293 honest intersection fires.
        let mut reg = RemoteSubscriberRegistry::new();
        let d = DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(
            30,
            0,
            Some("home/*/temp"),
        ));
        reg.dispatch_declare(&d, &HashMap::new());
        assert!(reg.has_matching("*/sensor/temp"));
        assert!(reg.has_matching("*/*/temp"));
    }

    #[test]
    fn subscriber_has_matching_false_when_two_patterns_have_disjoint_anchors() {
        // Pub-side mirror of the Q-side disjoint-anchor negative test.
        let mut reg = RemoteSubscriberRegistry::new();
        let d = DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(
            31,
            0,
            Some("home/**/temp"),
        ));
        reg.dispatch_declare(&d, &HashMap::new());
        assert!(!reg.has_matching("kitchen/**/temp"));
    }

    #[test]
    fn subscriber_has_matching_true_when_double_star_intersects_either_direction() {
        // Pub-side mirror — `home/** ∩ **/temp` shares `home/temp`
        // and any `home/<x>.../temp`. Backtracking on both sides.
        let mut reg = RemoteSubscriberRegistry::new();
        let d =
            DeclareOwnedVariant::CodecZenohDeclSubscriber(decl_subscriber(32, 0, Some("home/**")));
        reg.dispatch_declare(&d, &HashMap::new());
        assert!(reg.has_matching("**/temp"));
        assert!(reg.has_matching("**"));
    }
}
