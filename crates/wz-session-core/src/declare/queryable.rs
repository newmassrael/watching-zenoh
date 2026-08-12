// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `RemoteQueryableRegistry` — application-layer registry tracking
//! the peer's outbound `DeclQueryable` / `UndeclQueryable` records.
//! Q-side mirror of [`crate::declare::subscriber::RemoteSubscriberRegistry`];
//! see [`crate::declare`] module docs for the rationale.
//!
//! R311dp / di-16 — migrated to wz-session-core (was
//! `wz-runtime-tokio::declare::queryable`). `has_matching` is an
//! inherent method on the registry calling
//! [`crate::keyexpr_match::keyexpr_intersect_patterns`] directly —
//! no extension-trait split (R311dn-pre lift made this possible).

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
/// `DeclQueryable` / `UndeclQueryable` records. Q-side mirror of
/// [`crate::declare::subscriber::RemoteSubscriberRegistry`]; the
/// dispatch + callback contracts are identical, only the codec record
/// types differ.
///
/// Why a separate registry rather than a single
/// "RemoteDeclarationRegistry" that handles both: keeping the two
/// surfaces separate lets consumers wire metrics / debug callbacks
/// independently for "peer subscribers" vs "peer queryables"
/// (z_get-side topology in particular is interested only in the
/// queryable subset). Cost is a small amount of duplicated dispatch
/// code; benefit is type-safe consumer wiring and an honest scope
/// boundary that matches zenoh-pico's
/// `Z_FEATURE_SUBSCRIPTION` vs `Z_FEATURE_QUERYABLE` compile-time
/// feature split.
pub struct RemoteQueryableRegistry<D: DeclSink, U: UndeclSink> {
    /// R311gb (Track 2) — shared 2-list observer machinery composed from
    /// [`crate::decl_sink::DeclObserverPair`] (SSOT across the three
    /// `DeclSink` registries). `D = BoxedDeclSink` / `U = BoxedUndeclSink`
    /// on AP, consumer-supplied closed `enum`s on MCU.
    observers: DeclObserverPair<D, U>,
    /// R288 — peer-declared queryables tracked by `{id -> resolved
    /// keyexpr}`. Populated on every inbound `DeclQueryable` whose
    /// keyexpr resolves through `peer_keyexpr_table`, and entries
    /// removed on the matching `UndeclQueryable`. Backbone for
    /// `Querier::get_matching_status` which iterates this map at
    /// consult time to decide whether any currently-declared peer
    /// queryable's keyexpr intersects the querier's keyexpr.
    ///
    /// Why a HashMap (rather than a Vec or BTreeMap): the membership
    /// invariant is by id, undeclare removal is keyed by id, and the
    /// only iteration consumer ([`Self::has_matching`]) does not
    /// depend on ordering. HashMap gives O(1) insert + remove + the
    /// rare full-iteration on get_matching_status calls.
    ///
    /// R311gb (Track 2) — wire-side membership state (populated by
    /// `dispatch_declare` consuming owned `Declare` records, read by
    /// `has_matching`); `alloc`-gated per the borrow boundary.
    #[cfg(feature = "alloc")]
    declared: HashMap<u64, String>,
    /// R311kh — matching-listener watches (pico `Z_FEATURE_MATCHING`),
    /// the Q-side mirror of the subscriber registry's list: re-evaluated
    /// against the `declared` table on every membership mutation, firing
    /// each watch's sink on a verdict flip (the listener form of the
    /// polling `Querier::get_matching_status`).
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    matching_watches: MatchingWatchList<BoxedMatchingSink>,
}

impl<D: DeclSink, U: UndeclSink> Default for RemoteQueryableRegistry<D, U> {
    fn default() -> Self {
        Self::with_sink_backing()
    }
}

impl<D: DeclSink, U: UndeclSink> RemoteQueryableRegistry<D, U> {
    /// New empty registry over explicit sink backings `D` / `U`. Both
    /// observer lists start empty; an empty registry processes inbound
    /// `Declare(Decl*Queryable)` records as no-ops.
    ///
    /// R311gb-3d — the generic constructor (no-`alloc` / MCU entry point,
    /// paired with the `*_sink` installers). AP callers use the inferring
    /// [`new`](RemoteQueryableRegistry::new) shorthand, which fixes
    /// `D = BoxedDeclSink` / `U = BoxedUndeclSink`.
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
    /// [`on_queryable_declared`](RemoteQueryableRegistry::on_queryable_declared)
    /// convenience wrapper funnels through here. Duplicate sinks allowed;
    /// dispatch fires them in registration order. R311lb — returns the
    /// registry-local observer id for
    /// [`remove_queryable_declared_sink`](Self::remove_queryable_declared_sink).
    pub fn on_queryable_declared_sink(&mut self, sink: D) -> Result<u64, RegisterError> {
        self.observers.install_decl(sink)
    }

    /// R311gb-3d — install an explicit [`UndeclSink`] observer. The
    /// `alloc`-only
    /// [`on_queryable_undeclared`](RemoteQueryableRegistry::on_queryable_undeclared)
    /// convenience wrapper funnels through here. R311lb — returns the
    /// registry-local observer id for
    /// [`remove_queryable_undeclared_sink`](Self::remove_queryable_undeclared_sink).
    pub fn on_queryable_undeclared_sink(&mut self, sink: U) -> Result<u64, RegisterError> {
        self.observers.install_undecl(sink)
    }

    /// R311lb — remove the declaration observer keyed by `id` (the
    /// return of
    /// [`on_queryable_declared_sink`](Self::on_queryable_declared_sink)).
    /// Returns whether one was removed; double removal is a `false`
    /// no-op. The removal half of the Session-tier decl-listener
    /// surface (R311lc).
    pub fn remove_queryable_declared_sink(&mut self, id: u64) -> bool {
        self.observers.uninstall_decl(id)
    }

    /// R311lb — remove the undeclaration observer keyed by `id`. Same
    /// contract as
    /// [`remove_queryable_declared_sink`](Self::remove_queryable_declared_sink).
    pub fn remove_queryable_undeclared_sink(&mut self, id: u64) -> bool {
        self.observers.uninstall_undecl(id)
    }

    /// Number of installed `on_queryable_declared` callbacks.
    pub fn on_decl_len(&self) -> usize {
        self.observers.decl_len()
    }

    /// Number of installed `on_queryable_undeclared` callbacks.
    pub fn on_undecl_len(&self) -> usize {
        self.observers.undecl_len()
    }

    /// R288 — count of currently-declared peer queryables (those whose
    /// inbound `DeclQueryable` has been dispatched and whose
    /// `UndeclQueryable` has not). Exposed for diagnostic surfaces
    /// (test fixtures, metrics) and for the `get_matching_status`
    /// implementation that wants to short-circuit when no peer is
    /// declared at all.
    #[cfg(feature = "alloc")]
    pub fn declared_count(&self) -> usize {
        self.declared.len()
    }

    /// R288 — iterate over currently-declared peer queryables as
    /// `(id, resolved_keyexpr)` pairs. Ordering is unspecified (the
    /// backing storage is a `HashMap`). Useful for debug surfaces
    /// that want to enumerate every peer-side declaration; the
    /// `has_matching` accessor below is the production consult
    /// path.
    #[cfg(feature = "alloc")]
    pub fn iter_declared(&self) -> impl Iterator<Item = (u64, &str)> + '_ {
        self.declared.iter().map(|(id, ke)| (*id, ke.as_str()))
    }

    /// Backbone for `Querier::get_matching_status` (R288 surfaced
    /// the API; R293 lifted the underlying matcher to honest
    /// wildcard-vs-wildcard intersection). Returns `true` iff at
    /// least one currently-declared peer queryable's keyexpr
    /// intersects `query_keyexpr` under
    /// [`crate::keyexpr_match::keyexpr_intersect_patterns`] — i.e.
    /// there exists at least one literal `/`-separated keyexpr that
    /// both sides match.
    ///
    /// The semantic covers every textbook case:
    ///
    /// * both literals — intersect iff byte-equal,
    /// * one-side pattern covering the other-side literal (any
    ///   `**` / `*` / `$*` shape) — intersect via the asymmetric
    ///   pattern-vs-literal walk inside `keyexpr_intersect_patterns`,
    /// * two-pattern overlap where neither contains the other
    ///   (e.g. `home/*/temp` vs `*/sensor/temp` share
    ///   `home/sensor/temp`) — intersect via the two-side
    ///   `**`-backtracking recursion. This case was the R288
    ///   bidirectional-asymmetric approximation's gap; R293 closed
    ///   it.
    ///
    /// `peer-declared` keyexprs arrive over the wire as runtime
    /// strings (resolved by `resolve_wireexpr` against the peer
    /// keyexpr alias table); the wz spec's "compile-time fixed
    /// KeyExpr set + O(1) table lookup" promise (Appendix C of the
    /// SCE-forge RFC) governs wz's *own* declared keyexprs, not the
    /// peer-side. The matcher here is therefore the production
    /// answer for the peer-declared domain.
    #[cfg(feature = "alloc")]
    pub fn has_matching(&self, query_keyexpr: &str) -> bool {
        declared_intersects(&self.declared, query_keyexpr)
    }

    /// R311kh — register a matching-listener watch over `keyexpr`, the
    /// Q-side mirror of the subscriber registry's
    /// `declare_matching_listener`: fires on every verdict flip of
    /// [`Self::has_matching`]`(keyexpr)` caused by an inbound
    /// `DeclQueryable` / `UndeclQueryable`, seeded with the current
    /// verdict (registration never fires).
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn declare_matching_listener(&mut self, keyexpr: &str, sink: BoxedMatchingSink) -> u64 {
        let initial = self.has_matching(keyexpr);
        self.matching_watches
            .register(String::from(keyexpr), initial, sink)
    }

    /// R311kh — remove a matching-listener watch. Returns whether one
    /// was removed.
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn undeclare_matching_listener(&mut self, id: u64) -> bool {
        self.matching_watches.unregister(id)
    }

    /// Number of registered matching-listener watches.
    #[cfg(all(feature = "session-matching", feature = "alloc"))]
    pub fn matching_listener_len(&self) -> usize {
        self.matching_watches.len()
    }

    /// Route an inbound `Declare` envelope's inner body through the
    /// remote-queryable callbacks. Same scope rules as
    /// [`crate::declare::subscriber::RemoteSubscriberRegistry::dispatch_declare`]:
    /// only `DeclQueryable` / `UndeclQueryable` arms route here,
    /// others (Subscriber, Token, Kexpr, Final) are no-ops at this
    /// layer.
    /// R311gb (Track 2) — no-heap declaration fire: hand each installed
    /// `on_decl` observer the borrowed [`DeclView`]. The MCU no-heap
    /// fan-out SSOT; the wire path
    /// ([`dispatch_declare`](Self::dispatch_declare)) funnels through here
    /// after updating the `declared` table. Returns the count fired.
    pub fn dispatch_declared_borrowed(&mut self, view: &dyn DeclView) -> usize {
        self.observers.fire_declared(view)
    }

    /// R311gb (Track 2) — no-heap undeclaration fire: hand each installed
    /// `on_undecl` observer the bare `id`. Returns the count fired.
    pub fn dispatch_undeclared(&mut self, id: u64) -> usize {
        self.observers.fire_undeclared(id)
    }

    /// R311gb (Track 2) — `all(codec-declare, alloc)`-gated wire dispatch;
    /// updates the `alloc` `declared` table then funnels through the
    /// no-heap fire SSOT.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_declare<'a>(
        &mut self,
        body: &DeclareOwnedVariant,
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        match body {
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl) => {
                let resolved = match resolve_wireexpr_in(&decl.keyexpr.body, peer_keyexpr_table) {
                    Some(s) => s,
                    None => return,
                };
                // R288 — track peer-declared queryable so
                // get_matching_status can consult the membership at
                // a later point. Late-arrival semantics — a
                // subsequent declare with the same id overwrites
                // the prior entry (peer renamed the keyexpr), which
                // matches zenoh-pico's same-id-replaces behaviour.
                self.declared.insert(decl.id, resolved.clone());
                let view = BorrowedDecl {
                    id: decl.id,
                    keyexpr: &resolved,
                };
                self.dispatch_declared_borrowed(&view);
                // R311kh — membership changed: flip-fire the matching
                // watches (disjoint field borrows via the free-fn consult).
                #[cfg(feature = "session-matching")]
                self.matching_watches
                    .reevaluate(|k| declared_intersects(&self.declared, k));
            }
            DeclareOwnedVariant::CodecZenohUndeclQueryable(undecl) => {
                // R288 — drop the membership entry first so a
                // get_matching_status fired from inside the
                // on_undecl callback chain observes the post-
                // undeclare state. Missing-id remove is silent.
                self.declared.remove(&undecl.id);
                self.dispatch_undeclared(undecl.id);
                // R311kh — see the DeclQueryable arm.
                #[cfg(feature = "session-matching")]
                self.matching_watches
                    .reevaluate(|k| declared_intersects(&self.declared, k));
            }
            // Other sub-variants do not reach this registry.
            _ => {}
        }
    }

    /// Drain a `Vec<NetworkMessage>` through [`Self::dispatch_declare`].
    /// Mirror of the sibling registries.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_messages<'a>(
        &mut self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: impl Into<MappingSpaces<'a>>,
    ) {
        let peer_keyexpr_table = peer_keyexpr_table.into();
        for message in messages {
            if let NetworkMessage::Declare(decl) = message {
                self.dispatch_declare(&decl.body, peer_keyexpr_table);
            }
        }
    }

    /// `IterationEvent` adapter; mirror of the sibling registries.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
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

/// R311gb-3d — AP / `alloc`-profile convenience constructors (the
/// `BoxedDeclSink` / `BoxedUndeclSink` instantiation only). Mirror of the
/// subscriber-side block; the no-`alloc` profile installs consumer-
/// supplied sinks through the generic `*_sink` installers.
#[cfg(feature = "alloc")]
impl RemoteQueryableRegistry<BoxedDeclSink, BoxedUndeclSink> {
    /// New empty AP registry backed by heap-boxed closures. Inferring
    /// shorthand for
    /// [`with_sink_backing`](RemoteQueryableRegistry::with_sink_backing).
    pub fn new() -> Self {
        Self::with_sink_backing()
    }

    /// Install a closure fired on every inbound `Declare(DeclQueryable)`
    /// whose keyexpr resolves. The closure receives `&dyn DeclView` (the
    /// peer-declared `id` + resolved keyexpr) — the R311gb-3d seam
    /// contract replaces the prior `(&DeclQueryableOwned, &str)`
    /// ([`feedback_signature_stability`] wire-data exemption). Heap-boxed
    /// via [`BoxedDeclSink`]. R311lb — returns the registry-local
    /// observer id (see [`Self::remove_queryable_declared_sink`]).
    pub fn on_queryable_declared(
        &mut self,
        callback: impl FnMut(&dyn crate::decl_sink::DeclView) + Send + 'static,
    ) -> u64 {
        // AP backing: the observer `BoundedVec` grows past the advisory
        // `N`, so installing never fails here.
        self.on_queryable_declared_sink(BoxedDeclSink::new(callback))
            .expect("observer install on the alloc backing never exceeds declared capacity")
    }

    /// Install a closure fired on every inbound `Declare(UndeclQueryable)`.
    /// The closure receives the bare `id` (`u64`). Heap-boxed via
    /// [`BoxedUndeclSink`]. R311lb — returns the registry-local observer
    /// id (see [`Self::remove_queryable_undeclared_sink`]).
    pub fn on_queryable_undeclared(&mut self, callback: impl FnMut(u64) + Send + 'static) -> u64 {
        self.on_queryable_undeclared_sink(BoxedUndeclSink::new(callback))
            .expect("observer install on the alloc backing never exceeds declared capacity")
    }
}

// R311gb (Track 2) — test gate now explicit (was inherited from the
// module's `codec-declare` gate); exercises `dispatch_declare` +
// `has_matching`, now `all(codec-declare, alloc)`-gated.
#[cfg(all(test, feature = "codec-declare"))]
mod tests {
    //! R311ds — wider behavioural tests migrated here from the
    //! wz-runtime-tokio `declare/queryable.rs` shell (R311dr-wider-tests
    //! carry closure). `Mutex` is `std` under `#[cfg(test)]` per the
    //! wz-codecs sibling-crate convention; production stays no_std.

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
    fn queryable_empty_registry_dispatch_is_noop() {
        let mut reg = RemoteQueryableRegistry::new();
        let body =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(7, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(reg.on_decl_len(), 0);
        assert_eq!(reg.on_undecl_len(), 0);
    }

    #[test]
    fn queryable_declare_callback_fires_on_literal_keyexpr() {
        let mut reg = RemoteQueryableRegistry::new();
        let captured: Arc<Mutex<Vec<(u64, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_queryable_declared(move |decl| {
            captured_for_cb
                .lock()
                .unwrap()
                .push((decl.id(), decl.keyexpr().to_string()));
        });
        let body =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(8, 0, Some("home/door")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(
            *captured.lock().unwrap(),
            vec![(8, "home/door".to_string())]
        );
    }

    #[test]
    fn queryable_callback_skipped_on_unresolvable_mapping_id() {
        let mut reg = RemoteQueryableRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_for_cb = fired.clone();
        reg.on_queryable_declared(move |_d| {
            fired_for_cb.fetch_add(1, Ordering::SeqCst);
        });
        let body = DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(1, 77, None));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(fired.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn queryable_undeclare_callback_fires() {
        let mut reg = RemoteQueryableRegistry::new();
        let captured: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_queryable_undeclared(move |id| {
            captured_for_cb.lock().unwrap().push(id);
        });
        let body = DeclareOwnedVariant::CodecZenohUndeclQueryable(undecl_queryable(99));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(*captured.lock().unwrap(), vec![99]);
    }

    #[test]
    fn queryable_declared_count_starts_at_zero_and_tracks_decl_undecl_lifecycle() {
        let mut reg = RemoteQueryableRegistry::new();
        assert_eq!(reg.declared_count(), 0);

        // DeclQueryable id=10 keyexpr=home/temp → count 1
        let decl1 =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(10, 0, Some("home/temp")));
        reg.dispatch_declare(&decl1, &HashMap::new());
        assert_eq!(reg.declared_count(), 1);

        // DeclQueryable id=11 keyexpr=home/door → count 2
        let decl2 =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(11, 0, Some("home/door")));
        reg.dispatch_declare(&decl2, &HashMap::new());
        assert_eq!(reg.declared_count(), 2);

        // UndeclQueryable id=10 → count 1 (only id=11 remains)
        let undecl1 = DeclareOwnedVariant::CodecZenohUndeclQueryable(undecl_queryable(10));
        reg.dispatch_declare(&undecl1, &HashMap::new());
        assert_eq!(reg.declared_count(), 1);
        let remaining: Vec<(u64, &str)> = reg.iter_declared().collect();
        assert_eq!(remaining, vec![(11, "home/door")]);

        // UndeclQueryable id=11 → count 0
        let undecl2 = DeclareOwnedVariant::CodecZenohUndeclQueryable(undecl_queryable(11));
        reg.dispatch_declare(&undecl2, &HashMap::new());
        assert_eq!(reg.declared_count(), 0);
    }

    #[test]
    fn queryable_has_matching_false_on_empty_registry() {
        let reg = RemoteQueryableRegistry::new();
        assert!(!reg.has_matching("home/temp"));
        assert!(!reg.has_matching("anything"));
    }

    #[test]
    fn queryable_has_matching_true_on_literal_keyexpr_equality() {
        let mut reg = RemoteQueryableRegistry::new();
        let body =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(7, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/temp"));
        assert!(!reg.has_matching("home/door"));
    }

    #[test]
    fn queryable_has_matching_true_when_peer_pattern_covers_query_literal() {
        let mut reg = RemoteQueryableRegistry::new();
        let body =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(8, 0, Some("home/**")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/temp"));
        assert!(reg.has_matching("home/door/inner"));
        assert!(!reg.has_matching("other/x"));
    }

    #[test]
    fn queryable_has_matching_true_when_query_pattern_covers_peer_literal() {
        let mut reg = RemoteQueryableRegistry::new();
        let body =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(9, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/**"));
        assert!(reg.has_matching("**"));
        assert!(!reg.has_matching("other/**"));
    }

    #[test]
    fn queryable_has_matching_false_after_undeclare() {
        let mut reg = RemoteQueryableRegistry::new();
        let decl =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(12, 0, Some("home/temp")));
        reg.dispatch_declare(&decl, &HashMap::new());
        assert!(reg.has_matching("home/temp"));
        let undecl = DeclareOwnedVariant::CodecZenohUndeclQueryable(undecl_queryable(12));
        reg.dispatch_declare(&undecl, &HashMap::new());
        assert!(!reg.has_matching("home/temp"));
    }

    #[test]
    fn queryable_has_matching_with_mixed_peers_finds_any_match() {
        let mut reg = RemoteQueryableRegistry::new();
        let d1 =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(20, 0, Some("other/foo")));
        let d2 =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(21, 0, Some("home/temp")));
        let d3 = DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(22, 0, Some("a/b/c")));
        reg.dispatch_declare(&d1, &HashMap::new());
        reg.dispatch_declare(&d2, &HashMap::new());
        reg.dispatch_declare(&d3, &HashMap::new());
        assert_eq!(reg.declared_count(), 3);
        // Match on the middle entry; other entries do not interfere.
        assert!(reg.has_matching("home/temp"));
        // Match on the last entry via query-pattern asymmetric arm.
        assert!(reg.has_matching("a/**"));
        // No match on either side.
        assert!(!reg.has_matching("nothing/here"));
    }

    // ── R293 — honest two-pattern overlap (was a false-negative under
    // the pre-R293 bidirectional asymmetric pattern-match approx) ──

    #[test]
    fn queryable_has_matching_true_when_two_patterns_share_literal_via_mid_star() {
        // The textbook two-pattern overlap case: `home/*/temp` (peer)
        // and `*/sensor/temp` (querier) share `home/sensor/temp` (and
        // any `home/<x>/temp` where `<x> == sensor` literally). Pre-
        // R293 the matcher only walked pattern-vs-literal on each
        // direction; neither arm fired for two patterns-without-
        // containment, so this case returned false. R293 honest
        // intersection returns true.
        let mut reg = RemoteQueryableRegistry::new();
        let d = DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(
            30,
            0,
            Some("home/*/temp"),
        ));
        reg.dispatch_declare(&d, &HashMap::new());
        assert!(reg.has_matching("*/sensor/temp"));
        assert!(reg.has_matching("*/*/temp"));
    }

    #[test]
    fn queryable_has_matching_false_when_two_patterns_have_disjoint_anchors() {
        // `home/**/temp ∩ kitchen/**/temp` — literal anchor at chunk
        // 0 disagrees on both sides and no `**` shape can bridge the
        // anchor disagreement. Negative-side coverage for the same
        // two-pattern domain as the test above.
        let mut reg = RemoteQueryableRegistry::new();
        let d = DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(
            31,
            0,
            Some("home/**/temp"),
        ));
        reg.dispatch_declare(&d, &HashMap::new());
        assert!(!reg.has_matching("kitchen/**/temp"));
    }

    #[test]
    fn queryable_has_matching_true_when_double_star_intersects_either_direction() {
        // `home/** ∩ **/temp` shares `home/temp` and any
        // `home/<x>/.../temp`. Both sides are unrestricted-tail / -head
        // patterns; the matcher must walk both **-backtracks.
        let mut reg = RemoteQueryableRegistry::new();
        let d =
            DeclareOwnedVariant::CodecZenohDeclQueryable(decl_queryable(32, 0, Some("home/**")));
        reg.dispatch_declare(&d, &HashMap::new());
        assert!(reg.has_matching("**/temp"));
        assert!(reg.has_matching("**"));
    }

    #[test]
    fn queryable_dispatch_messages_routes_only_queryable_arms() {
        let mut reg = RemoteQueryableRegistry::new();
        let decl_count = Arc::new(AtomicUsize::new(0));
        let undecl_count = Arc::new(AtomicUsize::new(0));
        let d = decl_count.clone();
        let u = undecl_count.clone();
        reg.on_queryable_declared(move |_d| {
            d.fetch_add(1, Ordering::SeqCst);
        });
        reg.on_queryable_undeclared(move |_u| {
            u.fetch_add(1, Ordering::SeqCst);
        });

        // Mix of Subscriber + Queryable envelopes — only Queryable
        // arms route into this registry.
        let messages =
            vec![
                NetworkMessage::Declare(Box::new(declare_envelope_decl_subscriber(
                    decl_subscriber(1, 0, Some("not-this")),
                ))),
                NetworkMessage::Declare(Box::new(declare_envelope_decl_queryable(decl_queryable(
                    2,
                    0,
                    Some("yes-this"),
                )))),
                NetworkMessage::Declare(Box::new(declare_envelope_undecl_queryable(
                    undecl_queryable(2),
                ))),
            ];
        reg.dispatch_messages(&messages, &HashMap::new());
        assert_eq!(
            decl_count.load(Ordering::SeqCst),
            1,
            "only the queryable decl routes here"
        );
        assert_eq!(undecl_count.load(Ordering::SeqCst), 1);
    }
}
