// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `RemoteQueryableRegistry` — application-layer registry tracking
//! the peer's outbound `DeclQueryable` / `UndeclQueryable` records.
//! Q-side mirror of [`crate::declare::RemoteSubscriberRegistry`];
//! see [`crate::declare`] module docs for the rationale.

use std::collections::HashMap;

use wz_codecs::decl_queryable::DeclQueryable;
use wz_codecs::declare::DeclareVariant;
use wz_codecs::undecl_queryable::UndeclQueryable;

use super::resolve_wireexpr;
use crate::session_glue::{DriverLoopOutcome, IterationEvent, NetworkMessage};

/// Boxed callback invoked when an inbound
/// `Declare(DeclQueryable)` is decoded and its keyexpr resolves to a
/// literal. Same shape as
/// [`crate::declare::DeclSubscriberCallback`] — the codec records
/// carry identical field layout (header / id / keyexpr) and the
/// application-level "peer declared a queryable on this keyexpr"
/// signal mirrors the subscriber surface; consumers may install a
/// queryable-side counterpart of every subscriber-side hook (metrics,
/// route table, debug log).
pub type DeclQueryableCallback = Box<dyn FnMut(&DeclQueryable, &str) + Send + 'static>;

/// Boxed callback invoked when an inbound
/// `Declare(UndeclQueryable)` is decoded. The undeclare body has no
/// keyexpr field; the peer identifies the prior queryable by `id`.
pub type UndeclQueryableCallback = Box<dyn FnMut(&UndeclQueryable) + Send + 'static>;

/// Application-layer registry tracking the peer's outbound
/// `DeclQueryable` / `UndeclQueryable` records. Q-side mirror of
/// [`crate::declare::RemoteSubscriberRegistry`]; the dispatch +
/// callback contracts are identical, only the codec record types
/// differ.
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
pub struct RemoteQueryableRegistry {
    on_decl: Vec<DeclQueryableCallback>,
    on_undecl: Vec<UndeclQueryableCallback>,
    /// R288 — peer-declared queryables tracked by `{id -> resolved
    /// keyexpr}`. Populated on every inbound `DeclQueryable` whose
    /// keyexpr resolves through `peer_keyexpr_table`, and entries
    /// removed on the matching `UndeclQueryable`. Backbone for
    /// [`Querier::get_matching_status`] which iterates this map at
    /// consult time to decide whether any currently-declared peer
    /// queryable's keyexpr intersects the querier's keyexpr.
    ///
    /// Why a HashMap (rather than a Vec or BTreeMap): the membership
    /// invariant is by id, undeclare removal is keyed by id, and the
    /// only iteration consumer ([`Self::has_matching`]) does not
    /// depend on ordering. HashMap gives O(1) insert + remove + the
    /// rare full-iteration on get_matching_status calls.
    declared: HashMap<u64, String>,
}

impl Default for RemoteQueryableRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RemoteQueryableRegistry {
    /// New empty registry. Both callback lists start empty; an empty
    /// registry processes inbound `Declare(Decl*Queryable)` records
    /// as no-ops.
    pub fn new() -> Self {
        Self {
            on_decl: Vec::new(),
            on_undecl: Vec::new(),
            declared: HashMap::new(),
        }
    }

    /// Install a callback fired on every inbound
    /// `Declare(DeclQueryable)` whose keyexpr resolves through the
    /// peer keyexpr table. Duplicate callbacks allowed; dispatch
    /// fires them in registration order.
    pub fn on_queryable_declared(
        &mut self,
        callback: impl FnMut(&DeclQueryable, &str) + Send + 'static,
    ) {
        self.on_decl.push(Box::new(callback));
    }

    /// Install a callback fired on every inbound
    /// `Declare(UndeclQueryable)`.
    pub fn on_queryable_undeclared(
        &mut self,
        callback: impl FnMut(&UndeclQueryable) + Send + 'static,
    ) {
        self.on_undecl.push(Box::new(callback));
    }

    /// Number of installed `on_queryable_declared` callbacks.
    pub fn on_decl_len(&self) -> usize {
        self.on_decl.len()
    }

    /// Number of installed `on_queryable_undeclared` callbacks.
    pub fn on_undecl_len(&self) -> usize {
        self.on_undecl.len()
    }

    /// R288 — count of currently-declared peer queryables (those whose
    /// inbound `DeclQueryable` has been dispatched and whose
    /// `UndeclQueryable` has not). Exposed for diagnostic surfaces
    /// (test fixtures, metrics) and for the `get_matching_status`
    /// implementation that wants to short-circuit when no peer is
    /// declared at all.
    pub fn declared_count(&self) -> usize {
        self.declared.len()
    }

    /// R288 — iterate over currently-declared peer queryables as
    /// `(id, resolved_keyexpr)` pairs. Ordering is unspecified (the
    /// backing storage is a `HashMap`). Useful for debug surfaces
    /// that want to enumerate every peer-side declaration; the
    /// `has_matching` accessor below is the production consult
    /// path.
    pub fn iter_declared(&self) -> impl Iterator<Item = (u64, &str)> + '_ {
        self.declared.iter().map(|(id, ke)| (*id, ke.as_str()))
    }

    /// Backbone for `Querier::get_matching_status` (R288 surfaced
    /// the API; R293 lifted the underlying matcher to honest
    /// wildcard-vs-wildcard intersection). Returns `true` iff at
    /// least one currently-declared peer queryable's keyexpr
    /// intersects `query_keyexpr` under
    /// [`crate::pubsub::keyexpr_intersect_patterns`] — i.e. there
    /// exists at least one literal `/`-separated keyexpr that both
    /// sides match.
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
    pub fn has_matching(&self, query_keyexpr: &str) -> bool {
        let query_chunks: Vec<&str> = query_keyexpr.split('/').collect();
        self.declared.values().any(|peer_keyexpr| {
            let peer_chunks: Vec<&str> = peer_keyexpr.split('/').collect();
            crate::pubsub::keyexpr_intersect_patterns(&peer_chunks, &query_chunks)
        })
    }

    /// Route an inbound `Declare` envelope's inner body through the
    /// remote-queryable callbacks. Same scope rules as
    /// [`crate::declare::RemoteSubscriberRegistry::dispatch_declare`]:
    /// only `DeclQueryable` / `UndeclQueryable` arms route here,
    /// others (Subscriber, Token, Kexpr, Final) are no-ops at this
    /// layer.
    pub fn dispatch_declare(
        &mut self,
        body: &DeclareVariant,
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        match body {
            DeclareVariant::CodecZenohDeclQueryable(decl) => {
                let resolved = match resolve_wireexpr(&decl.keyexpr.body, peer_keyexpr_table) {
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
                for cb in &mut self.on_decl {
                    cb(decl, &resolved);
                }
            }
            DeclareVariant::CodecZenohUndeclQueryable(undecl) => {
                // R288 — drop the membership entry first so a
                // get_matching_status fired from inside the
                // on_undecl callback chain observes the post-
                // undeclare state. Missing-id remove is silent
                // (peer sent UndeclQueryable for an id we never
                // saw a DeclQueryable for; this is a peer-side
                // contract violation we do not surface here).
                self.declared.remove(&undecl.id);
                for cb in &mut self.on_undecl {
                    cb(undecl);
                }
            }
            // Other sub-variants do not reach this registry.
            _ => {}
        }
    }

    /// Drain a `Vec<NetworkMessage>` through [`Self::dispatch_declare`].
    /// Mirror of
    /// [`crate::declare::RemoteSubscriberRegistry::dispatch_messages`].
    pub fn dispatch_messages(
        &mut self,
        messages: &[NetworkMessage],
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        for message in messages {
            if let NetworkMessage::Declare(decl) = message {
                self.dispatch_declare(&decl.body, peer_keyexpr_table);
            }
        }
    }

    /// `IterationEvent` adapter; mirror of
    /// [`crate::declare::RemoteSubscriberRegistry::dispatch_iteration_event`].
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

#[cfg(test)]
mod tests {
    use super::super::test_helpers::*;
    use super::*;
    use portable_atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[test]
    fn queryable_empty_registry_dispatch_is_noop() {
        let mut reg = RemoteQueryableRegistry::new();
        let body = DeclareVariant::CodecZenohDeclQueryable(decl_queryable(7, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(reg.on_decl_len(), 0);
        assert_eq!(reg.on_undecl_len(), 0);
    }

    #[test]
    fn queryable_declare_callback_fires_on_literal_keyexpr() {
        let mut reg = RemoteQueryableRegistry::new();
        let captured: Arc<Mutex<Vec<(u64, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_queryable_declared(move |decl, resolved| {
            captured_for_cb
                .lock()
                .unwrap()
                .push((decl.id, resolved.to_string()));
        });
        let body = DeclareVariant::CodecZenohDeclQueryable(decl_queryable(8, 0, Some("home/door")));
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
        reg.on_queryable_declared(move |_d, _r| {
            fired_for_cb.fetch_add(1, Ordering::SeqCst);
        });
        let body = DeclareVariant::CodecZenohDeclQueryable(decl_queryable(1, 77, None));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(fired.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn queryable_undeclare_callback_fires() {
        let mut reg = RemoteQueryableRegistry::new();
        let captured: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_queryable_undeclared(move |u| {
            captured_for_cb.lock().unwrap().push(u.id);
        });
        let body = DeclareVariant::CodecZenohUndeclQueryable(undecl_queryable(99));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(*captured.lock().unwrap(), vec![99]);
    }

    #[test]
    fn queryable_declared_count_starts_at_zero_and_tracks_decl_undecl_lifecycle() {
        let mut reg = RemoteQueryableRegistry::new();
        assert_eq!(reg.declared_count(), 0);

        // DeclQueryable id=10 keyexpr=home/temp → count 1
        let decl1 =
            DeclareVariant::CodecZenohDeclQueryable(decl_queryable(10, 0, Some("home/temp")));
        reg.dispatch_declare(&decl1, &HashMap::new());
        assert_eq!(reg.declared_count(), 1);

        // DeclQueryable id=11 keyexpr=home/door → count 2
        let decl2 =
            DeclareVariant::CodecZenohDeclQueryable(decl_queryable(11, 0, Some("home/door")));
        reg.dispatch_declare(&decl2, &HashMap::new());
        assert_eq!(reg.declared_count(), 2);

        // UndeclQueryable id=10 → count 1 (only id=11 remains)
        let undecl1 = DeclareVariant::CodecZenohUndeclQueryable(undecl_queryable(10));
        reg.dispatch_declare(&undecl1, &HashMap::new());
        assert_eq!(reg.declared_count(), 1);
        let remaining: Vec<(u64, &str)> = reg.iter_declared().collect();
        assert_eq!(remaining, vec![(11, "home/door")]);

        // UndeclQueryable id=11 → count 0
        let undecl2 = DeclareVariant::CodecZenohUndeclQueryable(undecl_queryable(11));
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
        let body = DeclareVariant::CodecZenohDeclQueryable(decl_queryable(7, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/temp"));
        assert!(!reg.has_matching("home/door"));
    }

    #[test]
    fn queryable_has_matching_true_when_peer_pattern_covers_query_literal() {
        let mut reg = RemoteQueryableRegistry::new();
        let body = DeclareVariant::CodecZenohDeclQueryable(decl_queryable(8, 0, Some("home/**")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/temp"));
        assert!(reg.has_matching("home/door/inner"));
        assert!(!reg.has_matching("other/x"));
    }

    #[test]
    fn queryable_has_matching_true_when_query_pattern_covers_peer_literal() {
        let mut reg = RemoteQueryableRegistry::new();
        let body = DeclareVariant::CodecZenohDeclQueryable(decl_queryable(9, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/**"));
        assert!(reg.has_matching("**"));
        assert!(!reg.has_matching("other/**"));
    }

    #[test]
    fn queryable_has_matching_false_after_undeclare() {
        let mut reg = RemoteQueryableRegistry::new();
        let decl =
            DeclareVariant::CodecZenohDeclQueryable(decl_queryable(12, 0, Some("home/temp")));
        reg.dispatch_declare(&decl, &HashMap::new());
        assert!(reg.has_matching("home/temp"));
        let undecl = DeclareVariant::CodecZenohUndeclQueryable(undecl_queryable(12));
        reg.dispatch_declare(&undecl, &HashMap::new());
        assert!(!reg.has_matching("home/temp"));
    }

    #[test]
    fn queryable_has_matching_with_mixed_peers_finds_any_match() {
        let mut reg = RemoteQueryableRegistry::new();
        let d1 = DeclareVariant::CodecZenohDeclQueryable(decl_queryable(20, 0, Some("other/foo")));
        let d2 = DeclareVariant::CodecZenohDeclQueryable(decl_queryable(21, 0, Some("home/temp")));
        let d3 = DeclareVariant::CodecZenohDeclQueryable(decl_queryable(22, 0, Some("a/b/c")));
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
        let d = DeclareVariant::CodecZenohDeclQueryable(decl_queryable(30, 0, Some("home/*/temp")));
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
        let d =
            DeclareVariant::CodecZenohDeclQueryable(decl_queryable(31, 0, Some("home/**/temp")));
        reg.dispatch_declare(&d, &HashMap::new());
        assert!(!reg.has_matching("kitchen/**/temp"));
    }

    #[test]
    fn queryable_has_matching_true_when_double_star_intersects_either_direction() {
        // `home/** ∩ **/temp` shares `home/temp` and any
        // `home/<x>/.../temp`. Both sides are unrestricted-tail / -head
        // patterns; the matcher must walk both **-backtracks.
        let mut reg = RemoteQueryableRegistry::new();
        let d = DeclareVariant::CodecZenohDeclQueryable(decl_queryable(32, 0, Some("home/**")));
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
        reg.on_queryable_declared(move |_d, _r| {
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
