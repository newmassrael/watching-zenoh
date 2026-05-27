// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `RemoteSubscriberRegistry` — application-layer registry tracking
//! the peer's outbound `DeclSubscriber` / `UndeclSubscriber` records.
//! See [`crate::declare`] module docs for the cross-registry rationale
//! and callback contract.

use std::collections::HashMap;

use wz_codecs::decl_subscriber::DeclSubscriber;
use wz_codecs::declare::DeclareVariant;
use wz_codecs::undecl_subscriber::UndeclSubscriber;

use super::resolve_wireexpr;
use crate::session_glue::{DriverLoopOutcome, IterationEvent, NetworkMessage};

/// Boxed callback invoked when an inbound
/// `Declare(DeclSubscriber)` is decoded and its keyexpr resolves to a
/// literal. The callback receives the codec record + the resolved
/// keyexpr literal so consumers don't have to re-resolve.
pub type DeclSubscriberCallback = Box<dyn FnMut(&DeclSubscriber, &str) + Send + 'static>;

/// Boxed callback invoked when an inbound
/// `Declare(UndeclSubscriber)` is decoded. The undeclare body has no
/// keyexpr field; the peer identifies the prior subscription by `id`.
pub type UndeclSubscriberCallback = Box<dyn FnMut(&UndeclSubscriber) + Send + 'static>;

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
pub struct RemoteSubscriberRegistry {
    on_decl: Vec<DeclSubscriberCallback>,
    on_undecl: Vec<UndeclSubscriberCallback>,
    /// R290 — peer-declared subscribers tracked by `{id -> resolved
    /// keyexpr}`. Pub-side analogue of the `declared` map landed on
    /// [`crate::declare::RemoteQueryableRegistry`] in R288. Populated
    /// on every inbound `DeclSubscriber` whose keyexpr resolves
    /// through `peer_keyexpr_table`, and entries removed on the
    /// matching `UndeclSubscriber`. Backbone for
    /// [`crate::session::Publisher::get_matching_status`] which
    /// iterates this map at consult time to decide whether any
    /// currently-declared peer subscriber's keyexpr intersects the
    /// publisher's keyexpr.
    ///
    /// Same HashMap rationale as the Q-side: by-id membership
    /// invariant, by-id Undecl removal, no ordering dependency on
    /// the rare full-iteration consult path.
    declared: HashMap<u64, String>,
}

impl Default for RemoteSubscriberRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RemoteSubscriberRegistry {
    /// New empty registry. Both callback lists start empty; an empty
    /// registry processes inbound `Declare(Decl*)` records as no-ops.
    pub fn new() -> Self {
        Self {
            on_decl: Vec::new(),
            on_undecl: Vec::new(),
            declared: HashMap::new(),
        }
    }

    /// Install a callback fired on every inbound
    /// `Declare(DeclSubscriber)` whose keyexpr resolves through the
    /// peer keyexpr table. Duplicate callbacks are explicitly allowed
    /// (e.g. one for metrics, one for route-table maintenance);
    /// dispatch fires them in registration order.
    pub fn on_subscriber_declared(
        &mut self,
        callback: impl FnMut(&DeclSubscriber, &str) + Send + 'static,
    ) {
        self.on_decl.push(Box::new(callback));
    }

    /// Install a callback fired on every inbound
    /// `Declare(UndeclSubscriber)`. Same registration-order +
    /// duplicates-allowed contract as
    /// [`Self::on_subscriber_declared`].
    pub fn on_subscriber_undeclared(
        &mut self,
        callback: impl FnMut(&UndeclSubscriber) + Send + 'static,
    ) {
        self.on_undecl.push(Box::new(callback));
    }

    /// Number of installed `on_subscriber_declared` callbacks.
    pub fn on_decl_len(&self) -> usize {
        self.on_decl.len()
    }

    /// Number of installed `on_subscriber_undeclared` callbacks.
    pub fn on_undecl_len(&self) -> usize {
        self.on_undecl.len()
    }

    /// R290 — count of currently-declared peer subscribers (those
    /// whose inbound `DeclSubscriber` has been dispatched and whose
    /// `UndeclSubscriber` has not). Pub-side mirror of
    /// [`crate::declare::RemoteQueryableRegistry::declared_count`].
    pub fn declared_count(&self) -> usize {
        self.declared.len()
    }

    /// R290 — iterate over currently-declared peer subscribers as
    /// `(id, resolved_keyexpr)` pairs. Pub-side mirror of
    /// [`crate::declare::RemoteQueryableRegistry::iter_declared`].
    /// Ordering is unspecified (HashMap iteration).
    pub fn iter_declared(&self) -> impl Iterator<Item = (u64, &str)> + '_ {
        self.declared.iter().map(|(id, ke)| (*id, ke.as_str()))
    }

    /// Backbone for `Publisher::get_matching_status` (R290 surfaced
    /// the API; R293 lifted the underlying matcher to honest
    /// wildcard-vs-wildcard intersection). Pub-side mirror of
    /// [`crate::declare::RemoteQueryableRegistry::has_matching`];
    /// returns `true` iff at least one currently-declared peer
    /// subscriber's keyexpr intersects `publish_keyexpr` under
    /// [`crate::pubsub::keyexpr_intersect_patterns`] — i.e. there
    /// exists at least one literal `/`-separated keyexpr that both
    /// sides match. The Q-side has_matching doc-comment carries the
    /// per-case textbook expansion (literal-literal byte-equal,
    /// one-side wildcard, two-side wildcard overlap); the semantic
    /// is symmetric across Pub-side and Q-side because the matcher
    /// itself is symmetric.
    pub fn has_matching(&self, publish_keyexpr: &str) -> bool {
        let publish_chunks: Vec<&str> = publish_keyexpr.split('/').collect();
        self.declared.values().any(|peer_keyexpr| {
            let peer_chunks: Vec<&str> = peer_keyexpr.split('/').collect();
            crate::pubsub::keyexpr_intersect_patterns(&peer_chunks, &publish_chunks)
        })
    }

    /// Route an inbound `Declare` envelope's inner body through the
    /// remote-subscriber callbacks. `DeclareVariant` arms other than
    /// `DeclSubscriber` / `UndeclSubscriber` are no-ops here —
    /// the queryable / token / kexpr / final arms route through
    /// their own dedicated registries (R121k-3, R121k-4, and the
    /// existing [`crate::pubsub::SubscriberRegistry::absorb_declare`]
    /// respectively).
    ///
    /// `peer_keyexpr_table` is the same table maintained by
    /// [`crate::pubsub::SubscriberRegistry`] from inbound
    /// `Declare(DeclKexpr)` records. Unresolvable keyexprs (mapping
    /// id not yet declared) drop the dispatch silently rather than
    /// firing on a partial keyexpr.
    pub fn dispatch_declare(
        &mut self,
        body: &DeclareVariant,
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        match body {
            DeclareVariant::CodecZenohDeclSubscriber(decl) => {
                let resolved = match resolve_wireexpr(&decl.keyexpr.body, peer_keyexpr_table) {
                    Some(s) => s,
                    None => return,
                };
                // R290 — same membership-tracking pattern as the
                // Q-side registry: same-id-replaces semantic, no
                // explicit conflict surfacing.
                self.declared.insert(decl.id, resolved.clone());
                for cb in &mut self.on_decl {
                    cb(decl, &resolved);
                }
            }
            DeclareVariant::CodecZenohUndeclSubscriber(undecl) => {
                // R290 — drop the membership entry first so a
                // get_matching_status fired from inside the
                // on_undecl callback chain observes the post-
                // undeclare state.
                self.declared.remove(&undecl.id);
                for cb in &mut self.on_undecl {
                    cb(undecl);
                }
            }
            // Other sub-variants do not reach this registry.
            _ => {}
        }
    }

    /// Drain a `Vec<NetworkMessage>` (typically the
    /// `FramePayload.messages` field surfaced by
    /// [`crate::session_glue::drive_session_until_terminal`]) through
    /// [`Self::dispatch_declare`]. Mirrors
    /// [`crate::query::QueryableRegistry::dispatch_messages`] /
    /// [`crate::pubsub::SubscriberRegistry::dispatch_messages`] so the
    /// observer in production code can fan one event into every
    /// registry uniformly.
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

    /// Convenience adapter that pulls the `FramePayload.messages` out
    /// of an `IterationEvent::Poll(DriverLoopOutcome::FramePayload)`
    /// and forwards to [`Self::dispatch_messages`]. Mirror of
    /// [`crate::query::QueryableRegistry::dispatch_iteration_event`] /
    /// [`crate::pubsub::SubscriberRegistry::dispatch_iteration_event`].
    /// Other `IterationEvent` variants (`Lease`, non-FramePayload
    /// `Poll` outcomes) are no-ops.
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
    fn empty_registry_dispatch_is_noop() {
        let mut reg = RemoteSubscriberRegistry::new();
        let body =
            DeclareVariant::CodecZenohDeclSubscriber(decl_subscriber(7, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(reg.on_decl_len(), 0);
        assert_eq!(reg.on_undecl_len(), 0);
    }

    #[test]
    fn declare_callback_fires_on_literal_keyexpr() {
        let mut reg = RemoteSubscriberRegistry::new();
        let captured: Arc<Mutex<Vec<(u64, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_subscriber_declared(move |decl, resolved| {
            captured_for_cb
                .lock()
                .unwrap()
                .push((decl.id, resolved.to_string()));
        });

        let body =
            DeclareVariant::CodecZenohDeclSubscriber(decl_subscriber(7, 0, Some("home/temp")));
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
        reg.on_subscriber_declared(move |_decl, resolved| {
            captured_for_cb.lock().unwrap().push(resolved.to_string());
        });

        let mut peer_table = HashMap::new();
        peer_table.insert(11u64, "sensors/temp".to_string());

        // mapping_id=11, no suffix -> table lookup -> "sensors/temp"
        let body = DeclareVariant::CodecZenohDeclSubscriber(decl_subscriber(1, 11, None));
        reg.dispatch_declare(&body, &peer_table);
        // mapping_id=11, suffix="/extra" -> concat
        let body = DeclareVariant::CodecZenohDeclSubscriber(decl_subscriber(2, 11, Some("/extra")));
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
        reg.on_subscriber_declared(move |_decl, _resolved| {
            fired_for_cb.fetch_add(1, Ordering::SeqCst);
        });

        // mapping_id=99 not in (empty) peer table -> skip.
        let body = DeclareVariant::CodecZenohDeclSubscriber(decl_subscriber(1, 99, None));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(
            fired.load(Ordering::SeqCst),
            0,
            "unresolvable mapping id must skip the callback (no partial keyexpr fire)"
        );
    }

    #[test]
    fn undeclare_callback_fires_on_undecl_subscriber() {
        let mut reg = RemoteSubscriberRegistry::new();
        let captured: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_subscriber_undeclared(move |u| {
            captured_for_cb.lock().unwrap().push(u.id);
        });

        let body = DeclareVariant::CodecZenohUndeclSubscriber(undecl_subscriber(42));
        reg.dispatch_declare(&body, &HashMap::new());

        let captured = captured.lock().unwrap();
        assert_eq!(*captured, vec![42]);
    }

    #[test]
    fn multiple_decl_callbacks_fire_in_registration_order() {
        let mut reg = RemoteSubscriberRegistry::new();
        let order: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
        let order_a = order.clone();
        let order_b = order.clone();
        reg.on_subscriber_declared(move |_d, _r| order_a.lock().unwrap().push(1));
        reg.on_subscriber_declared(move |_d, _r| order_b.lock().unwrap().push(2));
        assert_eq!(reg.on_decl_len(), 2);

        let body = DeclareVariant::CodecZenohDeclSubscriber(decl_subscriber(3, 0, Some("a/b")));
        reg.dispatch_declare(&body, &HashMap::new());

        assert_eq!(*order.lock().unwrap(), vec![1, 2]);
    }

    #[test]
    fn nonlocal_keyexpr_arm_resolves_identically_to_local_arm() {
        let mut reg = RemoteSubscriberRegistry::new();
        let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_subscriber_declared(move |_d, r| {
            captured_for_cb.lock().unwrap().push(r.to_string())
        });

        let body = DeclareVariant::CodecZenohDeclSubscriber(decl_subscriber_nonlocal(
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
        reg.on_subscriber_declared(move |_d, _r| {
            fired_for_cb.fetch_add(1, Ordering::SeqCst);
        });

        // A DeclFinal envelope must not fire the subscriber callback
        // — it lives in the SubscriberRegistry's path (DeclKexpr /
        // UndeclKexpr) or the future RemoteQueryableRegistry path
        // (DeclQueryable).
        let body = DeclareVariant::CodecZenohDeclFinal(wz_codecs::decl_final::DeclFinal::default());
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
        reg.on_subscriber_declared(move |_d, _r| {
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
        reg.on_subscriber_declared(move |_d, _r| {
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

        let decl1 =
            DeclareVariant::CodecZenohDeclSubscriber(decl_subscriber(10, 0, Some("home/temp")));
        reg.dispatch_declare(&decl1, &HashMap::new());
        assert_eq!(reg.declared_count(), 1);

        let decl2 =
            DeclareVariant::CodecZenohDeclSubscriber(decl_subscriber(11, 0, Some("home/door")));
        reg.dispatch_declare(&decl2, &HashMap::new());
        assert_eq!(reg.declared_count(), 2);

        let undecl1 = DeclareVariant::CodecZenohUndeclSubscriber(undecl_subscriber(10));
        reg.dispatch_declare(&undecl1, &HashMap::new());
        assert_eq!(reg.declared_count(), 1);
        let remaining: Vec<(u64, &str)> = reg.iter_declared().collect();
        assert_eq!(remaining, vec![(11, "home/door")]);

        let undecl2 = DeclareVariant::CodecZenohUndeclSubscriber(undecl_subscriber(11));
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
            DeclareVariant::CodecZenohDeclSubscriber(decl_subscriber(7, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/temp"));
        assert!(!reg.has_matching("home/door"));
    }

    #[test]
    fn subscriber_has_matching_true_when_peer_pattern_covers_publish_literal() {
        let mut reg = RemoteSubscriberRegistry::new();
        let body = DeclareVariant::CodecZenohDeclSubscriber(decl_subscriber(8, 0, Some("home/**")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/temp"));
        assert!(reg.has_matching("home/door/inner"));
        assert!(!reg.has_matching("other/x"));
    }

    #[test]
    fn subscriber_has_matching_true_when_publish_pattern_covers_peer_literal() {
        let mut reg = RemoteSubscriberRegistry::new();
        let body =
            DeclareVariant::CodecZenohDeclSubscriber(decl_subscriber(9, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert!(reg.has_matching("home/**"));
        assert!(reg.has_matching("**"));
        assert!(!reg.has_matching("other/**"));
    }

    #[test]
    fn subscriber_has_matching_false_after_undeclare() {
        let mut reg = RemoteSubscriberRegistry::new();
        let decl =
            DeclareVariant::CodecZenohDeclSubscriber(decl_subscriber(12, 0, Some("home/temp")));
        reg.dispatch_declare(&decl, &HashMap::new());
        assert!(reg.has_matching("home/temp"));
        let undecl = DeclareVariant::CodecZenohUndeclSubscriber(undecl_subscriber(12));
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
        let d =
            DeclareVariant::CodecZenohDeclSubscriber(decl_subscriber(30, 0, Some("home/*/temp")));
        reg.dispatch_declare(&d, &HashMap::new());
        assert!(reg.has_matching("*/sensor/temp"));
        assert!(reg.has_matching("*/*/temp"));
    }

    #[test]
    fn subscriber_has_matching_false_when_two_patterns_have_disjoint_anchors() {
        // Pub-side mirror of the Q-side disjoint-anchor negative test.
        let mut reg = RemoteSubscriberRegistry::new();
        let d =
            DeclareVariant::CodecZenohDeclSubscriber(decl_subscriber(31, 0, Some("home/**/temp")));
        reg.dispatch_declare(&d, &HashMap::new());
        assert!(!reg.has_matching("kitchen/**/temp"));
    }

    #[test]
    fn subscriber_has_matching_true_when_double_star_intersects_either_direction() {
        // Pub-side mirror — `home/** ∩ **/temp` shares `home/temp`
        // and any `home/<x>.../temp`. Backtracking on both sides.
        let mut reg = RemoteSubscriberRegistry::new();
        let d = DeclareVariant::CodecZenohDeclSubscriber(decl_subscriber(32, 0, Some("home/**")));
        reg.dispatch_declare(&d, &HashMap::new());
        assert!(reg.has_matching("**/temp"));
        assert!(reg.has_matching("**"));
    }
}
