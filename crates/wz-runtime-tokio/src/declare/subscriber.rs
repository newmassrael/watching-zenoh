// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311do / di-15 — `RemoteSubscriberRegistry` migrated to
//! `wz-session-core::declare::subscriber`. This file is the AP-side
//! shell: it re-exports the public surface so consumers continue to
//! write `wz_runtime_tokio::declare::RemoteSubscriberRegistry` (via
//! the parent module's `pub use`) and hosts the AP-bound test fixtures
//! that exercise the registry through `crate::sync::Mutex` +
//! `std::sync::Arc`.

pub use wz_session_core::declare::subscriber::{
    DeclSubscriberCallback, RemoteSubscriberRegistry, UndeclSubscriberCallback,
};

#[cfg(test)]
mod tests {
    use super::super::test_helpers::*;
    use super::*;
    use hashbrown::HashMap;
    use portable_atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use wz_codecs::declare::DeclareVariant;

    use crate::session_glue::NetworkMessage;
    use crate::sync::Mutex;

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
