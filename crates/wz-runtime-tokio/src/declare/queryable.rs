// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311dp / di-16 — `RemoteQueryableRegistry` migrated to
//! `wz-session-core::declare::queryable`. This file is the AP-side
//! shell: it re-exports the public surface so consumers continue to
//! write `wz_runtime_tokio::declare::RemoteQueryableRegistry` (via
//! the parent module's `pub use`) and hosts the AP-bound test fixtures
//! that exercise the registry through `crate::sync::Mutex` +
//! `std::sync::Arc`.

pub use wz_session_core::declare::queryable::{
    DeclQueryableCallback, RemoteQueryableRegistry, UndeclQueryableCallback,
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
