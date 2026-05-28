// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311dq / di-17 — `LivelinessSubscriberRegistry` migrated to
//! `wz-session-core::declare::liveliness_subscriber`. This file is
//! the AP-side shell: it re-exports the public surface so consumers
//! continue to write `wz_runtime_tokio::declare::LivelinessSubscriber*`
//! (via the parent module's `pub use`) and hosts the AP-bound
//! #[cfg(test)] mod that exercises the registry through
//! `crate::sync::Mutex` + `std::sync::Arc`.

pub use wz_session_core::declare::liveliness_subscriber::{
    LivelinessSample, LivelinessSampleCallback, LivelinessSampleKind, LivelinessSubscriberRegistry,
};

// R311q — tests are gated on `liveliness-subscriber` (the feature the
// dispatch behaviour exists for) AND on `codec-declare` (the feature
// that materialises `NetworkMessage::Declare` + the `decl_token` /
// `undecl_token` fixtures). The feature chain
// `liveliness-subscriber → declare-interest → codec-declare` makes
// these two conditions equivalent in practice; both are spelled out
// here for self-documentation.
#[cfg(all(test, feature = "liveliness-subscriber", feature = "codec-declare"))]
mod tests {
    use super::*;
    use crate::session_glue::NetworkMessage;
    use hashbrown::HashMap;
    use portable_atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use wz_session_core::declare::test_helpers::*;

    use crate::sync::Mutex;
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
