// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311di-14 — `LivelinessRegistry` migrated to
//! `wz-session-core::declare::liveliness`. This file is the AP-side
//! shell: it re-exports the public surface so consumers continue to
//! write `wz_runtime_tokio::declare::LivelinessRegistry` (via the
//! parent module's `pub use`) and hosts the AP-bound test fixtures
//! that exercise the registry through `crate::sync::Mutex` +
//! `std::sync::Arc`.

pub use wz_session_core::declare::liveliness::{
    DeclTokenCallback, LivelinessRegistry, UndeclTokenCallback,
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
    fn liveliness_empty_registry_dispatch_is_noop() {
        let mut reg = LivelinessRegistry::new();
        let body = DeclareVariant::CodecZenohDeclToken(decl_token(7, 0, Some("liveliness/x")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(reg.on_decl_len(), 0);
        assert_eq!(reg.on_undecl_len(), 0);
    }

    #[test]
    fn liveliness_declare_callback_fires_on_literal_keyexpr() {
        let mut reg = LivelinessRegistry::new();
        let captured: Arc<Mutex<Vec<(u64, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_token_declared(move |decl, resolved| {
            captured_for_cb
                .lock()
                .unwrap()
                .push((decl.id, resolved.to_string()));
        });
        let body =
            DeclareVariant::CodecZenohDeclToken(decl_token(11, 0, Some("liveliness/device42")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(
            *captured.lock().unwrap(),
            vec![(11, "liveliness/device42".to_string())]
        );
    }

    #[test]
    fn liveliness_undeclare_callback_fires() {
        let mut reg = LivelinessRegistry::new();
        let captured: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_token_undeclared(move |u| {
            captured_for_cb.lock().unwrap().push(u.id);
        });
        let body = DeclareVariant::CodecZenohUndeclToken(undecl_token(11));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(*captured.lock().unwrap(), vec![11]);
    }

    #[test]
    fn liveliness_callback_skipped_on_unresolvable_mapping_id() {
        let mut reg = LivelinessRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_for_cb = fired.clone();
        reg.on_token_declared(move |_d, _r| {
            fired_for_cb.fetch_add(1, Ordering::SeqCst);
        });
        let body = DeclareVariant::CodecZenohDeclToken(decl_token(1, 55, None));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(fired.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn liveliness_dispatch_messages_undecl_and_decl_route_independently() {
        // Mirror of the subscriber-side counterpart test: a stream
        // mixing DeclToken + UndeclToken envelopes fans into the two
        // callback paths in arrival order. Same liveliness signal as
        // the wire emits (peer's token came alive → went away).
        let mut reg = LivelinessRegistry::new();
        let decl_count = Arc::new(AtomicUsize::new(0));
        let undecl_count = Arc::new(AtomicUsize::new(0));
        let d = decl_count.clone();
        let u = undecl_count.clone();
        reg.on_token_declared(move |_d, _r| {
            d.fetch_add(1, Ordering::SeqCst);
        });
        reg.on_token_undeclared(move |_u| {
            u.fetch_add(1, Ordering::SeqCst);
        });

        let messages = vec![
            NetworkMessage::Declare(Box::new(declare_envelope_decl_token(decl_token(
                1,
                0,
                Some("x"),
            )))),
            NetworkMessage::Declare(Box::new(declare_envelope_undecl_token(undecl_token(1)))),
            NetworkMessage::Declare(Box::new(declare_envelope_decl_token(decl_token(
                2,
                0,
                Some("y"),
            )))),
        ];
        reg.dispatch_messages(&messages, &HashMap::new());
        assert_eq!(decl_count.load(Ordering::SeqCst), 2);
        assert_eq!(undecl_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn liveliness_dispatch_messages_routes_only_token_arms() {
        let mut reg = LivelinessRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_cb = counter.clone();
        reg.on_token_declared(move |_d, _r| {
            counter_for_cb.fetch_add(1, Ordering::SeqCst);
        });

        // Subscriber + Queryable + Token mix — only Token arm routes.
        let messages =
            vec![
                NetworkMessage::Declare(Box::new(declare_envelope_decl_subscriber(
                    decl_subscriber(1, 0, Some("a")),
                ))),
                NetworkMessage::Declare(Box::new(declare_envelope_decl_queryable(decl_queryable(
                    2,
                    0,
                    Some("b"),
                )))),
                NetworkMessage::Declare(Box::new(declare_envelope_decl_token(decl_token(
                    3,
                    0,
                    Some("liveliness/c"),
                )))),
            ];
        reg.dispatch_messages(&messages, &HashMap::new());
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "only DeclToken routes into LivelinessRegistry"
        );
    }
}
