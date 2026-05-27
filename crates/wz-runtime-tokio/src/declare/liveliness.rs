// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `LivelinessRegistry` — application-layer registry tracking the
//! peer's outbound `DeclToken` / `UndeclToken` records, i.e. the
//! liveliness layer in zenoh's protocol stack
//! (`_z_liveliness_process_token_declare` /
//! `_z_liveliness_process_token_undeclare` upstream).

use hashbrown::HashMap;

use wz_codecs::decl_token::DeclToken;
use wz_codecs::declare::DeclareVariant;
use wz_codecs::undecl_token::UndeclToken;

use super::resolve_wireexpr;
use crate::session_glue::{DriverLoopOutcome, IterationEvent, NetworkMessage};

/// Boxed callback invoked when an inbound `Declare(DeclToken)` is
/// decoded and its keyexpr resolves to a literal. Liveliness signal —
/// "an entity (process / device / sub-system) just declared itself
/// alive on keyexpr X". Consumers wire this into watchdog or
/// presence-detection logic, e.g. a UI that surfaces "online" badges.
pub type DeclTokenCallback = Box<dyn FnMut(&DeclToken, &str) + Send + 'static>;

/// Boxed callback invoked when an inbound `Declare(UndeclToken)` is
/// decoded. The undeclare body carries only `id: u64`; the peer
/// identifies the prior liveliness token by the same id used in its
/// earlier `DeclToken`. Liveliness signal — "the entity that was
/// alive on keyexpr X is now gone (graceful undeclare; lease-based
/// expiry surfaces separately through the session FSM)".
pub type UndeclTokenCallback = Box<dyn FnMut(&UndeclToken) + Send + 'static>;

/// Application-layer registry tracking the peer's outbound
/// `DeclToken` / `UndeclToken` records — the liveliness layer in
/// zenoh's protocol stack (`_z_liveliness_process_token_declare` /
/// `_z_liveliness_process_token_undeclare` upstream).
///
/// Why a separate registry rather than reusing
/// [`crate::declare::RemoteSubscriberRegistry`] /
/// [`crate::declare::RemoteQueryableRegistry`]: liveliness signals
/// are a distinct application surface from pub/sub topology — a
/// consumer that wires "process X is alive" logic does not (and
/// should not) also fire on "process X just subscribed to Y".
/// Keeping the registries split matches zenoh-pico's structural
/// separation and lets consumers reason about each surface
/// independently.
pub struct LivelinessRegistry {
    on_decl: Vec<DeclTokenCallback>,
    on_undecl: Vec<UndeclTokenCallback>,
}

impl Default for LivelinessRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LivelinessRegistry {
    /// New empty registry. Both callback lists start empty; an empty
    /// registry processes inbound `Declare(Decl*Token)` records as
    /// no-ops.
    pub fn new() -> Self {
        Self {
            on_decl: Vec::new(),
            on_undecl: Vec::new(),
        }
    }

    /// Install a callback fired on every inbound
    /// `Declare(DeclToken)` whose keyexpr resolves through the peer
    /// keyexpr table. Duplicate callbacks allowed; dispatch fires
    /// them in registration order.
    pub fn on_token_declared(&mut self, callback: impl FnMut(&DeclToken, &str) + Send + 'static) {
        self.on_decl.push(Box::new(callback));
    }

    /// Install a callback fired on every inbound
    /// `Declare(UndeclToken)`.
    pub fn on_token_undeclared(&mut self, callback: impl FnMut(&UndeclToken) + Send + 'static) {
        self.on_undecl.push(Box::new(callback));
    }

    /// Number of installed `on_token_declared` callbacks.
    pub fn on_decl_len(&self) -> usize {
        self.on_decl.len()
    }

    /// Number of installed `on_token_undeclared` callbacks.
    pub fn on_undecl_len(&self) -> usize {
        self.on_undecl.len()
    }

    /// Route an inbound `Declare` envelope's inner body through the
    /// liveliness callbacks. Only `DeclToken` / `UndeclToken` arms
    /// route here; Subscriber, Queryable, Kexpr, and Final arms are
    /// handled by their own dedicated registries.
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
                for cb in &mut self.on_decl {
                    cb(decl, &resolved);
                }
            }
            DeclareVariant::CodecZenohUndeclToken(undecl) => {
                for cb in &mut self.on_undecl {
                    cb(undecl);
                }
            }
            // Other sub-variants do not reach this registry.
            _ => {}
        }
    }

    /// Drain a `Vec<NetworkMessage>` through [`Self::dispatch_declare`].
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

    /// `IterationEvent` adapter; mirror of the other Remote* registries.
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
