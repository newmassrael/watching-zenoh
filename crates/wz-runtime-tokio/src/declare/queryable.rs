// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `RemoteQueryableRegistry` — application-layer registry tracking
//! the peer's outbound `DeclQueryable` / `UndeclQueryable` records.
//! Q-side mirror of [`crate::declare::RemoteSubscriberRegistry`];
//! see [`crate::declare`] module docs for the rationale.

use std::collections::HashMap;

use wz_codecs::declare::DeclareVariant;
use wz_codecs::decl_queryable::DeclQueryable;
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
pub type DeclQueryableCallback =
    Box<dyn FnMut(&DeclQueryable, &str) + Send + 'static>;

/// Boxed callback invoked when an inbound
/// `Declare(UndeclQueryable)` is decoded. The undeclare body has no
/// keyexpr field; the peer identifies the prior queryable by `id`.
pub type UndeclQueryableCallback =
    Box<dyn FnMut(&UndeclQueryable) + Send + 'static>;

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
                for cb in &mut self.on_decl {
                    cb(decl, &resolved);
                }
            }
            DeclareVariant::CodecZenohUndeclQueryable(undecl) => {
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
    use super::*;
    use super::super::test_helpers::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
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
            captured_for_cb.lock().unwrap().push((decl.id, resolved.to_string()));
        });
        let body =
            DeclareVariant::CodecZenohDeclQueryable(decl_queryable(8, 0, Some("home/door")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(*captured.lock().unwrap(), vec![(8, "home/door".to_string())]);
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
        let body =
            DeclareVariant::CodecZenohUndeclQueryable(undecl_queryable(99));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(*captured.lock().unwrap(), vec![99]);
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
        let messages = vec![
            NetworkMessage::Declare(Box::new(declare_envelope_decl_subscriber(
                decl_subscriber(1, 0, Some("not-this")),
            ))),
            NetworkMessage::Declare(Box::new(declare_envelope_decl_queryable(
                decl_queryable(2, 0, Some("yes-this")),
            ))),
            NetworkMessage::Declare(Box::new(declare_envelope_undecl_queryable(
                undecl_queryable(2),
            ))),
        ];
        reg.dispatch_messages(&messages, &HashMap::new());
        assert_eq!(decl_count.load(Ordering::SeqCst), 1, "only the queryable decl routes here");
        assert_eq!(undecl_count.load(Ordering::SeqCst), 1);
    }
}
