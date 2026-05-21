// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Application-layer remote-declaration registries — route decoded
//! `Declare(Decl*|Undecl*)` records to user-registered callbacks so
//! the application sees "the peer just declared a subscriber/
//! queryable/token" or "the peer just undeclared one".
//!
//! ## Scope (R121k-2)
//!
//! This round lands [`RemoteSubscriberRegistry`] only — the
//! `DeclSubscriber` + `UndeclSubscriber` sub-types of the inbound
//! `Declare` envelope. R121k-3 and R121k-4 add
//! `RemoteQueryableRegistry` and `LivelinessRegistry` respectively;
//! all three follow the same shape so the dispatch wiring (R121k-5)
//! can fan a single `Declare` body through every relevant registry
//! without per-sub-type custom code.
//!
//! ## Why a separate registry rather than absorbing into [`crate::pubsub::SubscriberRegistry`]
//!
//! - **Direction**: [`crate::pubsub::SubscriberRegistry`] holds the
//!   LOCAL subscribers — keyexpr callbacks the application registered
//!   so wz can fire them on inbound `Push`. The remote registries
//!   hold the PEER's declarations — informational signals that "a
//!   peer is now subscribing to this keyexpr", typically consumed by
//!   metrics, debug logging, or a future router/forwarding layer.
//!   Keeping them separate avoids conflating the "I subscribe to X"
//!   and "peer subscribes to X" surfaces.
//! - **Threading and ownership**: same `!Sync` contract as the
//!   pub/sub and query registries (caller wraps in
//!   `Arc<Mutex<…>>` for cross-task sharing). No interior mutability
//!   in the registry itself — callback storage is straight `Vec<…>`.
//! - **MCU runtime compatibility**: `FnMut` callbacks, no `async fn`,
//!   no `Future` in the trait surface. The dispatch path stays
//!   suitable for the `(c11, bare_metal)` runtime crate target once
//!   that crate adopts the same registry shape.
//!
//! ## Callback contract
//!
//! `on_subscriber_declared` callbacks receive the decoded
//! [`DeclSubscriber`] by reference plus the resolved keyexpr literal
//! (composition rule mirrors [`crate::pubsub::SubscriberRegistry`]:
//! `id == 0` → suffix verbatim; `id != 0` → `table[id] + suffix`).
//! If the inner keyexpr references a mapping id the peer has not yet
//! declared, the dispatch skips the callback entirely rather than
//! firing on a partial keyexpr — recording the declaration without
//! its resolved form would be a half-truth and most consumers (metrics
//! aggregation, route tables, log lines) would mis-render or mis-key.
//!
//! `on_subscriber_undeclared` callbacks receive the decoded
//! [`UndeclSubscriber`] by reference. The undeclare body carries only
//! `id: u64` (no keyexpr), so no resolution is needed — the peer
//! identifies the subscription it is tearing down by the same id it
//! used in its earlier `DeclSubscriber`.

use std::collections::HashMap;

use wz_codecs::declare::DeclareVariant;
use wz_codecs::decl_subscriber::DeclSubscriber;
use wz_codecs::undecl_subscriber::UndeclSubscriber;
use wz_codecs::wireexpr::WireexprVariant;

use crate::session_glue::{DriverLoopOutcome, IterationEvent, NetworkMessage};

/// Boxed callback invoked when an inbound
/// `Declare(DeclSubscriber)` is decoded and its keyexpr resolves to a
/// literal. The callback receives the codec record + the resolved
/// keyexpr literal so consumers don't have to re-resolve.
pub type DeclSubscriberCallback =
    Box<dyn FnMut(&DeclSubscriber, &str) + Send + 'static>;

/// Boxed callback invoked when an inbound
/// `Declare(UndeclSubscriber)` is decoded. The undeclare body has no
/// keyexpr field; the peer identifies the prior subscription by `id`.
pub type UndeclSubscriberCallback =
    Box<dyn FnMut(&UndeclSubscriber) + Send + 'static>;

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
                for cb in &mut self.on_decl {
                    cb(decl, &resolved);
                }
            }
            DeclareVariant::CodecZenohUndeclSubscriber(undecl) => {
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

/// Resolve a `Wireexpr` to its literal keyexpr string using a peer
/// mapping table. Mirror of
/// [`crate::pubsub::SubscriberRegistry::resolve_wireexpr`] but free-
/// standing so [`RemoteSubscriberRegistry`] (and future siblings)
/// don't need a reference to the SubscriberRegistry to resolve.
fn resolve_wireexpr(
    body: &WireexprVariant,
    table: &HashMap<u64, String>,
) -> Option<String> {
    let (id, suffix_opt) = match body {
        WireexprVariant::WireexprLocal(arm) => (arm.id, arm.suffix.as_deref()),
        WireexprVariant::WireexprNonlocal(arm) => (arm.id, arm.suffix.as_deref()),
    };
    if id == 0 {
        suffix_opt.map(str::to_string)
    } else {
        let base = table.get(&id)?.clone();
        Some(match suffix_opt {
            Some(s) => {
                let mut out = base;
                out.push_str(s);
                out
            }
            None => base,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::sync::Mutex;
    use wz_codecs::declare::Declare;
    use wz_codecs::wireexpr::Wireexpr;
    use wz_codecs::wireexpr_local::WireexprLocal;
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocal;

    fn decl_subscriber(id: u64, mapping_id: u64, suffix: Option<&str>) -> DeclSubscriber {
        let suffix_owned = suffix.map(str::to_string);
        let suffix_len = suffix.map(|s| s.len() as u64);
        let keyexpr = Wireexpr {
            body: WireexprVariant::WireexprLocal(WireexprLocal {
                id: mapping_id,
                suffix_len,
                suffix: suffix_owned,
            }),
        };
        DeclSubscriber {
            id,
            keyexpr,
            ..DeclSubscriber::default()
        }
    }

    fn decl_subscriber_nonlocal(id: u64, mapping_id: u64, suffix: Option<&str>) -> DeclSubscriber {
        let suffix_owned = suffix.map(str::to_string);
        let suffix_len = suffix.map(|s| s.len() as u64);
        let keyexpr = Wireexpr {
            body: WireexprVariant::WireexprNonlocal(WireexprNonlocal {
                id: mapping_id,
                suffix_len,
                suffix: suffix_owned,
            }),
        };
        DeclSubscriber {
            id,
            keyexpr,
            ..DeclSubscriber::default()
        }
    }

    fn undecl_subscriber(id: u64) -> UndeclSubscriber {
        UndeclSubscriber {
            id,
            ..UndeclSubscriber::default()
        }
    }

    fn declare_envelope_decl_subscriber(d: DeclSubscriber) -> Declare {
        Declare {
            body: DeclareVariant::CodecZenohDeclSubscriber(d),
            ..Declare::default()
        }
    }

    fn declare_envelope_undecl_subscriber(u: UndeclSubscriber) -> Declare {
        Declare {
            body: DeclareVariant::CodecZenohUndeclSubscriber(u),
            ..Declare::default()
        }
    }

    #[test]
    fn empty_registry_dispatch_is_noop() {
        let mut reg = RemoteSubscriberRegistry::new();
        let body = DeclareVariant::CodecZenohDeclSubscriber(decl_subscriber(7, 0, Some("home/temp")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(reg.on_decl_len(), 0);
        assert_eq!(reg.on_undecl_len(), 0);
    }

    #[test]
    fn declare_callback_fires_on_literal_keyexpr() {
        let mut reg = RemoteSubscriberRegistry::new();
        let captured: Arc<Mutex<Vec<(u64, String)>>> =
            Arc::new(Mutex::new(Vec::new()));
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
        let body =
            DeclareVariant::CodecZenohDeclSubscriber(decl_subscriber(2, 11, Some("/extra")));
        reg.dispatch_declare(&body, &peer_table);

        let captured = captured.lock().unwrap();
        assert_eq!(*captured, vec!["sensors/temp".to_string(), "sensors/temp/extra".to_string()]);
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

        let body =
            DeclareVariant::CodecZenohDeclSubscriber(decl_subscriber(3, 0, Some("a/b")));
        reg.dispatch_declare(&body, &HashMap::new());

        assert_eq!(*order.lock().unwrap(), vec![1, 2]);
    }

    #[test]
    fn nonlocal_keyexpr_arm_resolves_identically_to_local_arm() {
        let mut reg = RemoteSubscriberRegistry::new();
        let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_subscriber_declared(move |_d, r| captured_for_cb.lock().unwrap().push(r.to_string()));

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
        let body = DeclareVariant::CodecZenohDeclFinal(
            wz_codecs::decl_final::DeclFinal::default(),
        );
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

        let messages = vec![
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

        let messages = vec![
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
}
