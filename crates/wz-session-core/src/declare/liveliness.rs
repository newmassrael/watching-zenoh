// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `LivelinessRegistry` — application-layer registry tracking the
//! peer's outbound `DeclToken` / `UndeclToken` records, i.e. the
//! liveliness layer in zenoh's protocol stack
//! (`_z_liveliness_process_token_declare` /
//! `_z_liveliness_process_token_undeclare` upstream).

// R311gb (Track 2) — String / HashMap back the `alloc` wire-dispatch
// params; the no-alloc control plane stores observers in a `BoundedVec`
// and fires through the borrowed `DeclView` seam. (No `declared` table /
// `has_matching` here — liveliness is a pure observer fan-out.)
// String / HashMap appear only in the `all(codec-declare, alloc)` wire-
// dispatch params (no `declared` membership table here), so they carry
// that gate rather than bare `alloc`.
#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use alloc::string::String;
#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use hashbrown::HashMap;

#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use wz_codecs::declare::DeclareOwnedVariant;

#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use crate::decl_sink::BorrowedDecl;
#[cfg(feature = "alloc")]
use crate::decl_sink::{BoxedDeclSink, BoxedUndeclSink};
use crate::decl_sink::{DeclObserverPair, DeclSink, DeclView, UndeclSink};
#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use crate::network_message::NetworkMessage;
use crate::registry_error::RegisterError;
#[cfg(all(feature = "codec-declare", feature = "alloc"))]
use crate::wireexpr_resolve::resolve_wireexpr;

/// Application-layer registry tracking the peer's outbound
/// `DeclToken` / `UndeclToken` records — the liveliness layer in
/// zenoh's protocol stack (`_z_liveliness_process_token_declare` /
/// `_z_liveliness_process_token_undeclare` upstream).
///
/// Why a separate registry rather than reusing the subscriber or
/// queryable Remote* registries: liveliness signals are a distinct
/// application surface from pub/sub topology — a consumer that wires
/// "process X is alive" logic does not (and should not) also fire on
/// "process X just subscribed to Y". Keeping the registries split
/// matches zenoh-pico's structural separation and lets consumers
/// reason about each surface independently.
pub struct LivelinessRegistry<D: DeclSink, U: UndeclSink> {
    /// R311gb (Track 2) — shared 2-list observer machinery composed from
    /// [`crate::decl_sink::DeclObserverPair`] (SSOT across the three
    /// `DeclSink` registries). `D = BoxedDeclSink` / `U = BoxedUndeclSink`
    /// on AP, consumer-supplied closed `enum`s on MCU.
    observers: DeclObserverPair<D, U>,
}

impl<D: DeclSink, U: UndeclSink> Default for LivelinessRegistry<D, U> {
    fn default() -> Self {
        Self::with_sink_backing()
    }
}

impl<D: DeclSink, U: UndeclSink> LivelinessRegistry<D, U> {
    /// New empty registry over explicit sink backings `D` / `U`. Both
    /// observer lists start empty; an empty registry processes inbound
    /// `Declare(Decl*Token)` records as no-ops.
    ///
    /// R311gb-3d — the generic constructor (no-`alloc` / MCU entry point,
    /// paired with the `*_sink` installers). AP callers use the inferring
    /// [`new`](LivelinessRegistry::new) shorthand.
    pub fn with_sink_backing() -> Self {
        Self {
            observers: DeclObserverPair::new(),
        }
    }

    /// R311gb-3d — install an explicit [`DeclSink`] observer (the
    /// seam-native entry point). The `alloc`-only
    /// [`on_token_declared`](LivelinessRegistry::on_token_declared)
    /// convenience wrapper funnels through here. R311lb — returns the
    /// registry-local observer id for
    /// [`remove_token_declared_sink`](Self::remove_token_declared_sink).
    pub fn on_token_declared_sink(&mut self, sink: D) -> Result<u64, RegisterError> {
        self.observers.install_decl(sink)
    }

    /// R311gb-3d — install an explicit [`UndeclSink`] observer. The
    /// `alloc`-only
    /// [`on_token_undeclared`](LivelinessRegistry::on_token_undeclared)
    /// convenience wrapper funnels through here. R311lb — returns the
    /// registry-local observer id for
    /// [`remove_token_undeclared_sink`](Self::remove_token_undeclared_sink).
    pub fn on_token_undeclared_sink(&mut self, sink: U) -> Result<u64, RegisterError> {
        self.observers.install_undecl(sink)
    }

    /// R311lb — remove the declaration observer keyed by `id` (the
    /// return of [`on_token_declared_sink`](Self::on_token_declared_sink)).
    /// Returns whether one was removed; double removal is a `false`
    /// no-op. The removal half of the Session-tier decl-listener
    /// surface (R311lc).
    pub fn remove_token_declared_sink(&mut self, id: u64) -> bool {
        self.observers.uninstall_decl(id)
    }

    /// R311lb — remove the undeclaration observer keyed by `id`. Same
    /// contract as
    /// [`remove_token_declared_sink`](Self::remove_token_declared_sink).
    pub fn remove_token_undeclared_sink(&mut self, id: u64) -> bool {
        self.observers.uninstall_undecl(id)
    }

    /// Number of installed `on_token_declared` callbacks.
    pub fn on_decl_len(&self) -> usize {
        self.observers.decl_len()
    }

    /// Number of installed `on_token_undeclared` callbacks.
    pub fn on_undecl_len(&self) -> usize {
        self.observers.undecl_len()
    }

    /// Route an inbound `Declare` envelope's inner body through the
    /// liveliness callbacks. Only `DeclToken` / `UndeclToken` arms
    /// route here; Subscriber, Queryable, Kexpr, and Final arms are
    /// handled by their own dedicated registries.
    /// R311gb (Track 2) — no-heap token-declaration fire: hand each
    /// installed `on_decl` observer the borrowed [`DeclView`]. The MCU
    /// no-heap fan-out SSOT; the wire path
    /// ([`dispatch_declare`](Self::dispatch_declare)) funnels through here.
    /// Returns the count fired.
    pub fn dispatch_declared_borrowed(&mut self, view: &dyn DeclView) -> usize {
        self.observers.fire_declared(view)
    }

    /// R311gb (Track 2) — no-heap token-undeclaration fire: hand each
    /// installed `on_undecl` observer the bare `id`. Returns the count
    /// fired.
    pub fn dispatch_undeclared(&mut self, id: u64) -> usize {
        self.observers.fire_undeclared(id)
    }

    /// R311gb (Track 2) — `all(codec-declare, alloc)`-gated wire dispatch;
    /// funnels through the no-heap fire SSOT.
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
    pub fn dispatch_declare(
        &mut self,
        body: &DeclareOwnedVariant,
        peer_keyexpr_table: &HashMap<u64, String>,
    ) {
        match body {
            DeclareOwnedVariant::CodecZenohDeclToken(decl) => {
                let resolved = match resolve_wireexpr(&decl.keyexpr.body, peer_keyexpr_table) {
                    Some(s) => s,
                    None => return,
                };
                let view = BorrowedDecl {
                    id: decl.id,
                    keyexpr: &resolved,
                };
                self.dispatch_declared_borrowed(&view);
            }
            DeclareOwnedVariant::CodecZenohUndeclToken(undecl) => {
                self.dispatch_undeclared(undecl.id);
            }
            // Other sub-variants do not reach this registry.
            _ => {}
        }
    }

    /// Drain a `Vec<NetworkMessage>` through [`Self::dispatch_declare`].
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
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
    #[cfg(all(feature = "codec-declare", feature = "alloc"))]
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

/// R311gb-3d — AP / `alloc`-profile convenience constructors (the
/// `BoxedDeclSink` / `BoxedUndeclSink` instantiation only). Mirror of the
/// subscriber / queryable blocks; the no-`alloc` profile installs
/// consumer-supplied sinks through the generic `*_sink` installers.
#[cfg(feature = "alloc")]
impl LivelinessRegistry<BoxedDeclSink, BoxedUndeclSink> {
    /// New empty AP registry backed by heap-boxed closures. Inferring
    /// shorthand for
    /// [`with_sink_backing`](LivelinessRegistry::with_sink_backing).
    pub fn new() -> Self {
        Self::with_sink_backing()
    }

    /// Install a closure fired on every inbound `Declare(DeclToken)` whose
    /// keyexpr resolves. The closure receives `&dyn DeclView` (the peer-
    /// declared `id` + resolved keyexpr) — the R311gb-3d seam contract
    /// replaces the prior `(&DeclTokenOwned, &str)`
    /// ([`feedback_signature_stability`] wire-data exemption). Heap-boxed
    /// via [`BoxedDeclSink`]. R311lb — returns the registry-local
    /// observer id (see [`Self::remove_token_declared_sink`]).
    pub fn on_token_declared(
        &mut self,
        callback: impl FnMut(&dyn crate::decl_sink::DeclView) + Send + 'static,
    ) -> u64 {
        self.on_token_declared_sink(BoxedDeclSink::new(callback))
            .expect("observer install on the alloc backing never exceeds declared capacity")
    }

    /// Install a closure fired on every inbound `Declare(UndeclToken)`.
    /// The closure receives the bare `id` (`u64`). Heap-boxed via
    /// [`BoxedUndeclSink`]. R311lb — returns the registry-local observer
    /// id (see [`Self::remove_token_undeclared_sink`]).
    pub fn on_token_undeclared(&mut self, callback: impl FnMut(u64) + Send + 'static) -> u64 {
        self.on_token_undeclared_sink(BoxedUndeclSink::new(callback))
            .expect("observer install on the alloc backing never exceeds declared capacity")
    }
}

// R311gb (Track 2) — test gate now explicit (was inherited from the
// module's `codec-declare` gate); exercises `dispatch_declare` (owned
// `DeclareOwnedVariant`), now `all(codec-declare, alloc)`-gated.
#[cfg(all(test, feature = "codec-declare"))]
mod tests {
    //! R311dm self-tests + R311ds wider behavioural tests for
    //! `LivelinessRegistry`.
    //!
    //! The R311dm thin tests exercise the callback-count surface
    //! without any fixture chain — pure no_std + alloc — so a
    //! `cargo test -p wz-session-core --features codec-declare`
    //! regression lands at the same seam where the production code
    //! lives. The R311ds tests (migrated from the wz-runtime-tokio
    //! `declare/liveliness.rs` shell, R311dr-wider-tests carry
    //! closure) add callback fan-out value capture + mixed-message
    //! dispatch via the shared fixture builders. Their
    //! `Arc<Mutex<…>>` capture cells use `std` under `#[cfg(test)]`
    //! per the wz-codecs sibling-crate convention; the production
    //! artifact stays strictly no_std.

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

    use crate::lease::LeaseCheckOutcome;
    use crate::network_message::NetworkMessage;

    #[test]
    fn empty_registry_reports_zero_callback_counts() {
        let reg = LivelinessRegistry::new();
        assert_eq!(reg.on_decl_len(), 0);
        assert_eq!(reg.on_undecl_len(), 0);
    }

    #[test]
    fn on_token_declared_increments_declare_count() {
        let mut reg = LivelinessRegistry::new();
        reg.on_token_declared(|_d| {});
        reg.on_token_declared(|_d| {});
        assert_eq!(reg.on_decl_len(), 2);
        assert_eq!(reg.on_undecl_len(), 0);
    }

    #[test]
    fn on_token_undeclared_increments_undeclare_count() {
        let mut reg = LivelinessRegistry::new();
        reg.on_token_undeclared(|_u| {});
        assert_eq!(reg.on_decl_len(), 0);
        assert_eq!(reg.on_undecl_len(), 1);
    }

    #[test]
    fn dispatch_iteration_event_lease_branch_is_noop() {
        // The Lease arm of IterationEvent does not produce a
        // FramePayload, so dispatch_iteration_event short-circuits
        // without touching the (empty) callback set.
        let mut reg = LivelinessRegistry::new();
        let event = IterationEvent::Lease(LeaseCheckOutcome::NoBaseline);
        reg.dispatch_iteration_event(event, &HashMap::new());
        assert_eq!(reg.on_decl_len(), 0);
        assert_eq!(reg.on_undecl_len(), 0);
    }

    // ── R311ds — wider behavioural tests (migrated from the
    // wz-runtime-tokio shell) ──

    #[test]
    fn liveliness_empty_registry_dispatch_is_noop() {
        let mut reg = LivelinessRegistry::new();
        let body = DeclareOwnedVariant::CodecZenohDeclToken(decl_token(7, 0, Some("liveliness/x")));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(reg.on_decl_len(), 0);
        assert_eq!(reg.on_undecl_len(), 0);
    }

    #[test]
    fn liveliness_declare_callback_fires_on_literal_keyexpr() {
        let mut reg = LivelinessRegistry::new();
        let captured: Arc<Mutex<Vec<(u64, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_for_cb = captured.clone();
        reg.on_token_declared(move |decl| {
            captured_for_cb
                .lock()
                .unwrap()
                .push((decl.id(), decl.keyexpr().to_string()));
        });
        let body = DeclareOwnedVariant::CodecZenohDeclToken(decl_token(
            11,
            0,
            Some("liveliness/device42"),
        ));
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
        reg.on_token_undeclared(move |id| {
            captured_for_cb.lock().unwrap().push(id);
        });
        let body = DeclareOwnedVariant::CodecZenohUndeclToken(undecl_token(11));
        reg.dispatch_declare(&body, &HashMap::new());
        assert_eq!(*captured.lock().unwrap(), vec![11]);
    }

    #[test]
    fn liveliness_callback_skipped_on_unresolvable_mapping_id() {
        let mut reg = LivelinessRegistry::new();
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_for_cb = fired.clone();
        reg.on_token_declared(move |_d| {
            fired_for_cb.fetch_add(1, Ordering::SeqCst);
        });
        let body = DeclareOwnedVariant::CodecZenohDeclToken(decl_token(1, 55, None));
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
        reg.on_token_declared(move |_d| {
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
        reg.on_token_declared(move |_d| {
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
