// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311gc — statechart-injection seam: the Anti-Corruption-Layer adapter
//! that turns a keyexpr-matched [`crate::sink::SampleView`] into a named
//! SCXML semantic-event injection.
//!
//! ## Why this exists (R311gc routing-model ratify, 2026-06-01)
//!
//! SCE's `<sce:on-sample>` codegen is **transport-socket-granular** and
//! has zero knowledge of zenoh keyexprs (SCE `SampleMeta::key_expr` is an
//! opaque pass-through, not a routing key). zenoh keyexpr demux — chunk
//! wildcards (`*` / `**` / `$*`) and the peer DECLARE alias table — is
//! wz's domain. The two layers reconcile at the **semantic event name**:
//! wz matches the keyexpr (the [`crate::pubsub::SubscriberRegistry`] job),
//! then injects a *domain* event (`"temp_update"`, not the keyexpr
//! literal) into the statechart. The statechart never learns the vendor
//! wire naming — this is the Anti-Corruption Layer / Ports-and-Adapters
//! boundary, keeping the SCXML core (the behaviour SSOT, portable across
//! the AP and MCU profiles) decoupled from zenoh.
//!
//! ## The seam
//!
//! [`EventInjector`] is the Dependency-Inversion seam over the statechart
//! engine's public event ingress. It mirrors the SCE-generated runtime's
//! `Engine::raise_external_by_name(event_name, event_data)` (a `&str`
//! name + `&str` data — the W3C SCXML 6.4.6 external-event ingress)
//! without wz-session-core depending on `sce-rust-runtime`: the concrete
//! impl wrapping a real `Engine` lives in a bridge / runtime crate where
//! both types are visible. This is the same inversion
//! [`crate::response_sink::ResponseSink`] uses to keep the application-
//! layer observer runtime-agnostic.
//!
//! [`StatechartSink`] is the [`crate::sink::SampleSink`] adapter: one per
//! keyexpr subscription slot, it carries the domain event name that slot
//! maps to and, on each matched sample, injects that event. The payload
//! does **not** flow through the event (Q-Wire-4: SCXML external events
//! carry empty `_event.data`); a statechart that needs the sample *value*
//! consumes it through the SCE Worker `inbox<E>` ingress instead — this
//! sink is the signal path.
//!
//! ## Profiles (ARCHITECTURE.md §2.4 static-first, dynamic-opt-in)
//!
//! - **AP / dynamic** — a `StatechartSink<I>` is registered per keyexpr
//!   in the [`crate::pubsub::SubscriberRegistry`]; the registry's keyexpr
//!   match selects which event injects.
//! - **MCU / static** — the switchboard generator emits a closed
//!   `keyexpr -> event` match that calls the engine's
//!   `raise_external_by_name` directly, with the engine threaded as a
//!   parameter (no per-slot sink storage); that generated path targets
//!   the same [`EventInjector`] contract.
//!
//! Build-time, the switchboard's target event names must be validated
//! against the link's `<sce:inbound>` contract (the forge-ast.v1
//! `LinkInboundEvent` rows) so a mistargeted name fails the build rather
//! than silently no-op'ing at runtime (`raise_external_by_name` ignores
//! an unknown event). That cross-check lands with the generator
//! (R311gc-2+); this module is the additive runtime seam it builds on,
//! ahead of the engine-bridge wiring — the same additive-first shape the
//! R311gb sink seams (`sink` / `query_sink` / `reply_sink` / `decl_sink`)
//! used.

use crate::sink::{SampleSink, SampleView};

/// Dependency-Inversion seam over the statechart engine's external-event
/// ingress. Mirrors the SCE-generated `Engine::raise_external_by_name`
/// (a `&str` event name + `&str` event data, W3C SCXML 6.4.6); the
/// concrete impl wrapping a real engine lives in a bridge crate so this
/// crate stays free of an `sce-rust-runtime` dependency. See the
/// [module docs](self) for the Anti-Corruption-Layer rationale.
pub trait EventInjector {
    /// Inject a named external SCXML event. `event_data` is the W3C
    /// `_event.data` payload string (empty for the signal-only path that
    /// [`StatechartSink`] drives — value-carrying ingress uses the SCE
    /// Worker `inbox<E>` path instead). An unknown name is the engine's
    /// concern to ignore; the switchboard's build-time `<sce:inbound>`
    /// cross-check is what keeps an unknown name from ever reaching here.
    fn inject(&mut self, event_name: &str, event_data: &str);
}

// Reference transparency: a `&mut` to an injector is still an injector, so
// a caller holding the engine handle by mutable borrow can pass it through
// without re-wrapping. Mirrors the blanket impls on
// [`crate::response_sink::ResponseSink`].
impl<I: EventInjector + ?Sized> EventInjector for &mut I {
    fn inject(&mut self, event_name: &str, event_data: &str) {
        (**self).inject(event_name, event_data)
    }
}

/// [`SampleSink`] adapter that injects a fixed SCXML semantic event when a
/// keyexpr-matched sample is delivered — the Anti-Corruption-Layer
/// translation point. Registered per keyexpr subscription slot; the
/// [`crate::pubsub::SubscriberRegistry`] performs the keyexpr match and
/// this sink maps "my slot matched" to "inject my domain event". The
/// sample payload is not forwarded (the event carries empty data per
/// Q-Wire-4); value-carrying ingress uses the SCE Worker `inbox<E>` path.
pub struct StatechartSink<I: EventInjector> {
    event_name: &'static str,
    injector: I,
}

impl<I: EventInjector> StatechartSink<I> {
    /// Map this subscription slot to `event_name`, injecting through
    /// `injector`. `event_name` is `&'static str` because the target is a
    /// member of the statechart's fixed event-name contract (the
    /// `<sce:inbound>` / generated event set), never a runtime-built
    /// string — so the binding stays heap-free on the no-`alloc` profile.
    pub fn new(event_name: &'static str, injector: I) -> Self {
        Self {
            event_name,
            injector,
        }
    }
}

impl<I: EventInjector> SampleSink for StatechartSink<I> {
    fn deliver(&mut self, _sample: &dyn SampleView) {
        // ACL signal path: the matched sample triggers the domain event;
        // its payload flows separately (the SCE Worker inbox), so the
        // SCXML external event carries empty `_event.data` (Q-Wire-4).
        self.injector.inject(self.event_name, "");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reliability::Reliability;
    use crate::sample_kind::SampleKind;
    use crate::sink::BorrowedSample;
    use std::string::{String, ToString};
    use std::vec::Vec;

    // Records each injected (event_name, data) pair — the shape a real
    // engine bridge replaces with `Engine::raise_external_by_name`.
    #[derive(Default)]
    struct RecordingInjector {
        calls: Vec<(String, String)>,
    }

    impl EventInjector for RecordingInjector {
        fn inject(&mut self, event_name: &str, event_data: &str) {
            self.calls
                .push((event_name.to_string(), event_data.to_string()));
        }
    }

    #[test]
    fn matched_sample_injects_configured_event_with_empty_data() {
        let mut sink = StatechartSink::new("temp_update", RecordingInjector::default());
        sink.deliver(&BorrowedSample {
            keyexpr: "home/livingroom/temp",
            payload: b"22.0",
            kind: SampleKind::Put,
            reliability: Reliability::Reliable,
        });
        // ACL: the statechart sees the domain event, never the keyexpr
        // literal or the payload (signal path; value goes via Worker inbox).
        assert_eq!(sink.injector.calls.len(), 1);
        assert_eq!(sink.injector.calls[0].0, "temp_update");
        assert_eq!(sink.injector.calls[0].1, "");
    }

    #[test]
    fn each_delivery_injects_once() {
        let mut sink = StatechartSink::new("tick", RecordingInjector::default());
        for _ in 0..3 {
            sink.deliver(&BorrowedSample {
                keyexpr: "a/b",
                payload: b"",
                kind: SampleKind::Del,
                reliability: Reliability::BestEffort,
            });
        }
        assert_eq!(sink.injector.calls.len(), 3);
        assert!(sink
            .injector
            .calls
            .iter()
            .all(|(n, d)| n == "tick" && d.is_empty()));
    }

    // The `&mut I` blanket impl lets a borrowed injector be used as a sink
    // backing without re-wrapping (engine-handle-by-borrow ergonomics).
    #[test]
    fn borrowed_injector_satisfies_the_seam() {
        let mut injector = RecordingInjector::default();
        {
            let mut sink = StatechartSink::new("evt", &mut injector);
            sink.deliver(&BorrowedSample {
                keyexpr: "x",
                payload: b"",
                kind: SampleKind::Put,
                reliability: Reliability::Reliable,
            });
        }
        assert_eq!(injector.calls.len(), 1);
        assert_eq!(injector.calls[0].0, "evt");
    }
}
