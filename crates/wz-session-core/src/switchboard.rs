// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311gh — the switchboard: a zenoh-keyexpr -> SCXML-domain-event inbound
//! adapter (the Anti-Corruption Layer of the statechart-injection seam).
//!
//! ## Position (R311gh gc-2 structure ratify, ledger Round 311gh)
//!
//! The statechart [`Engine`](https://docs.rs/sce-rust-runtime) is the
//! behaviour SSOT (W3C SCXML), portable across the AP and MCU profiles.
//! It is driven by *named* external events through one inbound port,
//! [`EventInjector`] — a Dependency-Inversion seam over the SCE runtime's
//! `Engine::raise_external_by_name` (a `&str` name + `&str` data, W3C
//! SCXML 6.4.6). The switchboard is the inbound adapter that turns a
//! keyexpr-matched inbound sample into a port call: wz owns the zenoh
//! keyexpr demux — chunk wildcards (`*` / `**` / `$*`) and the peer
//! DECLARE alias table, already resolved into [`SampleView::keyexpr`] by
//! the time a sample reaches here — then injects a *domain* event
//! (`"temp_update"`, not the keyexpr literal) so the SCXML core never
//! learns the vendor wire naming (Ports-and-Adapters / ACL boundary).
//!
//! ## Why this is its own adapter (not a [`crate::sink::SampleSink`])
//!
//! Statechart injection and application data callbacks are two distinct
//! inbound adapters that merely *share* the keyexpr matcher:
//!  - a data callback is self-contained — the closure IS the behaviour;
//!  - statechart injection has no behaviour of its own, only a target
//!    event name plus the port; it needs the Engine.
//!
//! Storing an Engine handle inside a [`crate::sink::SampleSink`] (to make
//! it fit the [`crate::pubsub::SubscriberRegistry`]) would either alias
//! the driver-owned Engine behind a lock or interpose a second event
//! queue in front of the engine's own external queue — both smells.
//! Instead the switchboard *threads* the port: [`SwitchboardRegistry::dispatch`]
//! takes `&mut dyn EventInjector`, so the session driver — which owns the
//! Engine — passes it in at dispatch time. This is the SAME control-flow
//! shape the MCU static switchboard (the gc-3 generated closed `match`)
//! uses, so AP and MCU share one ingress shape with no per-profile
//! divergence. The keyexpr matcher ([`crate::keyexpr_match`]) is reused,
//! so matching is never duplicated.
//!
//! ## Profiles (ARCHITECTURE.md §2.4 static-first, dynamic-opt-in)
//!  - **AP / dynamic** — [`SwitchboardRegistry`] is populated at runtime
//!    from the per-machine `wz-switchboard.yaml` sidecar; `dispatch`
//!    matches each inbound sample and injects the mapped event.
//!  - **MCU / static** — the gc-3 generator emits a closed `keyexpr ->
//!    event` `match` over the same [`EventInjector`] port (no registry,
//!    no heap), the event names validated at build time against the
//!    machine's `external_ingress_events` set (forge-ast.v1).
//!
//! Only the **signal** path (empty `_event.data`) is wired here. The
//! value path (`inject(name, serialize(decode(sample)))`, validated
//! against the EventSchema field contract) lands with the typed-payload
//! decode round — the value-serialization SSOT was deferred to gc-3
//! (ledger Round 311gh carry).

/// Dependency-Inversion seam over the statechart engine's external-event
/// ingress. Mirrors the SCE-generated `Engine::raise_external_by_name`
/// (a `&str` event name + `&str` event data, W3C SCXML 6.4.6); the
/// concrete impl wrapping a real engine lives in the `wz-statechart-bridge`
/// crate so this crate stays free of an `sce-rust-runtime` dependency. See
/// the [module docs](self) for the Anti-Corruption-Layer rationale.
///
/// Unconditional and `alloc`-free: the trait is the ingress contract both
/// the AP [`SwitchboardRegistry`] and the MCU generated `match` call, and
/// the no-heap profile must be able to name it.
pub trait EventInjector {
    /// Inject a named external SCXML event. `event_data` is the W3C
    /// `_event.data` payload string (empty for the signal path the
    /// switchboard drives today; the value path passes the serialized
    /// sample value). An unknown name is the engine's concern to ignore
    /// (`raise_external_by_name` graceful-ignores names not in the event
    /// enum); the switchboard's build-time `external_ingress_events`
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

#[cfg(all(feature = "alloc", feature = "switchboard"))]
pub use alloc_impl::{SwitchboardEntry, SwitchboardRegistry};

#[cfg(all(feature = "alloc", feature = "switchboard"))]
mod alloc_impl {
    use super::EventInjector;
    use crate::driver_loop::{DriverLoopOutcome, IterationEvent};
    use crate::keyexpr_match::keyexpr_pattern_matches;
    use crate::network_message::NetworkMessage;
    use crate::reliability::Reliability;
    use crate::sample_kind::SampleKind;
    use crate::sink::{BorrowedSample, SampleView};
    use crate::wireexpr_resolve::resolve_wireexpr;
    use alloc::string::String;
    use alloc::vec::Vec;
    use hashbrown::HashMap;
    use wz_codecs::push::PushOwnedVariant;

    /// One `keyexpr-pattern -> domain-event` row of the AP dynamic
    /// switchboard. `event_name` is an owned `String` (not `&'static str`)
    /// because the AP table is populated from the runtime
    /// `wz-switchboard.yaml` sidecar; the [`EventInjector`] port takes
    /// `&str`, so the same dispatch serves the MCU `&'static` case.
    pub struct SwitchboardEntry {
        /// Canonicalized pattern, pre-split on `/` — same stored form as
        /// [`crate::pubsub::SubscriberRegistry`], so a wz subscriber and a
        /// switchboard entry on the same keyexpr agree byte-for-byte with
        /// the peer's `Declare(DeclKexpr)` wire form.
        pattern_chunks: Vec<String>,
        /// The SCXML domain event injected when an inbound sample's
        /// resolved keyexpr matches `pattern_chunks`.
        event_name: String,
    }

    /// AP / dynamic switchboard table: `keyexpr-pattern -> domain-event`
    /// rows consulted on each inbound sample. Not a
    /// [`crate::sink::SampleSink`] — it threads the [`EventInjector`] port
    /// through [`dispatch`](SwitchboardRegistry::dispatch) rather than
    /// storing an engine handle (see the [module docs](super)). `!Sync` by
    /// construction; a cross-task caller wraps it in `Arc<Mutex<…>>`,
    /// mirroring [`crate::pubsub::SubscriberRegistry`].
    #[derive(Default)]
    pub struct SwitchboardRegistry {
        entries: Vec<SwitchboardEntry>,
    }

    impl SwitchboardRegistry {
        /// New empty switchboard.
        pub fn new() -> Self {
            Self::default()
        }

        /// Map a keyexpr pattern to a domain event. Pattern syntax matches
        /// zenoh chunk wildcards (`*` single chunk, `**` zero-or-more
        /// chunks, `$*` intra-chunk substring); the pattern is
        /// canonicalized (so the stored chunks agree with the wire form a
        /// peer emits) before being split. A structurally invalid pattern
        /// is stored raw with a `log::warn!`, matching
        /// [`crate::pubsub::SubscriberRegistry::register_sink`] — the
        /// matcher still operates, the build-time cross-check is the
        /// authoritative guard.
        pub fn register(
            &mut self,
            keyexpr_pattern: impl Into<String>,
            event_name: impl Into<String>,
        ) {
            let raw = keyexpr_pattern.into();
            let canonical = match crate::keyexpr_canon::canonize_keyexpr(&raw) {
                Ok(canon) => canon,
                Err(err) => {
                    log::warn!(
                        "SwitchboardRegistry::register: keyexpr `{raw}` is not canonical \
                         ({err}); storing raw form. The matcher still operates but the \
                         stored chunks may drift from the canonical form a peer emits."
                    );
                    raw
                }
            };
            let pattern_chunks: Vec<String> = canonical.split('/').map(String::from).collect();
            self.entries.push(SwitchboardEntry {
                pattern_chunks,
                event_name: event_name.into(),
            });
        }

        /// Number of registered rows (diagnostic / test).
        pub fn len(&self) -> usize {
            self.entries.len()
        }

        /// Whether the switchboard has no rows.
        pub fn is_empty(&self) -> bool {
            self.entries.is_empty()
        }

        /// Match `sample`'s resolved keyexpr against every row and inject
        /// the mapped domain event through `injector` for each match
        /// (registration order). Returns the number of events injected.
        ///
        /// The Engine is *not* stored: the caller (the session driver,
        /// which owns the Engine) threads `injector` in — the same shape
        /// the MCU generated `match` uses. Signal path only: the event
        /// carries empty `_event.data` (the value path is the
        /// typed-payload decode round, gc-3).
        pub fn dispatch(&self, sample: &dyn SampleView, injector: &mut dyn EventInjector) -> usize {
            let target = sample.keyexpr();
            let mut injected: usize = 0;
            for entry in &self.entries {
                let chunks: Vec<&str> = entry.pattern_chunks.iter().map(String::as_str).collect();
                if keyexpr_pattern_matches(&chunks, target) {
                    injector.inject(&entry.event_name, "");
                    injected = injected.saturating_add(1);
                }
            }
            injected
        }

        /// Fan an [`IterationEvent`] into the switchboard: for each inbound
        /// `FramePayload` Push, resolve its keyexpr against `peer_table`
        /// (the shared [`resolve_wireexpr`] SSOT — the same resolver the
        /// data-callback / declare consumer registries use), then
        /// [`dispatch`](Self::dispatch) the resulting sample through
        /// `injector`. Returns the number of events injected.
        ///
        /// `peer_table` is the subscribers' single peer keyexpr table,
        /// passed in by the [`ApplicationLayerObserver`](crate::observer)
        /// fan-out so resolution is never duplicated. Only `FramePayload`
        /// Push messages drive injection; every other `IterationEvent`
        /// (Lease, non-Push records) is a no-op. This is the wire-inbound
        /// (ACL = wire -> domain) path; local self-publishes do not inject.
        pub fn dispatch_iteration_event(
            &self,
            event: IterationEvent<'_>,
            peer_table: &HashMap<u64, String>,
            injector: &mut dyn EventInjector,
        ) -> usize {
            let IterationEvent::Poll(DriverLoopOutcome::FramePayload {
                messages, reliable, ..
            }) = event
            else {
                return 0;
            };
            let reliability = Reliability::from_reliable_bool(*reliable);
            let mut injected: usize = 0;
            for message in messages {
                let NetworkMessage::Push(push) = message else {
                    continue;
                };
                let Some(resolved) = resolve_wireexpr(&push.keyexpr.body, peer_table) else {
                    continue;
                };
                // kind + payload are extracted faithfully even though the
                // signal path reads only the keyexpr: the value path (gc-3)
                // injects the payload, so the SampleView must already carry
                // it. Mirrors SubscriberRegistry::dispatch_push's body arm.
                let (kind, payload): (SampleKind, &[u8]) = match &push.body {
                    PushOwnedVariant::CodecZenohMsgPut(put) => {
                        (SampleKind::Put, put.payload.as_slice())
                    }
                    PushOwnedVariant::CodecZenohMsgDel(_) => (SampleKind::Del, &[]),
                    // Unknown/Default body tag: neither a confirmed Put nor
                    // Del — drop rather than inject on an ambiguous sample.
                    _ => continue,
                };
                let sample = BorrowedSample {
                    keyexpr: resolved.as_str(),
                    payload,
                    kind,
                    reliability,
                };
                injected = injected.saturating_add(self.dispatch(&sample, injector));
            }
            injected
        }
    }
}

#[cfg(all(test, feature = "alloc", feature = "switchboard"))]
mod tests {
    use super::*;
    use crate::reliability::Reliability;
    use crate::sample_kind::SampleKind;
    use crate::sink::BorrowedSample;
    use std::string::{String, ToString};
    use std::vec::Vec;

    // Records each injected (event_name, data) pair — the shape a real
    // engine bridge (wz-statechart-bridge::EngineInjector) replaces with
    // `Engine::raise_external_by_name`.
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

    fn sample(keyexpr: &str) -> BorrowedSample<'_> {
        BorrowedSample {
            keyexpr,
            payload: b"22.0",
            kind: SampleKind::Put,
            reliability: Reliability::Reliable,
        }
    }

    #[test]
    fn matched_sample_injects_mapped_event_with_empty_data() {
        let mut board = SwitchboardRegistry::new();
        board.register("home/livingroom/temp", "temp_update");
        let mut inj = RecordingInjector::default();

        let fired = board.dispatch(&sample("home/livingroom/temp"), &mut inj);

        assert_eq!(fired, 1);
        assert_eq!(inj.calls.len(), 1);
        // ACL: the statechart sees the domain event, never the keyexpr
        // literal or the payload (signal path; value path is gc-3).
        assert_eq!(inj.calls[0].0, "temp_update");
        assert_eq!(inj.calls[0].1, "");
    }

    #[test]
    fn non_matching_keyexpr_injects_nothing() {
        let mut board = SwitchboardRegistry::new();
        board.register("home/livingroom/temp", "temp_update");
        let mut inj = RecordingInjector::default();

        let fired = board.dispatch(&sample("home/kitchen/humidity"), &mut inj);

        assert_eq!(fired, 0);
        assert!(inj.calls.is_empty());
    }

    #[test]
    fn wildcard_pattern_matches() {
        let mut board = SwitchboardRegistry::new();
        board.register("home/**/temp", "temp_update");
        let mut inj = RecordingInjector::default();

        assert_eq!(board.dispatch(&sample("home/livingroom/temp"), &mut inj), 1);
        assert_eq!(board.dispatch(&sample("home/a/b/c/temp"), &mut inj), 1);
        assert_eq!(board.dispatch(&sample("away/livingroom/temp"), &mut inj), 0);
        assert_eq!(inj.calls.len(), 2);
        assert!(inj
            .calls
            .iter()
            .all(|(n, d)| n == "temp_update" && d.is_empty()));
    }

    #[test]
    fn every_matching_row_fires_in_registration_order() {
        let mut board = SwitchboardRegistry::new();
        board.register("home/*/temp", "zone_temp");
        board.register("home/livingroom/temp", "living_temp");
        let mut inj = RecordingInjector::default();

        let fired = board.dispatch(&sample("home/livingroom/temp"), &mut inj);

        assert_eq!(fired, 2);
        assert_eq!(inj.calls[0].0, "zone_temp");
        assert_eq!(inj.calls[1].0, "living_temp");
    }

    // The `&mut I` blanket impl lets a borrowed injector thread through the
    // dispatch without re-wrapping (engine-handle-by-borrow ergonomics —
    // the wz-statechart-bridge EngineInjector is passed exactly this way).
    #[test]
    fn borrowed_injector_satisfies_the_port() {
        let mut board = SwitchboardRegistry::new();
        board.register("x", "evt");
        let mut inj = RecordingInjector::default();
        {
            let mut borrowed = &mut inj;
            board.dispatch(&sample("x"), &mut borrowed);
        }
        assert_eq!(inj.calls.len(), 1);
        assert_eq!(inj.calls[0].0, "evt");
    }

    // Build a wire-inbound Put Push carrying a literal keyexpr (id=0 ⇒
    // resolve_wireexpr returns the suffix verbatim, no table lookup).
    fn put_push(keyexpr: &str, payload: &[u8]) -> wz_codecs::push::PushOwned {
        use wz_codecs::push::{Push, PushOwnedVariant};
        use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
        use wz_codecs::wireexpr_local::WireexprLocal;
        let mut push = Push {
            keyexpr: Wireexpr {
                body: WireexprVariant::WireexprLocal(WireexprLocal {
                    id: 0,
                    suffix_len: Some(keyexpr.len() as u64),
                    suffix: Some(keyexpr),
                }),
            },
            ..Push::default()
        }
        .into_owned();
        if let PushOwnedVariant::CodecZenohMsgPut(ref mut put) = push.body {
            put.payload_len = payload.len() as u64;
            put.payload = payload.to_vec();
        }
        push
    }

    fn frame_event(push: wz_codecs::push::PushOwned) -> crate::driver_loop::DriverLoopOutcome {
        use crate::network_message::NetworkMessage;
        use std::boxed::Box;
        use std::vec;
        crate::driver_loop::DriverLoopOutcome::FramePayload {
            reliable: true,
            sn: 0,
            messages: vec![NetworkMessage::Push(Box::new(push))],
            has_ext: false,
            extensions: Vec::new(),
        }
    }

    #[test]
    fn wire_inbound_push_injects_mapped_event() {
        use crate::driver_loop::IterationEvent;
        use hashbrown::HashMap;

        let mut board = SwitchboardRegistry::new();
        board.register("home/livingroom/temp", "temp_update");
        let mut inj = RecordingInjector::default();
        let table: HashMap<u64, String> = HashMap::new();

        let outcome = frame_event(put_push("home/livingroom/temp", b"22.0"));
        let fired =
            board.dispatch_iteration_event(IterationEvent::Poll(&outcome), &table, &mut inj);

        assert_eq!(fired, 1);
        assert_eq!(inj.calls.len(), 1);
        assert_eq!(inj.calls[0].0, "temp_update");
        // signal path: empty `_event.data` regardless of the Put payload.
        assert_eq!(inj.calls[0].1, "");
    }

    #[test]
    fn wire_inbound_push_non_matching_injects_nothing() {
        use crate::driver_loop::IterationEvent;
        use hashbrown::HashMap;

        let mut board = SwitchboardRegistry::new();
        board.register("home/livingroom/temp", "temp_update");
        let mut inj = RecordingInjector::default();
        let table: HashMap<u64, String> = HashMap::new();

        let outcome = frame_event(put_push("home/kitchen/humidity", b"55"));
        let fired =
            board.dispatch_iteration_event(IterationEvent::Poll(&outcome), &table, &mut inj);

        assert_eq!(fired, 0);
        assert!(inj.calls.is_empty());
    }
}
