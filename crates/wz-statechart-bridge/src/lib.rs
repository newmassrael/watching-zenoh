// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![no_std]

//! R311gh gc-2b — the engine bridge: the concrete
//! [`EventInjector`] adapter
//! over a borrowed SCE [`Engine`].
//!
//! ## Why this crate exists (orphan rule)
//!
//! The statechart-injection port [`EventInjector`] is owned by
//! `wz-session-core`; the [`Engine`] is owned by `sce-rust-runtime`. Rust's
//! orphan rule forbids `impl EventInjector for Engine<P>` in any third
//! crate that owns neither type, so the bridge owns a local newtype
//! [`EngineInjector`] and impls the trait over *that*. The payoff:
//! `wz-session-core` stays free of any `sce-rust-runtime` dependency (the
//! behaviour SSOT and the codec/session tier never see the engine type),
//! and both profiles consume one shared adapter:
//!  - **AP** — `wz-runtime-tokio`'s session driver constructs an
//!    `EngineInjector(&mut engine)` per inbound dispatch and threads it
//!    into `SwitchboardRegistry::dispatch`.
//!  - **MCU** — the gc-3 generated static `match` threads the same
//!    `EngineInjector` into its closed `keyexpr -> event` dispatch.
//!
//! Both pass the injector *by borrow at dispatch time*; the engine is
//! never stored inside a sink or aliased behind a lock (R311gh gc-2
//! structure ratify, ledger Round 311gh).
//!
//! ## `#![no_std]`
//!
//! The adapter uses only [`Engine`], [`StatePolicy`], and `&str`, so it
//! carries no std/alloc of its own. The `no_std` Cargo feature forwards
//! the bare-metal engine selection to sce-rust-runtime; AP builds leave it
//! off (sce-rust-runtime resolves to its std default via the
//! wz-runtime-tokio edge).
//!
//! ## Testing
//!
//! [`EngineInjector::inject`] is a one-line delegation to
//! `Engine::raise_external_by_name`; the generic trait impl below *is* the
//! type-level contract proof (it would not compile if the bound were
//! wrong). The behavioural test — inject a named event, drive a macrostep,
//! observe the transition — needs a concrete generated `StatePolicy` and
//! a script engine, which live in `wz-runtime-tokio`; it is exercised
//! there against `SessionFsmUnicastPolicy` at the gc-2c integration point
//! rather than reconstructed behind a hand-written fake policy here.

use sce_rust_runtime::{Engine, StatePolicy};
use wz_session_core::switchboard::EventInjector;

/// A borrowed SCE [`Engine`] viewed as the wz
/// [`EventInjector`] inbound port. Constructed transiently at the dispatch
/// site (the session driver owns the engine for its whole lifetime and
/// lends it for the duration of one switchboard dispatch), so it holds a
/// `&mut` rather than owning the engine — no aliasing, no second queue.
///
/// Generic over the document's `StatePolicy` `P`, so one adapter serves
/// every generated state machine (`SessionFsmUnicastPolicy`,
/// `ScoutingPolicy`, and the per-deploy SCXML machines).
pub struct EngineInjector<'e, P: StatePolicy> {
    engine: &'e mut Engine<P>,
}

impl<'e, P: StatePolicy> EngineInjector<'e, P> {
    /// Wrap a borrowed engine as the injector port.
    pub fn new(engine: &'e mut Engine<P>) -> Self {
        Self { engine }
    }
}

impl<P: StatePolicy> EventInjector for EngineInjector<'_, P> {
    /// Delegate to the engine's W3C SCXML 6.4.6 external-event-by-name
    /// ingress. `raise_external_by_name` graceful-ignores a name not in
    /// the document's event enum; the switchboard's build-time
    /// `external_ingress_events` cross-check (gc-3) is what guarantees an
    /// unknown name never reaches here.
    fn inject(&mut self, event_name: &str, event_data: &str) {
        self.engine.raise_external_by_name(event_name, event_data);
    }
}
