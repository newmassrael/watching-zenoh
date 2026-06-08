// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![cfg(feature = "switchboard")]

//! R311gi gc-2c — switchboard inject integration.
//!
//! A wire-inbound `Push` drives a domain-event injection into a REAL SCE
//! `Engine` through the `wz-statechart-bridge` `EngineInjector` + the
//! `ApplicationLayerObserver` switchboard fan-out. This exercises the full
//! AP path with the production types end to end —
//!   wire Push -> resolve_wireexpr -> EngineInjector -> Engine::raise_external_by_name
//! — rather than the `RecordingInjector` the wz-session-core unit tests use.
//!
//! The session FSM policy stands in for an application statechart here:
//! gc-2c proves the bridge + fan-out mechanics; the purpose-built app
//! SCXML machine (and the live wz-ap-demo wiring, where the app's own
//! on_event closure constructs the `EngineInjector` over its app engine,
//! R311gj) arrives with the gc-3 generator.

use std::sync::Arc;

use sce_rust_runtime::Engine;
use wz_codecs::push::{Push, PushOwned, PushOwnedVariant};
use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
use wz_codecs::wireexpr_local::WireexprLocal;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::SessionFsmUnicastPolicy;
use wz_runtime_tokio::session_glue::{
    new_session_actions, new_session_engine, BoxedLinkDriver, DriverLoopOutcome, IterationEvent,
    NetworkMessage, SessionActionsBinding,
};
use wz_runtime_tokio_test_support::{fixture_session_init_params, NoopOutboundDriver};
use wz_statechart_bridge::EngineInjector;

/// Build a wire-inbound Put Push carrying a literal keyexpr (id=0 ⇒
/// resolve_wireexpr returns the suffix verbatim, no peer-table lookup).
fn put_push(keyexpr: &str, payload: &[u8]) -> PushOwned {
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
    .try_into_owned()
    .unwrap();
    if let PushOwnedVariant::CodecZenohMsgPut(ref mut put) = push.body {
        put.payload_len = payload.len() as u64;
        put.payload = wz_session_core::codec_bound::bounded_bytes(payload).unwrap();
    }
    push
}

fn frame_event(push: PushOwned) -> DriverLoopOutcome {
    DriverLoopOutcome::FramePayload {
        reliable: true,
        sn: 0,
        messages: vec![NetworkMessage::Push(Box::new(push))],
        has_ext: false,
        extensions: Vec::new(),
    }
}

fn fresh_engine() -> Engine<SessionFsmUnicastPolicy<SessionActionsBinding>> {
    let outbound: Arc<dyn BoxedLinkDriver + Send + Sync> = Arc::new(NoopOutboundDriver::default());
    let actions = new_session_actions(outbound, fixture_session_init_params(), TokioTime::new());
    let mut engine = new_session_engine(&actions);
    engine.initialize();
    engine
}

#[test]
fn wire_push_injects_domain_event_into_real_engine() {
    let mut engine = fresh_engine();
    let mut observer = ApplicationLayerObserver::new();
    observer
        .switchboard
        .register("home/livingroom/temp", "temp_update");

    let outcome = frame_event(put_push("home/livingroom/temp", b"22.0"));
    let mut injector = EngineInjector::new(&mut engine);
    let fired = observer.dispatch_switchboard(IterationEvent::Poll(&outcome), &mut injector);

    // One mapped keyexpr matched -> exactly one inject() -> one
    // Engine::raise_external_by_name call on the real engine.
    assert_eq!(fired, 1);
}

#[test]
fn wire_push_on_unmapped_keyexpr_injects_nothing() {
    let mut engine = fresh_engine();
    let mut observer = ApplicationLayerObserver::new();
    observer
        .switchboard
        .register("home/livingroom/temp", "temp_update");

    let outcome = frame_event(put_push("home/kitchen/humidity", b"55"));
    let mut injector = EngineInjector::new(&mut engine);
    let fired = observer.dispatch_switchboard(IterationEvent::Poll(&outcome), &mut injector);

    assert_eq!(fired, 0);
}
