// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! gc-3 carry #2 — value-path observer fan-out integration.
//!
//! A wire-inbound `Push` drives the demo's application machine through the
//! PRODUCTION `ApplicationLayerObserver` switchboard fan-out + the generated
//! `SensorMonitorInjector` value seam — the exact path the wz-ap-demo binary
//! wires (`runner.rs`: `obs.dispatch_switchboard(event, &mut injector)`).
//! Where the gc-2c `wz-runtime-tokio/tests/switchboard_inject.rs` proved the
//! SIGNAL path (empty `_event.data` via `EngineInjector`), this proves the
//! VALUE path: the inbound payload is decoded by the temp_payload codec into
//! the typed `_event.data` and the native guard observes it. In-process Push
//! (no TCP) keeps the test deterministic; the external-peer e2e is the Layer E
//! follow-on.

use wz_ap_demo_app::temp_payload::TempPayload;
use wz_ap_demo_app::{new_engine, register_bindings, SensorMonitorInjector, SensorMonitorState};
use wz_codecs::push::{Push, PushOwned, PushOwnedVariant};
use wz_codecs::wireexpr::{Wireexpr, WireexprVariant};
use wz_codecs::wireexpr_local::WireexprLocal;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::session_glue::{DriverLoopOutcome, IterationEvent, NetworkMessage};

/// Encode a temp_payload frame (single big-endian uint16 centidegrees) the way
/// a real publisher would, so the fan-out decode reads back the exact bytes.
fn temp_wire(centi: u16) -> Vec<u8> {
    TempPayload {
        celsius_centi: centi,
    }
    .encode_to_vec()
}

/// Build a wire-inbound Put Push carrying a literal keyexpr (id=0 ⇒
/// resolve_wireexpr returns the suffix verbatim, no peer-table lookup) and the
/// given payload bytes.
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
        put.payload = wz_session_core::codec_owned::owned_bytes(payload).unwrap();
    }
    push
}

fn frame_event(push: PushOwned) -> DriverLoopOutcome {
    DriverLoopOutcome::FramePayload {
        priority: wz_session_core::qos::Priority::DEFAULT,
        reliable: true,
        sn: 0,
        messages: vec![NetworkMessage::Push(Box::new(push))],
        has_ext: false,
        extensions: Vec::new(),
    }
}

#[test]
fn inbound_temp_push_drives_app_engine_to_hot_via_fan_out() {
    let mut engine = new_engine();
    assert_eq!(engine.get_current_state(), SensorMonitorState::Idle);

    let mut observer = ApplicationLayerObserver::new();
    register_bindings(&mut observer.switchboard);

    // 35.00 C > the 30.00 C native guard threshold.
    let outcome = frame_event(put_push("demo/sensor/temp", &temp_wire(3500)));
    let fired = {
        let mut injector = SensorMonitorInjector::new(&mut engine);
        observer.dispatch_switchboard(IterationEvent::Poll(&outcome), &mut injector)
    };
    engine.step();

    assert_eq!(fired, 1, "the temp value row fired through the fan-out");
    assert_eq!(
        engine.get_current_state(),
        SensorMonitorState::Hot,
        "the inbound payload decoded to celsius_centi=3500 and satisfied the guard"
    );
}

#[test]
fn inbound_cold_temp_push_leaves_app_engine_idle_via_fan_out() {
    let mut engine = new_engine();
    let mut observer = ApplicationLayerObserver::new();
    register_bindings(&mut observer.switchboard);

    // 20.00 C < threshold — the value row still fires but the guard misses.
    let outcome = frame_event(put_push("demo/sensor/temp", &temp_wire(2000)));
    let fired = {
        let mut injector = SensorMonitorInjector::new(&mut engine);
        observer.dispatch_switchboard(IterationEvent::Poll(&outcome), &mut injector)
    };
    engine.step();

    assert_eq!(fired, 1, "the value row fired (event injected)");
    assert_eq!(
        engine.get_current_state(),
        SensorMonitorState::Idle,
        "decoded celsius_centi=2000 must not satisfy the guard"
    );
}

#[test]
fn inbound_reset_push_returns_app_engine_to_idle_via_fan_out() {
    let mut engine = new_engine();
    let mut observer = ApplicationLayerObserver::new();
    register_bindings(&mut observer.switchboard);

    // Drive to hot first.
    let hot = frame_event(put_push("demo/sensor/temp", &temp_wire(3500)));
    {
        let mut injector = SensorMonitorInjector::new(&mut engine);
        observer.dispatch_switchboard(IterationEvent::Poll(&hot), &mut injector);
    }
    engine.step();
    assert_eq!(engine.get_current_state(), SensorMonitorState::Hot);

    // The reset row is a SIGNAL binding: empty _event.data, payload ignored.
    let reset = frame_event(put_push("demo/sensor/reset", b"whatever"));
    let fired = {
        let mut injector = SensorMonitorInjector::new(&mut engine);
        observer.dispatch_switchboard(IterationEvent::Poll(&reset), &mut injector)
    };
    engine.step();

    assert_eq!(fired, 1, "the reset signal row fired through the fan-out");
    assert_eq!(engine.get_current_state(), SensorMonitorState::Idle);
}

#[test]
fn inbound_unmapped_keyexpr_injects_nothing_via_fan_out() {
    let mut engine = new_engine();
    let mut observer = ApplicationLayerObserver::new();
    register_bindings(&mut observer.switchboard);

    let outcome = frame_event(put_push("office/temp", &temp_wire(3500)));
    let fired = {
        let mut injector = SensorMonitorInjector::new(&mut engine);
        observer.dispatch_switchboard(IterationEvent::Poll(&outcome), &mut injector)
    };
    engine.step();

    assert_eq!(fired, 0);
    assert_eq!(engine.get_current_state(), SensorMonitorState::Idle);
}
