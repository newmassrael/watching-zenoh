// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! gc-3 carry #2 — the wz-ap-demo live application machine.
//!
//! `build.rs` runs sce-codegen over `sources/{sensor_monitor,
//! temp_update_schema, temp_payload}.scxml` and then wz-switchboard-codegen
//! over `wz-switchboard.yaml` + the emitted forge-asts. This crate `include!`s
//! the generated artifacts and re-exports them under a small, sce-free public
//! API so `wz-ap-demo` can drive the live value path without naming an
//! sce-rust-runtime / sce-forge-runtime type directly:
//!  - [`new_engine`] — a fresh, initialized engine for the demo machine;
//!  - [`register_bindings`] — install the demo's switchboard rows
//!    (`demo/sensor/temp` value, `demo/sensor/reset` signal) onto a registry,
//!    mirroring `wz-switchboard.yaml`;
//!  - [`SensorMonitorInjector`] — the generated value-capable
//!    [`EventInjector`](wz_session_core::switchboard::EventInjector) the
//!    observer fan-out threads;
//!  - [`Engine`] / [`SensorMonitorPolicy`] / [`SensorMonitorState`] re-exports
//!    so the demo can construct + inspect the engine through this crate.
//!
//! The machine is deliberately focused (idle/hot, one temp value event + one
//! reset signal) so the live wire path stays simple: the wz-switchboard-example
//! crate owns the multi-codec / multi-event demonstration; this crate owns the
//! LIVE deploy wiring an external zenoh peer drives end to end.

// The generated state machine carries a budget of `#![allow(...)]` inner
// attributes the `include!` mid-module strips (build.rs); restore them here as
// outer attributes on the wrapping module (mirrors wz-switchboard-example).
#[allow(non_snake_case)]
#[allow(unused_imports)]
#[allow(dead_code)]
#[allow(unused_variables)]
#[allow(unused_mut)]
#[allow(unused_labels)]
#[allow(unreachable_patterns)]
#[allow(unreachable_code)]
#[allow(unused_assignments)]
#[allow(clippy::style)]
#[allow(clippy::complexity)]
pub mod sensor_monitor {
    include!(concat!(env!("OUT_DIR"), "/sensor_monitor_sm.rs"));
}

#[allow(non_snake_case)]
#[allow(unused_imports)]
#[allow(dead_code)]
#[allow(unused_variables)]
#[allow(unused_mut)]
#[allow(clippy::style)]
#[allow(clippy::complexity)]
pub mod temp_payload {
    include!(concat!(env!("OUT_DIR"), "/temp_payload.rs"));
}

// The generated dispatch: `use sensor_monitor::SensorMonitorInject;` + a
// crate-root `pub fn dispatch_switchboard(...)` + `pub struct
// SensorMonitorInjector`. Included at crate root so its `sensor_monitor::` /
// `temp_payload::` references resolve to the sibling modules above.
include!(concat!(env!("OUT_DIR"), "/dispatch_switchboard.rs"));

use wz_session_core::switchboard::SwitchboardRegistry;

/// Re-export of the SCE engine type so the demo can hold an
/// `Engine<SensorMonitorPolicy>` through this crate (no direct sce dep).
pub use sce_rust_runtime::Engine;
pub use sensor_monitor::{SensorMonitorPolicy, SensorMonitorState};

/// Construct a fresh, initialized engine for the demo's application machine.
/// The engine starts in [`SensorMonitorState::Idle`].
pub fn new_engine() -> Engine<SensorMonitorPolicy> {
    let mut engine = Engine::new(SensorMonitorPolicy::new());
    engine.initialize();
    engine
}

/// Install the demo's switchboard rows onto `board`, mirroring
/// `wz-switchboard.yaml`: a VALUE row (`demo/sensor/temp` -> `temp_update`,
/// decoded by the temp_payload codec) and a SIGNAL row (`demo/sensor/reset` ->
/// `reset`, empty `_event.data`). The demo calls this on the observer's
/// `switchboard` registry before `drive_session` starts so an inbound sample
/// on either keyexpr fans out to the application engine.
///
/// The static `dispatch_switchboard` and this dynamic registration share the
/// same routing by construction (both derive from the one sidecar); the value
/// row's codec<->payload decode is supplied by [`SensorMonitorInjector`], which
/// the registry's type-erased rows resolve through `inject_value`.
pub fn register_bindings(board: &mut SwitchboardRegistry) {
    board.register_value("demo/sensor/temp", "temp_update");
    board.register("demo/sensor/reset", "reset");
}

#[cfg(test)]
mod tests {
    use super::temp_payload::TempPayload;
    use super::{dispatch_switchboard, new_engine, SensorMonitorState};

    // The temp_payload codec's wire form: a single big-endian u16 (centidegrees).
    // A real publisher encodes via this same codec, so the test runs a true
    // encode -> wire -> decode round-trip.
    fn temp_wire(centi: u16) -> Vec<u8> {
        TempPayload {
            celsius_centi: centi,
        }
        .encode_to_vec()
    }

    #[test]
    fn hot_sample_drives_machine_to_hot() {
        let mut engine = new_engine();
        assert_eq!(engine.get_current_state(), SensorMonitorState::Idle);

        // 35.00 C > the 30.00 C native guard threshold.
        let injected = dispatch_switchboard("demo/sensor/temp", &temp_wire(3500), &mut engine);
        engine.step();

        assert_eq!(injected, 1, "the temp value row fired");
        assert_eq!(
            engine.get_current_state(),
            SensorMonitorState::Hot,
            "decoded celsius_centi=3500 satisfies the native typed guard"
        );
    }

    #[test]
    fn cold_sample_leaves_machine_idle() {
        let mut engine = new_engine();

        // 20.00 C < threshold — the typed guard misses.
        let injected = dispatch_switchboard("demo/sensor/temp", &temp_wire(2000), &mut engine);
        engine.step();

        assert_eq!(injected, 1, "the row still fired (event injected)");
        assert_eq!(
            engine.get_current_state(),
            SensorMonitorState::Idle,
            "decoded celsius_centi=2000 must not satisfy the guard"
        );
    }

    #[test]
    fn reset_signal_row_returns_to_idle() {
        let mut engine = new_engine();
        // Drive to hot first.
        dispatch_switchboard("demo/sensor/temp", &temp_wire(3500), &mut engine);
        engine.step();
        assert_eq!(engine.get_current_state(), SensorMonitorState::Hot);

        // The reset row is a SIGNAL binding (no codec): empty _event.data,
        // injected via raise_external_by_name. Payload bytes are ignored.
        let injected = dispatch_switchboard("demo/sensor/reset", &[], &mut engine);
        engine.step();

        assert_eq!(injected, 1, "the reset signal row fired");
        assert_eq!(
            engine.get_current_state(),
            SensorMonitorState::Idle,
            "reset returns the machine to idle"
        );
    }

    #[test]
    fn unmatched_keyexpr_injects_nothing() {
        let mut engine = new_engine();
        let injected = dispatch_switchboard("office/temp", &temp_wire(3500), &mut engine);
        engine.step();
        assert_eq!(injected, 0);
        assert_eq!(engine.get_current_state(), SensorMonitorState::Idle);
    }
}
