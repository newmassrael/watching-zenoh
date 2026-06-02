// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! gc-3c — the switchboard value path, wired end to end.
//!
//! `build.rs` runs sce-codegen over `sources/{sensor_monitor,
//! temp_update_schema, temp_payload}.scxml` and then wz-switchboard-codegen
//! over `wz-switchboard.yaml` + the emitted forge-asts. This crate `include!`s
//! the three generated artifacts:
//!  - [`sensor_monitor`] — the SCXML state machine (with the
//!    `SensorMonitorInject::raise_temp_update` typed seam SCE generated from
//!    the imported EventSchema);
//!  - [`temp_payload`] — the wire codec that decodes a sample's bytes into
//!    `{ celsius_centi: u16 }`;
//!  - the crate-root `dispatch_switchboard` — the generated closed dispatch
//!    that matches an inbound keyexpr and injects the typed `_event.data`.
//!
//! The tests are the first REAL compile + run of a value-path dispatch: the
//! gc-3b golden only asserted the emitted *string*; here it type-checks
//! against SCE's actual generated `Engine<SensorMonitorPolicy>` +
//! `SensorMonitorTempUpdatePayload` and drives a live engine.

// The generated state machine carries a budget of `#![allow(...)]` inner
// attributes the `include!` mid-module strips (build.rs); restore them here as
// outer attributes on the wrapping module (mirrors wz-runtime-tokio/src/lib.rs).
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
// crate-root `pub fn dispatch_switchboard(target, payload, engine)`. Included
// at crate root so its `sensor_monitor::` / `temp_payload::` references
// resolve to the sibling modules above.
include!(concat!(env!("OUT_DIR"), "/dispatch_switchboard.rs"));

#[cfg(test)]
mod tests {
    use super::dispatch_switchboard;
    use super::sensor_monitor::{SensorMonitorPolicy, SensorMonitorState};
    use sce_rust_runtime::Engine;

    // The temp_payload codec's wire form: one big-endian u16 (centidegrees).
    // A real publisher encodes via the same codec; here we lay the 2 bytes out
    // directly so the test exercises the generated *decode* the dispatch runs.
    fn temp_bytes(centi: u16) -> [u8; 2] {
        [(centi >> 8) as u8, (centi & 0xff) as u8]
    }

    #[test]
    fn hot_sample_drives_machine_to_hot() {
        let mut engine = Engine::new(SensorMonitorPolicy::new());
        engine.initialize();
        assert_eq!(engine.get_current_state(), SensorMonitorState::Idle);

        // 35.00 C > the 30.00 C native guard threshold.
        let bytes = temp_bytes(3500);
        let injected = dispatch_switchboard("home/livingroom/temp", &bytes, &mut engine);
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
        let mut engine = Engine::new(SensorMonitorPolicy::new());
        engine.initialize();

        // 20.00 C < threshold — the typed guard misses.
        let bytes = temp_bytes(2000);
        let injected = dispatch_switchboard("home/livingroom/temp", &bytes, &mut engine);
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
        let mut engine = Engine::new(SensorMonitorPolicy::new());
        engine.initialize();
        // Drive to hot first.
        dispatch_switchboard("home/livingroom/temp", &temp_bytes(3500), &mut engine);
        engine.step();
        assert_eq!(engine.get_current_state(), SensorMonitorState::Hot);

        // The reset row is a SIGNAL binding (no codec): empty _event.data,
        // injected via raise_external_by_name. Payload bytes are ignored.
        let injected = dispatch_switchboard("home/kitchen/reset", &[], &mut engine);
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
        let mut engine = Engine::new(SensorMonitorPolicy::new());
        engine.initialize();
        let injected = dispatch_switchboard("office/temp", &temp_bytes(3500), &mut engine);
        engine.step();
        assert_eq!(injected, 0);
        assert_eq!(engine.get_current_state(), SensorMonitorState::Idle);
    }
}

// The AP dynamic half of the value path: the same machine driven through the
// runtime-populated `SwitchboardRegistry` + the generated `SensorMonitorInjector`
// (instead of the static `dispatch_switchboard`). The state outcomes mirror the
// static tests above byte-for-byte — proving one guard semantics across the AP
// (dynamic) and MCU (static) profiles, the gc-3 cross-profile SSOT.
#[cfg(test)]
mod ap_dynamic_tests {
    use super::sensor_monitor::{SensorMonitorPolicy, SensorMonitorState};
    use super::SensorMonitorInjector;
    use sce_rust_runtime::Engine;
    use wz_session_core::reliability::Reliability;
    use wz_session_core::sample_kind::SampleKind;
    use wz_session_core::sink::BorrowedSample;
    use wz_session_core::switchboard::SwitchboardRegistry;

    fn temp_bytes(centi: u16) -> [u8; 2] {
        [(centi >> 8) as u8, (centi & 0xff) as u8]
    }

    // Populate a registry from the SAME routing as wz-switchboard.yaml: the temp
    // row is a value binding, the reset row a signal binding. In production the
    // AP loader fills this by parsing the runtime sidecar; here we register the
    // two rows directly (the routing data is what is dynamic, not the codecs).
    fn registry() -> SwitchboardRegistry {
        let mut board = SwitchboardRegistry::new();
        board.register_value("home/*/temp", "temp_update");
        board.register("home/*/reset", "reset");
        board
    }

    fn put_sample<'a>(keyexpr: &'a str, payload: &'a [u8]) -> BorrowedSample<'a> {
        BorrowedSample {
            keyexpr,
            payload,
            kind: SampleKind::Put,
            reliability: Reliability::Reliable,
        }
    }

    #[test]
    fn hot_sample_drives_machine_to_hot_via_registry() {
        let board = registry();
        let mut engine = Engine::new(SensorMonitorPolicy::new());
        engine.initialize();
        assert_eq!(engine.get_current_state(), SensorMonitorState::Idle);

        let bytes = temp_bytes(3500);
        let sample = put_sample("home/livingroom/temp", &bytes);
        // Construct the value injector at the dispatch site (borrows the engine
        // for the duration of one dispatch — the same shape the bridge
        // EngineInjector uses for the session FSM).
        let mut injector = SensorMonitorInjector::new(&mut engine);
        let injected = board.dispatch(&sample, &mut injector);
        engine.step();

        assert_eq!(injected, 1, "the temp value row fired via the registry");
        assert_eq!(
            engine.get_current_state(),
            SensorMonitorState::Hot,
            "dynamic decode of celsius_centi=3500 satisfies the native typed guard"
        );
    }

    #[test]
    fn cold_sample_leaves_machine_idle_via_registry() {
        let board = registry();
        let mut engine = Engine::new(SensorMonitorPolicy::new());
        engine.initialize();

        let bytes = temp_bytes(2000);
        let sample = put_sample("home/livingroom/temp", &bytes);
        let mut injector = SensorMonitorInjector::new(&mut engine);
        let injected = board.dispatch(&sample, &mut injector);
        engine.step();

        assert_eq!(injected, 1, "the row fired (event injected)");
        assert_eq!(
            engine.get_current_state(),
            SensorMonitorState::Idle,
            "decoded celsius_centi=2000 must not satisfy the guard"
        );
    }

    #[test]
    fn reset_signal_row_returns_to_idle_via_registry() {
        let board = registry();
        let mut engine = Engine::new(SensorMonitorPolicy::new());
        engine.initialize();
        {
            let hot = temp_bytes(3500);
            let sample = put_sample("home/livingroom/temp", &hot);
            let mut injector = SensorMonitorInjector::new(&mut engine);
            board.dispatch(&sample, &mut injector);
        }
        engine.step();
        assert_eq!(engine.get_current_state(), SensorMonitorState::Hot);

        // The reset row is a SIGNAL binding: the injector's `inject` seam raises
        // an empty _event.data via raise_external_by_name (payload ignored).
        let sample = put_sample("home/kitchen/reset", &[]);
        let mut injector = SensorMonitorInjector::new(&mut engine);
        let injected = board.dispatch(&sample, &mut injector);
        engine.step();

        assert_eq!(injected, 1, "the reset signal row fired");
        assert_eq!(engine.get_current_state(), SensorMonitorState::Idle);
    }

    #[test]
    fn unmatched_keyexpr_injects_nothing_via_registry() {
        let board = registry();
        let mut engine = Engine::new(SensorMonitorPolicy::new());
        engine.initialize();

        let bytes = temp_bytes(3500);
        let sample = put_sample("office/temp", &bytes);
        let mut injector = SensorMonitorInjector::new(&mut engine);
        let injected = board.dispatch(&sample, &mut injector);
        engine.step();

        assert_eq!(injected, 0);
        assert_eq!(engine.get_current_state(), SensorMonitorState::Idle);
    }
}
