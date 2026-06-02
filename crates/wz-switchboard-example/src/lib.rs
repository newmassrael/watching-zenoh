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
