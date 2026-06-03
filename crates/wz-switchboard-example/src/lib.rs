// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! gc-3c — the switchboard value path, wired end to end (multi-event).
//!
//! `build.rs` runs sce-codegen over `sources/{sensor_monitor,
//! temp_update_schema, temp_payload, humidity_update_schema,
//! humidity_payload}.scxml` and then wz-switchboard-codegen over
//! `wz-switchboard.yaml` + the emitted forge-asts. This crate `include!`s the
//! generated artifacts:
//!  - [`sensor_monitor`] — the SCXML state machine (with the
//!    `SensorMonitorInject::{raise_temp_update, raise_humidity_update}` typed
//!    seams SCE generated from the two imported EventSchemas);
//!  - [`temp_payload`] — the wire codec that decodes a sample's bytes into
//!    `{ celsius_centi: u16, sensor_id: &str, raw: &[u8] }` (borrowed views);
//!  - [`humidity_payload`] — the SECOND wire codec, a single `{ percent: u8 }`;
//!  - the crate-root `dispatch_switchboard` — the generated closed dispatch
//!    that matches an inbound keyexpr and injects the typed `_event.data`.
//!
//! The tests are the REAL compile + run of a value-path dispatch: the gc-3b
//! golden only asserted the emitted *string*; here it type-checks against
//! SCE's actual generated `Engine<SensorMonitorPolicy>` +
//! `SensorMonitor{TempUpdate,HumidityUpdate}Payload` and drives a live engine.
//!
//! Two value EVENTS exercise the generator's multi-codec / multi-event join:
//! `temp_update` (codec `temp_payload`) and `humidity_update` (codec
//! `humidity_payload`). The generator resolves a separate schema<->codec
//! pairing per event and emits a distinct decode helper + injector arm for
//! each. The temp schema mixes a primitive (`celsius_centi`), a scalar string
//! (`sensor_id`), and a scalar bytes (`raw`) field — the codec decodes
//! `sensor_id` / `raw` as borrowed `&str` / `&[u8]` but the payload struct
//! holds them owned (`String` / `Vec<u8>`), so the dispatch threads a
//! `.into()` deep-copy for each; native string (`sensor_id === 'kitchen'`) and
//! bytes (`raw === 'ack'`) guards observe them semantically (the bytes guard
//! lowers to `ev.raw == b"ack"` since SCE pin d665780d9). The humidity schema
//! is a single primitive (`percent: u8`) over a structurally different wire
//! shape, and its native `percent >= 90` guard proves the second codec's
//! decoded field reaches a guard verbatim.

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

// The SECOND value event's wire codec (multi-event carry): decodes a single
// big-endian uint8 percent. Included as its own sibling module so the
// generated dispatch's `humidity_payload::HumidityPayload` reference resolves.
#[allow(non_snake_case)]
#[allow(unused_imports)]
#[allow(dead_code)]
#[allow(unused_variables)]
#[allow(unused_mut)]
#[allow(clippy::style)]
#[allow(clippy::complexity)]
pub mod humidity_payload {
    include!(concat!(env!("OUT_DIR"), "/humidity_payload.rs"));
}

// The generated dispatch: `use sensor_monitor::SensorMonitorInject;` + a
// crate-root `pub fn dispatch_switchboard(target, payload, engine)`. Included
// at crate root so its `sensor_monitor::` / `temp_payload::` references
// resolve to the sibling modules above.
include!(concat!(env!("OUT_DIR"), "/dispatch_switchboard.rs"));

#[cfg(test)]
mod tests {
    use super::dispatch_switchboard;
    use super::humidity_payload::HumidityPayload;
    use super::sensor_monitor::{SensorMonitorPolicy, SensorMonitorState};
    use super::temp_payload::TempPayload;
    use sce_rust_runtime::Engine;

    // The temp_payload codec's wire form: a big-endian u16 (centidegrees) +
    // a length-prefixed UTF-8 `sensor_id` + a length-prefixed `raw` blob. A
    // real publisher encodes via this same codec, so the test runs a true
    // encode -> wire -> decode round-trip (the generated `encode_to_vec`
    // produces exactly the bytes the dispatch's `decode` reads back) rather
    // than hand-laying the VLE length prefixes.
    fn temp_wire_full(centi: u16, sensor_id: &str, raw: &[u8]) -> Vec<u8> {
        TempPayload {
            celsius_centi: centi,
            sensor_id_len: sensor_id.len() as u64,
            sensor_id,
            raw_len: raw.len() as u64,
            raw,
        }
        .encode_to_vec()
    }

    // Common case: no `raw` blob (the celsius / sensor_id guards ignore it).
    fn temp_wire(centi: u16, sensor_id: &str) -> Vec<u8> {
        temp_wire_full(centi, sensor_id, b"")
    }

    // The SECOND value event's codec: a single big-endian uint8 percent. A real
    // humidity publisher encodes via this same codec, so the dispatch decodes
    // back exactly these bytes — a structurally different wire shape from
    // temp_payload, proving the multi-codec join.
    fn humidity_wire(percent: u8) -> Vec<u8> {
        HumidityPayload { percent }.encode_to_vec()
    }

    #[test]
    fn hot_sample_drives_machine_to_hot() {
        let mut engine = Engine::new(SensorMonitorPolicy::new());
        engine.initialize();
        assert_eq!(engine.get_current_state(), SensorMonitorState::Idle);

        // 35.00 C > the 30.00 C native guard threshold. The borrowed `sensor_id`
        // view is deep-copied into the owned payload field on the way in.
        let wire = temp_wire(3500, "livingroom");
        let injected = dispatch_switchboard("home/livingroom/temp", &wire, &mut engine);
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
        let wire = temp_wire(2000, "livingroom");
        let injected = dispatch_switchboard("home/livingroom/temp", &wire, &mut engine);
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
        dispatch_switchboard(
            "home/livingroom/temp",
            &temp_wire(3500, "livingroom"),
            &mut engine,
        );
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
        let injected =
            dispatch_switchboard("office/temp", &temp_wire(3500, "livingroom"), &mut engine);
        engine.step();
        assert_eq!(injected, 0);
        assert_eq!(engine.get_current_state(), SensorMonitorState::Idle);
    }

    #[test]
    fn alarm_sample_branches_on_decoded_string() {
        // The machine has a second native guard reading `_event.data.sensor_id`
        // (a string-equality `===`), so the borrowed-then-owned `sensor_id`
        // value is observed semantically: only the `kitchen` sensor escalates a
        // hot reading to `alarm`; any other hot reading stays `hot`. This proves
        // the `&str -> String` field-move delivered the correct value, not just
        // that the payload compiled.
        let mut engine = Engine::new(SensorMonitorPolicy::new());
        engine.initialize();

        // A hot livingroom sample reaches `hot` (sensor_id guard misses).
        dispatch_switchboard(
            "home/livingroom/temp",
            &temp_wire(3500, "livingroom"),
            &mut engine,
        );
        engine.step();
        assert_eq!(engine.get_current_state(), SensorMonitorState::Hot);

        // A hot kitchen sample escalates `hot -> alarm` on the string guard.
        dispatch_switchboard(
            "home/kitchen/temp",
            &temp_wire(3600, "kitchen"),
            &mut engine,
        );
        engine.step();
        assert_eq!(
            engine.get_current_state(),
            SensorMonitorState::Alarm,
            "decoded sensor_id=\"kitchen\" satisfies the native string guard"
        );
    }

    #[test]
    fn non_kitchen_hot_sample_stays_hot() {
        // Discriminating / regression test: the hot->alarm guard reads
        // `_event.data.sensor_id`, NOT celsius. A hot reading from a non-kitchen
        // sensor (celsius well over the 3000 threshold) must therefore stay
        // `hot`, not escalate. Under the SCE per-state guard-index collision
        // (pre-pin-1474bd0a9) the hot guard was mis-rendered as `celsius > 3000`,
        // so this very sample wrongly went to `alarm`; the assertion below is
        // the guard that would have caught that bug.
        let mut engine = Engine::new(SensorMonitorPolicy::new());
        engine.initialize();
        dispatch_switchboard(
            "home/livingroom/temp",
            &temp_wire(3500, "livingroom"),
            &mut engine,
        );
        engine.step();
        assert_eq!(engine.get_current_state(), SensorMonitorState::Hot);

        // Hotter still (3600 > 3000), but a bedroom sensor — sensor_id misses.
        let injected = dispatch_switchboard(
            "home/bedroom/temp",
            &temp_wire(3600, "bedroom"),
            &mut engine,
        );
        engine.step();
        assert_eq!(injected, 1, "the temp value row still fired");
        assert_eq!(
            engine.get_current_state(),
            SensorMonitorState::Hot,
            "non-kitchen hot sample must stay hot (sensor_id guard misses, \
             not the celsius guard)"
        );
    }

    #[test]
    fn alarm_acknowledged_by_decoded_bytes() {
        // The alarm->idle guard reads `_event.data.raw` (a bytes field) and
        // compares it to the literal "ack" (lowered to `ev.raw == b"ack"` since
        // SCE pin d665780d9). This observes the borrowed-then-owned
        // `&[u8] -> Vec<u8>` field-move semantically: only a payload carrying
        // the exact `ack` bytes acknowledges the alarm; other bytes leave the
        // machine in alarm.
        let mut engine = Engine::new(SensorMonitorPolicy::new());
        engine.initialize();
        // idle -> hot (celsius) -> alarm (kitchen sensor_id).
        dispatch_switchboard(
            "home/livingroom/temp",
            &temp_wire(3500, "livingroom"),
            &mut engine,
        );
        engine.step();
        dispatch_switchboard(
            "home/kitchen/temp",
            &temp_wire(3600, "kitchen"),
            &mut engine,
        );
        engine.step();
        assert_eq!(engine.get_current_state(), SensorMonitorState::Alarm);

        // Wrong bytes — the raw guard misses, machine stays in alarm.
        dispatch_switchboard(
            "home/kitchen/temp",
            &temp_wire_full(3600, "kitchen", b"nope"),
            &mut engine,
        );
        engine.step();
        assert_eq!(
            engine.get_current_state(),
            SensorMonitorState::Alarm,
            "raw=b\"nope\" must not acknowledge the alarm"
        );

        // The exact `ack` bytes acknowledge: alarm -> idle.
        let injected = dispatch_switchboard(
            "home/kitchen/temp",
            &temp_wire_full(3600, "kitchen", b"ack"),
            &mut engine,
        );
        engine.step();
        assert_eq!(injected, 1, "the temp value row fired");
        assert_eq!(
            engine.get_current_state(),
            SensorMonitorState::Idle,
            "decoded raw=b\"ack\" satisfies the native bytes guard"
        );
    }

    #[test]
    fn saturated_humidity_drives_machine_to_hot() {
        // The SECOND value event: a `home/*/humidity` sample is decoded by the
        // DIFFERENT codec (humidity_payload) into the DIFFERENT EventSchema
        // (humidity_update), and its native uint8 guard (`percent >= 90`) drives
        // idle -> hot. This is the multi-codec / multi-event path: the same
        // dispatch resolves a separate schema<->codec join for humidity_update,
        // distinct from temp_update's.
        let mut engine = Engine::new(SensorMonitorPolicy::new());
        engine.initialize();
        assert_eq!(engine.get_current_state(), SensorMonitorState::Idle);

        let injected =
            dispatch_switchboard("home/bathroom/humidity", &humidity_wire(95), &mut engine);
        engine.step();

        assert_eq!(injected, 1, "the humidity value row fired");
        assert_eq!(
            engine.get_current_state(),
            SensorMonitorState::Hot,
            "decoded percent=95 satisfies the native uint8 guard"
        );
    }

    #[test]
    fn comfortable_humidity_leaves_machine_idle() {
        // Discriminating: a below-threshold humidity (45% < 90%) must miss the
        // guard, proving the decoded uint8 value reaches the guard (not a
        // coincidental match). The row still fires (event injected) but the
        // machine stays idle.
        let mut engine = Engine::new(SensorMonitorPolicy::new());
        engine.initialize();

        let injected =
            dispatch_switchboard("home/bathroom/humidity", &humidity_wire(45), &mut engine);
        engine.step();

        assert_eq!(injected, 1, "the humidity row fired (event injected)");
        assert_eq!(
            engine.get_current_state(),
            SensorMonitorState::Idle,
            "decoded percent=45 must not satisfy the >= 90 guard"
        );
    }
}

// The AP dynamic half of the value path: the same machine driven through the
// runtime-populated `SwitchboardRegistry` + the generated `SensorMonitorInjector`
// (instead of the static `dispatch_switchboard`). The state outcomes mirror the
// static tests above byte-for-byte — proving one guard semantics across the AP
// (dynamic) and MCU (static) profiles, the gc-3 cross-profile SSOT.
#[cfg(test)]
mod ap_dynamic_tests {
    use super::humidity_payload::HumidityPayload;
    use super::sensor_monitor::{SensorMonitorPolicy, SensorMonitorState};
    use super::temp_payload::TempPayload;
    use super::SensorMonitorInjector;
    use sce_rust_runtime::Engine;
    use wz_session_core::reliability::Reliability;
    use wz_session_core::sample_kind::SampleKind;
    use wz_session_core::sink::BorrowedSample;
    use wz_session_core::switchboard::SwitchboardRegistry;

    // Encode a temp_payload frame the way a real publisher would (celsius u16 +
    // length-prefixed `sensor_id` + length-prefixed `raw`), so the registry-
    // driven decode reads back the borrowed string/bytes the generated injector
    // then owns into the typed payload.
    fn temp_wire_full(centi: u16, sensor_id: &str, raw: &[u8]) -> Vec<u8> {
        TempPayload {
            celsius_centi: centi,
            sensor_id_len: sensor_id.len() as u64,
            sensor_id,
            raw_len: raw.len() as u64,
            raw,
        }
        .encode_to_vec()
    }

    fn temp_wire(centi: u16, sensor_id: &str) -> Vec<u8> {
        temp_wire_full(centi, sensor_id, b"")
    }

    // The second value event's wire form (single big-endian uint8 percent).
    fn humidity_wire(percent: u8) -> Vec<u8> {
        HumidityPayload { percent }.encode_to_vec()
    }

    // Populate a registry from the SAME routing as wz-switchboard.yaml: the temp
    // + humidity rows are value bindings, the reset row a signal binding. In
    // production the AP loader fills this by parsing the runtime sidecar; here we
    // register the rows directly (the routing data is what is dynamic, not the
    // codecs). Two value rows for two events make this the AP-side multi-event
    // mirror of the static dispatch.
    fn registry() -> SwitchboardRegistry {
        let mut board = SwitchboardRegistry::new();
        board.register_value("home/*/temp", "temp_update");
        board.register_value("home/*/humidity", "humidity_update");
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

        let bytes = temp_wire(3500, "livingroom");
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

        let bytes = temp_wire(2000, "livingroom");
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
            let hot = temp_wire(3500, "livingroom");
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

        let bytes = temp_wire(3500, "livingroom");
        let sample = put_sample("office/temp", &bytes);
        let mut injector = SensorMonitorInjector::new(&mut engine);
        let injected = board.dispatch(&sample, &mut injector);
        engine.step();

        assert_eq!(injected, 0);
        assert_eq!(engine.get_current_state(), SensorMonitorState::Idle);
    }

    #[test]
    fn alarm_sample_branches_on_decoded_string_via_registry() {
        // Cross-profile parity for the static `alarm_sample_branches_on_decoded_string`:
        // the AP dynamic registry + generated injector deliver the same owned
        // `sensor_id` to the native string guard, so a hot kitchen sample
        // escalates `hot -> alarm` identically.
        let board = registry();
        let mut engine = Engine::new(SensorMonitorPolicy::new());
        engine.initialize();
        {
            let hot = temp_wire(3500, "livingroom");
            let sample = put_sample("home/livingroom/temp", &hot);
            let mut injector = SensorMonitorInjector::new(&mut engine);
            board.dispatch(&sample, &mut injector);
        }
        engine.step();
        assert_eq!(engine.get_current_state(), SensorMonitorState::Hot);

        let kitchen = temp_wire(3600, "kitchen");
        let sample = put_sample("home/kitchen/temp", &kitchen);
        let mut injector = SensorMonitorInjector::new(&mut engine);
        let injected = board.dispatch(&sample, &mut injector);
        engine.step();

        assert_eq!(
            injected, 1,
            "the kitchen temp value row fired via the registry"
        );
        assert_eq!(
            engine.get_current_state(),
            SensorMonitorState::Alarm,
            "dynamic decode of sensor_id=\"kitchen\" satisfies the native string guard"
        );

        // Cross-profile parity for `alarm_acknowledged_by_decoded_bytes`: the
        // owned `raw` bytes field reaches the native bytes guard via the
        // registry path too — the exact `ack` blob acknowledges `alarm -> idle`.
        let ack = temp_wire_full(3600, "kitchen", b"ack");
        let sample = put_sample("home/kitchen/temp", &ack);
        let mut injector = SensorMonitorInjector::new(&mut engine);
        let injected = board.dispatch(&sample, &mut injector);
        engine.step();
        assert_eq!(injected, 1, "the ack temp value row fired via the registry");
        assert_eq!(
            engine.get_current_state(),
            SensorMonitorState::Idle,
            "dynamic decode of raw=b\"ack\" satisfies the native bytes guard"
        );
    }

    #[test]
    fn saturated_humidity_drives_machine_to_hot_via_registry() {
        // Cross-profile parity for the static `saturated_humidity_drives_machine_to_hot`:
        // the AP dynamic registry + generated injector resolve the SECOND value
        // event's codec (humidity_payload) by the same name-keyed `inject_value`
        // arm the static dispatch uses, decode the uint8 percent, and drive
        // idle -> hot identically. This proves the multi-event injector match
        // (two value arms) works on the dynamic path, not just the static one.
        let board = registry();
        let mut engine = Engine::new(SensorMonitorPolicy::new());
        engine.initialize();
        assert_eq!(engine.get_current_state(), SensorMonitorState::Idle);

        let bytes = humidity_wire(95);
        let sample = put_sample("home/bathroom/humidity", &bytes);
        let mut injector = SensorMonitorInjector::new(&mut engine);
        let injected = board.dispatch(&sample, &mut injector);
        engine.step();

        assert_eq!(injected, 1, "the humidity value row fired via the registry");
        assert_eq!(
            engine.get_current_state(),
            SensorMonitorState::Hot,
            "dynamic decode of percent=95 satisfies the native uint8 guard"
        );
    }
}
