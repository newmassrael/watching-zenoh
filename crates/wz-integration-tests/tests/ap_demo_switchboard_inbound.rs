// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// gc-3 carry #2 (R311ha) — live switchboard value-path e2e.
//
// Closes the "live wz-ap-demo wiring" carry: a REAL foreign peer
// (zenoh-pico's z_put CLI) publishes a temperature sample to the demo's
// switchboard value keyexpr (demo/sensor/temp), and the demo's session
// inbound -> ApplicationLayerObserver switchboard fan-out -> generated
// SensorMonitorInjector decodes the wire payload into the typed
// _event.data and drives the application statechart engine idle -> hot.
// This is the first time a published sample drives a real SCE application
// machine end to end across a foreign-implementation wire, vs the
// in-process Push the wz-ap-demo-app fan-out test uses.
//
// Test flow (mirrors ap_demo_round_trip):
//   1. Reserve a free TCP port; spawn wz-ap-demo --listen with RUST_LOG=info.
//   2. Wait for "listening on"; release the port reservation.
//   3. z_put -k demo/sensor/temp -v <2 ASCII bytes> -e tcp/<addr> -m client.
//   4. Wait for "APP SWITCHBOARD FIRED" with "app_state=Hot" — proves the
//      handshake completed, the Push resolved to the switchboard value row,
//      the temp_payload codec decoded the wire bytes, and the native guard
//      observed celsius_centi > 3000.
//   5. SIGTERM the demo; surface captured stderr on any failed assertion.
//
// Wire-payload note: zenoh-pico's z_put -v takes a STRING value, so the
// payload is the literal ASCII bytes. temp_payload decodes a big-endian
// uint16 from the first two bytes, and every printable ASCII byte is >= 0x20,
// so any two-character value decodes to celsius_centi >= 0x2020 (8224) — well
// over the 3000 (30.00 C) guard. The value here ("OK") therefore reaches Hot;
// the chosen string is decode-convenient, not a realistic temperature. The
// SUB-threshold discrimination (a cold sample that must STAY idle) needs
// arbitrary wire bytes the CLI cannot express, so it is covered by the
// in-process fan-out test (wz-ap-demo-app/tests/fan_out_value_path.rs,
// `inbound_cold_temp_push_leaves_app_engine_idle_via_fan_out`). This e2e owns
// the LIVE-wire plumbing proof; that test owns the value-discrimination proof.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
    PortReservation,
};

// wz-proves: pubsub-put pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenoh-pico CLI); Layer E runs via --ignored"]
fn switchboard_value_path_against_zenoh_pico_z_put() {
    let demo = wz_ap_demo_binary();
    let z_put = zenoh_pico_cli_binary("z_put");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let listen_addr = format!("127.0.0.1:{port}");
    let endpoint = format!("tcp/{listen_addr}");
    // The demo's own pub/sub subscriber binds to --key; keep it disjoint from
    // the switchboard keyexpr so only the switchboard handles demo/sensor/temp.
    let sub_key = "demo/test";
    // The switchboard value keyexpr (wz-ap-demo-app/wz-switchboard.yaml).
    let switchboard_key = "demo/sensor/temp";

    let stderr_capture = tempfile::tempfile().expect("tempfile for demo stderr");
    let stderr_capture_writer = stderr_capture.try_clone().expect("dup stderr handle");
    let mut stderr_capture_reader = stderr_capture;

    let mut child = ChildGuard::wrap(
        "wz-ap-demo (--listen, switchboard)",
        Command::new(&demo)
            .arg("--listen")
            .arg(&listen_addr)
            .arg("--key")
            .arg(sub_key)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_capture_writer))
            .spawn()
            .expect("spawn wz-ap-demo"),
    );

    let bound = wait_for_substring(
        &mut stderr_capture_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = child.child_mut().kill();
        let _ = child.child_mut().wait();
        panic!(
            "wz-ap-demo did not log 'listening on' within 5s\n--- captured stderr ---\n{captured}"
        );
    }
    drop(port_res);

    // Publish a temperature sample to the switchboard value keyexpr. "OK"
    // decodes big-endian to celsius_centi = 0x4F4B (20299) > the 3000 guard.
    let z_put_status = Command::new(&z_put)
        .args([
            "-k",
            switchboard_key,
            "-v",
            "OK",
            "-e",
            &endpoint,
            "-m",
            "client",
        ])
        .status();

    // Hard gate: the switchboard value row must have fired AND driven the app
    // machine to Hot. A missing line means the handshake, the keyexpr
    // resolver, the codec decode, or the native guard regressed.
    let fired_result = wait_for_substring(
        &mut stderr_capture_reader,
        "APP SWITCHBOARD FIRED",
        Duration::from_secs(5),
    );

    let _ = child.child_mut().kill();
    let _ = child.child_mut().wait();

    let captured = read_captured(&mut stderr_capture_reader);
    eprintln!("--- captured wz-ap-demo stderr ---\n{captured}");

    let fired_captured = match fired_result {
        Ok(c) => c,
        Err(c) => panic!(
            "wz-ap-demo did not log 'APP SWITCHBOARD FIRED' within 5s after z_put published to \
             {switchboard_key}\nz_put exit: {z_put_status:?}\n\
             --- captured demo stderr at deadline ---\n{c}"
        ),
    };
    // The transition is the value-path witness: only a decoded celsius_centi >
    // 3000 drives idle -> hot (a signal row could not), so app_state=Hot proves
    // the wire bytes were decoded into the typed _event.data and the native
    // guard observed them.
    assert!(
        fired_captured.contains("app_state=Hot"),
        "switchboard fired but the app machine did not reach Hot — the decoded \
         celsius_centi did not satisfy the native guard.\n--- captured demo stderr ---\n{captured}"
    );
}
