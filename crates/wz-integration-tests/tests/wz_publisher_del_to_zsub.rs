// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R219 — Del-mode publisher round-trip integration test.
//!
//! Drives the wz-ap-demo binary (R219 `--delete <keyexpr>` mode)
//! against an external zenoh-pico `z_sub` CLI peer over real TCP.
//! Mirrors [`wz_publisher_to_zsub`] but exercises the outbound
//! `MsgDel` body path instead of `MsgPut(payload)`.
//!
//! Two witnesses combine to verify the Del path end-to-end:
//!
//! * The wz-side codec round-trip
//!   (`build_push_del_literal_round_trips_through_frame_decode_as_msg_del`
//!   in `wz-runtime-tokio::session_glue`) proves the encoder emits
//!   the `MsgDel` inner MID (0x02), not `MsgPut` (0x01) — codec-
//!   level correctness witness.
//!
//! * This integration test proves zenoh-pico's
//!   `_z_network_message_decode` accepts the wire form, the
//!   subscriber's local matcher fires on the keyexpr, and `z_sub`'s
//!   `data_handler` callback receives the sample — interop witness.
//!   Together they pin both ends of the round-trip.
//!
//! z_sub's stock `data_handler` prints the keyexpr + payload but
//! does NOT distinguish the sample kind (`Z_SAMPLE_KIND_DELETE` vs
//! `Z_SAMPLE_KIND_PUT`). The integration test therefore observes the
//! Del as `>> [Subscriber] Received ('demo/test': '')` (empty payload
//! substring). The codec-level witness above is what makes the
//! "this was actually a Del" claim — a Put with empty value would
//! appear identically in z_sub's output but would round-trip as
//! `MsgPut` in the codec witness, not `MsgDel`.
//!
//! Test flow:
//!   1. Pick a free TCP port (PortReservation; common module).
//!   2. Spawn wz-ap-demo --listen 127.0.0.1:<port> --delete
//!      demo/test with RUST_LOG=info; capture stderr.
//!   3. Wait for "listening on" to confirm bind, then drop the port
//!      reservation.
//!   4. Spawn z_sub -k "demo/**" -e tcp/127.0.0.1:<port> -m client
//!      via `stdbuf -oL` (line-buffered stdout — see
//!      `wz_publisher_to_zsub` doc for the buffering gotcha).
//!   5. Wait up to 10s for `>> [Subscriber] Received` AND `demo/test`
//!      AND the empty-payload marker `: '')` to land in z_sub's
//!      stdout.
//!   6. Tear down both children + surface captured streams on failure.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
    PortReservation, Z_SUB_INIT_TIMEOUT,
};

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenoh-pico CLI); Layer E runs via --ignored"]
fn wz_publisher_del_round_trip_against_zenoh_pico_z_sub() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let listen_addr = format!("127.0.0.1:{port}");
    let endpoint = format!("tcp/{listen_addr}");
    // Publisher emits Del on "demo/test"; z_sub subscribes to
    // "demo/**" so the local matcher accepts. Wildcard subscription
    // matches both Put and Del — zenoh-pico's keyexpr matcher
    // does not gate on sample kind.
    let publish_key = "demo/test";
    let sub_key = "demo/**";

    // ── wz-ap-demo (acceptor + Del publisher) ────────────────
    let demo_stderr = tempfile::tempfile().expect("tempfile for demo stderr");
    let demo_stderr_writer = demo_stderr.try_clone().expect("dup demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;

    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--listen --delete)",
        Command::new(&demo)
            .arg("--listen")
            .arg(&listen_addr)
            .arg("--delete")
            .arg(publish_key)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo"),
    );

    let bound = wait_for_substring(
        &mut demo_stderr_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = demo_child.child_mut().kill();
        let _ = demo_child.child_mut().wait();
        panic!(
            "wz-ap-demo did not log 'listening on' within 5s\n\
             --- captured demo stderr ---\n{captured}"
        );
    }
    drop(port_res);

    // ── z_sub (client + subscriber) ──────────────────────────
    let z_sub_stdout = tempfile::tempfile().expect("tempfile for z_sub stdout");
    let z_sub_stdout_writer = z_sub_stdout.try_clone().expect("dup z_sub stdout handle");
    let mut z_sub_stdout_reader = z_sub_stdout;

    let mut z_sub_child = ChildGuard::wrap(
        "z_sub client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub)
            .args(["-k", sub_key, "-e", &endpoint, "-m", "client"])
            .stdout(Stdio::from(z_sub_stdout_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_sub via stdbuf"),
    );

    let session_opening = wait_for_substring(
        &mut z_sub_stdout_reader,
        "Opening session",
        Z_SUB_INIT_TIMEOUT,
    );
    let received_substr = ">> [Subscriber] Received";
    let received = wait_for_substring(
        &mut z_sub_stdout_reader,
        received_substr,
        Duration::from_secs(10),
    );

    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();

    let demo_captured = read_captured(&mut demo_stderr_reader);
    let z_sub_captured = read_captured(&mut z_sub_stdout_reader);
    eprintln!("--- captured wz-ap-demo stderr ---\n{demo_captured}");
    eprintln!("--- captured z_sub stdout ---\n{z_sub_captured}");

    if let Err(c) = &session_opening {
        panic!(
            "z_sub did not log 'Opening session' within 10s — z_sub binary failed to \
             initialize. Captured z_sub stdout:\n{c}\n\
             --- captured demo stderr ---\n{demo_captured}"
        );
    }

    let received_text = match received {
        Ok(c) => c,
        Err(c) => panic!(
            "z_sub did not log '{received_substr}' within 10s — wz-ap-demo Del Push \
             did not reach z_sub's subscriber callback.\n\
             --- captured z_sub stdout at deadline ---\n{c}\n\
             --- captured demo stderr at deadline ---\n{demo_captured}"
        ),
    };

    // Belt-and-suspenders gates. The `received_substr` check
    // already passed; these pin the keyexpr + the empty-payload
    // marker so a regression on either localizes the failure.
    // The empty-payload pattern `: '')` is the wire-shape
    // signature of a MsgDel; pair this with the wz-side codec
    // round-trip unit test (in wz-runtime-tokio::session_glue)
    // to confirm "this was actually a Del", since z_sub's
    // data_handler does not surface z_sample_kind.
    assert!(
        received_text.contains(publish_key),
        "z_sub captured the 'Received' line but the publish keyexpr \
         '{publish_key}' is missing.\n\
         --- captured z_sub stdout ---\n{received_text}"
    );
    assert!(
        received_text.contains(": '')"),
        "z_sub captured the 'Received' line but the empty-payload marker \"': '')\" is \
         missing — the Del wire form should print as \"Received ('demo/test': '')\".\n\
         --- captured z_sub stdout ---\n{received_text}"
    );
}
