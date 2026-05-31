// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Facade-subset behavioural e2e: declare-observer.
//!
//! Drives `wz-e2e-declare-observer` — a binary whose facade dependency
//! pins EXACTLY the `declare-observer` coherent subset (codec-declare,
//! declare-subscriber, declare-queryable, liveliness-token,
//! liveliness-subscriber) — against zenoh-pico's `z_sub`. It proves the
//! inbound-declare OBSERVER plane interoperates on the wire with a
//! foreign implementation when compiled in isolation, the behavioural
//! counterpart of the C4b / C4c `declare-observer` BUILD subset — the
//! LAST matrix entry to gain a behavioural e2e twin.
//!
//! Direction (the inbound-declare MIRROR of the outbound planes; wz is
//! the data SOURCE in pubsub / queryable, here wz is a passive SINK):
//! wz is the acceptor + OBSERVER, zenoh-pico `z_sub` is the client +
//! DECLARER. z_sub (client mode) connects and PROACTIVELY emits its
//! `Declare(DeclSubscriber)` the instant the session is Established —
//! wz sends NO Interest first; the remote-subscriber dispatch in
//! wz-session-core `declare/subscriber.rs` routes any inbound
//! DeclSubscriber into the registry and fires wz's callback
//! unconditionally. wz logs `REMOTE SUBSCRIBER DECLARED`; the test gates
//! on that wz-side witness plus a belt-and-suspenders assertion that the
//! resolved keyexpr literal matches what z_sub declared (proving the
//! peer-keyexpr resolution path carried the literal across the wire).
//!
//! The witness is on the WZ side (its callback's stderr line), so unlike
//! the queryable / zget tests there is no foreign-CLI-stdout capture
//! race to design around — z_sub is long-running (loops until killed)
//! and wz's single long-running process owns the only asserted stream.
//! See `wz_e2e_pubsub_to_zsub.rs` for the per-step harness rationale
//! (port reservation, line-buffered foreign-CLI stdout via stdbuf, the
//! two-stage substring wait, captured-output-on-failure).

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_e2e_declare_observer_binary, zenoh_pico_cli_binary,
    ChildGuard, PortReservation,
};

#[test]
#[ignore = "binary-dep e2e (wz-e2e-declare-observer + zenoh-pico CLI); Layer E2 runs via --ignored"]
fn wz_e2e_declare_observer_round_trip_against_zenoh_pico_z_sub() {
    let bin = wz_e2e_declare_observer_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let port_res = PortReservation::pick();
    let port = port_res.port();
    let listen_addr = format!("127.0.0.1:{port}");
    let endpoint = format!("tcp/{listen_addr}");
    // z_sub declares THIS keyexpr; wz's observer reports the resolved
    // literal, so the test asserts wz saw exactly what z_sub declared.
    // A literal (not a wildcard) keeps the resolved-literal assertion
    // exact — the keyexpr the observer surfaces must echo it byte-for-byte.
    let declare_key = "demo/observe/sensor";

    // ── wz-e2e-declare-observer (acceptor + observer) ─────────
    let bin_stderr = tempfile::tempfile().expect("tempfile for binary stderr");
    let bin_stderr_writer = bin_stderr.try_clone().expect("dup binary stderr handle");
    let mut bin_stderr_reader = bin_stderr;

    let mut bin_child = ChildGuard::wrap(
        "wz-e2e-declare-observer (--listen --observe)",
        Command::new(&bin)
            .arg("--listen")
            .arg(&listen_addr)
            .arg("--observe")
            .arg(declare_key)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(bin_stderr_writer))
            .spawn()
            .expect("spawn wz-e2e-declare-observer"),
    );

    let bound = wait_for_substring(
        &mut bin_stderr_reader,
        "listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = bin_child.child_mut().kill();
        let _ = bin_child.child_mut().wait();
        panic!(
            "wz-e2e-declare-observer did not log 'listening on' within 5s\n\
             --- captured stderr ---\n{captured}"
        );
    }
    drop(port_res);

    // ── z_sub (client + declarer) ────────────────────────────
    // z_sub in client mode connects to wz and declares a subscriber on
    // `declare_key` the instant the session opens — the inbound Declare
    // wz observes. Its stdout is captured only for failure diagnostics;
    // the asserted witness is on the wz side.
    let z_sub_stdout = tempfile::tempfile().expect("tempfile for z_sub stdout");
    let z_sub_stdout_writer = z_sub_stdout.try_clone().expect("dup z_sub stdout handle");
    let mut z_sub_stdout_reader = z_sub_stdout;

    let mut z_sub_child = ChildGuard::wrap(
        "z_sub client (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub)
            .args(["-k", declare_key, "-e", &endpoint, "-m", "client"])
            .stdout(Stdio::from(z_sub_stdout_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_sub via stdbuf"),
    );

    // Gate on wz's observer-callback witness: the inbound DeclSubscriber
    // routed through the drive loop and fired on_subscriber_declared.
    let declared = wait_for_substring(
        &mut bin_stderr_reader,
        "REMOTE SUBSCRIBER DECLARED",
        Duration::from_secs(10),
    );

    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    let _ = bin_child.child_mut().kill();
    let _ = bin_child.child_mut().wait();

    let bin_captured = read_captured(&mut bin_stderr_reader);
    let z_sub_captured = read_captured(&mut z_sub_stdout_reader);
    eprintln!("--- captured wz-e2e-declare-observer stderr ---\n{bin_captured}");
    eprintln!("--- captured z_sub stdout ---\n{z_sub_captured}");

    let declared_text = match declared {
        Ok(c) => c,
        Err(c) => panic!(
            "wz-e2e-declare-observer did not log 'REMOTE SUBSCRIBER DECLARED' within 10s — \
             the foreign z_sub's Declare(DeclSubscriber) did not reach wz's \
             RemoteSubscriberRegistry through the wire dispatch path under the \
             declare-observer subset.\n\
             --- captured wz-e2e-declare-observer stderr at deadline ---\n{c}\n\
             --- captured z_sub stdout at deadline ---\n{z_sub_captured}"
        ),
    };

    // wz's callback logs e.g.
    //   "REMOTE SUBSCRIBER DECLARED observe='demo/observe/sensor' keyexpr='demo/observe/sensor' sub_id=0"
    // Assert the resolved keyexpr literal matches what z_sub declared so
    // a regression in peer-keyexpr resolution or the DeclSubscriber wire
    // shape localises here.
    assert!(
        declared_text.contains(declare_key),
        "wz-e2e-declare-observer captured 'REMOTE SUBSCRIBER DECLARED' but the declared \
         keyexpr '{declare_key}' is missing — the observer fired but the resolved literal \
         drifted from what z_sub declared.\n\
         --- captured wz-e2e-declare-observer stderr ---\n{declared_text}"
    );
    assert!(
        declared_text.contains("keyexpr="),
        "wz-e2e-declare-observer 'REMOTE SUBSCRIBER DECLARED' line lacks the 'keyexpr=' field \
         — the resolved-literal projection regressed.\n\
         --- captured wz-e2e-declare-observer stderr ---\n{declared_text}"
    );
}
