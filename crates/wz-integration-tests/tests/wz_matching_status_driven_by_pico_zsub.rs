// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y347 — `session-matching`, witnessed by a real zenoh-pico peer.
//!
//! ## Why this test exists
//!
//! `session-matching` is `preset-ap-full` AND `preset-ap-client`, it is wz's
//! parity for pico's `Z_FEATURE_MATCHING` / `z_publisher_declare_matching_listener`
//! — and it carried ZERO cross-impl proof. Its inventory entry carried no reason
//! prose at all, so nothing even claimed what it was.
//!
//! ## What makes pico the witness, and not a bystander
//!
//! This atom is unusual in the corpus: wz does not have to SEND anything for the
//! proof to bind. A matching listener fires on every matching-status TRANSITION
//! caused by an INBOUND remote `Declare(DeclSubscriber)` / `Declare(UndeclSubscriber)`
//! (`Publisher::declare_matching_listener`). So the peer is not a receiver being
//! checked — the peer is the CAUSE, and wz is the thing under test.
//!
//! Both edges are pico's, and pico's alone:
//!
//! * `matching=true`  — `z_declare_subscriber` (z_sub.c) puts a DeclSubscriber on
//!   the wire. wz has no local subscriber here (no `--key`), so nothing else could
//!   have raised it.
//! * `matching=false` — `z_sub -n 1` breaks its loop once one message has landed
//!   and runs `z_drop(z_move(sub))` (z_sub.c:91), which retracts the declaration.
//!   wz observes the UndeclSubscriber and drops the status back.
//!
//! ## Why the burst is held
//!
//! `--publish-after-ms` (R311y345's ordering knob, a pure delay) buys the
//! determinism this test needs. Without it the demo bursts the instant it reaches
//! Established, which can precede pico's DeclSubscriber; pico would then never
//! reach its `-n 1` count, never undeclare, and the `false` edge would never
//! happen. Holding the burst puts pico's declare strictly first. The hold is
//! generous rather than tight — it costs one second of wall time and removes a
//! race, and this file's sibling `wz_keepalive_holds_pico_session.rs` already
//! shows the knob crossing a far wider window.
//!
//! ## Why the assertions are ORDERED, and why the listener line comes first
//!
//! `declare_matching_listener` is TRANSITION-only (pico parity: registration
//! never fires). Two consequences this test is built around:
//!
//! 1. The listener MUST be installed before pico's DeclSubscriber is dispatched,
//!    or the `true` edge is simply missed. The demo installs it pre-drive; the
//!    "DECLARED MATCHING LISTENER" line is this test's proof that it did, and it
//!    is asserted FIRST (R311y338's fixture rule: a fixture owns its own
//!    precondition). With `session-matching` off, `declare_matching_listener`
//!    returns a typed reject and the demo logs a WARN instead — so this assertion
//!    is also the anti-vacuity arm. Without it, a build with the feature off
//!    would simply print no MATCHING STATUS lines, and a test that waited only
//!    for `matching=true` could not tell "the feature is off" from "the
//!    transition has not happened yet". It would time out either way and blame
//!    the wrong thing.
//! 2. `true` then `false` are asserted in that order on a forward-scanning
//!    reader, so the sequence itself is part of the claim: a listener that fired
//!    once and latched would fail the second wait.
//!
//! This test binds to the atom's OWN gated code (`feedback: claim binds to atom
//! code`). `Publisher::declare_matching_listener` is
//! `#[cfg(all(feature = "session-matching", feature = "declare-subscriber"))]`.
//! Its sibling `Publisher::get_matching_status` is gated on `declare-subscriber`
//! ALONE — polling it would prove the registry, not this atom, which is why the
//! demo's knob installs the CALLBACK.
//!
//! Same lane and spawn shape as `wz_batched_frame_to_pico_zsub.rs`.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard, PortReservation,
    Z_SUB_INIT_TIMEOUT,
};

/// How long the demo holds its burst after Established, so pico's declare lands
/// first. See the module doc.
const PUBLISH_HOLD_MS: &str = "1000";

/// Ceiling for each matching edge. Budget for the far edge: the burst starts at
/// PUBLISH_HOLD_MS, pico's `while(1) { ...; sleep(1); }` notices its count up to
/// a second later, then undeclares; the demo's deferred-fire drain runs on the
/// sweep task's 100ms default cadence. Generous by design — a matching-status
/// test that flakes would be worse than no test at all.
const MATCHING_TIMEOUT: Duration = Duration::from_secs(20);

// wz-proves: session-matching pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenoh-pico CLI); Layer E runs via --ignored"]
fn pico_declare_and_undeclare_drive_wz_matching_status_both_ways() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let port_res = PortReservation::pick();
    let listen_addr = format!("127.0.0.1:{}", port_res.port());
    let endpoint = format!("tcp/{listen_addr}");

    let publish_key = "demo/matching";
    let sub_key = "demo/**";
    let publish_value = "pico-drives-the-transition";

    // ── wz-ap-demo (acceptor + publisher + matching listener) ────────────────
    let demo_stderr = tempfile::tempfile().expect("tempfile for demo stderr");
    let demo_stderr_writer = demo_stderr.try_clone().expect("dup demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;

    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--listen --publish --matching-log)",
        Command::new(&demo)
            .arg("--listen")
            .arg(&listen_addr)
            .arg("--publish")
            .arg(publish_key)
            .arg("--value")
            .arg(publish_value)
            .arg("--matching-log")
            .arg("--publish-after-ms")
            .arg(PUBLISH_HOLD_MS)
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

    // ── z_sub (client + subscriber), exiting after ONE message ──────────────
    // `-n 1` is what makes this test a PAIR rather than a single edge: z_sub.c
    // breaks its loop once one message has landed and then `z_drop`s the
    // subscriber, which is the UndeclSubscriber the `false` edge needs.
    // `stdbuf -oL` — z_sub printf's to a pipe are block-buffered by glibc; the
    // sibling tests carry the same guard.
    let z_sub_stdout = tempfile::tempfile().expect("tempfile for z_sub stdout");
    let z_sub_stdout_writer = z_sub_stdout.try_clone().expect("dup z_sub stdout handle");

    let mut z_sub_child = ChildGuard::wrap(
        "z_sub client (zenoh-pico, -n 1)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub)
            .args(["-k", sub_key, "-e", &endpoint, "-m", "client", "-n", "1"])
            .stdout(Stdio::from(z_sub_stdout_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_sub via stdbuf"),
    );

    // ── The anti-vacuity arm, asserted BEFORE either edge: if the listener was
    //    never installed there is nothing to observe, and both waits below would
    //    time out for a reason that has nothing to do with pico.
    //
    //    It is asserted AFTER z_sub spawns, and that is forced, not a preference:
    //    the demo installs the listener at run_demo scope, which it only reaches
    //    once a peer has connected and the session is open. Waiting for the line
    //    before spawning z_sub deadlocks the test against the demo — measured, in
    //    the first run of this file.
    //
    //    The order is still SAFE, and the safety is structural rather than
    //    lucky: an inbound Declare is dispatched by the drive loop, and the drive
    //    loop starts AFTER install_session_handles returns. So pico's
    //    DeclSubscriber can sit in the socket during the gap, but it cannot be
    //    dispatched before the listener that must observe it exists.
    if let Err(captured) = wait_for_substring(
        &mut demo_stderr_reader,
        "DECLARED MATCHING LISTENER",
        Z_SUB_INIT_TIMEOUT,
    ) {
        let _ = demo_child.child_mut().kill();
        let _ = z_sub_child.child_mut().kill();
        panic!(
            "wz-ap-demo never installed a matching listener, so this test proves \
             NOTHING about session-matching (feature off => typed reject + a WARN \
             line)\n--- captured demo stderr ---\n{captured}"
        );
    }

    // ── Edge 1: pico's DeclSubscriber raises the status.
    let rise = format!("MATCHING STATUS keyexpr='{publish_key}' matching=true");
    if let Err(captured) = wait_for_substring(&mut demo_stderr_reader, &rise, Z_SUB_INIT_TIMEOUT) {
        let _ = demo_child.child_mut().kill();
        let _ = z_sub_child.child_mut().kill();
        panic!(
            "pico's z_sub declared a subscriber matching '{publish_key}', but wz's \
             matching listener never reported matching=true. wz has no local \
             subscriber here, so pico's DeclSubscriber is the ONLY thing that could \
             have raised it.\n--- captured demo stderr ---\n{captured}"
        );
    }

    // ── Edge 2: pico's UndeclSubscriber drops it back. This is the half a
    //    single-edge test would miss, and the half that proves wz tracks the
    //    retraction rather than latching on first sight.
    let fall = format!("MATCHING STATUS keyexpr='{publish_key}' matching=false");
    if let Err(captured) = wait_for_substring(&mut demo_stderr_reader, &fall, MATCHING_TIMEOUT) {
        let _ = demo_child.child_mut().kill();
        let _ = z_sub_child.child_mut().kill();
        panic!(
            "wz reported matching=true but never matching=false. pico's z_sub takes \
             one message (-n 1) then z_drop's its subscriber, which puts an \
             UndeclSubscriber on the wire; wz either never saw it or latched the \
             status.\n--- captured demo stderr ---\n{captured}"
        );
    }

    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
}
