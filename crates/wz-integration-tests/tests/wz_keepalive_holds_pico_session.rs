// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y345 — `transport-keepalive`, witnessed by a real zenoh-pico peer.
//!
//! ## Why this test exists
//!
//! `transport-keepalive` had a dozen host-side tests (`session_keepalive_tx.rs`,
//! `session_fsm_lease_deadline.rs`, ...) and ZERO cross-impl proof, while its
//! codec sibling `codec-keep-alive` was proven against pico by
//! `layer3_keep_alive.rs`'s byte-parity. That is the sibling-asymmetry shape:
//! the BYTES were checked against pico and the BEHAVIOUR never was. A KeepAlive
//! frame that is byte-perfect but emitted too late keeps nothing alive, and no
//! test in this tree could tell the difference.
//!
//! ## What makes pico the witness, and not a bystander
//!
//! The assertion does not read a wz counter. It rests on pico's OWN lease
//! timer — foreign code wz cannot influence:
//!
//!   * wz-ap-demo advertises `lease_ms: 10_000` (wz-ap-demo/src/args.rs) and
//!     emits KeepAlive every `lease / LEASE_EXPIRE_FACTOR`, factor 3
//!     (wz-session-core/src/lease.rs) — so roughly every 3.3s.
//!   * pico expires a line silent for the adopted lease. wz's factor of 3 is
//!     itself transcribed from pico's `Z_TRANSPORT_LEASE_EXPIRE_FACTOR`
//!     (lease.rs:15 cites pico's CMakeLists), so the two agree on the shape.
//!   * The demo therefore holds its Put burst for [`IDLE_MS`] after Established
//!     via `--publish-after-ms`. That window is WIDER than the 10s lease and
//!     spans ~4 KeepAlive emissions.
//!
//! If wz's KeepAlive is absent or late, pico tears the session down at ~10s and
//! the Put at 14s reaches a dead socket — `z_sub` never prints it. Nothing in
//! wz asserts that; pico's timer does.
//!
//! ## The anti-vacuity arm, and why the wait alone is not enough
//!
//! A `wait_for_substring` that merely takes 14s to succeed would ALSO pass if
//! the burst fired at t=0 — the idle window would never have opened and the
//! lease would never have been at risk. So the demo's own "holding the burst" /
//! "idle window elapsed" lines are asserted FIRST, in order: the test refuses to
//! conclude anything about keepalive until it has confirmed the line really was
//! silent across a lease. R311y338's fixture rule — the precondition is OWNED
//! here, not borrowed from a timing coincidence.
//!
//! Verified RED before it was believed (R311y345): with the KeepAlive emit
//! suppressed in `session_actions`, z_sub receives nothing and the final
//! assertion fires with pico's session already gone. That failure IS the proof;
//! the green is only its other half.
//!
//! ## Lane
//!
//! Layer E (`--ignored`, binary-dep: wz-ap-demo + the zenoh-pico CLI) — the same
//! lane and prereq as its `wz_publisher_to_zsub.rs` sibling, whose spawn shape
//! this mirrors. ~17s wall clock: the lease window is real time and cannot be
//! compressed without a demo lease knob, which does not exist and is not worth
//! inventing for one test.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
    PortReservation, Z_SUB_INIT_TIMEOUT,
};

/// Idle window between Established and the Put burst. MUST exceed the demo's
/// advertised `lease_ms` (10_000) or the session is never at risk and the test
/// proves nothing. 14s leaves margin on both sides: enough that a slow runner
/// cannot make the window fall short of the lease, and enough that ~4 KeepAlive
/// emissions (one per ~3.3s) land inside it.
const IDLE_MS: u64 = 14_000;

/// Ceiling for the post-idle witness: the idle window itself plus the burst and
/// z_sub's print.
const PUT_TIMEOUT: Duration = Duration::from_secs(IDLE_MS / 1000 + 8);

// wz-proves: transport-keepalive wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenoh-pico CLI); Layer E runs via --ignored"]
fn wz_keepalive_holds_a_pico_session_open_across_the_lease() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let port_res = PortReservation::pick();
    let listen_addr = format!("127.0.0.1:{}", port_res.port());
    let endpoint = format!("tcp/{listen_addr}");

    let publish_key = "demo/keepalive";
    let sub_key = "demo/**";
    let publish_value = "held-across-the-lease";

    // ── wz-ap-demo (acceptor + publisher, burst held past the lease) ─────────
    let demo_stderr = tempfile::tempfile().expect("tempfile for demo stderr");
    let demo_stderr_writer = demo_stderr.try_clone().expect("dup demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;

    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--listen --publish --publish-after-ms)",
        Command::new(&demo)
            .arg("--listen")
            .arg(&listen_addr)
            .arg("--publish")
            .arg(publish_key)
            .arg("--value")
            .arg(publish_value)
            .arg("--publish-after-ms")
            .arg(IDLE_MS.to_string())
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

    // ── z_sub (client + subscriber) ─────────────────────────────────────────
    // `stdbuf -oL` — z_sub printf's to a pipe are block-buffered by glibc, so
    // without it the "Received" line can sit in the child's buffer past every
    // timeout here. The sibling tests carry the same guard.
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

    // ── The anti-vacuity arm, asserted BEFORE the payload. These two lines, in
    //    order, are what separate "the session survived a real idle window" from
    //    "the burst fired at once and nothing was ever at risk". Without them a
    //    green here would be indistinguishable from a test that proves nothing.
    if let Err(captured) = wait_for_substring(
        &mut demo_stderr_reader,
        "holding the burst",
        Z_SUB_INIT_TIMEOUT,
    ) {
        let _ = demo_child.child_mut().kill();
        let _ = z_sub_child.child_mut().kill();
        panic!(
            "wz-ap-demo never entered the idle window, so the lease was never at \
             risk and this test proves NOTHING about keepalive\n\
             --- captured demo stderr ---\n{captured}"
        );
    }
    // This is the arm the RED proof actually fired (R311y345): with the
    // KeepAlive emit suppressed, the demo does not merely fail to deliver — its
    // session is TERMINATED at exactly the 10s lease and the process is gone
    // before it can log the elapsed window. So the honest message names that
    // cause first; `ActionTrace { .. send_keep_alive: 0 .. }` in the capture
    // below is what distinguishes it from a demo that died for another reason.
    if let Err(captured) =
        wait_for_substring(&mut demo_stderr_reader, "idle window elapsed", PUT_TIMEOUT)
    {
        let _ = demo_child.child_mut().kill();
        let _ = z_sub_child.child_mut().kill();
        panic!(
            "wz-ap-demo never finished the {IDLE_MS}ms idle window. If the capture \
             below ends in 'session ended: Terminated' roughly 10s after \
             Established, that IS the keepalive failure: the peer expired wz's \
             silent line at the adopted lease. Check `send_keep_alive` in the \
             action trace — 0 emits over a 14s window is the defect, not a flake.\n\
             --- captured demo stderr ---\n{captured}"
        );
    }

    // ── The proof. pico held the session across a lease-width silence, so it
    //    still has a live line to deliver this Put on. Had wz's KeepAlive not
    //    arrived, pico's own lease timer closed the session ~4s ago.
    for needle in ["Received", publish_key, publish_value] {
        if let Err(captured) = wait_for_substring(&mut z_sub_stdout_reader, needle, PUT_TIMEOUT) {
            let demo_log = read_captured(&mut demo_stderr_reader);
            let _ = demo_child.child_mut().kill();
            let _ = z_sub_child.child_mut().kill();
            panic!(
                "z_sub never saw '{needle}' after a {IDLE_MS}ms idle window.\n\
                 pico expires a silent line at the adopted lease (10s), so the \
                 session it needed to deliver this Put on is gone — wz's KeepAlive \
                 did not hold it open.\n\
                 --- captured z_sub stdout ---\n{captured}\n\
                 --- captured demo stderr ---\n{demo_log}"
            );
        }
    }
}
