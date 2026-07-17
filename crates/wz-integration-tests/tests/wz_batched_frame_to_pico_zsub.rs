// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y345 — `transport-batching`, witnessed by a real zenoh-pico peer.
//!
//! ## Why this test exists
//!
//! `transport-batching` is tagged COMPLETE on the A3 implementation axis — "a
//! REAL measured TX buffer ... No residual", host-tested, default feature — and
//! carried ZERO cross-impl proof. That combination is precisely what the north
//! star cares about: the batching is BUILT and nobody had ever checked that the
//! frame it produces is one a foreign implementation can read.
//!
//! It is not a hypothetical worry. wz's batcher is deliberately STRICTER than
//! the pico primary it mirrors (its own reason: pico "blind-appends mixed
//! reliability" where wz enforces zenoh's CurrentFrame/NewFrame homogeneity), so
//! the two ends do NOT agree by construction — exactly the case where only a
//! real peer settles it.
//!
//! ## What makes pico the witness, and not a bystander
//!
//! With a batch window open, every Push is ABSORBED into one open T_MID_FRAME
//! (`SessionLinkActions::batch_start`, the `zp_start_batching` parity) until the
//! window closes. So the burst's [`BURST_COUNT`] Pushes reach the wire as ONE
//! frame carrying a message CHAIN — not one frame each. Nothing drains that
//! buffer in between: not the 200ms cadence, only a flush, a conduit change, or
//! an MTU overflow.
//!
//! pico must therefore walk that chain to its end to surface every Push. If wz's
//! chain is malformed — a wrong length, a bad SN, a stray header — pico stops at
//! the break and delivers FEWER than [`BURST_COUNT`]. The assertion is a COUNT
//! for exactly that reason: "at least one arrived" would pass on a decoder that
//! read the first message and gave up, which is the defect this exists to catch.
//!
//! ## The anti-vacuity arm
//!
//! A count of [`BURST_COUNT`] receipts is only evidence of chain-walking if the
//! burst really was ONE frame. Unbatched, the same 5 Pushes arrive as 5 frames
//! and pico prints the same 5 lines — indistinguishable at the subscriber. So
//! the demo's own "opened a TX batch window" / "closed the TX batch window"
//! lines are asserted FIRST, in order: they bracket the burst, and while the
//! window is open the sends CANNOT have left as separate frames. R311y338's
//! fixture rule — the precondition is OWNED here, not inferred from the count.
//!
//! Verified RED before it was believed (R311y345), and the number is the point:
//! dropping ONE byte from the flushed chain makes z_sub surface **4 of 5** — not
//! 0. pico walks the chain, decodes four messages, and stops at the truncated
//! fifth. So a `wait_for_substring("Received")` — "at least one arrived" —
//! PASSES that corrupted frame. Only the count catches it. That is why this
//! test counts, and it is measured rather than reasoned.
//!
//! ## Lane
//!
//! Layer E (`--ignored`, binary-dep: wz-ap-demo + the zenoh-pico CLI), the same
//! lane and spawn shape as `wz_publisher_to_zsub.rs`.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard, PortReservation,
    Z_SUB_INIT_TIMEOUT,
};

/// The demo's `PUBLISHER_BURST_COUNT` (wz-ap-demo/src/tasks.rs). Restated rather
/// than imported — the demo is a spawned BINARY here, not a dependency, so there
/// is nothing to import from. If the demo's burst changes, this test fails on
/// the count and the mismatch is the message, which is the honest failure.
const BURST_COUNT: usize = 5;

/// Ceiling for the batched frame to land and z_sub to print every message in it.
/// The burst spans 5 x 200ms inside the window, so the flush cannot start before
/// ~1s.
const BATCH_TIMEOUT: Duration = Duration::from_secs(15);

// wz-proves: transport-batching wz->pico
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenoh-pico CLI); Layer E runs via --ignored"]
fn pico_walks_the_whole_message_chain_of_a_wz_batched_frame() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let port_res = PortReservation::pick();
    let listen_addr = format!("127.0.0.1:{}", port_res.port());
    let endpoint = format!("tcp/{listen_addr}");

    let publish_key = "demo/batched";
    let sub_key = "demo/**";
    let publish_value = "one-frame-many-messages";

    // ── wz-ap-demo (acceptor + publisher, burst wrapped in a batch window) ───
    let demo_stderr = tempfile::tempfile().expect("tempfile for demo stderr");
    let demo_stderr_writer = demo_stderr.try_clone().expect("dup demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;

    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--listen --publish --batch)",
        Command::new(&demo)
            .arg("--listen")
            .arg(&listen_addr)
            .arg("--publish")
            .arg(publish_key)
            .arg("--value")
            .arg(publish_value)
            .arg("--batch")
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
    // `stdbuf -oL` — z_sub printf's to a pipe are block-buffered by glibc; the
    // sibling tests carry the same guard.
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

    // ── The anti-vacuity arm, asserted BEFORE the count. These two lines
    //    bracket the burst: while the window between them is open the Pushes
    //    CANNOT leave as separate frames. Without them, 5 receipts would be
    //    indistinguishable from the ordinary one-frame-per-Push path and this
    //    test would prove nothing about batching.
    if let Err(captured) = wait_for_substring(
        &mut demo_stderr_reader,
        "opened a TX batch window",
        Z_SUB_INIT_TIMEOUT,
    ) {
        let _ = demo_child.child_mut().kill();
        let _ = z_sub_child.child_mut().kill();
        panic!(
            "wz-ap-demo never opened a batch window, so the burst went out as \
             separate frames and this test proves NOTHING about batching\n\
             --- captured demo stderr ---\n{captured}"
        );
    }
    if let Err(captured) = wait_for_substring(
        &mut demo_stderr_reader,
        "closed the TX batch window",
        BATCH_TIMEOUT,
    ) {
        let _ = demo_child.child_mut().kill();
        let _ = z_sub_child.child_mut().kill();
        panic!(
            "wz-ap-demo never closed the batch window, so the batched frame was \
             never flushed to the wire\n\
             --- captured demo stderr ---\n{captured}"
        );
    }

    // ── The proof: pico surfaced EVERY message in the chain, not just the
    //    first. A decoder that stopped at a malformed boundary would deliver
    //    fewer, which is why this counts rather than merely matching.
    let deadline = std::time::Instant::now() + BATCH_TIMEOUT;
    let captured = loop {
        let captured = wz_integration_tests::common::read_captured(&mut z_sub_stdout_reader);
        if captured.matches(publish_value).count() >= BURST_COUNT {
            break captured;
        }
        if std::time::Instant::now() >= deadline {
            let demo_log = wz_integration_tests::common::read_captured(&mut demo_stderr_reader);
            let seen = captured.matches(publish_value).count();
            let _ = demo_child.child_mut().kill();
            let _ = z_sub_child.child_mut().kill();
            panic!(
                "z_sub surfaced {seen} of {BURST_COUNT} messages from wz's batched \
                 frame.\n\
                 All {BURST_COUNT} Pushes rode ONE frame as a message chain, so a \
                 short count means pico stopped walking it — wz's chain is not one \
                 pico can read to the end. (0 of {BURST_COUNT} = the frame was \
                 rejected outright.)\n\
                 --- captured z_sub stdout ---\n{captured}\n\
                 --- captured demo stderr ---\n{demo_log}"
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        captured.contains(publish_key),
        "z_sub surfaced the payloads but not the keyexpr '{publish_key}'\n\
         --- captured z_sub stdout ---\n{captured}"
    );
}
