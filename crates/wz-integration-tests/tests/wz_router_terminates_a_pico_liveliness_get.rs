// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y778 — the `DeclareFinal` R311y773 added, witnessed by the ONE requester
//! in either upstream that observably waits for it.
//!
//! ## Why this fixture exists, and why it is not the one R311y773 imagined
//!
//! R311y773 closed a real gap: `RouteTable::record_interest` returned on
//! `!body.su()` before emitting anything, so a CURRENT interest naming any kind
//! but SUBSCRIBERS got no terminator. It then named the victim as a queryable
//! interest, and R311y777 retracted that by reading both upstreams:
//!
//! * pico's write filter — what `z_declare_querier` installs — lets
//!   `_Z_INTEREST_MSG_TYPE_FINAL` fall into `default: break;`
//!   (`src/net/filtering.c:198-223`) and recomputes its state from
//!   `ctx->targets`, which a Final never touches.
//! * zenoh's Rust session handles `DeclareFinal` by removing an entry from
//!   `state.liveliness_queries` and nothing else
//!   (`zenoh/src/api/session.rs:2713-2718`).
//! * the ONE consumer that acts is pico's liveliness query:
//!   `_z_liveliness_process_declare_final` unregisters the pending query by
//!   interest id (`src/session/liveliness.c:248-252`).
//!
//! So the plane that waits is the LIVELINESS GET, and this is its witness.
//!
//! ## What is asserted is a DURATION, and that is the honest shape
//!
//! `z_liveliness_get` with default options takes `Z_GET_TIMEOUT_DEFAULT`
//! (10_000 ms, `include/zenoh-pico/config.h.in:208`), so an unterminated query
//! does not hang forever — it waits out its own timeout and then completes.
//! That is exactly the corrected claim, and it makes the discriminator a clock
//! rather than a hang: WITH the Final the get finishes promptly; WITHOUT it the
//! same fixture takes the full ten seconds.
//!
//! The bound below is deliberately far from BOTH ends: comfortably above the
//! sub-second completion a terminated query shows, and comfortably below pico's
//! 10s fallback, so neither a slow machine nor a fast timeout can flip it.
//!
//! ## Why the router must carry `routing-routes`
//!
//! `--router` alone holds faces and forwards nothing (`NoOpForwarder`);
//! `routing-routes` installs the `RoutingForwarder` whose `RouteTable` owns
//! `record_interest` — the function under test. A run against the NoOp build
//! would prove nothing and look identical.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard, PortReservation,
};

/// The keyexpr pico asks about. No token exists anywhere in this fixture, and
/// that is the point: the get's CORRECT answer is "none", delivered by the
/// terminator. A fixture with a live token would be testing the reply path
/// instead, and would complete for a reason that is not this one.
const GET_KEY: &str = "demo/**";

/// How long the get may take. pico's own fallback is 10s; a terminated query
/// completes in well under one. Five sits between them with room on both sides.
const COMPLETION_BOUND: Duration = Duration::from_secs(5);

// wz-proves: declare-final pico->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenoh-pico CLI); Layer E runs via --ignored"]
fn a_wz_router_terminates_a_pico_liveliness_get_instead_of_letting_it_time_out() {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let z_get_liveliness = zenoh_pico_cli_binary("z_get_liveliness");
    let port_res = PortReservation::pick();
    let listen_addr = format!("127.0.0.1:{}", port_res.port());
    let endpoint = format!("tcp/{listen_addr}");

    // ── wz-ap-demo in ROUTER mode, with the RouteTable forwarder ────────────
    let demo_stderr = tempfile::tempfile().expect("tempfile for demo stderr");
    let demo_stderr_writer = demo_stderr.try_clone().expect("dup demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--router, routing-routes)",
        Command::new(&demo)
            .arg("--router")
            .arg(&listen_addr)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --router"),
    );

    let bound = wait_for_substring(
        &mut demo_stderr_reader,
        "router: listening on",
        Duration::from_secs(10),
    );
    if let Err(captured) = &bound {
        let _ = demo_child.child_mut().kill();
        panic!(
            "wz-ap-demo never bound its router socket within 10s. Without a router \
             there is no RouteTable and nothing for this test to be about (was the \
             binary built with --features routing-router,routing-routes?).\n\
             --- captured wz-ap-demo stderr ---\n{captured}"
        );
    }
    drop(port_res);

    // ── pico's liveliness GET, timed ────────────────────────────────────────
    let pico_stdout = tempfile::tempfile().expect("tempfile for z_get_liveliness stdout");
    let pico_stdout_writer = pico_stdout.try_clone().expect("dup pico handle");
    let mut pico_stdout_reader = pico_stdout;
    let started = Instant::now();
    let mut pico_child = ChildGuard::wrap(
        "z_get_liveliness (zenoh-pico, client of the wz router)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_get_liveliness)
            .args(["-k", GET_KEY, "-e", &endpoint, "-m", "client"])
            .stdout(Stdio::from(pico_stdout_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_get_liveliness via stdbuf"),
    );

    // The get's completion IS its process exit: `z_get_liveliness` blocks in
    // `z_recv` on a FIFO handler until the query is dropped, and the query is
    // dropped either by the terminator or by its own timeout. So the clock is
    // read on `wait()`, not on a printed line -- there is no "done" print to
    // grep, and inventing one would mean patching the upstream example.
    let elapsed = loop {
        match pico_child.child_mut().try_wait() {
            Ok(Some(_)) => break started.elapsed(),
            Ok(None) => {
                if started.elapsed() > COMPLETION_BOUND {
                    break started.elapsed();
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("waiting on z_get_liveliness failed: {e}"),
        }
    };

    let pico_captured = read_captured(&mut pico_stdout_reader);
    let demo_captured = read_captured(&mut demo_stderr_reader);
    let _ = pico_child.child_mut().kill();
    let _ = demo_child.child_mut().kill();

    // ANTI-VACUITY: the get must have actually been SENT. Without this line the
    // process could have exited early for any reason -- a failed session open,
    // a bad keyexpr -- and the duration would look like a pass.
    assert!(
        pico_captured.contains("Sending liveliness query"),
        "z_get_liveliness never sent its query, so its exit time says nothing \
         about the terminator.\n--- z_get_liveliness stdout ---\n{pico_captured}\n\
         --- wz-ap-demo stderr ---\n{demo_captured}"
    );

    assert!(
        elapsed < COMPLETION_BOUND,
        "pico's liveliness GET took {elapsed:?}, at or past the {COMPLETION_BOUND:?} \
         bound -- which is what it does when the router never terminates the \
         interest: it waits out Z_GET_TIMEOUT_DEFAULT (10s) instead. wz's \
         RouteTable::record_interest is supposed to answer a CURRENT interest of \
         ANY kind with a DeclareFinal.\n--- z_get_liveliness stdout ---\n{pico_captured}\n\
         --- wz-ap-demo stderr ---\n{demo_captured}"
    );
}
