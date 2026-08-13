// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y775 — the QUERYABLES Interest, witnessed by a real zenohd deciding
//! whether to tell wz about a real pico queryable.
//!
//! ## The half its sibling could not cover
//!
//! `wz_matching_status_through_zenohd_router` proves the SUBSCRIBERS interest:
//! a pico `z_sub` behind zenohd reaches wz's publisher-side matching listener.
//! That says nothing about the queryable plane, which is a different bit on the
//! wire (`Q` = 0x04, not `S` = 0x02), a different registry
//! (`RemoteQueryableRegistry`), a different feature gate (`declare-queryable`),
//! and a different gate inside the router: `hat/router/queries.rs:255-259`
//! requires `options.queryables()` on a matching face interest before it
//! propagates a queryable declaration, exactly as its pubsub twin requires
//! `options.subscribers()`.
//!
//! So this file swaps one process and one wz surface, and nothing else: pico
//! `z_queryable` instead of `z_sub`, `--querier-matching-log` instead of
//! `--matching-log`.
//!
//! ## Why each of the three processes is load-bearing
//!
//! - **pico `z_queryable`** is the CAUSE. It declares `demo/**` at zenohd; wz
//!   declares no local queryable, so nothing else could raise the status.
//! - **zenohd** is the JUDGE. It holds pico's declaration on one face and
//!   decides, from wz's own interest, whether wz's face hears about it.
//! - **wz** is under test: `Querier::declare_matching_listener` emits the
//!   Interest and the listener reports the transition.
//!
//! ## The log line is the querier's own, on purpose
//!
//! The demo logs `QUERIER MATCHING STATUS` for this plane and `MATCHING STATUS`
//! for the publisher's. A shared prefix would let a run that proved the
//! subscriber plane satisfy a grep meant for this one — the two planes would
//! become indistinguishable from outside, which is precisely the confusion this
//! file exists to remove.
//!
//! ## What a failure here means
//!
//! Reverting `Querier::declare_matching_listener`'s emit makes this time out
//! while its subscriber-plane sibling stays green, which localises the defect to
//! the queryable half rather than to the interest machinery as a whole.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, spawn_zenohd_on_ephemeral_tcp,
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, ChildGuard,
};

/// wz's querier keyexpr — a literal, so the match against pico's wildcard is a
/// real intersect rather than string equality.
const QUERIER_KEY: &str = "demo/matching/queryable";
/// pico's queryable — a wildcard covering the querier's literal.
const QUERYABLE_KEY: &str = "demo/**";

/// Ceiling for the rise. Same budget and same reasoning as the subscriber-plane
/// sibling: wz dials zenohd and Establishes, declares the listener (which emits
/// the Interest), zenohd answers from its CURRENT dump, and the demo's
/// deferred-fire drain runs on the sweep task's 100ms cadence.
const MATCHING_TIMEOUT: Duration = Duration::from_secs(25);

// wz-proves: declare-interest zenohd->wz
#[test]
#[ignore = "binary-dep e2e (zenohd + wz-ap-demo + zenoh-pico CLI); Layer E runs via --ignored"]
fn a_wz_querier_matching_listener_behind_zenohd_learns_of_a_pico_queryable() {
    let demo = wz_ap_demo_binary();
    // R311y776 — see the sibling fixture: a stale demo makes a red here point at
    // the router instead of at the build.
    assert_demo_binary_newer_than_sources(&demo);
    let z_queryable = zenoh_pico_cli_binary("z_queryable");

    let (mut zenohd, port) = spawn_zenohd_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    let endpoint = format!("tcp/127.0.0.1:{port}");

    // ── pico z_queryable (client of zenohd), declaring first ────────────────
    //
    // FIRST on purpose: wz's Interest is CurrentFuture, so either order should
    // work, but declaring first exercises the CURRENT dump — the half that is
    // unreachable without the interest. `stdbuf -oL` because pico's printf to a
    // pipe is block-buffered by glibc.
    let pico_stdout = tempfile::tempfile().expect("tempfile for z_queryable stdout");
    let pico_stdout_writer = pico_stdout.try_clone().expect("dup z_queryable handle");
    let mut pico_stdout_reader = pico_stdout;
    let mut pico_child = ChildGuard::wrap(
        "z_queryable (zenoh-pico, client of zenohd)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_queryable)
            .args(["-k", QUERYABLE_KEY, "-e", &endpoint, "-m", "client"])
            .stdout(Stdio::from(pico_stdout_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_queryable via stdbuf"),
    );

    // z_queryable prints this AFTER `z_declare_queryable` returns
    // (`examples/unix/c11/z_queryable.c:107-116`), so it is the queryable
    // EXISTING at zenohd rather than the process merely starting. Without this
    // gate a timeout later could not distinguish "zenohd withheld the
    // declaration" — the thing under test — from "pico was still starting".
    if let Err(captured) = wait_for_substring(
        &mut pico_stdout_reader,
        "Press CTRL-C to quit",
        Duration::from_secs(10),
    ) {
        let _ = pico_child.child_mut().kill();
        let _ = zenohd.child_mut().kill();
        panic!(
            "z_queryable never declared its queryable within 10s, so this test had \
             nothing for zenohd to withhold or forward.\n\
             --- captured z_queryable stdout ---\n{captured}"
        );
    }

    // ── wz-ap-demo (client of zenohd, querier + matching listener) ──────────
    let demo_stderr = tempfile::tempfile().expect("tempfile for demo stderr");
    let demo_stderr_writer = demo_stderr.try_clone().expect("dup demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect zenohd --querier-matching-log)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--querier-matching-log")
            .arg(QUERIER_KEY)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --querier-matching-log"),
    );

    // ANTI-VACUITY, before the transition: the callback was installed. With
    // `session-matching` (or `declare-queryable`) off the demo WARNs instead,
    // and a test that only waited for the rise would time out and blame the
    // router.
    let declared = wait_for_substring(
        &mut demo_stderr_reader,
        "DECLARED QUERIER MATCHING LISTENER",
        Duration::from_secs(20),
    );
    if let Err(captured) = &declared {
        let _ = demo_child.child_mut().kill();
        let _ = pico_child.child_mut().kill();
        let _ = zenohd.child_mut().kill();
        panic!(
            "wz-ap-demo never declared a querier matching listener, so nothing \
             downstream of it could mean anything.\n\
             --- captured wz-ap-demo stderr ---\n{captured}"
        );
    }

    // THE CLAIM, on the querier's OWN log line so the publisher plane cannot
    // satisfy it.
    let rise = format!("QUERIER MATCHING STATUS keyexpr='{QUERIER_KEY}' matching=true");
    let outcome = wait_for_substring(&mut demo_stderr_reader, &rise, MATCHING_TIMEOUT);

    let demo_captured = read_captured(&mut demo_stderr_reader);
    let pico_captured = read_captured(&mut pico_stdout_reader);
    let _ = demo_child.child_mut().kill();
    let _ = pico_child.child_mut().kill();
    let _ = zenohd.child_mut().kill();

    if let Err(seen) = outcome {
        panic!(
            "wz's QUERIER matching listener never rose behind zenohd within {:?}. A real \
             pico queryable on `{QUERYABLE_KEY}` was declared at the router BEFORE wz \
             connected, and wz queries `{QUERIER_KEY}` which it covers -- so either wz \
             emitted no QUERYABLES interest or zenohd did not answer it.\n\
             --- wz-ap-demo stderr ---\n{seen}{demo_captured}\n\
             --- z_queryable stdout ---\n{pico_captured}",
            MATCHING_TIMEOUT,
        );
    }
}
