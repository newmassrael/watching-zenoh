// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y774 — the SUBSCRIBERS Interest built at R311y771, witnessed by a real
//! zenohd deciding whether to tell wz anything at all.
//!
//! ## What this test is for, and why the existing matching witness cannot do it
//!
//! `wz_matching_status_driven_by_pico_zsub.rs` already proves wz's matching
//! listener fires from a real pico declaration — but the two are DIRECTLY
//! peered there, and a pico peer pushes its declarations unsolicited. That
//! topology cannot see the defect R311y771 closed, because nothing in it ever
//! consults an interest.
//!
//! A zenoh ROUTER does. `hat/router/pubsub.rs:120-125` forwards a subscriber
//! declaration to a destination face only when that face's own
//! `remote_interests` holds one with `options.subscribers()` matching the
//! resource. Until R311y771 every Interest wz emitted carried `TO` and only
//! `TO`, so a wz face behind zenohd was told about NO remote subscriber, ever —
//! silently, with no error on any side. Putting zenohd between the two peers is
//! the whole point of this file: it is the one topology in which the interest is
//! load-bearing.
//!
//! ## Why each of the three processes is load-bearing
//!
//! - **pico `z_sub`** is the CAUSE. It declares `demo/**` at zenohd; wz declares
//!   no local subscriber, so nothing else could raise the status.
//! - **zenohd** is the JUDGE. It holds pico's declaration on one face and
//!   decides, from wz's own interest, whether wz's face hears about it.
//! - **wz** is under test: `Publisher::declare_matching_listener` emits the
//!   Interest and the listener reports the transition.
//!
//! ## The anti-vacuity arm is the `DECLARED MATCHING LISTENER` line
//!
//! With `session-matching` off the demo logs a WARN instead of installing the
//! callback, and then a test that waited only for `matching=true` could not tell
//! "the feature is absent" from "the transition has not happened yet" — it would
//! time out either way and blame the wrong thing. So the listener line is
//! asserted FIRST, on a forward-scanning reader, as this fixture's own
//! precondition.
//!
//! ## What a failure here means
//!
//! Reverting `Publisher::declare_matching_listener`'s emit (or pointing it back
//! at the token builder) makes this test time out waiting for `matching=true`,
//! while `wz_matching_status_driven_by_pico_zsub` — the direct-peer sibling —
//! stays green. That difference IS the claim: the interest matters exactly when
//! a router is in the path.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, spawn_zenohd_on_ephemeral_tcp, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard,
};

/// wz's publisher keyexpr — a literal, so the match against pico's wildcard is a
/// real intersect rather than string equality.
const PUBLISH_KEY: &str = "demo/matching/routed";
/// pico's subscription — a wildcard covering the publisher's literal.
const SUB_KEY: &str = "demo/**";

/// Ceiling for the rise. Budget: wz dials zenohd and Establishes, declares the
/// listener (which emits the Interest), zenohd answers from its CURRENT dump,
/// and the demo's deferred-fire drain runs on the sweep task's 100ms cadence.
/// Generous rather than tight — a matching-status test that flakes would be
/// worse than no test at all, and the same reasoning sets the sibling's bound.
const MATCHING_TIMEOUT: Duration = Duration::from_secs(25);

// wz-proves: declare-interest zenohd->wz
#[test]
#[ignore = "binary-dep e2e (zenohd + wz-ap-demo + zenoh-pico CLI); Layer E runs via --ignored"]
fn a_wz_matching_listener_behind_zenohd_learns_of_a_pico_subscriber() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");

    // R311y413 — the port is DISCOVERED from zenohd's own announcement; naming
    // one in advance is what let another process hold it and zenohd exit 255.
    let (mut zenohd, port) = spawn_zenohd_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    let endpoint = format!("tcp/127.0.0.1:{port}");

    // ── pico z_sub (client of zenohd), declaring the subscription first ──────
    //
    // FIRST on purpose. wz's Interest is CurrentFuture, so either order should
    // work — but declaring first exercises the CURRENT dump, which is the half
    // that was completely unreachable before R311y771. `stdbuf -oL` because
    // z_sub's printf to a pipe is block-buffered by glibc; every sibling test
    // carries the same guard.
    let z_sub_stdout = tempfile::tempfile().expect("tempfile for z_sub stdout");
    let z_sub_stdout_writer = z_sub_stdout.try_clone().expect("dup z_sub stdout handle");
    let mut z_sub_stdout_reader = z_sub_stdout;
    let mut z_sub_child = ChildGuard::wrap(
        "z_sub subscriber (zenoh-pico, client of zenohd)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub)
            .args(["-k", SUB_KEY, "-e", &endpoint, "-m", "client"])
            .stdout(Stdio::from(z_sub_stdout_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_sub via stdbuf"),
    );

    // z_sub prints this AFTER `z_declare_subscriber` returns, so it is the
    // subscription EXISTING at zenohd rather than the process merely starting.
    // Without this gate a timeout later could not distinguish "zenohd withheld
    // the declaration" — the thing under test — from "pico was still starting".
    if let Err(captured) = wait_for_substring(
        &mut z_sub_stdout_reader,
        "Press CTRL-C to quit",
        Duration::from_secs(10),
    ) {
        let _ = z_sub_child.child_mut().kill();
        let _ = zenohd.child_mut().kill();
        panic!(
            "z_sub never declared its subscription within 10s, so this test had \
             nothing for zenohd to withhold or forward.\n\
             --- captured z_sub stdout ---\n{captured}"
        );
    }

    // ── wz-ap-demo (client of zenohd, publisher + matching listener) ─────────
    let demo_stderr = tempfile::tempfile().expect("tempfile for demo stderr");
    let demo_stderr_writer = demo_stderr.try_clone().expect("dup demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect zenohd --publish --matching-log)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--publish")
            .arg(PUBLISH_KEY)
            .arg("--value")
            .arg("routed-matching")
            .arg("--matching-log")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect --matching-log"),
    );

    // ANTI-VACUITY, asserted before the transition: the callback was installed.
    // With `session-matching` off this line is absent and the demo WARNs, and a
    // test that only waited for `matching=true` would time out and blame the
    // router.
    let declared = wait_for_substring(
        &mut demo_stderr_reader,
        "DECLARED MATCHING LISTENER",
        Duration::from_secs(20),
    );
    if let Err(captured) = &declared {
        let _ = demo_child.child_mut().kill();
        let _ = z_sub_child.child_mut().kill();
        let _ = zenohd.child_mut().kill();
        panic!(
            "wz-ap-demo never declared a matching listener, so nothing downstream \
             of it could mean anything (session-matching off, or the connect \
             failed).\n--- captured wz-ap-demo stderr ---\n{captured}"
        );
    }

    // THE CLAIM. Before R311y771 wz registered no SUBSCRIBERS interest, so
    // zenohd had no reason to forward pico's declaration to wz's face and this
    // wait timed out.
    let rise = format!("MATCHING STATUS keyexpr='{PUBLISH_KEY}' matching=true");
    let outcome = wait_for_substring(&mut demo_stderr_reader, &rise, MATCHING_TIMEOUT);

    let demo_captured = read_captured(&mut demo_stderr_reader);
    let pico_captured = read_captured(&mut z_sub_stdout_reader);
    let _ = demo_child.child_mut().kill();
    let _ = z_sub_child.child_mut().kill();
    let _ = zenohd.child_mut().kill();

    if let Err(seen) = outcome {
        panic!(
            "wz's matching listener never rose behind zenohd within {:?}. A real pico \
             subscriber on `{SUB_KEY}` was declared at the router BEFORE wz connected, \
             and wz publishes `{PUBLISH_KEY}` which it covers -- so either wz emitted no \
             SUBSCRIBERS interest (the R311y771 defect) or zenohd did not answer it.\n\
             --- wz-ap-demo stderr ---\n{seen}{demo_captured}\n\
             --- z_sub stdout ---\n{pico_captured}",
            MATCHING_TIMEOUT,
        );
    }
}
