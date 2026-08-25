// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y355 — `session-reconnect`, witnessed against a FOREIGN router that was
//! restarted underneath a live wz session.
//!
//! ## The atom, and the observable that is only ever its own
//!
//! `session-reconnect` is the long-lived supervisor
//! (`open_session_with_reconnect`) that, on link loss, re-dials and REPLAYS the
//! declaration cache (`replay_declarations`) so the surviving session resumes
//! against the new link. The existing wz-only e2e (`session_reconnect_e2e.rs`)
//! proves the replay against a wz acceptor; this one proves it against a real
//! zenohd, which is the cross-impl half no wz<->wz test can reach.
//!
//! The observable is engineered so that ONLY a reconnect-plus-replay can produce
//! it: two DIFFERENT keyexprs, `demo/pre` before the sever and `demo/post` after,
//! both under the subscriber's `demo/**` filter. `demo/post` is published to a
//! FRESH zenohd process (a same-port respawn of the one that was killed), which
//! has no memory of wz's subscription. For wz to receive `demo/post` at all, its
//! `demo/**` subscription must have been REPLAYED to that fresh router after the
//! supervisor re-dialled it. So a `SUBSCRIBER FIRED ... keyexpr='demo/post'` line
//! is the replay, foreign-observed.
//!
//! ## Why the twin is not optional here
//!
//! The trap this round nearly shipped: with `--reconnect` REMOVED, a naive read
//! says wz dies on link loss and `demo/post` never arrives — so a positive-only
//! test looks sufficient. It is not obviously so, and "structurally cannot" is a
//! claim. The twin runs the identical fixture without `--reconnect` and asserts
//! `demo/post` never fires (measured: the non-reconnect demo exits on link loss,
//! `record_established_at` stays 1). Only the pair says the resumption is caused
//! by the supervisor and not by some incidental survival of the link.
//!
//! (A methodology note that belongs in the file it bit: the hand-verification of
//! this pair was first run by killing a shell subprocess wrapping zenohd rather
//! than zenohd itself. zenohd stayed alive, the "fresh" respawn never bound, and
//! BOTH arms received `demo/post` — which read exactly like a vacuous twin and
//! would have condemned a correct design. Killing the real PID and confirming the
//! death is why the pair discriminates. The Rust fixture below spawns zenohd as a
//! direct `Command` child, so `ChildGuard`'s kill targets the process itself.)

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_zenohd, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard, PortReservation,
};

const SUB_FILTER: &str = "demo/**";
const PRE_KEY: &str = "demo/pre";
const POST_KEY: &str = "demo/post";

/// Retry budget for landing a put through the freshly-respawned router. The
/// supervisor re-dials on a ~1s cadence and the replay follows the next
/// Established, so the window is a few seconds; this covers it generously without
/// being a bare sleep — each attempt checks the witness and stops the moment it
/// lands.
const PUT_ATTEMPTS: usize = 40;
const PUT_INTERVAL: Duration = Duration::from_millis(600);

/// One `z_put` from a pico client against the router on `port`. Returns whether
/// the CLI exited 0; a put that cannot connect (router mid-respawn) is a normal
/// retry, not a failure.
fn pico_put(port: u16, key: &str, value: &str) -> bool {
    let z_put = zenoh_pico_cli_binary("z_put");
    Command::new(&z_put)
        .args([
            "-k",
            key,
            "-v",
            value,
            "-e",
            &format!("tcp/127.0.0.1:{port}"),
            "-m",
            "client",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run one arm of the pair. `reconnect` toggles the single flag under test; the
/// fixture is otherwise identical, which is what makes the two arms a controlled
/// comparison. Returns wz's captured stderr after teardown.
fn run_arm(reconnect: bool) -> String {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let port = port_res.port();

    // ── zenohd #1: the foreign router wz first attaches to.
    let mut zenohd1 = spawn_zenohd(port, || {
        tempfile::tempfile().expect("tempfile for zenohd#1 probe stderr")
    });

    // ── wz-ap-demo: a subscriber on demo/**, optionally reconnect-supervised.
    let wz_stderr = tempfile::tempfile().expect("tempfile for wz stderr");
    let wz_writer = wz_stderr.try_clone().expect("dup wz stderr handle");
    let mut wz_reader = wz_stderr;
    let mut cmd = Command::new(&demo);
    cmd.arg("--connect")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--key")
        .arg(SUB_FILTER);
    if reconnect {
        cmd.arg("--reconnect");
    }
    let mut wz = ChildGuard::wrap(
        "wz-ap-demo subscriber (--connect zenohd --key demo/**)",
        cmd.env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(wz_writer))
            .spawn()
            .expect("spawn wz-ap-demo --key"),
    );

    // Gate on the lifecycle actually chosen: the reconnect arm logs the
    // supervised-open line, the twin logs the one-shot steady-state line. Waiting
    // on the right one proves the arm took the path it claims.
    let established_marker = if reconnect {
        "reconnect-supervised session Established"
    } else {
        "session Established; entering steady state"
    };
    if let Err(captured) =
        wait_for_substring(&mut wz_reader, established_marker, Duration::from_secs(10))
    {
        let _ = wz.child_mut().kill();
        let _ = zenohd1.child_mut().kill();
        panic!(
            "wz never reached {established_marker:?} against zenohd within 10s.\n\
             --- captured wz stderr ---\n{captured}"
        );
    }

    // ── baseline: a pre-sever put must reach wz, proving the subscription routes
    //    at all before anything is disturbed.
    let mut pre_landed = false;
    for _ in 0..PUT_ATTEMPTS {
        pico_put(port, PRE_KEY, "x");
        if wait_for_substring(
            &mut wz_reader,
            &format!("keyexpr='{PRE_KEY}'"),
            PUT_INTERVAL,
        )
        .is_ok()
        {
            pre_landed = true;
            break;
        }
    }
    if !pre_landed {
        let captured = read_captured(&mut wz_reader);
        let _ = wz.child_mut().kill();
        let _ = zenohd1.child_mut().kill();
        panic!(
            "the pre-sever put on {PRE_KEY} never reached wz, so the fixture proved nothing \
             about reconnect -- the subscription did not route even before the sever.\n\
             --- captured wz stderr ---\n{captured}"
        );
    }

    // ── SEVER: kill zenohd#1 and reap it. wz's link drops. port_res is STILL
    //    held so no other in-process test can grab the freed port in the gap.
    let _ = zenohd1.child_mut().kill();
    let _ = zenohd1.child_mut().wait();

    // ── RESPAWN zenohd#2 on the SAME port: a fresh process with no knowledge of
    //    wz's subscription. Anything it routes to wz was re-declared to it.
    let mut zenohd2 = spawn_zenohd(port, || {
        tempfile::tempfile().expect("tempfile for zenohd#2 probe stderr")
    });
    drop(port_res);

    // ── the discriminating observable: a post-sever put on a DIFFERENT keyexpr,
    //    retried until it lands (reconnect arm) or the budget is spent (twin).
    let mut post_landed = false;
    for _ in 0..PUT_ATTEMPTS {
        pico_put(port, POST_KEY, "y");
        if wait_for_substring(
            &mut wz_reader,
            &format!("keyexpr='{POST_KEY}'"),
            PUT_INTERVAL,
        )
        .is_ok()
        {
            post_landed = true;
            break;
        }
    }

    // ── teardown. The reconnect arm is SIGTERM'd so the supervisor drains and
    //    logs its reconnect count; the twin has usually exited already.
    graceful_terminate(wz.child_mut(), Duration::from_secs(5));
    let _ = zenohd2.child_mut().kill();
    let _ = zenohd2.child_mut().wait();

    // `wait_for_substring` CONSUMES the reader, so the pre/post witness lines are
    // no longer in the tail `read_captured` returns. Encode the landings as
    // explicit boolean markers the assertions match, and append the tail (which
    // carries the `reconnects=` line logged at graceful shutdown) for both the
    // corroborating assertion and the diagnostics.
    let mut result = String::new();
    if pre_landed {
        result.push_str("PRE_LANDED\n");
    }
    if post_landed {
        result.push_str("POST_LANDED\n");
    }
    result.push_str(&read_captured(&mut wz_reader));
    result
}

// wz-proves: session-reconnect wz->zenohd
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenohd restart + zenoh-pico z_put CLI); Layer Z runs via --ignored"]
fn wz_reconnect_resumes_subscription_against_a_respawned_zenohd() {
    let captured = run_arm(true);
    assert!(
        captured.contains("POST_LANDED"),
        "wz did not receive the post-sever put on {POST_KEY}. It was published to a FRESH \
         zenohd that only routes what wz re-declared, so this means the supervisor did not \
         re-dial and replay the subscription.\n--- captured wz stderr ---\n{captured}"
    );
    assert!(
        captured.contains("reconnects=1"),
        "wz received the replayed data but its supervisor did not report reconnects=1 at \
         teardown -- the resumption did not go through exactly one reconnect.\n\
         --- captured wz stderr ---\n{captured}"
    );
}

/// The twin, and the arm that makes the claim above the ATOM's rather than the
/// subscriber's. Identical fixture, `--reconnect` removed.
///
/// The `none` declaration below is honest, not an omission: this arm witnesses no
/// atom on its own — it witnesses that the sibling's `demo/post` receipt is caused
/// by the reconnect supervisor. A4-4 rejects a silent corpus test.
///
/// (Spelled only in the `//` line, never here: A4 parses the marker token wherever
/// it appears. R311y352 and R311y354 both hit this in prose; noted so R311y355 is
/// the round that stops.)
// The `zenohd` substring in this fn name is load-bearing (R311y356 hotfix): Layer E's
// catch-all filters `#[ignore]` tests by FUNCTION NAME via `--skip zenohd`, and the
// `ci` job's Layer E has no zenohd, so a zenohd-dependent test whose fn name lacks
// `zenohd` is swept in and panics at `zenohd_binary()`. The POSITIVE arm above already
// carries `zenohd`; this twin did not until y356. Keep it.
// wz-proves: none -- anti-vacuity twin: without --reconnect the same fixture never
// delivers demo/post, so the sibling's receipt is the reconnect, not survival.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenohd restart + zenoh-pico z_put CLI); Layer Z runs via --ignored"]
fn wz_without_reconnect_does_not_resume_after_the_zenohd_respawns() {
    let captured = run_arm(false);
    assert!(
        captured.contains("PRE_LANDED"),
        "the twin's baseline pre-sever put on {PRE_KEY} never landed, so its negative result \
         below is vacuous -- it must first prove the subscription routed at all.\n\
         --- captured wz stderr ---\n{captured}"
    );
    assert!(
        !captured.contains("POST_LANDED"),
        "a non-reconnect wz received the post-respawn put on {POST_KEY}. Either the demo now \
         reconnects without --reconnect, or the sibling's green is not evidence of \
         session-reconnect at all -- it would pass with the flag off.\n\
         --- captured wz stderr ---\n{captured}"
    );
}
