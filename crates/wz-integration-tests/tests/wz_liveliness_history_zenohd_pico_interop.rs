// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y354 — `liveliness-history`, witnessed as a REPLAY of a token a real
//! zenoh-pico had already declared, answered by a real zenohd.
//!
//! ## The atom, and the one observable that is only ever its own
//!
//! `liveliness-history` is `history = true` on a liveliness subscriber: the
//! outbound Interest carries the CURRENT bit (wire mode `CurrentFuture`), so the
//! subscriber is replayed the tokens that ALREADY EXIST instead of only those
//! declared from now on. `runner.rs` states the same thing from the demo side:
//! history "makes the subscriber order-independent of token declare time".
//!
//! So the atom's observable is a token declared STRICTLY BEFORE the subscriber
//! existed. That is what these two tests are built around, and it is why the
//! ordering here is the reverse of the usual fixture: pico declares first, on
//! purpose, and wz subscribes late, on purpose.
//!
//! ## Why zenohd is in this topology and pico alone is not
//!
//! R311y353 measured it: `vendor/zenoh-pico/src/session/interest.c:533-535`
//! returns early — "Nothing to do on unicast" — so zenoh-pico NEVER answers an
//! Interest over a unicast transport. A history replay IS an Interest answer, so
//! a wz<->pico unicast witness for this atom is impossible for the same reason
//! `liveliness-get`'s was. zenohd answers; pico originates the token. All three
//! processes are load-bearing.
//!
//! ## The pair, and why the twin is the point
//!
//! A single positive test here would be nearly worthless: `LIVELINESS SAMPLE PUT`
//! is what `liveliness-subscriber` logs for ANY token, future ones included, so a
//! green run would not distinguish "the pre-existing token was replayed" from
//! "some token arrived somehow". The twin is what makes the claim the atom's:
//!
//! - [`wz_liveliness_history_replays_a_zenohd_routed_pico_token`]
//!   — history ON: the sample arrives, carrying pico's exact token.
//! - [`wz_liveliness_without_history_ignores_the_zenohd_routed_token`]
//!   — history OFF, IDENTICAL fixture otherwise: the session Establishes and the
//!   sample never comes.
//!
//! The two differ in one CLI flag. Together they say the replay is caused by
//! `history`, not by the token existing or the subscriber working — which is
//! exactly the claim, and neither test makes it alone. Both arms were measured
//! before this file was written: history ON -> 1 sample, history OFF -> 0.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, spawn_zenohd_on_ephemeral_tcp, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, ChildGuard,
};

/// The literal pico declares, and the exact string the replay must carry. The
/// subscriber's filter is a wildcard, so a sample naming THIS token can only be a
/// real intersect against a real declaration, never an echo of the request.
const PICO_TOKEN: &str = "demo/token/pico";
const SUB_FILTER: &str = "demo/**";

/// How long the twin waits, AFTER wz reports steady state, before concluding the
/// replay never came.
///
/// A negative assertion is only worth its bound, so this one is anchored rather
/// than picked: in the positive arm the sample lands within ~2s of the demo
/// starting, and that arm's own wait below is `SAMPLE_TIMEOUT`. This is longer
/// than that, so the twin cannot pass merely by being asked earlier than its
/// sibling was.
const NO_SAMPLE_WINDOW: Duration = Duration::from_secs(8);
const SAMPLE_TIMEOUT: Duration = Duration::from_secs(20);

/// One arm of the pair: zenohd, then a pico token holder gated on its OWN
/// declaration banner, then wz subscribing with or without history.
///
/// The banner gate is what makes both arms mean anything: it proves the token
/// exists BEFORE wz is spawned, which is the precondition the whole atom is about.
/// A sleep here would leave "the token was late" and "history did nothing" looking
/// identical from the sample side.
fn run_arm(history: bool) -> String {
    let demo = wz_ap_demo_binary();
    let z_liveliness = zenoh_pico_cli_binary("z_liveliness");

    // R311y413 — the port is DISCOVERED from zenohd's own announcement; naming
    // one in advance is what let another process hold it and zenohd exit 255.
    let (mut zenohd, port) = spawn_zenohd_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    let endpoint = format!("tcp/127.0.0.1:{port}");

    let pico_stdout = tempfile::tempfile().expect("tempfile for z_liveliness stdout");
    let pico_stdout_writer = pico_stdout.try_clone().expect("dup z_liveliness handle");
    let mut pico_stdout_reader = pico_stdout;
    let mut pico_child = ChildGuard::wrap(
        "z_liveliness token holder (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_liveliness)
            .args(["-k", PICO_TOKEN, "-e", &endpoint, "-m", "client"])
            .stdout(Stdio::from(pico_stdout_writer))
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn z_liveliness via stdbuf"),
    );

    // z_liveliness prints this AFTER `z_liveliness_declare_token` returns
    // (examples/unix/c11/z_liveliness.c), so it is the token EXISTING, not the
    // process merely starting.
    if let Err(captured) = wait_for_substring(
        &mut pico_stdout_reader,
        "Press CTRL-C to undeclare liveliness token",
        Duration::from_secs(10),
    ) {
        let _ = pico_child.child_mut().kill();
        let _ = zenohd.child_mut().kill();
        panic!(
            "z_liveliness never declared its token within 10s. Neither arm of this pair \
             means anything without it: the positive arm would have nothing to replay and \
             the twin would pass on an empty world.\n\
             --- captured z_liveliness stdout ---\n{captured}"
        );
    }

    let demo_stderr = tempfile::tempfile().expect("tempfile for wz-ap-demo stderr");
    let demo_stderr_writer = demo_stderr.try_clone().expect("dup demo stderr handle");
    let mut demo_stderr_reader = demo_stderr;
    let mut cmd = Command::new(&demo);
    cmd.arg("--connect")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--liveliness-subscribe")
        .arg(SUB_FILTER);
    if history {
        cmd.arg("--liveliness-subscribe-history");
    }
    let mut demo_child = ChildGuard::wrap(
        "wz-ap-demo (--connect zenohd --liveliness-subscribe)",
        cmd.env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr_writer))
            .spawn()
            .expect("spawn wz-ap-demo --liveliness-subscribe"),
    );

    // Both arms gate on steady state before judging. In the twin this is what
    // makes the absence MEAN something: wz connected, Established, and emitted
    // its subscriber's Interest, and the replay still did not come.
    let established = wait_for_substring(
        &mut demo_stderr_reader,
        "session Established; entering steady state",
        Duration::from_secs(15),
    );
    if let Err(captured) = &established {
        let _ = demo_child.child_mut().kill();
        let _ = pico_child.child_mut().kill();
        let _ = zenohd.child_mut().kill();
        panic!(
            "wz-ap-demo never reached steady state against zenohd within 15s, so this arm \
             tested nothing about history.\n--- captured wz-ap-demo stderr ---\n{captured}"
        );
    }

    let expected = format!("LIVELINESS SAMPLE PUT filter='{SUB_FILTER}' keyexpr='{PICO_TOKEN}'");
    let outcome = if history {
        wait_for_substring(&mut demo_stderr_reader, &expected, SAMPLE_TIMEOUT)
    } else {
        // The twin cannot "wait for nothing", so it sleeps its bound and then reads
        // whatever landed. Anything present is a real replay and a real failure.
        std::thread::sleep(NO_SAMPLE_WINDOW);
        Ok(String::new())
    };

    let mut demo_captured = read_captured(&mut demo_stderr_reader);
    if let Ok(seen) = &outcome {
        demo_captured = format!("{seen}{demo_captured}");
    }
    let pico_captured = read_captured(&mut pico_stdout_reader);
    let _ = demo_child.child_mut().kill();
    let _ = demo_child.child_mut().wait();
    let _ = pico_child.child_mut().kill();
    let _ = pico_child.child_mut().wait();
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();

    if history {
        if let Err(captured) = outcome {
            panic!(
                "history=true, and pico's token was NOT replayed. Expected {expected:?} -- \
                 z_liveliness had declared '{PICO_TOKEN}' to zenohd before wz was spawned \
                 (gated on its banner), and wz reached steady state, so neither the token \
                 nor the session can explain this.\n\
                 --- captured wz-ap-demo stderr ---\n{captured}\n\
                 --- captured z_liveliness stdout ---\n{pico_captured}"
            );
        }
    }
    demo_captured
}

// The `zenohd` substring in BOTH function names in this file is load-bearing, not
// cosmetic (R311y356 hotfix): Layer E's catch-all sweep runs every `#[ignore]` test
// EXCEPT those matching `--skip zenohd`, and it filters by FUNCTION NAME, not file
// name. The `ci` job's Layer E does not build zenohd, so a zenohd-dependent test
// whose fn name lacks `zenohd` is swept in and panics at `zenohd_binary()`
// (lib.rs:367). This shipped green on y354 because local run-ci HAS zenohd built, so
// Layer E ran these and passed; hosted CI caught it. Keep `zenohd` in the fn name.
// wz-proves: liveliness-history wz->zenohd
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenohd + zenoh-pico z_liveliness CLI); Layer Z runs via --ignored"]
fn wz_liveliness_history_replays_a_zenohd_routed_pico_token() {
    let captured = run_arm(true);
    let expected = format!("LIVELINESS SAMPLE PUT filter='{SUB_FILTER}' keyexpr='{PICO_TOKEN}'");
    assert!(
        captured.contains(&expected),
        "the replay arrived but not with pico's token -- expected {expected:?}.\n\
         --- captured wz-ap-demo stderr ---\n{captured}"
    );
}

/// The twin, and the arm that makes the claim above the ATOM's rather than the
/// subscriber's. Identical fixture, one flag removed.
///
/// The `none` declaration below is honest, not an omission: this arm witnesses no
/// atom on its own — it witnesses that the sibling's sample is caused by `history`.
/// Declared rather than left silent because A4-4 rejects a silent corpus test, and
/// a silent test makes the proof number under-report.
///
/// (Spelled only in the `//` line, never here: A4 parses the marker token wherever
/// it appears, so naming it in prose reads as a second, malformed declaration.
/// R311y352 hit this and left a warning in its own file; R311y354 hit it anyway.)
// wz-proves: none -- anti-vacuity twin for the history arm above; it shows the
// replay is caused by `history` and not by the token existing, and claims no atom.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo + zenohd + zenoh-pico z_liveliness CLI); Layer Z runs via --ignored"]
fn wz_liveliness_without_history_ignores_the_zenohd_routed_token() {
    let captured = run_arm(false);
    assert!(
        !captured.contains("LIVELINESS SAMPLE"),
        "history=false is FUTURE-ONLY, but a token declared BEFORE the subscriber was \
         replayed anyway. Either the `history` flag no longer gates the CURRENT bit, or \
         the sibling test's green is not evidence of this atom at all -- it would pass \
         with history off too.\n--- captured wz-ap-demo stderr ---\n{captured}"
    );
}
