// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y448 — the INERT-reporting gate for the `advanced` / `group` demo flags.
//!
//! `wz-ap-demo` keeps its CLI FEATURE-UNIFORM: `--advanced-subscribe`,
//! `--advanced-publish` and `--group-join` parse in every build, and a build
//! without the atom behind them drops the capability and says so. That is a
//! different contract from `--peer` / `--router`, which REJECT with exit 2 when
//! their feature is absent (`wz_peer_reject_without_feature`), and the difference
//! is deliberate: the reject arm guards a run MODE that would otherwise silently
//! do nothing, while these three are additive roles a demo can legitimately be
//! built without.
//!
//! UNTIL THIS FILE, NOTHING EXERCISED THE INERT BRANCH. The advanced/group legs
//! build `--features advanced` (or `group`) and assert the NEGATIVE
//! `!captured.contains("is INERT")` — 14 of the 15. The exception is
//! `zenoh_ext_cache_refuses_a_get_without_anyke`
//! (`wz_advanced_pubsub_zenoh_ext_interop.rs:900`), the pure-foreign
//! discriminator: it spawns zenohd + the zenoh-ext example + a pico `z_get` and
//! NO wz binary at all, so it neither builds the feature nor asserts the
//! negative. The Layer E catch-all skips that whole family by fn-name substring.
//! So the `#[cfg(not(feature = ...))]` arms in `runner.rs` compiled everywhere
//! and RAN nowhere, while FOUR fixtures' failure messages ("If this says INERT,
//! the demo was built without `--features advanced`") depended on their wording:
//! `wz_advanced_pubsub_zenoh_ext_interop.rs:304`, `:1023`, `:1297` and
//! `wz_group_membership_zenoh_ext_interop.rs:164` — the last squarely inside this
//! round's own advanced/GROUP scope. R311y447-review named the gap after the
//! round widened it by a field; this closes it. (R311y449 corrected both counts:
//! R311y448 wrote "every leg" and "three fixtures".)
//!
//! Like `wz_peer_reject_without_feature`, this needs the DEFAULT binary, so it
//! rides a dedicated run-ci lane that builds that binary immediately before
//! running it. Every TEST fn name here carries the `inert` token so the Layer E
//! catch-all skips it (the helpers `tempfile` and `run_default_demo_with` do not,
//! and need not — only test-fn names reach libtest's `--skip`; R311y448 wrote
//! "every fn name", which its own file did not satisfy).
//!
//! R311y449 — WHY THE SKIP IS THERE, corrected. R311y448 recorded it as
//! necessity: "the Layer E catch-all, whose binary is whichever variant a prior
//! lane last built". That premise is FALSE and has been since R311y265:
//! `layer_e_ap_demo_round_trip` builds the DEFAULT demo ITSELF
//! (`scripts/run-ci.sh:4985`) before its sweep, so these three legs would have
//! PASSED there, not failed. The measurement y448 cited (`--features
//! advanced,group` reds all three) is real but describes a build that lane
//! cannot present. The skip is kept on the honest grounds: it avoids a duplicate
//! run, and keeps three process-spawning legs out of a ~49-test fully-parallel
//! sweep. Contrast `--skip zenoh_ext`, which IS necessary — those legs need
//! `--features advanced` against the sweep's default binary.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, spawn_listen_acceptor, wait_for_substring, wz_ap_demo_binary, ChildGuard,
};

/// How long to wait for a marker before calling the run failed.
const MARKER_TIMEOUT: Duration = Duration::from_secs(20);

fn tempfile() -> std::fs::File {
    tempfile::tempfile().expect("create tempfile")
}

/// Run the DEFAULT-build demo against a wz acceptor with `extra_args`, and return
/// its captured stderr once the session is up and the handles are installed.
///
/// The peer is a second `wz-ap-demo --listen`, so the fixture needs no foreign
/// binary and cannot SKIP. It has to be a real session: the INERT warnings are
/// emitted only after Established, so a run that never connected would produce no
/// line and read as a broken contract.
///
/// TWO emitters, not one (R311y449 — R311y448 named only the first): the
/// `--advanced-subscribe` warning comes from `install_session_handles`
/// (`runner.rs:1057-1068`), while `--group-join` (`:1168-1178`) and
/// `--advanced-publish` (`:1180-1195`) come from `spawn_background_tasks`
/// (`runner.rs:1108-1209`). The barrier below is valid for all three because both
/// functions return before the `"driving session FSM"` line, but this is exactly
/// the doc a future reader would use to reason about that validity.
fn run_default_demo_with(extra_args: &[&str]) -> String {
    let demo = wz_ap_demo_binary();
    let (_acceptor, mut acc_out) = spawn_listen_acceptor(
        &demo,
        "127.0.0.1:0",
        "demo/inert/peer",
        "wz-ap-demo (--listen acceptor)",
        tempfile(),
    );
    let acc_captured = wait_for_substring(&mut acc_out, "listening on 127.0.0.1:", MARKER_TIMEOUT)
        .unwrap_or_else(|snapshot| {
            panic!("the acceptor never announced its port\n--- acceptor ---\n{snapshot}")
        });
    let port = wz_integration_tests::common::listen_port(&acc_captured);

    let stderr = tempfile();
    let writer = stderr.try_clone().expect("dup wz-ap-demo stderr");
    let mut reader = stderr;
    let mut cmd = Command::new(&demo);
    cmd.arg("--connect").arg(format!("127.0.0.1:{port}"));
    for a in extra_args {
        cmd.arg(a);
    }
    let _child = ChildGuard::wrap(
        "wz-ap-demo (default build, INERT flags)",
        cmd.env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo"),
    );

    // Barrier on the line that PROVES the handles were installed, not on a sleep:
    // the INERT warnings are emitted in that same pass, so once this is on the log
    // their absence is a real absence rather than a race.
    wait_for_substring(&mut reader, "driving session FSM", MARKER_TIMEOUT).unwrap_or_else(
        |snapshot| {
            panic!(
                "wz-ap-demo never reached the session-FSM drive, so the pass that \
                 emits the INERT warnings never ran\n--- captured ---\n{snapshot}"
            )
        },
    );
    read_captured(&mut reader)
}

/// Assert `captured` carries an INERT report for `flag` naming `feature`, and
/// that the capability was NOT activated.
fn assert_inert(captured: &str, flag: &str, feature: &str, activation_marker: &str) {
    assert!(
        captured.contains(&format!("{flag}=")),
        "no INERT report mentions {flag}\n--- captured ---\n{captured}"
    );
    assert!(
        captured.contains("is INERT"),
        "the demo did not report {flag} as INERT. Three fixtures' failure messages \
         tell a developer to look for exactly this wording\n--- captured ---\n{captured}"
    );
    // NAMING THE FEATURE is the actionable half. A bare "is INERT" leaves a
    // developer with a silent no-op and no next step, which is what the
    // advanced/group fixtures point at when they fail.
    assert!(
        captured.contains(&format!("built without the `{feature}` feature")),
        "the INERT report for {flag} does not name the missing `{feature}` feature\n\
         --- captured ---\n{captured}"
    );
    // INERT must mean INERT: the flag parsed, and nothing acted on it. The three
    // marker strings exist verbatim — `DECLARED ADVANCED SUBSCRIBER`
    // (`runner.rs:1035`), `DECLARED ADVANCED PUBLISHER` (`tasks.rs:281`) and
    // `JOINED GROUP` (`tasks.rs:191`) — so this is not a negative against a string
    // that never exists.
    //
    // R311y449 — IT IS DECORATIVE, and the honest statement is stronger than
    // R311y448's. Two independent reasons, both verified:
    //   (1) STRUCTURAL. The marker emits sit under `#[cfg(feature = "advanced")]`
    //       / `#[cfg(feature = "group")]` and the INERT emits under the exact
    //       complement, so exactly one arm compiles per binary. No build exists in
    //       which the three assertions above pass AND a marker can appear.
    //   (2) TIMING, for 2 of the 3. `DECLARED ADVANCED PUBLISHER` and `JOINED
    //       GROUP` are logged from spawned tokio tasks, unordered against the
    //       `"driving session FSM"` barrier this fixture reads at; only `DECLARED
    //       ADVANCED SUBSCRIBER` shares the synchronous pass.
    // R311y448 said instead that the `is INERT` assertion "fires first, so this
    // one has never been the sole failure". The conclusion holds but names the
    // wrong assertion: on a feature-ON build the line reads `DECLARED ADVANCED
    // SUBSCRIBER keyexpr=...`, which contains neither needle, so the FIRST
    // assertion (`{flag}=`) is what trips.
    assert!(
        !captured.contains(activation_marker),
        "the demo logged {activation_marker:?} on a build without `{feature}`, so \
         {flag} was not inert at all\n--- captured ---\n{captured}"
    );
}

#[test]
#[ignore = "binary-dep e2e (DEFAULT wz-ap-demo build); run-ci Layer E4i"]
fn advanced_subscribe_is_inert_without_the_advanced_feature() {
    let captured = run_default_demo_with(&["--advanced-subscribe", "demo/inert/x"]);
    assert_inert(
        &captured,
        "--advanced-subscribe",
        "advanced",
        "DECLARED ADVANCED SUBSCRIBER",
    );
    // R311y447-review (REVIEWER 3) — the ignored-options tail is asserted rather
    // than left decorative. `recovery_periodic_ms` was added to this line by
    // R311y447 and reached no gate at all; a field nothing reads is a field that
    // can silently stop being printed.
    for ignored in [
        "history_max=",
        "history_max_age=",
        "recovery=",
        "recovery_heartbeat=",
        "recovery_periodic_ms=",
    ] {
        assert!(
            captured.contains(ignored),
            "the INERT report drops {ignored:?} from the options it says it is \
             ignoring, so a caller cannot see what was discarded\n\
             --- captured ---\n{captured}"
        );
    }
}

#[test]
#[ignore = "binary-dep e2e (DEFAULT wz-ap-demo build); run-ci Layer E4i"]
fn advanced_publish_is_inert_without_the_advanced_feature() {
    let captured =
        run_default_demo_with(&["--advanced-publish", "demo/inert/y", "--value", "INERTVAL"]);
    assert_inert(
        &captured,
        "--advanced-publish",
        "advanced",
        "DECLARED ADVANCED PUBLISHER",
    );
    // The publisher's tail carries the burst parameters; `value` is the one a
    // caller most needs echoed, since a dropped publish is otherwise invisible.
    assert!(
        captured.contains("value='INERTVAL'"),
        "the INERT report does not echo the discarded --value\n\
         --- captured ---\n{captured}"
    );
}

#[test]
#[ignore = "binary-dep e2e (DEFAULT wz-ap-demo build); run-ci Layer E4i"]
fn group_join_is_inert_without_the_group_feature() {
    let captured = run_default_demo_with(&["--group-join", "inertgroup"]);
    assert_inert(&captured, "--group-join", "group", "JOINED GROUP");
    assert!(
        captured.contains("member_id="),
        "the INERT report does not echo the discarded member id\n\
         --- captured ---\n{captured}"
    );
}
