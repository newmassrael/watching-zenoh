// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! zenoh-pico's OWN tests of its session-local delivery, built against the local header
//! arm and linked to wz's build of that arm, run against a real zenohd.
//!
//! `tests/z_api_local_subscriber_test.c` and `tests/z_api_local_queryable_test.c` are
//! upstream's witnesses for `Z_FEATURE_LOCAL_SUBSCRIBER` and `Z_FEATURE_LOCAL_QUERYABLE`.
//! Each walks all 27 combinations of a put's (a get's) `allowed_destination` and two
//! subscribers' (queryables') `allowed_origin`, one in the putting session and one in a
//! second session, and asserts which of them received what: a local leg exactly when the
//! two localities admit session-local traffic, a remote leg exactly when they admit remote.
//! The programs are upstream's text, unmodified; their `assert`s are the oracle. Both open
//! their sessions with `z_config_default`, a client that finds its router by multicast
//! scouting, hence the zenohd.
//!
//! The names carry `zenohd` so Layer E's `--skip zenohd` sweep leaves them to Layer Z,
//! which provisions the router (open-debt item 914).

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    compile_pico_source, project_root, spawn_zenohd_multicast_scouting_on_any_interface,
    PicoHeaderArm,
};

/// How long one upstream program gets: each combination sleeps about two seconds, and
/// the queryable program walks its 27 twice over.
const RUN_BOUND: Duration = Duration::from_secs(400);

/// Compile upstream's `tests/<name>.c` against the local arm, link wz's build of it, run
/// it beside a zenohd, and require a clean exit.
fn run_upstream_test(name: &str) {
    let src = project_root().join(format!("vendor/zenoh-pico/tests/{name}.c"));
    assert!(
        src.is_file(),
        "upstream {} missing; run `git submodule update --init vendor/zenoh-pico`",
        src.display()
    );
    let dir = tempfile::tempdir().expect("tempdir for the compiled test");
    let arm = PicoHeaderArm::Local;
    let cdylib = arm.wz_cdylib();
    let libdir = cdylib.parent().expect("cdylib has a parent").to_path_buf();
    let exe = compile_pico_source(
        &src,
        dir.path(),
        &arm.include_dirs(),
        &libdir,
        "wz_capi_pico",
    )
    .unwrap_or_else(|diag| {
        panic!("upstream {name}.c does not link against wz's local-arm build\n{diag}")
    });
    let (_router, _port) =
        spawn_zenohd_multicast_scouting_on_any_interface("zenohd for an upstream local test");
    let out = run(&exe);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "upstream {name}.c failed on wz (status {:?}):\n{text}",
        out.status.code()
    );
    assert!(
        text.contains("Testing"),
        "upstream {name}.c ran no case, so it compiled its stub `main`: the local arm's \
         header did not reach it\n{text}"
    );
}

fn run(exe: &Path) -> std::process::Output {
    Command::new(exe)
        .output_within(RUN_BOUND)
        .unwrap_or_else(|e| panic!("spawn {}: {e}", exe.display()))
}

// wz-proves: none -- upstream's own self-asserting test against wz; the router is the only foreign party
#[test]
#[ignore = "builds upstream's local-subscriber test and runs it beside a zenohd; run by run-ci Layer Z"]
fn upstreams_local_subscriber_test_passes_on_wz_beside_a_zenohd() {
    run_upstream_test("z_api_local_subscriber_test");
}

// wz-proves: none -- upstream's own self-asserting test against wz; the router is the only foreign party
#[test]
#[ignore = "builds upstream's local-queryable test and runs it beside a zenohd; run by run-ci Layer Z"]
fn upstreams_local_queryable_test_passes_on_wz_beside_a_zenohd() {
    run_upstream_test("z_api_local_queryable_test");
}
