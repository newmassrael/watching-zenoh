// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The rest of zenoh-pico's OWN public-API tests, built against the INTEGRATION header arm
//! (the configuration upstream's integration workflow builds them under: both session-local
//! switches and the admin space on), linked to wz's build of it, and run the way upstream's
//! CMake runs them.
//!
//! `pico_local_delivery_upstream_tests_on_wz` already holds two of the eighteen
//! `tests/z_api_*_test.c`; this file holds the other sixteen. Each program is upstream's text and
//! its own `assert`s are the oracle. What is reproduced from upstream's `CMakeLists.txt` and
//! `tests/api.sh` is the build and the run, not the verdict:
//!
//! * the programs that need no network (`null_drop`, `double_drop`, `bytes`, `encoding`) run
//!   alone, as upstream's `add_test` runs them;
//! * the ones under `BUILD_INTEGRATION` run beside a zenohd and are handed its locator as
//!   `argv[1]`, which is what `api.sh` does;
//! * `advanced_pubsub` and `callback_drop_on_undeclare` are linked with `tests/utils/tcp_proxy.c`
//!   and built with `Z_ADVANCED_PUBSUB_TEST_USE_TCP_PROXY`, as the CMake `if(UNIX)` arm does.
//!
//! Three programs are not run, and each is held by a test of its own that says why. They reach
//! into zenoh-pico's PRIVATE layer: `_z_*` functions the library happens to export, and the
//! fields of its structs (`sample->payload`), which a drop-in whose handles are opaque does not
//! have. `*_reaches_pico_internals_wz_does_not_export` pins the exact set of symbols each one
//! cannot link without, so the day wz exports one the test reds and the program moves to the run
//! list. The control (`WZ_PICO_API_ORACLE=1`, which links the real library) passes `source_info`
//! and `admin_space`; `timestamp` is built upstream against a library compiled with
//! `Z_TEST_HOOKS`, which the control library is not, so it fails the control too.
//!
//! One program carries a correction. `encoding`'s `test_encoding_with_id` checks `e2` after it
//! dropped it, where it means `e4`. The real library passes the unmodified text by accident:
//! `_z_encoding_clear` frees the schema and leaves the id, so a dropped encoding still reads as
//! set (MEASURED: the unmodified program passes against the real library under this arm). wz
//! frees the handle, as an owned value that was dropped should read as empty. The one line is
//! replaced, and the replacement is an exact match, so a changed upstream text reds rather than
//! being skipped.
//!
//! A program built against a header arm that lacks its feature compiles to a stub `main` that
//! prints `Missing config token to build this test` and exits 0. That is a pass nothing ran, so
//! it is refused here: the leg reds and names the missing token.
//!
//! Every name carries `zenohd` so Layer E's `--skip zenohd` sweep leaves the file to Layer Z,
//! which provisions the router, including the programs that need none: the file is one lane.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    compile_pico_program, project_root, spawn_zenohd_multicast_scouting_on_any_interface,
    zenoh_pico_integration_library_dir, PicoHeaderArm,
};

/// How long one upstream program gets. Several walk a matrix with a sleep per cell.
const RUN_BOUND: Duration = Duration::from_secs(400);

/// What upstream's CMake does differently for one target, and the one line of its text a leg
/// replaces.
#[derive(Default)]
struct Build {
    /// Compiled in beside the test (paths under `vendor/zenoh-pico/tests`).
    extra_sources: &'static [&'static str],
    /// `-D` words upstream gives the target.
    defines: &'static [&'static str],
    /// `(found, replacement)`: `found` must occur exactly once in the program.
    correction: Option<(&'static str, &'static str)>,
}

/// The `tests/utils/tcp_proxy.c` arm of upstream's `if(UNIX)`.
const WITH_TCP_PROXY: Build = Build {
    extra_sources: &["utils/tcp_proxy.c"],
    defines: &["Z_ADVANCED_PUBSUB_TEST_USE_TCP_PROXY"],
    correction: None,
};

/// `z_api_timestamp_test` is the one target upstream builds with its test hooks on.
const WITH_TEST_HOOKS: Build = Build {
    extra_sources: &[],
    defines: &["Z_TEST_HOOKS=1"],
    correction: None,
};

/// `test_encoding_with_id` drops `e2` and then checks it, where it means the `e4` just made.
const ENCODING_CHECKS_E4: Build = Build {
    extra_sources: &[],
    defines: &[],
    correction: Some((
        "z_encoding_from_substr(&e4, \"custom_id;custom_schema\", 16);\n    \
         assert(z_internal_encoding_check(&e2));",
        "z_encoding_from_substr(&e4, \"custom_id;custom_schema\", 16);\n    \
         assert(z_internal_encoding_check(&e4));",
    )),
};

/// A program compiled for the integration arm, and the directory that holds it.
struct Compiled {
    exe: PathBuf,
    _dir: tempfile::TempDir,
}

/// Compile upstream's `tests/<name>.c` against the integration arm and link it to wz's build of
/// it, or to the real library when `WZ_PICO_API_ORACLE` is set: the control that says whether a
/// red is wz's or the program's. `Err` carries the compiler's diagnostics.
fn compile_upstream_test(name: &str, build: &Build, against_wz: bool) -> Result<Compiled, String> {
    let tests_dir = project_root().join("vendor/zenoh-pico/tests");
    let upstream = tests_dir.join(format!("{name}.c"));
    assert!(
        upstream.is_file(),
        "upstream {} missing; run `git submodule update --init vendor/zenoh-pico`",
        upstream.display()
    );
    let dir = tempfile::tempdir().expect("tempdir for the compiled test");
    let src = match build.correction {
        None => upstream,
        Some((found, replacement)) => {
            let text = std::fs::read_to_string(&upstream).expect("read the upstream program");
            assert_eq!(
                text.matches(found).count(),
                1,
                "upstream {name}.c no longer has the line this leg corrects exactly once; the \
                 correction is stale"
            );
            let corrected = dir.path().join(format!("{name}.c"));
            std::fs::write(&corrected, text.replacen(found, replacement, 1))
                .expect("write the corrected program");
            corrected
        }
    };
    let extra: Vec<PathBuf> = build
        .extra_sources
        .iter()
        .map(|rel| tests_dir.join(rel))
        .collect();
    let arm = PicoHeaderArm::Integration;
    let (libdir, link) = if against_wz {
        let cdylib = arm.wz_cdylib();
        (
            cdylib.parent().expect("cdylib has a parent").to_path_buf(),
            "wz_capi_pico",
        )
    } else {
        (zenoh_pico_integration_library_dir(), "zenohpico")
    };
    // `utils/assert_helpers.h` and `utils/tcp_proxy.h` are included relative to `tests/`.
    let mut includes: Vec<PathBuf> = arm.include_dirs().to_vec();
    includes.push(tests_dir);
    let exe = compile_pico_program(
        &src,
        &extra,
        build.defines,
        dir.path(),
        &includes,
        &libdir,
        link,
    )?;
    Ok(Compiled { exe, _dir: dir })
}

/// Whether this run links the real library (the control) rather than wz's build.
fn against_wz() -> bool {
    std::env::var_os("WZ_PICO_API_ORACLE").is_none()
}

/// Compile upstream's `tests/<name>.c`, run it (beside a zenohd when `routed`) and require a
/// clean exit that ran a case.
fn run_upstream_test(name: &str, build: &Build, routed: bool) {
    let compiled = compile_upstream_test(name, build, against_wz())
        .unwrap_or_else(|diag| panic!("upstream {name}.c does not link (integration arm)\n{diag}"));
    let out = if routed {
        let (_router, port) = spawn_zenohd_multicast_scouting_on_any_interface(
            "zenohd for an upstream pico API test",
        );
        // `api.sh` runs `"$TESTBIN" "$LOCATOR"`; the programs that read it take `argv[1]`.
        run(&compiled.exe, Some(&format!("tcp/127.0.0.1:{port}")))
    } else {
        run(&compiled.exe, None)
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !text.contains("Missing config token to build this test"),
        "upstream {name}.c compiled to its stub `main`: the integration arm lacks a token it \
         needs, so nothing ran\n{text}"
    );
    assert!(
        out.status.success(),
        "upstream {name}.c failed (status {:?}):\n{text}",
        out.status.code()
    );
}

fn run(exe: &Path, locator: Option<&str>) -> std::process::Output {
    let mut cmd = Command::new(exe);
    if let Some(locator) = locator {
        cmd.arg(locator);
    }
    cmd.output_within(RUN_BOUND)
        .unwrap_or_else(|e| panic!("spawn {}: {e}", exe.display()))
}

/// The names a linker reports as `undefined reference to `NAME'`.
fn undefined_symbols(diag: &str) -> BTreeSet<String> {
    diag.lines()
        .filter_map(|line| {
            let rest = line.split("undefined reference to `").nth(1)?;
            Some(rest.trim_end_matches('\'').to_owned())
        })
        .collect()
}

/// Require that wz's build cannot link `name` for exactly the private symbols `expected` names.
fn assert_needs_only(name: &str, build: &Build, expected: &[&str]) {
    let expected: BTreeSet<String> = expected.iter().map(|s| (*s).to_owned()).collect();
    match compile_upstream_test(name, build, true) {
        Ok(_) => panic!(
            "upstream {name}.c now links against wz: move it to the run list \
             (`upstream_tests!`) and delete its pin"
        ),
        Err(diag) => {
            let got = undefined_symbols(&diag);
            assert_eq!(
                got, expected,
                "upstream {name}.c cannot link for a different set of symbols than the one \
                 pinned; a symbol wz now exports belongs off the list, a new one needs a reading\n\
                 {diag}"
            );
        }
    }
}

/// One `#[test]` per upstream program. `alone` programs need no router; `routed` ones run
/// beside a zenohd.
macro_rules! upstream_tests {
    ($( $kind:ident $fn_name:ident => $prog:literal $(, $build:expr)? ; )+) => {$(
        // wz-proves: none -- upstream's own self-asserting test against wz; the router is the only foreign party
        #[test]
        #[ignore = "builds one of upstream's zenoh-pico API tests and runs it against wz; run by run-ci Layer Z"]
        fn $fn_name() {
            let build = upstream_tests!(@build $($build)?);
            run_upstream_test($prog, &build, upstream_tests!(@routed $kind));
        }
    )+};
    (@build) => { Build::default() };
    (@build $b:expr) => { $b };
    (@routed alone) => { false };
    (@routed routed) => { true };
}

upstream_tests! {
    alone upstreams_null_drop_test_passes_on_wz_in_the_zenohd_lane => "z_api_null_drop_test";
    alone upstreams_double_drop_test_passes_on_wz_in_the_zenohd_lane => "z_api_double_drop_test";
    alone upstreams_bytes_test_passes_on_wz_in_the_zenohd_lane => "z_api_bytes_test";
    alone upstreams_encoding_test_passes_on_wz_in_the_zenohd_lane => "z_api_encoding_test", ENCODING_CHECKS_E4;
    routed upstreams_alignment_test_passes_on_wz_beside_a_zenohd => "z_api_alignment_test";
    routed upstreams_liveliness_test_passes_on_wz_beside_a_zenohd => "z_api_liveliness_test";
    routed upstreams_cancellation_test_passes_on_wz_beside_a_zenohd => "z_api_cancellation_test";
    routed upstreams_matching_test_passes_on_wz_beside_a_zenohd => "z_api_matching_test";
    routed upstreams_connectivity_test_passes_on_wz_beside_a_zenohd => "z_api_connectivity_test";
    routed upstreams_queryable_test_passes_on_wz_beside_a_zenohd => "z_api_queryable_test";
    routed upstreams_advanced_pubsub_test_passes_on_wz_beside_a_zenohd => "z_api_advanced_pubsub_test", WITH_TCP_PROXY;
    routed upstreams_callback_drop_on_undeclare_test_passes_on_wz_beside_a_zenohd => "z_api_callback_drop_on_undeclare_test", WITH_TCP_PROXY;
    routed upstreams_batching_test_passes_on_wz_beside_a_zenohd => "z_api_batching_test";
}

// wz-proves: none -- pins the set of pico-private symbols a program needs that wz does not export
#[test]
#[ignore = "compiles one of upstream's zenoh-pico API tests against wz; run by run-ci Layer Z"]
fn upstreams_source_info_test_reaches_pico_internals_wz_does_not_export_zenohd_lane() {
    // It reads the payload by the private `_z_bytes_*` accessors, off the `_z_sample_t` it is
    // handed as a struct.
    assert_needs_only(
        "z_api_source_info_test",
        &Build::default(),
        &["_z_bytes_len", "_z_bytes_to_buf"],
    );
}

// wz-proves: none -- pins the set of pico-private symbols a program needs that wz does not export
#[test]
#[ignore = "compiles one of upstream's zenoh-pico API tests against wz; run by run-ci Layer Z"]
fn upstreams_admin_space_test_reaches_pico_internals_wz_does_not_export_zenohd_lane() {
    // It builds its keyexprs and collects the replies with pico's private list, slist, string
    // and keyexpr helpers.
    assert_needs_only(
        "z_api_admin_space_test",
        &Build::default(),
        &[
            "_z_keyexpr_append_substr",
            "_z_list_find",
            "_z_list_free",
            "_z_list_len",
            "_z_list_push",
            "_z_slist_len",
            "_z_slist_next",
            "_z_slist_value",
            "_z_strstr",
        ],
    );
}

// wz-proves: none -- pins the set of pico-private symbols a program needs that wz does not export
#[test]
#[ignore = "compiles one of upstream's zenoh-pico API tests against wz; run by run-ci Layer Z"]
fn upstreams_timestamp_test_reaches_pico_internals_wz_does_not_export_zenohd_lane() {
    // It builds a pico session struct itself and overrides pico's clock through a hook that
    // exists only in a library compiled with `Z_TEST_HOOKS`.
    assert_needs_only(
        "z_api_timestamp_test",
        &WITH_TEST_HOOKS,
        &[
            "_z_session_clear",
            "_z_session_generate_zid",
            "_z_session_init",
            "_z_timestamp_cmp",
            "_z_timestamp_ntp64_from_time",
            "_z_timestamp_set_time_since_epoch_override",
        ],
    );
}
