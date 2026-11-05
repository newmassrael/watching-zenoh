// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! zenoh-c's OWN tests (`tests/z_api_*.c`, `z_int_*.c`, `z_leak_*.c`), built against upstream's
//! header, linked to wz's `libwz_capi_c`, and run the way its `tests/CMakeLists.txt` and CI run
//! them.
//!
//! Each program is upstream's text and its own `assert`s are the oracle. What is reproduced from
//! `CMakeLists.txt` is the build (C11 with the GNU extensions CMake leaves on, `ZENOHC_DYN_LIB`
//! for the shared library, `-pthread`, `tests/` on the include path) and the selection of which
//! targets exist: `z_api_shm_test` only where the header carries `Z_FEATURE_SHARED_MEMORY` and
//! `Z_FEATURE_UNSTABLE_API`, and the three programs of the unstable API (`advanced_pub_sub`,
//! `pub_cache_query_sub`, `cancellation_token`) only where it carries the latter; on a header
//! without them CMake does not build the target, and neither does this. The programs open their
//! own sessions over loopback TCP with scouting off, so no router is needed.
//!
//! The control (`WZ_ZENOHC_API_ORACLE=1`) links the real `libzenohc` instead of wz's library: it
//! says whether a red is wz's or the program's. Run it first when a leg reds.
//!
//! Not run, and why:
//!
//! * `z_api_alignment_test` -- upstream's own CI excludes it from both of its runs
//!   (`ctest -E "(unit_z_api_alignment_test|...)"`, `.github/workflows/ci.yml`): it counts the
//!   Hellos a multicast scout hears and asserts exactly one, which holds only on a host with
//!   precisely one zenoh node on the group. The real library aborts it on a quiet host too.
//! * `z_build_shared`, `z_build_static` -- checks of how CMake built the target (`ZENOHC_DYN_LIB`
//!   defined or not), not of the library.
//!
//! The leak programs run under `valgrind` through upstream's `run_leak_check.sh`, as CMake runs
//! them where valgrind exists. Where it does not they say so and return; `WZ_C1CC_REQUIRE` makes
//! that a failure, for the job that is meant to have it.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    compile_zenoh_c_upstream_test, project_root, wz_capi_c_cdylib, zenoh_c_oracle,
    zenoh_c_shared_library,
};

/// How long one upstream program gets. `cancellation_token` and `info` take 20 to 35 s on the
/// real library, and a leak program under valgrind is several times slower than that.
const RUN_BOUND: Duration = Duration::from_secs(600);

/// The oracle's three parts and the tests directory beside its examples.
struct Oracle {
    include: PathBuf,
    tests_dir: PathBuf,
}

/// The oracle, at the pinned version, or `None` with a loud note when it is absent. A checkout at
/// another version is a failure and not an absence: it is a different upstream than this tree
/// pins, which is what `scripts/install-zenoh-c.sh` refuses too.
fn oracle() -> Option<Oracle> {
    let Some((include, _libdir, examples)) = zenoh_c_oracle() else {
        let note = "the zenoh-c ORACLE is absent (headers, libzenohc.so and the clone of \
                    zenoh-c: `bash scripts/install-zenoh-c.sh`)";
        assert!(
            std::env::var_os("WZ_C1CC_REQUIRE").is_none(),
            "{note}; WZ_C1CC_REQUIRE is set, so this is a failure"
        );
        eprintln!("skip: {note}");
        return None;
    };
    let checkout = examples
        .parent()
        .expect("the examples directory has a parent")
        .to_path_buf();
    static PINNED: OnceLock<()> = OnceLock::new();
    PINNED.get_or_init(|| {
        let pin = std::fs::read_to_string(project_root().join("scripts/zenoh-c-oracle.pin"))
            .expect("read the zenoh-c oracle pin");
        let pinned = pin
            .lines()
            .find_map(|line| line.strip_prefix("ZENOH_C_VERSION="))
            .expect("the pin names ZENOH_C_VERSION")
            .trim()
            .to_owned();
        let checked_out = std::fs::read_to_string(checkout.join("version.txt"))
            .unwrap_or_default()
            .trim()
            .to_owned();
        assert_eq!(
            checked_out,
            pinned,
            "the zenoh-c checkout at {} is not the pinned version, so its tests are not the ones \
             this tree pins; move it as scripts/install-zenoh-c.sh says",
            checkout.display()
        );
    });
    Some(Oracle {
        include,
        tests_dir: checkout.join("tests"),
    })
}

/// Whether the oracle's own header has the feature `name` (`#define Z_FEATURE_...`).
fn header_has(oracle: &Oracle, name: &str) -> bool {
    let text = std::fs::read_to_string(oracle.include.join("zenoh_configure.h"))
        .expect("read the oracle's zenoh_configure.h");
    text.lines()
        .any(|line| line.trim() == format!("#define {name}"))
}

/// Whether this run links the real library (the control) rather than wz's.
fn against_wz() -> bool {
    std::env::var_os("WZ_ZENOHC_API_ORACLE").is_none()
}

/// The features of the header a program needs for CMake to build it at all.
#[derive(Clone, Copy)]
struct Needs(&'static [&'static str]);

/// Compile upstream's `tests/<name>.c` and run it. `leak` runs it under valgrind through
/// upstream's script.
fn run_upstream_test(name: &str, needs: Needs, leak: bool) {
    let Some(oracle) = oracle() else {
        return;
    };
    if let Some(missing) = needs.0.iter().find(|f| !header_has(&oracle, f)) {
        eprintln!(
            "not built: upstream's CMake does not build {name} where the header lacks {missing}, \
             and this header does"
        );
        return;
    }
    if leak && !valgrind_present() {
        let note = format!("valgrind is absent, so {name} cannot run as upstream's CMake runs it");
        assert!(
            std::env::var_os("WZ_C1CC_REQUIRE").is_none(),
            "{note}; WZ_C1CC_REQUIRE is set, so this is a failure"
        );
        eprintln!("skip: {note}");
        return;
    }
    let (libdir, link) = if against_wz() {
        let cdylib = wz_capi_c_cdylib();
        (
            cdylib.parent().expect("cdylib has a parent").to_path_buf(),
            "wz_capi_c",
        )
    } else {
        let real = zenoh_c_shared_library().expect("the real libzenohc is installed");
        (
            real.parent().expect("libzenohc has a parent").to_path_buf(),
            "zenohc",
        )
    };
    let dir = tempfile::tempdir().expect("tempdir for the compiled test");
    let exe = compile_zenoh_c_upstream_test(
        name,
        dir.path(),
        &oracle.include,
        &oracle.tests_dir,
        &libdir,
        link,
    )
    .unwrap_or_else(|diag| panic!("upstream {name}.c does not link against -l{link}\n{diag}"));
    let out = if leak {
        let script = oracle.tests_dir.join("run_leak_check.sh");
        Command::new("bash")
            .arg(&script)
            .arg(&exe)
            .output_within(RUN_BOUND)
    } else {
        Command::new(&exe).output_within(RUN_BOUND)
    }
    .unwrap_or_else(|e| panic!("run {name}: {e}"));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "upstream {name}.c failed against -l{link} (status {:?}):\n{text}",
        out.status.code()
    );
}

fn valgrind_present() -> bool {
    Command::new("valgrind")
        .arg("--version")
        .output_bounded()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The header features of the programs CMake builds only on the unstable API, and on shared
/// memory beside it.
const UNSTABLE: Needs = Needs(&["Z_FEATURE_UNSTABLE_API"]);
const SHM: Needs = Needs(&["Z_FEATURE_SHARED_MEMORY", "Z_FEATURE_UNSTABLE_API"]);
const ALWAYS: Needs = Needs(&[]);

/// One `#[test]` per upstream program. `capi_c` is in every name so that the sweep of Layer E,
/// which `--skip`s it, leaves the file to Layer C1cc, which provisions the oracle.
macro_rules! upstream_tests {
    ($( $kind:ident $fn_name:ident => $prog:literal, $needs:expr ; )+) => {$(
        // wz-proves: none -- upstream's own self-asserting test against wz; nothing foreign is needed
        #[test]
        #[ignore = "builds one of upstream's zenoh-c tests and runs it against wz; run by run-ci Layer C1cc"]
        fn $fn_name() {
            run_upstream_test($prog, $needs, upstream_tests!(@leak $kind));
        }
    )+};
    (@leak plain) => { false };
    (@leak leak) => { true };
}

upstream_tests! {
    plain upstreams_config_test_passes_on_wz_capi_c => "z_api_config_test", ALWAYS;
    plain upstreams_constants_test_passes_on_wz_capi_c => "z_api_constants", ALWAYS;
    plain upstreams_double_drop_test_passes_on_wz_capi_c => "z_api_double_drop_test", ALWAYS;
    plain upstreams_drop_options_test_passes_on_wz_capi_c => "z_api_drop_options", ALWAYS;
    plain upstreams_encoding_test_passes_on_wz_capi_c => "z_api_encoding_test", ALWAYS;
    plain upstreams_keyexpr_drop_test_passes_on_wz_capi_c => "z_api_keyexpr_drop_test", ALWAYS;
    plain upstreams_keyexpr_test_passes_on_wz_capi_c => "z_api_keyexpr_test", ALWAYS;
    plain upstreams_null_drop_test_passes_on_wz_capi_c => "z_api_null_drop_test", ALWAYS;
    plain upstreams_payload_test_passes_on_wz_capi_c => "z_api_payload_test", ALWAYS;
    plain upstreams_unitinialized_check_passes_on_wz_capi_c => "z_api_unitinialized_check", ALWAYS;
    plain upstreams_info_test_passes_on_wz_capi_c => "z_api_info", ALWAYS;
    plain upstreams_liveliness_test_passes_on_wz_capi_c => "z_api_liveliness", ALWAYS;
    plain upstreams_session_test_passes_on_wz_capi_c => "z_api_session_test", ALWAYS;
    plain upstreams_cancellation_token_test_passes_on_wz_capi_c => "z_api_cancellation_token_test", UNSTABLE;
    plain upstreams_shm_test_passes_on_wz_capi_c => "z_api_shm_test", SHM;
    plain upstreams_int_helpers_test_passes_on_wz_capi_c => "z_int_helpers_test", ALWAYS;
    plain upstreams_int_pub_sub_test_passes_on_wz_capi_c => "z_int_pub_sub_test", ALWAYS;
    plain upstreams_int_pub_sub_attachment_test_passes_on_wz_capi_c => "z_int_pub_sub_attachment_test", ALWAYS;
    plain upstreams_int_queryable_test_passes_on_wz_capi_c => "z_int_queryable_test", ALWAYS;
    plain upstreams_int_queryable_attachment_test_passes_on_wz_capi_c => "z_int_queryable_attachment_test", ALWAYS;
    plain upstreams_int_advanced_pub_sub_test_passes_on_wz_capi_c => "z_int_advanced_pub_sub_test", UNSTABLE;
    plain upstreams_int_pub_cache_query_sub_test_passes_on_wz_capi_c => "z_int_pub_cache_query_sub_test", UNSTABLE;
    leak upstreams_leak_pub_sub_test_passes_on_wz_capi_c => "z_leak_pub_sub_test", ALWAYS;
    leak upstreams_leak_queryable_get_test_passes_on_wz_capi_c => "z_leak_queryable_get_test", ALWAYS;
}
