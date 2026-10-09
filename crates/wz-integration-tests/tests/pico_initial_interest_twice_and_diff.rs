// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! §5.27 `api-compat-pico` -- a zenoh peer that dials a pico LISTENER is told, as it connects, that
//! what it was sent is everything the listener holds; compiled once against the real zenoh-pico and
//! once against wz, dialled by the same real zenoh-c peer, and compared line for line.
//!
//! ## What this exists to catch
//!
//! A zenoh peer's `z_open` does not return before the node it dialled has ended the declarations it
//! replays with the `DeclareFinal` of the initial interest (id 0); without it the open runs out
//! `scouting/delay` and logs "Scouting delay elapsed before start conditions are met". zenoh-pico
//! sends that Final: `_z_interest_push_declarations_to_peer` ends with it
//! (`vendor/zenoh-pico/src/session/interest.c` @ `z_result_t _z_interest_push_declarations_to_peer(`)
//! and runs for every peer link a pico PEER adds, accepted (`transport/unicast/accept.c`) and opened
//! (`transport/manager.c`) alike. The wz pico ABI sent none, so a zenoh-c peer dialling its listener
//! waited the half second out.
//!
//! The observable is the dialler's own log line and not a time: the real pico's accept task answers
//! a handshake some 375 ms after the dial, so the two libraries do not take the same milliseconds
//! to open and a bound on the time would grade pico's cadence. What is compared is whether the
//! delay ran out. The dialler's `scouting/delay` is 4 s and not the shipped 500 ms for the same
//! reason: with the shipped one the real pico's slow accept sometimes lost the race on a loaded
//! host (measured, the first run of this row), and a reference that is racy grades nothing.
//!
//! ## The oracle is a build product, and this row belongs to the lane that provisions it
//!
//! `libzenohpico.so` and the zenoh-c library come from `scripts/build-zenoh-pico-cli.sh` and the
//! zenoh-c build. The dialler is a real zenoh-c peer, so the row is owned by Layer C1cc, whose job
//! provisions that oracle and fails instead of skipping when it is absent (`WZ_C1CC_REQUIRE`).
//! Layer E, where the row first stood, runs in a job that provisions no zenoh-c: an absence that
//! FAILED the row there graded the job and not the listener. Layer E's `--ignored` sweep still
//! reaches the row, and where the oracle is absent it skips with a note, as the `zenoh_c_*` rows do.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    compile_zenoh_c_example, read_captured, wz_capi_pico_cdylib, zenoh_c_oracle,
    zenoh_c_shared_library, zenoh_pico_include_dirs, zenoh_pico_library_dir, ChildGuard,
};

/// The pico side: a peer that only LISTENS at `argv[1]` and holds the session for a few seconds.
const LISTENER_SRC: &str = r#"
#include <stdio.h>
#include <zenoh-pico.h>

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) {
        return 2;
    }
    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_loan_mut(config), Z_CONFIG_LISTEN_KEY, argv[1]);
    z_owned_session_t s;
    z_result_t rc = z_open(&s, z_move(config), NULL);
    printf("listener open rc=%d\n", (int)rc);
    if (rc < 0) {
        return 0;
    }
    z_sleep_ms(6000);
    z_close(z_loan_mut(s), NULL);
    z_drop(z_move(s));
    return 0;
}
"#;

/// The zenoh-c side, always linked to the real library: a peer with scouting off that dials
/// `argv[1]`. It prints only whether the open succeeded; its log is the harness's to read.
const DIALLER_SRC: &str = r#"
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include "zenoh.h"

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) {
        return 2;
    }
    zc_try_init_log_from_env();
    z_owned_config_t config;
    z_config_default(&config);
    char buf[160];
    zc_config_insert_json5(z_loan_mut(config), "mode", "\"peer\"");
    zc_config_insert_json5(z_loan_mut(config), "scouting/multicast/enabled", "false");
    zc_config_insert_json5(z_loan_mut(config), "listen/endpoints", "[]");
    /* A delay far past the real pico's own accept latency (about 375 ms), so that the delay
       running out means the Final never came and not that pico answered slowly. */
    zc_config_insert_json5(z_loan_mut(config), "scouting/delay", "4000");
    snprintf(buf, sizeof buf, "[\"%s\"]", argv[1]);
    zc_config_insert_json5(z_loan_mut(config), "connect/endpoints", buf);
    z_owned_session_t s;
    int rc = z_open(&s, z_move(config), NULL);
    printf("dialler open rc=%d\n", rc);
    if (rc < 0) {
        return 0;
    }
    usleep(200 * 1000);
    z_drop(z_move(s));
    return 0;
}
"#;

/// Compile the pico listener against upstream's headers, linked to `libname`.
fn compile_listener(out_dir: &Path, libdir: &Path, libname: &str, arm: &str) -> PathBuf {
    let src = out_dir.join(format!("listener_{arm}.c"));
    std::fs::write(&src, LISTENER_SRC).expect("write the listener source");
    let exe = out_dir.join(format!("listener_{arm}"));
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let mut cmd = Command::new(&cc);
    cmd.arg(&src).arg("-DZENOH_LINUX");
    for inc in zenoh_pico_include_dirs() {
        cmd.arg(format!("-I{}", inc.display()));
    }
    cmd.arg("-o")
        .arg(&exe)
        .arg(format!("-L{}", libdir.display()))
        .arg(format!("-l{libname}"))
        .arg(format!("-Wl,-rpath,{}", libdir.display()));
    let out = cmd.output_bounded().expect("spawn C compiler");
    assert!(
        out.status.success(),
        "{arm} listener failed to build against {libname}:\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    exe
}

/// Wait until the capture carries `needle`.
fn wait_for_line(capture: &mut File, needle: &str, budget: Duration, what: &str) {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if read_captured(capture).contains(needle) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "{what}: never printed {needle:?}:\n{}",
        read_captured(capture)
    );
}

/// One arm: the listener built as `listener`, dialled by the real zenoh-c peer `dialler`. Returns
/// the three lines the row compares.
fn run_arm(listener: &Path, dialler: &Path, dialler_libdir: &Path, arm: &str) -> String {
    let port = wz_runtime_tokio_test_support::free_port();
    let mut listener_capture = tempfile::tempfile().expect("the listener's capture");
    let listener_child = ChildGuard::wrap(
        format!("{arm} listener"),
        Command::new(listener)
            .arg(format!("tcp/127.0.0.1:{port}"))
            .stdout(listener_capture.try_clone().expect("dup stdout handle"))
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("{arm}: failed to run the listener: {e}")),
    );
    wait_for_line(
        &mut listener_capture,
        "listener open rc=",
        Duration::from_secs(15),
        &format!("{arm} listener"),
    );
    let listener_line = read_captured(&mut listener_capture)
        .lines()
        .find(|l| l.starts_with("listener open rc="))
        .unwrap_or_default()
        .to_owned();

    let out = Command::new(dialler)
        .arg(format!("tcp/127.0.0.1:{port}"))
        .env("LD_LIBRARY_PATH", dialler_libdir)
        .env("RUST_LOG", "warn")
        .output_bounded()
        .unwrap_or_else(|e| panic!("{arm}: failed to run the dialler: {e}"));
    drop(listener_child);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let dialler_line = stdout
        .lines()
        .find(|l| l.starts_with("dialler open rc="))
        .unwrap_or("dialler open rc=<none>")
        .to_owned();
    let waited_it_out = format!("{stdout}{stderr}")
        .contains("Scouting delay elapsed before start conditions are met");
    format!(
        "{listener_line}\n{dialler_line}\nscouting-delay-elapsed={}\n",
        if waited_it_out { "yes" } else { "no" }
    )
}

/// A zenoh-c peer that dials a pico listener is not left to wait out `scouting/delay`: the
/// listener ends what it replays with the Final of the initial interest, as zenoh-pico does.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a pico listener against both libraries and dials each with a real \
            zenoh-c peer; run by run-ci Layer C1cc (whose job provisions the zenoh-c oracle)"]
fn a_zenoh_peer_that_dials_a_pico_listener_is_not_left_waiting_on_wz_and_zenoh_pico() {
    let dir = tempfile::tempdir().expect("tempdir");
    // The dialler links the real zenoh-c library alone, so the pairing of its header with wz's
    // zenoh-c cdylib, which other rows check, is not a fact this row depends on.
    let Some((zc_include, _libdir, _examples)) = zenoh_c_oracle() else {
        eprintln!(
            "skip: the zenoh-c ORACLE is absent. This row needs zenoh-c's headers, libzenohc.so \
             and its examples (default prefix ~/.local, override WZ_ZENOH_C_PREFIX). \
             Layer C1cc with WZ_C1CC_REQUIRE=1 fails instead of skipping."
        );
        return;
    };
    let zc_lib = zenoh_c_shared_library().expect("the zenoh-c shared library");
    let zc_libdir = zc_lib
        .parent()
        .expect("libzenohc.so has a parent")
        .to_path_buf();
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).expect("source dir");
    std::fs::write(src.join("pico_dialler.c"), DIALLER_SRC).expect("write the dialler source");
    let dialler_dir = dir.path().join("zenohc");
    std::fs::create_dir_all(&dialler_dir).expect("build dir");
    let dialler = compile_zenoh_c_example(
        "pico_dialler",
        &dialler_dir,
        &zc_include,
        &src,
        &zc_libdir,
        "zenohc",
    )
    .unwrap_or_else(|d| panic!("the dialler does not link against libzenohc\n{d}"));

    let cdylib = wz_capi_pico_cdylib();
    let wz_libdir = cdylib.parent().expect("cdylib has a parent").to_path_buf();
    let reference_listener = compile_listener(
        dir.path(),
        &zenoh_pico_library_dir(),
        "zenohpico",
        "reference",
    );
    let wz_listener = compile_listener(dir.path(), &wz_libdir, "wz_capi_pico", "wz");

    let reference = run_arm(&reference_listener, &dialler, &zc_libdir, "reference");
    let wz = run_arm(&wz_listener, &dialler, &zc_libdir, "wz");
    for needle in [
        "listener open rc=0",
        "dialler open rc=0",
        "scouting-delay-elapsed=no",
    ] {
        assert!(
            reference.lines().any(|l| l == needle),
            "the REFERENCE arm has no `{needle}` line, so this row is measuring the harness \
             rather than wz:\n{reference}"
        );
    }
    assert_eq!(
        wz, reference,
        "§5.27 api-compat-pico: a zenoh peer that dials wz's pico listener is not told, as it is \
         by the real zenoh-pico, that the listener has sent everything it holds.\n--- wz ---\n{wz}\n\
         --- reference ---\n{reference}"
    );
}
