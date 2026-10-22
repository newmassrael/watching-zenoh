// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt item 911 (found on the way) — what `z_open` returns when the session cannot be
//! opened, on wz's pico drop-in and on the real library, case by case.
//!
//! zenoh-pico names the cause: a listen or connect link that cannot be opened is
//! `_Z_ERR_TRANSPORT_OPEN_FAILED` (`vendor/zenoh-pico/src/link/link.c` @
//! `ret = _Z_ERR_TRANSPORT_OPEN_FAILED;`), an endpoint whose scheme no link of the build serves
//! is `_Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN` (`ret = _Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN;`). A
//! program that branches on the code, retrying a busy port and giving up on a config error,
//! needs the drop-in to name the same cause.
//!
//! One small C program opens a session with one endpoint and prints what `z_open` returned; it
//! is compiled once against each library, and every case's code must be the real library's.

use std::path::Path;
use std::process::Command;

use wz_integration_tests::common::{
    compile_pico_source, zenoh_pico_include_dirs, zenoh_pico_library_dir, PicoHeaderArm,
};

/// The probe: `mode`, `listen` or `connect`, and the endpoint, then the code `z_open` returned.
const PROBE: &str = r#"#include <stdio.h>
#include <string.h>
#include "zenoh-pico.h"

int main(int argc, char **argv) {
    if (argc != 4) {
        return 2;
    }
    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_loan_mut(config), Z_CONFIG_MODE_KEY, argv[1]);
    zp_config_insert(z_loan_mut(config),
                     strcmp(argv[2], "listen") == 0 ? Z_CONFIG_LISTEN_KEY : Z_CONFIG_CONNECT_KEY, argv[3]);
    z_owned_session_t session;
    z_result_t rc = z_open(&session, z_move(config), NULL);
    printf("rc=%d\n", (int)rc);
    if (rc == Z_OK) {
        z_drop(z_move(session));
    }
    return 0;
}
"#;

/// What the probe built at `exe` prints for one case.
fn open_code(exe: &Path, mode: &str, key: &str, endpoint: &str) -> String {
    let out = Command::new(exe)
        .args([mode, key, endpoint])
        .output()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", exe.display()));
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|line| line.starts_with("rc="))
        .unwrap_or_else(|| {
            panic!(
                "{} printed no code for {mode} {key} {endpoint}\n{}",
                exe.display(),
                String::from_utf8_lossy(&out.stderr)
            )
        })
        .to_owned()
}

/// Each failing open returns on wz the code it returns on the real library.
///
/// # Control
///
/// Every case must fail on the real library; a case it opens is not a failure to compare.
// wz-proves: api-compat-pico pico->wz partial
#[test]
#[ignore = "cc-compiles a probe against both libraries; run by run-ci Layer M"]
fn a_failed_open_names_its_cause_as_the_real_library_does() {
    let dir = tempfile::tempdir().expect("tempdir for the probe");
    let src = dir.path().join("pico_open_code.c");
    std::fs::write(&src, PROBE).expect("write the probe");
    let real = compile_pico_source(
        &src,
        dir.path(),
        &zenoh_pico_include_dirs(),
        &zenoh_pico_library_dir(),
        "zenohpico",
    )
    .unwrap_or_else(|diag| panic!("the probe does not build against the real library\n{diag}"));
    let arm = PicoHeaderArm::MultiThreaded;
    let cdylib = arm.wz_cdylib();
    let wz = compile_pico_source(
        &src,
        dir.path(),
        &arm.include_dirs(),
        cdylib.parent().expect("the cdylib has a directory"),
        "wz_capi_pico",
    )
    .unwrap_or_else(|diag| panic!("the probe does not build against wz's drop-in\n{diag}"));

    // A port this test holds, so a listen on it cannot bind, and one held and refusing, so a
    // connect to it fails while no other test can take the number.
    let held = std::net::TcpListener::bind("127.0.0.1:0").expect("hold a port");
    let busy = held.local_addr().expect("its address").port();
    let refusing = wz_runtime_tokio_test_support::refusing_port();
    let closed = refusing.addr().port();
    let cases = [
        ("peer", "listen", format!("tcp/127.0.0.1:{busy}")),
        ("client", "connect", format!("tcp/127.0.0.1:{closed}")),
        ("peer", "listen", "nope/127.0.0.1:7447".to_owned()),
        ("peer", "listen", "reth/02:00:00:00:00:01".to_owned()),
    ];
    let mut differ = Vec::new();
    for (mode, key, endpoint) in &cases {
        let expected = open_code(&real, mode, key, endpoint);
        assert_ne!(
            expected, "rc=0",
            "the real library opened {mode} {key} {endpoint}: not a failure to compare"
        );
        let got = open_code(&wz, mode, key, endpoint);
        if got != expected {
            differ.push(format!(
                "{mode} {key} {endpoint}: real {expected}, wz {got}"
            ));
        }
    }
    drop(held);
    drop(refusing);
    assert!(
        differ.is_empty(),
        "z_open names a failure otherwise on wz than on the real library:\n{}",
        differ.join("\n")
    );
}
