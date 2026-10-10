// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! §5.27 `api-compat-pico` -- a config that carries BOTH a `listen` and a `connect` endpoint,
//! compiled once against the real zenoh-pico and once against wz, run against the same two
//! peers, and compared line for line.
//!
//! ## What this exists to catch
//!
//! The real zenoh-pico opens one session that listens at the one endpoint and dials the other:
//! `_z_locators_by_config` refuses the pair only in a build without unicast peers and otherwise
//! forces the mode to peer for any listen config and goes on (`vendor/zenoh-pico/src/net/session.c`
//! @ `static z_result_t _z_locators_by_config(`). The wz ABI refused the pair with
//! `Z_ERR_INVALID` until R3090, though the core it sits on has run a session that listens and
//! dials since R3067.
//!
//! ## The comparison
//!
//! One C driver is compiled against upstream's headers twice. It states `listen` and `connect`
//! together, subscribes to `demo/rt/**` and counts what reaches it: the peer it DIALS is a
//! wz-ap-demo that listens and publishes five Puts whose value starts `a`, and a second
//! wz-ap-demo DIALS the driver's listener once the driver is ready and publishes five starting
//! `b`. A session that did only one of the two hears five of one and none of the other. The
//! driver then puts once to the key both demos subscribe to, so that the traffic is shown to
//! run the other way too.
//!
//! The reference arm's content is asserted BEFORE the equality: two outputs that both opened
//! nothing are equal, and this row would then be measuring the harness.
//!
//! ## The oracle is a build product
//!
//! `libzenohpico.so` and its headers come from `scripts/build-zenoh-pico-cli.sh` and the peers
//! are wz-ap-demo. Absence is a hard FAIL rather than a skip.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, demo_log_filter, graceful_terminate, read_captured,
    wait_for_substring, wz_ap_demo_binary, wz_capi_pico_cdylib, zenoh_pico_include_dirs,
    zenoh_pico_library_dir, ChildGuard,
};

/// How long a demo holds its burst after Established, in milliseconds, so the driver's
/// subscription is declared first (see `spawn_demo`). The driver waits up to ~8 s for its five
/// samples, so a one-second hold leaves the wait nearly untouched.
const PUBLISH_HOLD_MS: &str = "1000";

/// The driver. `argv[1]` is the endpoint it listens at and `argv[2]` the endpoint it dials.
///
/// Every line is one observation, and nothing random is printed.
const DRIVER_SRC: &str = r#"
#include <stdio.h>
#include <string.h>
#include <zenoh-pico.h>

static volatile int count_a = 0;
static volatile int count_b = 0;

static void on_sample(z_loaned_sample_t *sample, void *ctx) {
    (void)ctx;
    z_owned_string_t value;
    z_bytes_to_string(z_sample_payload(sample), &value);
    const char *data = z_string_data(z_loan(value));
    if (z_string_len(z_loan(value)) > 0 && data[0] == 'a') {
        __atomic_add_fetch(&count_a, 1, __ATOMIC_SEQ_CST);
    } else if (z_string_len(z_loan(value)) > 0 && data[0] == 'b') {
        __atomic_add_fetch(&count_b, 1, __ATOMIC_SEQ_CST);
    }
    z_drop(z_move(value));
}

/* Wait for a counter to reach `want`, at most ~8 s, and return what it holds. */
static int wait_for(volatile int *counter, int want) {
    for (int i = 0; i < 160; i++) {
        if (__atomic_load_n(counter, __ATOMIC_SEQ_CST) >= want) {
            break;
        }
        z_sleep_ms(50);
    }
    return __atomic_load_n(counter, __ATOMIC_SEQ_CST);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 3) {
        printf("driver: usage: driver <listen endpoint> <connect endpoint>\n");
        return 2;
    }

    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_loan_mut(config), Z_CONFIG_LISTEN_KEY, argv[1]);
    zp_config_insert(z_loan_mut(config), Z_CONFIG_CONNECT_KEY, argv[2]);

    z_owned_session_t s;
    z_result_t rc = z_open(&s, z_move(config), NULL);
    printf("open rc=%d\n", (int)rc);
    if (rc < 0) {
        printf("DONE\n");
        return 0;
    }

    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "demo/rt/**");
    z_owned_closure_sample_t cb;
    z_closure(&cb, on_sample, NULL, NULL);
    z_owned_subscriber_t sub;
    if (z_declare_subscriber(z_loan(s), &sub, z_loan(ke), z_move(cb), NULL) < 0) {
        printf("driver: unable to declare the subscriber\n");
        return 1;
    }
    printf("READY\n");

    printf("from-the-dialled samples=%d\n", wait_for(&count_a, 5));
    printf("from-the-dialling samples=%d\n", wait_for(&count_b, 5));

    z_view_keyexpr_t out;
    z_view_keyexpr_from_str(&out, "demo/tx/from-driver");
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, "from-the-driver");
    rc = z_put(z_loan(s), z_loan(out), z_move(payload), NULL);
    printf("put rc=%d\n", (int)rc);
    z_sleep_ms(500);

    z_close(z_loan_mut(s), NULL);
    z_drop(z_move(s));
    printf("DONE\n");
    return 0;
}
"#;

/// Compile `source` against upstream's headers, linked to `lib`. Only the library differs
/// between the arms, which is the whole point.
fn compile_driver(
    out_dir: &Path,
    source: &str,
    libdir: &Path,
    libname: &str,
    arm: &str,
) -> PathBuf {
    let src = out_dir.join(format!("driver_{arm}.c"));
    std::fs::write(&src, source).expect("write driver source");
    let exe = out_dir.join(format!("driver_{arm}"));
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
        "{arm} arm failed to build against {libname}:\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    exe
}

/// Wait until the driver's capture carries one of `needles`, and say which. A driver whose open
/// failed prints `DONE` and no `READY`, which is an answer and not a hang.
fn wait_for_any_marker<'n>(
    capture: &mut File,
    needles: &[&'n str],
    budget: Duration,
    arm: &str,
) -> &'n str {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let seen = read_captured(capture);
        if let Some(needle) = needles.iter().find(|n| seen.contains(**n)) {
            return needle;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "{arm}: the driver never printed any of {needles:?}:\n{}",
        read_captured(capture)
    );
}

/// A wz-ap-demo that publishes five Puts of `value` under `demo/rt/<value>` and subscribes to
/// `demo/tx/**`. `mode_args` carries the role: `--connect <ep>` to dial the driver, `--listen
/// <host:port>` to be dialled. Its stderr is the caller's, so what it received can be counted.
///
/// The burst is HELD (`--publish-after-ms`, a pure delay) so the driver's subscription is declared
/// before the first Put leaves. Without it the demo bursts the instant it reaches Established,
/// which can precede the driver's `z_declare_subscriber`; a Put that reaches a peer with no
/// subscription yet is dropped, and the driver's count reads 4 where it waits for 5. Measured on
/// this test before the hold: 7 of 12 runs on one tree and 4 of 10 on the tree before it failed
/// with exactly `from-the-dialled samples=4`, and the real zenoh-pico arm read 5 only because its
/// open returns later. The hold is generous and not tight (it costs a second and removes a
/// race), the way `wz_matching_status_driven_by_pico_zsub.rs` holds its own burst for the same
/// reason.
fn spawn_demo(demo: &Path, mode_args: &[&str], value: &str, stderr: File, arm: &str) -> ChildGuard {
    ChildGuard::wrap(
        format!("{arm} demo {value}"),
        Command::new(demo)
            .args(mode_args)
            .args(["--key", "demo/tx/**"])
            .args(["--publish", &format!("demo/rt/{value}"), "--value", value])
            .args(["--publish-after-ms", PUBLISH_HOLD_MS])
            .env("RUST_LOG", demo_log_filter())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap_or_else(|e| panic!("{arm}: failed to start the demo {value}: {e}")),
    )
}

/// How many Puts on `demo/tx/**` a demo's log says it received.
fn received_from_the_driver(demo_stderr: &mut File) -> usize {
    read_captured(demo_stderr)
        .lines()
        .filter(|l| l.contains("SUBSCRIBER FIRED") && l.contains("keyexpr='demo/tx/"))
        .count()
}

/// Run one arm. Returns everything the driver printed, then the two lines the harness adds:
/// what each demo received from the driver.
fn run_arm(driver: &Path, arm: &str) -> String {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let port_dialled = wz_runtime_tokio_test_support::free_port();
    let port_listened = wz_runtime_tokio_test_support::free_port();
    let mut capture = tempfile::tempfile().expect("the driver capture");
    let mut dialled_stderr = tempfile::tempfile().expect("the dialled demo's stderr");
    let mut dialling_stderr = tempfile::tempfile().expect("the dialling demo's stderr");

    // The demo the driver dials listens, so it is ready first.
    let mut demos: Vec<ChildGuard> = vec![spawn_demo(
        &demo,
        &["--listen", &format!("127.0.0.1:{port_dialled}")],
        "a-dialled",
        dialled_stderr.try_clone().expect("dup the demo's stderr"),
        arm,
    )];
    wait_for_substring(
        &mut dialled_stderr,
        "listening on 127.0.0.1:",
        Duration::from_secs(15),
    )
    .unwrap_or_else(|e| panic!("{arm}: the demo never listened: {e}"));

    let mut driver_child = ChildGuard::wrap(
        format!("{arm} driver"),
        Command::new(driver)
            .arg(format!("tcp/127.0.0.1:{port_listened}"))
            .arg(format!("tcp/127.0.0.1:{port_dialled}"))
            .stdout(capture.try_clone().expect("dup stdout handle"))
            .stderr(capture.try_clone().expect("dup stderr handle"))
            .spawn()
            .unwrap_or_else(|e| panic!("{arm}: failed to run the driver: {e}")),
    );
    let reached = wait_for_any_marker(
        &mut capture,
        &["READY", "DONE"],
        Duration::from_secs(15),
        arm,
    );
    if reached == "READY" {
        // The session is open and listening: a second demo dials in.
        demos.push(spawn_demo(
            &demo,
            &["--connect", &format!("tcp/127.0.0.1:{port_listened}")],
            "b-dialling",
            dialling_stderr.try_clone().expect("dup the demo's stderr"),
            arm,
        ));
        wait_for_any_marker(&mut capture, &["DONE"], Duration::from_secs(40), arm);
    }

    // Let the demos' logs catch up with what the driver put before they are counted.
    std::thread::sleep(Duration::from_millis(500));
    let to_the_dialled = received_from_the_driver(&mut dialled_stderr);
    let to_the_dialling = received_from_the_driver(&mut dialling_stderr);
    for d in &mut demos {
        graceful_terminate(d.child_mut(), Duration::from_secs(5));
    }
    let status = driver_child
        .child_mut()
        .wait()
        .unwrap_or_else(|e| panic!("{arm}: waiting for the driver: {e}"));
    assert!(
        status.success(),
        "{arm}: the driver exited {status:?}\n--- its output ---\n{}",
        read_captured(&mut capture)
    );
    format!(
        "{}demo-dialled-received-from-driver={to_the_dialled}\n\
         demo-dialling-received-from-driver={to_the_dialling}\n",
        read_captured(&mut capture)
    )
}

/// A pico config that states `listen` and `connect` together opens one session that listens at
/// the one and dials the other: it hears the listener it dialled and the peer that dialled it,
/// and what it puts reaches both.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each against two \
            wz-ap-demo peers, one dialled and one dialling in; run by run-ci Layer E"]
fn a_config_that_states_listen_and_connect_listens_and_dials_on_wz_and_zenoh_pico() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cdylib = wz_capi_pico_cdylib();
    let wz_libdir = cdylib
        .parent()
        .expect("cdylib has a parent directory")
        .to_path_buf();
    let ref_driver = compile_driver(
        dir.path(),
        DRIVER_SRC,
        &zenoh_pico_library_dir(),
        "zenohpico",
        "reference",
    );
    let wz_driver = compile_driver(dir.path(), DRIVER_SRC, &wz_libdir, "wz_capi_pico", "wz");
    let reference = run_arm(&ref_driver, "reference");
    let wz = run_arm(&wz_driver, "wz");
    for needle in [
        "open rc=0",
        "from-the-dialled samples=5",
        "from-the-dialling samples=5",
        "put rc=0",
        "demo-dialled-received-from-driver=1",
        "demo-dialling-received-from-driver=1",
    ] {
        assert!(
            reference.lines().any(|l| l == needle),
            "the REFERENCE arm has no `{needle}` line, so this row is measuring the harness \
             rather than wz:\n{reference}"
        );
    }
    assert_eq!(
        wz, reference,
        "§5.27 api-compat-pico: wz's pico ABI does not listen and dial on one config as the \
         real zenoh-pico does.\n--- wz ---\n{wz}\n--- reference ---\n{reference}"
    );
}
