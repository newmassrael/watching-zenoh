// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Open-debt item 913 — upstream's own multicast peer test, `tests/z_test_peer_multicast.c`,
//! run against wz's pico drop-in.
//!
//! The program is upstream's and unmodified: four sessions in one process, each opened with
//! `mode=peer` and `listen=udp/224.0.0.224:7447#iface=lo`, each declaring a subscriber and a
//! queryable on `test/**`, publishing five times and getting five times on a key of its own,
//! and each asserting that its subscriber and its queryable heard at least fifteen times, five
//! from each of the other three. So a pass needs every session to have joined the group, every
//! put to reach the other three, and every get to reach their queryables and END on their
//! finals: the program reads each get's replies with `z_recv` until the channel closes, which it
//! does when the last member's final has come.
//!
//! ## What the harness adds, and why it is not a change to the program
//!
//! The program starts its four sessions with `_z_task_init` and joins them with
//! `_z_task_join`, which are pico's own system layer and not its API: a drop-in for the API
//! owes neither, and wz's does not export them. The harness compiles one C file that defines
//! the two on POSIX threads, as pico's unix system layer does
//! (`vendor/zenoh-pico/src/system/unix/system.c`), and then `#include`s upstream's file
//! verbatim, so every line of the test is upstream's.
//!
//! ## The calibration
//!
//! The same program against the real `libzenohpico.so` runs first. Multicast on the loopback
//! interface depends on the host, and a run where the reference fails says the environment
//! cannot carry the test, not that the drop-in is wrong.
//!
//! ## What a pass is read from
//!
//! Its exit status is not enough: a session that cannot open prints `Unable to open session!`
//! and returns from its thread before the asserts, and a header set that misses one of the
//! test's switches compiles a stub `main` that prints `Missing config token` and exits 0. So
//! each run is read for both, and for the receive lines each session prints.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    compile_pico_source, project_root, zenoh_pico_include_dirs, zenoh_pico_library_dir,
    PicoHeaderArm,
};

/// The program sleeps 5 s, puts for 5 s, gets for 5 s and sleeps 5 s more in each of its
/// four threads, and its `main` waits 20 s before joining them: about 25 s when every get
/// ends on its finals, and 70 s or more if every get waits out its 10 s timeout instead.
const RUN_BOUND: Duration = Duration::from_secs(150);

/// Longer than a run whose gets end on their finals takes, shorter than one whose five gets
/// per session each wait out the 10 s timeout: what tells the two apart.
const ENDS_ON_FINALS: Duration = Duration::from_secs(55);

/// How many sessions the program opens, and how many times each hears each of the others.
const SESSIONS: usize = 4;
const PER_PEER: usize = 5;

/// Upstream's test, in the vendored tree.
fn upstream_test() -> PathBuf {
    let src = project_root().join("vendor/zenoh-pico/tests/z_test_peer_multicast.c");
    assert!(
        src.is_file(),
        "upstream zenoh-pico test {} missing; run `git submodule update --init vendor/zenoh-pico`",
        src.display()
    );
    src
}

/// The C file wz's run compiles: pico's two task functions on POSIX threads, then upstream's
/// test, included whole.
fn with_task_functions(dir: &Path) -> PathBuf {
    let wrapper = dir.join("z_test_peer_multicast.c");
    let text = format!(
        "#include <pthread.h>\n\
         #include \"zenoh-pico.h\"\n\
         \n\
         z_result_t _z_task_init(_z_task_t *task, z_task_attr_t *attr, void *(*fun)(void *), void *arg) {{\n\
         \x20   return pthread_create(task, attr, fun, arg) == 0 ? _Z_RES_OK : _Z_ERR_GENERIC;\n\
         }}\n\
         \n\
         z_result_t _z_task_join(_z_task_t *task) {{\n\
         \x20   return pthread_join(*task, NULL) == 0 ? _Z_RES_OK : _Z_ERR_GENERIC;\n\
         }}\n\
         \n\
         #include \"{}\"\n",
        upstream_test().display()
    );
    std::fs::write(&wrapper, text).expect("write the harness C file");
    wrapper
}

/// Run `exe` to its end and return what it printed, checked for a stub, a session that did
/// not open, and the receive lines of every session.
fn run_and_read(label: &str, exe: &Path) -> String {
    let started = std::time::Instant::now();
    let out = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(exe)
        .output_within(RUN_BOUND)
        .unwrap_or_else(|e| panic!("{label}: cannot start {}: {e}", exe.display()));
    let took = started.elapsed();
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !printed.contains("Missing config token"),
        "{label}: the program compiled to its stub main; the header set misses one of its \
         switches\n{printed}"
    );
    assert!(
        !printed.contains("Unable to"),
        "{label}: a session failed a call before the asserts\n{printed}"
    );
    assert!(
        out.status.success(),
        "{label}: exited {:?}\n{printed}",
        out.status
    );
    for id in 0..SESSIONS {
        for (what, line) in [
            ("subscriber", format!(">> [Subscriber {id}] Received")),
            ("queryable", format!(" >> [Queryable {id}] Received")),
        ] {
            let heard = printed.matches(&line).count();
            assert!(
                heard >= (SESSIONS - 1) * PER_PEER,
                "{label}: session {id}'s {what} heard {heard} times, fewer than {} \
                 (five from each of the other three)\n{printed}",
                (SESSIONS - 1) * PER_PEER
            );
        }
        // Each get is answered: the other three reply on the same key, and the get's default
        // consolidation keeps one reply per key, so a session reads one per get. MEASURED on the
        // real library first: five per session, where the replies of three would be fifteen.
        let replies = printed
            .matches(&format!(">> [Query {id}] Received"))
            .count();
        assert!(
            replies >= PER_PEER,
            "{label}: session {id}'s five gets were answered {replies} times; each is answered \
             once its replies are consolidated\n{printed}"
        );
    }
    assert!(
        took < ENDS_ON_FINALS,
        "{label}: the run took {took:?}, the time of gets that waited out their timeout rather \
         than ending on the members' finals\n{printed}"
    );
    printed
}

/// The calibration: upstream's test against upstream's library, on this host.
// wz-proves: none -- the calibration: upstream's program on upstream's library says whether this host carries a loopback group, and runs no wz code
#[test]
#[ignore = "joins a multicast group on the loopback interface; run by run-ci Layer M"]
fn upstream_peer_multicast_test_passes_against_real_pico() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled test");
    let exe = compile_pico_source(
        &upstream_test(),
        dir.path(),
        &zenoh_pico_include_dirs(),
        &zenoh_pico_library_dir(),
        "zenohpico",
    )
    .unwrap_or_else(|diag| {
        panic!("upstream's test does not build against upstream's library\n{diag}")
    });
    run_and_read("z_test_peer_multicast on libzenohpico", &exe);
}

/// The claim: the same program against wz's pico drop-in.
// wz-proves: none -- upstream's own self-asserting test against wz; all four group members are wz, so no foreign party speaks
#[test]
#[ignore = "joins a multicast group on the loopback interface; run by run-ci Layer M"]
fn upstream_peer_multicast_test_passes_against_wz_capi_pico() {
    let dir = tempfile::tempdir().expect("tempdir for the compiled test");
    let arm = PicoHeaderArm::MultiThreaded;
    let cdylib = arm.wz_cdylib();
    let libdir = cdylib.parent().expect("the cdylib has a directory");
    let exe = compile_pico_source(
        &with_task_functions(dir.path()),
        dir.path(),
        &arm.include_dirs(),
        libdir,
        "wz_capi_pico",
    )
    .unwrap_or_else(|diag| {
        panic!(
            "upstream's z_test_peer_multicast.c does not build against wz's pico drop-in, so the \
             drop-in is not one for it\n{diag}"
        )
    });
    run_and_read("z_test_peer_multicast on wz-capi-pico", &exe);
}
