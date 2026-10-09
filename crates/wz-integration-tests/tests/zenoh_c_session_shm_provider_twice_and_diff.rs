// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` — a session's OWN shared-memory provider, obtained
//! through `z_obtain_shm_provider` and used through the shared-provider family,
//! on wz's cdylib as on the real `libzenohc.so`: one C program, compiled once,
//! linked twice, stdout diffed.
//!
//! ## Upstream's rule
//!
//! The runtime owns one provider when `transport/shared_memory` and its
//! `transport_optimization` are both enabled, sized `pool_size`, and builds it
//! lazily on a blocking task the first time anything asks
//! (`io/zenoh-transport/src/common/shm/interop.rs` @ `pub fn try_get_provider(&self) -> ProviderInitState {`).
//! zenoh-c answers that ask four ways (`zenoh-c/src/session.rs`): disabled,
//! initializing (which a blocking ask waits out), ready, error.
//!
//! ## The legs (R2957)
//!
//! - **A** — a default session, asked NON-blocking first: the first ask
//!   starts the build and answers INITIALIZING without a provider.
//! - **B** — the same session asked BLOCKING: READY, `Z_OK`, a provider.
//! - **C** — it allocates through `z_shared_shm_provider_loan_as`, i.e.
//!   wherever a provider is expected, and `z_shm_provider_available` on it
//!   answers `0`: upstream's default POSIX backend (talc) does not account,
//!   which this leg MEASURED and wz's native providers now follow.
//! - **D** — a shallow clone shares ONE backend: three quarters of the pool
//!   taken through the original leaves no room for three quarters more
//!   through the copy.
//! - **E** — a session with `transport_optimization` disabled: DISABLED.
//! - **F** — the gravestone: `null` then `check` answers false; `drop` of it
//!   is harmless.
//!
//! `pool_size` is set to 1 MiB, so the exhaustion in D is decided by a value
//! of this test's choosing rather than a default either side could share by
//! accident.

use std::path::{Path, PathBuf};
use std::process::Command;

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    assert_zenoh_c_arm_pairing, compile_zenoh_c_example, wz_capi_c_cdylib, zenoh_c_oracle,
    zenoh_c_shared_library, PortReservation,
};

/// The oracle, or `None` with a LOUD note naming what to do about it.
fn oracle_or_note() -> Option<PathBuf> {
    match zenoh_c_oracle() {
        Some((include, _libdir, _examples)) => Some(include),
        None => {
            eprintln!(
                "skip: the zenoh-c ORACLE is absent. This leg needs zenoh-c's headers \
                 and libzenohc.so (default prefix ~/.local, override WZ_ZENOH_C_PREFIX). \
                 Layer C1cc with WZ_C1CC_REQUIRE=1 fails instead of skipping."
            );
            None
        }
    }
}

const PROBE: &str = r#"#include <stdio.h>
#include <string.h>
#include "zenoh.h"

static int open_session(z_owned_session_t *s, const char *endpoint, int optimization) {
    z_owned_config_t config;
    if (z_config_default(&config) != Z_OK) { return -1; }
    if (zc_config_insert_json5(z_config_loan_mut(&config),
                               "scouting/multicast/enabled", "false") != Z_OK) { return -1; }
    char value[256];
    snprintf(value, sizeof value, "[\"%s\"]", endpoint);
    if (zc_config_insert_json5(z_config_loan_mut(&config), "listen/endpoints", value) != Z_OK) {
        return -1;
    }
    if (zc_config_insert_json5(z_config_loan_mut(&config),
                               "transport/shared_memory/transport_optimization/pool_size",
                               "1048576") != Z_OK) { return -1; }
    if (!optimization &&
        zc_config_insert_json5(z_config_loan_mut(&config),
                               "transport/shared_memory/transport_optimization/enabled",
                               "false") != Z_OK) { return -1; }
    return z_open(s, z_move(config), NULL) == Z_OK ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: probe <endpoint-a> <endpoint-b>\n"); return 2; }

    z_owned_session_t s;
    if (open_session(&s, argv[1], 1) < 0) { printf("open=FAILED\n"); return 1; }

    z_owned_shared_shm_provider_t provider;
    z_internal_shared_shm_provider_null(&provider);
    z_shm_provider_state state = Z_SHM_PROVIDER_STATE_ERROR;

    int rc = z_obtain_shm_provider(z_loan(s), false, &provider, &state);
    printf("A.rc=%d A.state=%d A.provider=%d\n", rc, (int)state,
           (int)z_internal_shared_shm_provider_check(&provider));

    rc = z_obtain_shm_provider(z_loan(s), true, &provider, &state);
    printf("B.rc=%d B.state=%d B.provider=%d\n", rc, (int)state,
           (int)z_internal_shared_shm_provider_check(&provider));

    if (rc == Z_OK) {
        const z_loaned_shm_provider_t *as_plain =
            z_shared_shm_provider_loan_as(z_shared_shm_provider_loan(&provider));
        size_t before = z_shm_provider_available(as_plain);
        printf("C.available=%zu\n", before);
        z_buf_layout_alloc_result_t alloc;
        z_shm_provider_alloc(&alloc, as_plain, 4096);
        printf("C.alloc.status=%d\n", (int)alloc.status);

        /* One backend, not two: three quarters of the pool taken through the
           ORIGINAL leaves no room for another three quarters through the COPY. */
        z_owned_shared_shm_provider_t copy;
        z_shared_shm_provider_clone(&copy, z_shared_shm_provider_loan(&provider));
        printf("D.copy=%d\n", (int)z_internal_shared_shm_provider_check(&copy));
        z_buf_layout_alloc_result_t big;
        z_shm_provider_alloc(&big, as_plain, 786432);
        z_buf_layout_alloc_result_t second;
        z_shm_provider_alloc(&second,
                             z_shared_shm_provider_loan_as(z_shared_shm_provider_loan(&copy)),
                             786432);
        printf("D.original.status=%d D.copy.status=%d\n", (int)big.status, (int)second.status);
        if (second.status == ZC_BUF_LAYOUT_ALLOC_STATUS_OK) {
            z_shm_mut_drop(z_shm_mut_move(&second.buf));
        }
        if (big.status == ZC_BUF_LAYOUT_ALLOC_STATUS_OK) {
            z_shm_mut_drop(z_shm_mut_move(&big.buf));
        }
        if (alloc.status == ZC_BUF_LAYOUT_ALLOC_STATUS_OK) {
            z_shm_mut_drop(z_shm_mut_move(&alloc.buf));
        }
        z_shared_shm_provider_drop(z_shared_shm_provider_move(&copy));
        z_shared_shm_provider_drop(z_shared_shm_provider_move(&provider));
    }

    z_owned_session_t off;
    if (open_session(&off, argv[2], 0) < 0) { printf("open.off=FAILED\n"); return 1; }
    z_owned_shared_shm_provider_t none;
    z_internal_shared_shm_provider_null(&none);
    rc = z_obtain_shm_provider(z_loan(off), true, &none, &state);
    printf("E.rc=%d E.state=%d E.provider=%d\n", rc, (int)state,
           (int)z_internal_shared_shm_provider_check(&none));

    z_owned_shared_shm_provider_t grave;
    z_internal_shared_shm_provider_null(&grave);
    printf("F.check=%d\n", (int)z_internal_shared_shm_provider_check(&grave));
    z_shared_shm_provider_drop(z_shared_shm_provider_move(&grave));

    z_session_drop(z_session_move(&off));
    z_session_drop(z_session_move(&s));
    printf("done\n");
    return 0;
}
"#;

/// Compile the probe once per library and run it, each on its own ports.
fn run_both_arms(include: &Path) -> (String, String) {
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("probe source dir");
    std::fs::write(src_dir.join("wz_session_shm.c"), PROBE).expect("write the probe source");

    let lib = wz_capi_c_cdylib();
    let wz_libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_zenoh_c_example(
        "wz_session_shm",
        dir.path(),
        include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!("§5.27 api-compat-c: the session-provider probe does NOT link against wz's cdylib.\n{diag}")
    });

    let reference = zenoh_c_shared_library().expect("the oracle resolved above");
    let libdir_ref = reference
        .parent()
        .expect("libzenohc.so has a parent")
        .to_path_buf();
    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let on_ref = compile_zenoh_c_example(
        "wz_session_shm",
        &ref_dir,
        include,
        &src_dir,
        &libdir_ref,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("the session-provider probe does not link against the REAL libzenohc.so\n{diag}")
    });

    let run = |exe: &Path, libdir: &Path| -> (bool, String) {
        // Two ports under ONE reservation, as the harness requires.
        let (reservation, second) = PortReservation::pick_pair();
        let out = Command::new(exe)
            .arg(format!("tcp/127.0.0.1:{}", reservation.port()))
            .arg(format!("tcp/127.0.0.1:{second}"))
            .env("LD_LIBRARY_PATH", libdir)
            .output_bounded()
            .unwrap_or_else(|why| panic!("spawn {}: {why}", exe.display()));
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    };
    let (ref_ok, ref_stdout) = run(&on_ref, &libdir_ref);
    let (wz_ok, wz_stdout) = run(&on_wz, &wz_libdir);
    assert!(
        ref_ok,
        "the REFERENCE arm failed, so this machine's oracle cannot serve as one here.\n{ref_stdout}"
    );
    assert!(
        wz_ok,
        "the session-provider probe exited non-zero on wz's C ABI.\n\
         --- stdout on wz ---\n{wz_stdout}\n--- reference printed ---\n{ref_stdout}"
    );
    (wz_stdout, ref_stdout)
}

/// THE GATE: a session's own provider is obtained, sized, shared and disabled
/// identically on wz and libzenohc.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "opens sessions and reads a zenoh-c oracle; run by run-ci Layer C1cc \
            (which builds the matching ABI arm this needs)"]
fn a_sessions_own_shm_provider_is_obtained_identically_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    let configure = std::fs::read_to_string(include.join("zenoh_configure.h")).unwrap_or_default();
    let defines = |name: &str| {
        configure
            .lines()
            .any(|l| l.trim() == format!("#define {name}"))
    };
    if !(defines("Z_FEATURE_UNSTABLE_API") && defines("Z_FEATURE_SHARED_MEMORY")) {
        eprintln!(
            "skip: this zenoh-c oracle is built without Z_FEATURE_SHARED_MEMORY and \
             Z_FEATURE_UNSTABLE_API, where z_obtain_shm_provider does not exist."
        );
        return;
    }
    assert_zenoh_c_arm_pairing(&include);
    let (wz_stdout, ref_stdout) = run_both_arms(&include);

    // The ORACLE first: two identical failures diff clean.
    assert!(
        ref_stdout.contains("done") && ref_stdout.contains("B.rc=0 B.state=2 B.provider=1"),
        "the reference did not hand out a ready provider on a blocking ask:\n{ref_stdout}"
    );
    assert!(
        ref_stdout.contains("D.copy=1\nD.original.status=0 D.copy.status=1"),
        "the reference's clone does not share ONE backend with its original, so the \
         exhaustion leg measures nothing:\n{ref_stdout}"
    );
    assert!(
        ref_stdout.contains("E.state=0 E.provider=0"),
        "the reference does not disable the provider with transport_optimization off:\n{ref_stdout}"
    );

    assert_eq!(
        wz_stdout, ref_stdout,
        "§5.27 api-compat-c: wz's C ABI and libzenohc disagree about a session's own \
         shared-memory provider.\n--- wz ---\n{wz_stdout}--- libzenohc ---\n{ref_stdout}"
    );
}
