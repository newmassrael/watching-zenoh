// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` -- what a subscriber of the PUBLISHING session is handed when the
//! payload lives in shared memory, on wz's cdylib as on the real `libzenohc.so`: one C
//! program, compiled once, linked twice, stdout diffed.
//!
//! ## Why this exists
//!
//! The legs that put a chunk on the wire (`zenoh_c_shm_and_advanced_on_wz_capi_c`, legs 7
//! and 8) see only the REMOTE leg of a publish. A publish also has a local one, and it is
//! not the same code: the session that publishes hands any subscriber of its own the
//! sample directly. Upstream hands that subscriber the buffer, the page the chunk lies on
//! and not a copy of its bytes, so the program that publishes a chunk and subscribes to it
//! in the same session sees a shared-memory buffer. wz handed it the bytes: its
//! `z_bytes_as_loaned_shm` answered `Z_EINVAL` where upstream's succeeds (MEASURED by a
//! probe of this program's shape, on both libraries, before the local leg was built).
//!
//! ## The three cases
//!
//! The callback asks upstream's `z_sub_shm.c` question of what it is handed: can the
//! payload be viewed as a shared-memory buffer, and can that view be written. The cases
//! are a chunk put on a literal key, a chunk put on a DECLARED key, and a plain-bytes put,
//! which is the control that the question does not answer `SHM` for everything.

use std::path::{Path, PathBuf};
use std::process::Command;

use wz_integration_tests::common::{
    assert_zenoh_c_arm_pairing, compile_zenoh_c_example, wz_capi_c_cdylib, zenoh_c_oracle,
    zenoh_c_shared_library,
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "zenoh.h"

/* upstream's z_sub_shm.c question, asked of what a LOCAL subscriber is handed */
static void on_sample(z_loaned_sample_t *sample, void *arg) {
    const char *label = (const char *)arg;
    const char *kind = "RAW";
    z_loaned_shm_t *shm = NULL;
    if (z_bytes_as_mut_loaned_shm(z_sample_payload_mut(sample), &shm) == Z_OK) {
        kind = z_shm_try_reloan_mut(shm) ? "SHM (MUT)" : "SHM (IMMUT)";
    }
    printf("%s kind=%s len=%zu\n", label, kind, z_bytes_len(z_sample_payload(sample)));
}

static int put_chunk(const z_loaned_session_t *s, const z_loaned_keyexpr_t *ke,
                     const z_loaned_shm_provider_t *provider) {
    z_buf_layout_alloc_result_t alloc;
    z_shm_provider_alloc_gc_defrag_blocking(&alloc, provider, 64);
    if (alloc.status != ZC_BUF_LAYOUT_ALLOC_STATUS_OK) { return -1; }
    memset(z_shm_mut_data_mut(z_loan_mut(alloc.buf)), 'x', 64);
    z_owned_bytes_t payload;
    if (z_bytes_from_shm_mut(&payload, z_move(alloc.buf)) != Z_OK) { return -2; }
    return z_put(s, ke, z_move(payload), NULL);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    z_owned_config_t config;
    z_config_default(&config);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MULTICAST_SCOUTING_KEY, "false");
    /* a session needs an endpoint to open on wz (see the note in the test) */
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_LISTEN_KEY, "[\"tcp/127.0.0.1:0\"]");
    z_owned_session_t s;
    if (z_open(&s, z_move(config), NULL) < 0) { printf("open failed\n"); return 1; }

    z_owned_shm_provider_t provider;
    if (z_shm_provider_default_new(&provider, 4096) != Z_OK) { printf("provider failed\n"); return 2; }

    z_view_keyexpr_t literal;
    z_view_keyexpr_from_str(&literal, "probe/literal");
    z_owned_closure_sample_t cb1;
    z_closure(&cb1, on_sample, NULL, (void *)"literal");
    z_owned_subscriber_t sub1;
    if (z_declare_subscriber(z_loan(s), &sub1, z_loan(literal), z_move(cb1), NULL) < 0) { return 3; }
    int literal_rc = put_chunk(z_loan(s), z_loan(literal), z_loan(provider));

    z_view_keyexpr_t named;
    z_view_keyexpr_from_str(&named, "probe/declared");
    z_owned_keyexpr_t declared;
    if (z_declare_keyexpr(z_loan(s), &declared, z_loan(named)) < 0) { return 4; }
    z_owned_closure_sample_t cb2;
    z_closure(&cb2, on_sample, NULL, (void *)"declared");
    z_owned_subscriber_t sub2;
    if (z_declare_subscriber(z_loan(s), &sub2, z_loan(named), z_move(cb2), NULL) < 0) { return 5; }
    int declared_rc = put_chunk(z_loan(s), z_loan(declared), z_loan(provider));

    z_view_keyexpr_t plain;
    z_view_keyexpr_from_str(&plain, "probe/plain");
    z_owned_closure_sample_t cb3;
    z_closure(&cb3, on_sample, NULL, (void *)"plain");
    z_owned_subscriber_t sub3;
    if (z_declare_subscriber(z_loan(s), &sub3, z_loan(plain), z_move(cb3), NULL) < 0) { return 6; }
    z_owned_bytes_t bytes;
    z_bytes_copy_from_str(&bytes, "plain bytes");
    int plain_rc = z_put(z_loan(s), z_loan(plain), z_move(bytes), NULL);

    /* The put results are printed AFTER a settle, because the real library runs a local
       callback inside z_put and wz's drive thread runs it just after: the kinds are the
       subject, and the order of a callback line against a put line is not. */
    z_sleep_ms(300);
    printf("puts literal=%d declared=%d plain=%d\n", literal_rc, declared_rc, plain_rc);
    printf("done\n");
    return 0;
}
"#;

/// Compile the probe once per library and return what each printed.
fn run_both_arms(include: &Path) -> (String, String) {
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("probe source dir");
    std::fs::write(src_dir.join("wz_shm_local.c"), PROBE).expect("write the probe source");

    let lib = wz_capi_c_cdylib();
    let wz_libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_zenoh_c_example(
        "wz_shm_local",
        dir.path(),
        include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!("§5.27 api-compat-c: the local-delivery probe does NOT link against wz's cdylib.\n{diag}")
    });

    let reference = zenoh_c_shared_library().expect("the oracle resolved above");
    let libdir_ref = reference
        .parent()
        .expect("libzenohc.so has a parent")
        .to_path_buf();
    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let on_ref = compile_zenoh_c_example(
        "wz_shm_local",
        &ref_dir,
        include,
        &src_dir,
        &libdir_ref,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("the local-delivery probe does not link against the REAL libzenohc.so\n{diag}")
    });

    let run = |exe: &Path, libdir: &Path| -> (bool, String) {
        let out = Command::new(exe)
            .env("LD_LIBRARY_PATH", libdir)
            .output()
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
        "the local-delivery probe exited non-zero on wz's C ABI.\n\
         --- stdout on wz ---\n{wz_stdout}\n--- reference printed ---\n{ref_stdout}"
    );
    (wz_stdout, ref_stdout)
}

/// THE GATE: a subscriber of the publishing session is handed the same kind of buffer on wz
/// and on libzenohc, for a chunk on a literal key, a chunk on a declared key and plain bytes.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_local_subscriber_is_handed_the_same_kind_of_buffer_on_wz_and_libzenohc() {
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
             Z_FEATURE_UNSTABLE_API, where the provider plane does not exist."
        );
        return;
    }
    assert_zenoh_c_arm_pairing(&include);
    let (wz_stdout, ref_stdout) = run_both_arms(&include);

    // The ORACLE first: two identical failures diff clean, and a reference that does not
    // hand a local subscriber a shared-memory buffer would make the equality below say
    // nothing about the leg this file exists for.
    for chunk_case in ["literal", "declared"] {
        assert!(
            ref_stdout
                .lines()
                .any(|l| l.starts_with(&format!("{chunk_case} kind=SHM"))),
            "the reference did not hand the `{chunk_case}` subscriber a shared-memory buffer, so \
             the rule this leg compares against is not what it assumes:\n{ref_stdout}"
        );
    }
    assert!(
        ref_stdout.contains("plain kind=RAW len=11"),
        "the reference did not hand the plain-bytes subscriber a raw payload:\n{ref_stdout}"
    );
    assert!(
        ref_stdout.contains("puts literal=0 declared=0 plain=0") && ref_stdout.contains("done"),
        "the reference did not put all three and run the probe to the end:\n{ref_stdout}"
    );

    assert_eq!(
        wz_stdout, ref_stdout,
        "§5.27 api-compat-c: wz's C ABI and libzenohc hand a local subscriber a different kind \
         of buffer for a payload in shared memory.\n--- wz ---\n{wz_stdout}--- libzenohc \
         ---\n{ref_stdout}"
    );
}
