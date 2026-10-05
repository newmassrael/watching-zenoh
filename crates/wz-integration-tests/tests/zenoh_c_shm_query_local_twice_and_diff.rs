// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` -- what a QUERYABLE of the asking session is handed when the query's
//! value lives in shared memory, on wz's cdylib as on the real `libzenohc.so`: one C program,
//! compiled once, linked twice, stdout diffed.
//!
//! ## Why this exists
//!
//! The legs that put a chunk-valued query on the wire (`zenoh_c_shm_and_advanced_on_wz_capi_c`,
//! legs 9 to 11) see only the REMOTE leg of a get. A get also has a local one, and it is not
//! the same code: the session that asks hands any queryable of its own the query directly.
//! Upstream hands that queryable the buffer, the page the chunk lies on and not a copy of its
//! bytes, so the program that asks with a chunk and answers in the same session sees a
//! shared-memory buffer. wz handed it the bytes: its `z_bytes_as_loaned_shm` answered `-1`
//! where upstream's answers `0` (MEASURED by a probe of this program's shape, on both
//! libraries, before the local leg was built).
//!
//! ## The three cases
//!
//! The queryable asks upstream's question of what it is handed: can the payload be viewed as a
//! shared-memory buffer. The cases are a `z_get` with a chunk, a `z_get` with plain bytes, which
//! is the control that the question does not answer `0` for everything, and a declared
//! querier's get with a chunk, because the querier takes its options' payload at a site of its
//! own.

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
#include "zenoh.h"

/* upstream's z_queryable_shm question, asked of what a LOCAL queryable is handed */
static void on_query(z_loaned_query_t *query, void *arg) {
    (void)arg;
    const z_loaned_bytes_t *payload = z_query_payload(query);
    if (payload == NULL) {
        printf("query: no value\n");
    } else {
        const z_loaned_shm_t *shm = NULL;
        int rc = z_bytes_as_loaned_shm(payload, &shm);
        printf("query: as_loaned_shm rc=%d len=%zu\n", rc, z_bytes_len(payload));
    }
    z_owned_bytes_t reply;
    z_bytes_copy_from_str(&reply, "ok");
    z_query_reply(query, z_query_keyexpr(query), z_move(reply), NULL);
}

static int make_value(z_owned_bytes_t *payload, int use_chunk,
                      const z_loaned_shm_provider_t *provider) {
    if (!use_chunk) {
        return z_bytes_copy_from_str(payload, "plain value");
    }
    z_buf_layout_alloc_result_t alloc;
    z_shm_provider_alloc_gc_defrag_blocking(&alloc, provider, 64);
    if (alloc.status != ZC_BUF_LAYOUT_ALLOC_STATUS_OK) { return -1; }
    memset(z_shm_mut_data_mut(z_loan_mut(alloc.buf)), 'x', 64);
    return z_bytes_from_shm_mut(payload, z_move(alloc.buf));
}

static int count_replies(z_owned_fifo_handler_reply_t *handler) {
    z_owned_reply_t reply;
    int replies = 0;
    while (z_recv(z_loan(*handler), &reply) == Z_OK) {
        if (z_reply_is_ok(z_loan(reply))) { replies++; }
        z_drop(z_move(reply));
    }
    z_drop(z_move(*handler));
    return replies;
}

static void run_get(const z_loaned_session_t *s, const z_loaned_keyexpr_t *ke, int use_chunk,
                    const z_loaned_shm_provider_t *provider) {
    z_owned_closure_reply_t closure;
    z_owned_fifo_handler_reply_t handler;
    z_fifo_channel_reply_new(&closure, &handler, 16);
    z_get_options_t opts;
    z_get_options_default(&opts);
    opts.timeout_ms = 3000;
    z_owned_bytes_t payload;
    if (make_value(&payload, use_chunk, provider) != Z_OK) { printf("value failed\n"); return; }
    opts.payload = z_move(payload);
    int rc = z_get(s, ke, "", z_move(closure), &opts);
    printf("%s get rc=%d replies=%d\n", use_chunk ? "chunk" : "plain", rc, count_replies(&handler));
}

static void run_querier(const z_loaned_session_t *s, const z_loaned_keyexpr_t *ke,
                        const z_loaned_shm_provider_t *provider) {
    z_owned_querier_t querier;
    if (z_declare_querier(s, &querier, ke, NULL) < 0) { printf("querier failed\n"); return; }
    z_owned_closure_reply_t closure;
    z_owned_fifo_handler_reply_t handler;
    z_fifo_channel_reply_new(&closure, &handler, 16);
    z_querier_get_options_t opts;
    z_querier_get_options_default(&opts);
    z_owned_bytes_t payload;
    if (make_value(&payload, 1, provider) != Z_OK) { printf("value failed\n"); return; }
    opts.payload = z_move(payload);
    int rc = z_querier_get(z_loan(querier), "", z_move(closure), &opts);
    printf("querier get rc=%d replies=%d\n", rc, count_replies(&handler));
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

    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "probe/q");
    z_owned_closure_query_t qcb;
    z_closure(&qcb, on_query, NULL, NULL);
    z_owned_queryable_t qable;
    if (z_declare_queryable(z_loan(s), &qable, z_loan(ke), z_move(qcb), NULL) < 0) { printf("queryable failed\n"); return 3; }

    run_get(z_loan(s), z_loan(ke), 1, z_loan(provider));
    run_get(z_loan(s), z_loan(ke), 0, z_loan(provider));
    run_querier(z_loan(s), z_loan(ke), z_loan(provider));
    printf("done\n");
    return 0;
}
"#;

/// Compile the probe once per library and return what each printed.
fn run_both_arms(include: &Path) -> (String, String) {
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("probe source dir");
    std::fs::write(src_dir.join("wz_shm_query_local.c"), PROBE).expect("write the probe source");

    let lib = wz_capi_c_cdylib();
    let wz_libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_zenoh_c_example(
        "wz_shm_query_local",
        dir.path(),
        include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!(
            "§5.27 api-compat-c: the local-query probe does NOT link against wz's cdylib.\n{diag}"
        )
    });

    let reference = zenoh_c_shared_library().expect("the oracle resolved above");
    let libdir_ref = reference
        .parent()
        .expect("libzenohc.so has a parent")
        .to_path_buf();
    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let on_ref = compile_zenoh_c_example(
        "wz_shm_query_local",
        &ref_dir,
        include,
        &src_dir,
        &libdir_ref,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("the local-query probe does not link against the REAL libzenohc.so\n{diag}")
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
        "the local-query probe exited non-zero on wz's C ABI.\n\
         --- stdout on wz ---\n{wz_stdout}\n--- reference printed ---\n{ref_stdout}"
    );
    (wz_stdout, ref_stdout)
}

/// The lines the probe's subject prints. The real library writes a tracing line to stdout on a
/// querier's first get, which is not what is compared.
fn subject_lines(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .filter(|l| {
            l.starts_with("query:")
                || l.contains(" get rc=")
                || l.starts_with("done")
                || l.ends_with("failed")
        })
        .collect()
}

/// THE GATE: a queryable of the asking session is handed the same kind of buffer on wz and on
/// libzenohc, for a `z_get` with a chunk, a `z_get` with plain bytes and a querier's get with a
/// chunk.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_local_queryable_is_handed_the_same_kind_of_buffer_on_wz_and_libzenohc() {
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
    let (wz_lines, ref_lines) = (subject_lines(&wz_stdout), subject_lines(&ref_stdout));

    // The ORACLE first: two identical failures diff clean, and a reference that does not hand
    // a local queryable a shared-memory buffer would make the equality below say nothing about
    // the leg this file exists for.
    let chunk_answers = ref_lines
        .iter()
        .filter(|l| l.starts_with("query: as_loaned_shm rc=0 len=64"))
        .count();
    assert_eq!(
        chunk_answers, 2,
        "the reference did not hand the queryable a shared-memory buffer for BOTH the get and the \
         querier's get, so the rule this leg compares against is not what it assumes:\n{ref_stdout}"
    );
    assert!(
        ref_lines
            .iter()
            .any(|l| l.starts_with("query: as_loaned_shm rc=-1 len=11")),
        "the reference did not hand the plain-bytes get a raw payload:\n{ref_stdout}"
    );
    assert!(
        ref_lines.contains(&"chunk get rc=0 replies=1")
            && ref_lines.contains(&"plain get rc=0 replies=1")
            && ref_lines.contains(&"querier get rc=0 replies=1")
            && ref_lines.contains(&"done"),
        "the reference did not run all three gets to a reply:\n{ref_stdout}"
    );

    assert_eq!(
        wz_lines, ref_lines,
        "§5.27 api-compat-c: wz's C ABI and libzenohc hand a local queryable a different kind of \
         buffer for a query value in shared memory.\n--- wz ---\n{wz_stdout}--- libzenohc \
         ---\n{ref_stdout}"
    );
}
