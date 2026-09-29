// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` — a query a session asks of ITSELF, kept by the
//! queryable that received it, holds the get open until it is dropped: one C
//! program, compiled once, linked against wz's cdylib and against the real
//! `libzenohc.so`, stdout diffed.
//!
//! ## Upstream's rule
//!
//! A local query is a `Query` like a remote one; its `QueryInner` carries the
//! session as its primitives, and dropping the last clone sends the
//! `ResponseFinal` along that route (`zenoh/src/api/queryable.rs` @
//! `impl Drop for QueryInner {`). So a `z_query_clone` taken inside the
//! callback keeps the local get open, a reply made through it later reaches
//! the get, and `z_query_drop` ends it.
//!
//! ## What this pins (R2953, open-debt item 836)
//!
//! wz's local get used to finalise as soon as the queryable callbacks
//! returned, and each C ABI's escaped query answered only on the wire: the
//! probe measured the get ended while the query was still held, and the late
//! reply lost. The legs read the reply closure's DROP count — the completion
//! signal on every path of both implementations — while the query is held,
//! and again after it is answered and dropped.
//!
//! Waited for, not read at once: wz runs a local queryable on its drive thread
//! rather than inside `z_get` (R311y554), so the hold is polled for. That
//! timing is its own question and is not what this leg claims.

use std::path::{Path, PathBuf};
use std::process::Command;

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

static const char *KE = "acdemo/held/thing";

/* The get's reply closure: replies counted, its drop is the completion. */
static volatile int replies = 0;
static volatile int dropped = 0;

static void reply_call(z_loaned_reply_t *reply, void *ctx) {
    (void)ctx;
    if (z_reply_is_ok(reply)) { replies++; }
}

static void reply_drop(void *ctx) {
    (void)ctx;
    dropped++;
}

/* The queryable HOLDS the query it receives and does not answer it. */
static z_owned_query_t held_query;
static volatile int held = 0;

static void on_query(z_loaned_query_t *query, void *ctx) {
    (void)ctx;
    if (!held) {
        z_query_clone(&held_query, query);
        held = 1;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: probe <listen-endpoint>\n"); return 2; }

    /* One session, listening on one endpoint and connected to nothing: wz's
       z_open refuses a config with neither endpoint. */
    z_owned_config_t config;
    if (z_config_default(&config) != Z_OK) { printf("config=FAILED\n"); return 1; }
    if (zc_config_insert_json5(z_config_loan_mut(&config),
                               "scouting/multicast/enabled", "false") != Z_OK) {
        printf("config.scouting=FAILED\n"); return 1;
    }
    char listen[256];
    snprintf(listen, sizeof listen, "[\"%s\"]", argv[1]);
    if (zc_config_insert_json5(z_config_loan_mut(&config),
                               "listen/endpoints", listen) != Z_OK) {
        printf("config.listen=FAILED\n"); return 1;
    }
    z_owned_session_t session;
    if (z_open(&session, z_move(config), NULL) != Z_OK) { printf("open=FAILED\n"); return 1; }

    z_view_keyexpr_t ke;
    if (z_view_keyexpr_from_str(&ke, KE) != Z_OK) { printf("ke=FAILED\n"); return 1; }
    z_owned_closure_query_t qcallback;
    z_closure_query(&qcallback, on_query, NULL, NULL);
    z_owned_queryable_t queryable;
    if (z_declare_queryable(z_loan(session), &queryable, z_loan(ke), z_move(qcallback), NULL)
        != Z_OK) {
        printf("queryable=FAILED\n"); return 1;
    }

    z_owned_closure_reply_t closure;
    z_closure_reply(&closure, reply_call, reply_drop, NULL);
    z_get_options_t g;
    z_get_options_default(&g);
    g.timeout_ms = 60000;
    printf("get.rc=%d\n", (int)z_get(z_loan(session), z_loan(ke), "", z_move(closure), &g));

    for (int i = 0; i < 300 && !held; i++) { z_sleep_ms(10); }
    printf("held=%d\n", held);
    /* Long enough for a wrongly-finalised get to have dropped its closure. */
    z_sleep_ms(300);
    printf("dropped_while_held=%d\n", dropped);

    if (held) {
        z_owned_bytes_t body;
        z_bytes_copy_from_str(&body, "late");
        printf("reply.rc=%d\n",
               (int)z_query_reply(z_query_loan(&held_query), z_loan(ke), z_move(body), NULL));
        z_query_drop(z_query_move(&held_query));
    }
    for (int i = 0; i < 300 && !dropped; i++) { z_sleep_ms(10); }
    printf("dropped_after_release=%d\n", dropped);
    printf("replies=%d\n", replies);

    z_queryable_drop(z_queryable_move(&queryable));
    z_session_drop(z_session_move(&session));
    printf("done\n");
    return 0;
}
"#;

/// Compile the probe once and run it against each library, each on its own
/// reserved port.
fn run_both_arms(include: &Path) -> (String, String) {
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("probe source dir");
    std::fs::write(src_dir.join("wz_local_held.c"), PROBE).expect("write the probe source");

    let lib = wz_capi_c_cdylib();
    let wz_libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_zenoh_c_example(
        "wz_local_held",
        dir.path(),
        include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!(
            "§5.27 api-compat-c: the held-query probe does NOT link against wz's cdylib.\n{diag}"
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
        "wz_local_held",
        &ref_dir,
        include,
        &src_dir,
        &libdir_ref,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("the held-query probe does not link against the REAL libzenohc.so\n{diag}")
    });

    let run = |exe: &Path, libdir: &Path| -> (bool, String) {
        let port = PortReservation::pick();
        let out = Command::new(exe)
            .arg(format!("tcp/127.0.0.1:{}", port.port()))
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
        "the held-query probe exited non-zero on wz's C ABI.\n\
         --- stdout on wz ---\n{wz_stdout}\n--- reference printed ---\n{ref_stdout}"
    );
    (wz_stdout, ref_stdout)
}

/// THE GATE: a session-local query a queryable keeps holds its get open until
/// it is dropped, and the reply made through it reaches the get, on wz as on
/// libzenohc.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "opens a session and reads a zenoh-c oracle; run by run-ci Layer C1cc \
            (which builds the matching ABI arm this needs)"]
fn a_held_local_query_keeps_its_get_open_identically_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    assert_zenoh_c_arm_pairing(&include);
    let (wz_stdout, ref_stdout) = run_both_arms(&include);

    // The ORACLE first and in full: two identical failures diff clean.
    assert!(
        ref_stdout.contains("done"),
        "the reference arm did not reach the end of the probe:\n{ref_stdout}"
    );
    assert!(
        ref_stdout.contains("held=1") && ref_stdout.contains("dropped_while_held=0"),
        "the reference does not keep a held local query's get open at this pin, so \
         the claim this leg holds wz to is not upstream's:\n{ref_stdout}"
    );
    assert!(
        ref_stdout.contains("dropped_after_release=1") && ref_stdout.contains("replies=1"),
        "the reference does not deliver the held query's reply and end the get on \
         its drop:\n{ref_stdout}"
    );

    assert_eq!(
        wz_stdout, ref_stdout,
        "§5.27 api-compat-c: wz's C ABI and libzenohc disagree about a held \
         session-local query.\n--- wz ---\n{wz_stdout}--- libzenohc ---\n{ref_stdout}"
    );
}
