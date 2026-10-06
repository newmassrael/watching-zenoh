// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` -- WHERE a delivery a session makes to itself runs: inside the call that
//! causes it, on the calling thread, as zenoh-c runs it.
//!
//! A put whose subscriber is in the same session, a get whose queryable is, a put made from
//! inside a callback: on the real `libzenohc.so` each completes its callbacks before the call
//! returns. wz staged them and ran them on its drive thread a moment later, so a program that
//! puts and then reads what its callback set read the old value, and one that printed from both
//! printed in the other order. That is not a race the program can be written around: it is the
//! order the program's own output has.
//!
//! One C program logs every callback and every return, in the order they happen, and pauses
//! after each operation so a delivery that lands late lands BEFORE the next marker, which is what
//! makes the ORDER the thing compared and not a race. It is compiled once and linked to each
//! library. The real library's log is asserted first, against the order measured.
//!
//! The rows are: a put, a publisher's put, a delete, a put from inside a callback (the inner
//! callback runs BETWEEN the outer one's first and last event, which is what "inline" means),
//! a get (the queryable, its reply, the reply's callback and the final, all before `z_get`
//! returns), a get from inside a callback, and a subscriber declared from inside one.

use std::path::PathBuf;
use std::process::Command;

use wz_integration_tests::common::{
    assert_zenoh_c_arm_pairing, compile_zenoh_c_example, wz_capi_c_cdylib, zenoh_c_oracle,
    zenoh_c_shared_library,
};

const PROBE: &str = r#"#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "zenoh.h"

static pthread_t g_main;
static char g_log[2048];
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static z_owned_session_t g_s;

/* "@c" marks an event that ran on the calling thread and "@o" one that ran on another. */
static void ev(const char* what) {
    pthread_mutex_lock(&g_mu);
    size_t n = strlen(g_log);
    snprintf(g_log + n, sizeof g_log - n, "%s@%c ", what, pthread_equal(pthread_self(), g_main) ? 'c' : 'o');
    pthread_mutex_unlock(&g_mu);
}

static void mark(const char* what) {
    pthread_mutex_lock(&g_mu);
    size_t n = strlen(g_log);
    snprintf(g_log + n, sizeof g_log - n, "[%s] ", what);
    pthread_mutex_unlock(&g_mu);
}

static void on_sub(z_loaned_sample_t* sample, void* arg) {
    (void)sample;
    ev((const char*)arg);
}

static void on_sub_nested(z_loaned_sample_t* sample, void* arg) {
    (void)sample; (void)arg;
    ev("outer-begin");
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "demo/inline/inner");
    z_owned_bytes_t p;
    z_bytes_copy_from_str(&p, "n");
    z_put(z_loan(g_s), z_loan(ke), z_move(p), NULL);
    ev("outer-end");
}

static void on_query(z_loaned_query_t* query, void* arg) {
    (void)arg;
    ev("query");
    z_owned_bytes_t p;
    z_bytes_copy_from_str(&p, "r");
    z_query_reply(query, z_query_keyexpr(query), z_move(p), NULL);
    ev("replied");
}

static void on_reply(z_loaned_reply_t* reply, void* arg) {
    (void)reply; (void)arg;
    ev("reply");
}

static void on_done(void* arg) {
    (void)arg;
    ev("done");
}

static void sub(const char* key, void (*cb)(z_loaned_sample_t*, void*), const char* tag);

static void on_sub_gets(z_loaned_sample_t* sample, void* arg) {
    (void)sample; (void)arg;
    ev("g-begin");
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "demo/inline/q");
    z_owned_closure_reply_t rc;
    z_closure(&rc, on_reply, on_done, NULL);
    z_get(z_loan(g_s), z_loan(ke), "", z_move(rc), NULL);
    ev("g-end");
}

static void on_sub_declares(z_loaned_sample_t* sample, void* arg) {
    (void)sample; (void)arg;
    ev("d-begin");
    sub("demo/inline/fresh", on_sub, "sub-fresh");
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "demo/inline/fresh");
    z_owned_bytes_t p;
    z_bytes_copy_from_str(&p, "f");
    z_put(z_loan(g_s), z_loan(ke), z_move(p), NULL);
    ev("d-end");
}

static void sub(const char* key, void (*cb)(z_loaned_sample_t*, void*), const char* tag) {
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, key);
    z_owned_closure_sample_t c;
    z_closure(&c, cb, NULL, (void*)tag);
    z_declare_background_subscriber(z_loan(g_s), z_loan(ke), z_move(c), NULL);
}

static void put_on(const char* key) {
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, key);
    z_owned_bytes_t p;
    z_bytes_copy_from_str(&p, "x");
    z_put(z_loan(g_s), z_loan(ke), z_move(p), NULL);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    g_main = pthread_self();
    z_owned_config_t config;
    z_config_default(&config);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MULTICAST_SCOUTING_KEY, "false");
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_LISTEN_KEY, "[\"tcp/127.0.0.1:0\"]");
    if (z_open(&g_s, z_move(config), NULL) < 0) { printf("open failed\n"); return 1; }

    sub("demo/inline/put", on_sub, "sub-put");
    sub("demo/inline/pub", on_sub, "sub-pub");
    sub("demo/inline/del", on_sub, "sub-del");
    sub("demo/inline/outer", on_sub_nested, "x");
    sub("demo/inline/inner", on_sub, "sub-inner");

    put_on("demo/inline/put");
    mark("ret:put");
    usleep(300 * 1000);

    {
        z_view_keyexpr_t ke;
        z_view_keyexpr_from_str(&ke, "demo/inline/pub");
        z_owned_publisher_t pub;
        z_declare_publisher(z_loan(g_s), &pub, z_loan(ke), NULL);
        z_owned_bytes_t p;
        z_bytes_copy_from_str(&p, "x");
        z_publisher_put(z_loan(pub), z_move(p), NULL);
        mark("ret:publisher_put");
        usleep(300 * 1000);
        z_drop(z_move(pub));
    }

    {
        z_view_keyexpr_t ke;
        z_view_keyexpr_from_str(&ke, "demo/inline/del");
        z_delete(z_loan(g_s), z_loan(ke), NULL);
        mark("ret:delete");
        usleep(300 * 1000);
    }

    put_on("demo/inline/outer");
    mark("ret:nested");
    usleep(300 * 1000);

    {
        z_view_keyexpr_t ke;
        z_view_keyexpr_from_str(&ke, "demo/inline/q");
        z_owned_closure_query_t qc;
        z_closure(&qc, on_query, NULL, NULL);
        z_owned_queryable_t q;
        z_declare_queryable(z_loan(g_s), &q, z_loan(ke), z_move(qc), NULL);
        z_owned_closure_reply_t rc;
        z_closure(&rc, on_reply, on_done, NULL);
        z_get(z_loan(g_s), z_loan(ke), "", z_move(rc), NULL);
        mark("ret:get");
        usleep(500 * 1000);

        sub("demo/inline/gets", on_sub_gets, "x");
        put_on("demo/inline/gets");
        mark("ret:put-that-gets");
        usleep(500 * 1000);
        z_drop(z_move(q));
    }

    sub("demo/inline/declares", on_sub_declares, "x");
    put_on("demo/inline/declares");
    mark("ret:put-that-declares");
    usleep(500 * 1000);

    printf("%s\n", g_log);
    z_drop(z_move(g_s));
    return 0;
}
"#;

/// The order the REAL library was measured to run it in, every callback on the calling thread.
const EXPECTED: &str = "sub-put@c [ret:put] sub-pub@c [ret:publisher_put] sub-del@c [ret:delete] \
outer-begin@c sub-inner@c outer-end@c [ret:nested] \
query@c replied@c reply@c done@c [ret:get] \
g-begin@c query@c replied@c reply@c done@c g-end@c [ret:put-that-gets] \
d-begin@c sub-fresh@c d-end@c [ret:put-that-declares]";

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

/// Run the probe linked to `libdir`'s library and return its one line of log.
fn run(exe: &std::path::Path, libdir: &std::path::Path) -> String {
    let out = Command::new(exe)
        .env("LD_LIBRARY_PATH", libdir)
        .output()
        .expect("run the probe");
    assert!(
        out.status.success(),
        "the probe exited {:?}:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// THE GATE: a delivery a session makes to itself runs inside the call that causes it, on the
/// calling thread, in the same order on wz as on the real library.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_delivery_a_session_makes_to_itself_runs_inside_the_call_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    assert_zenoh_c_arm_pairing(&include);
    let work = tempfile::tempdir().expect("tempdir for the compiled programs");
    let src = work.path().join("src");
    std::fs::create_dir_all(&src).expect("source dir");
    std::fs::write(src.join("inline_probe.c"), PROBE).expect("write the source");

    let reference_lib = zenoh_c_shared_library().expect("the oracle resolved above");
    let reference_dir = reference_lib.parent().expect("libzenohc.so has a parent");
    let wz_lib = wz_capi_c_cdylib();
    let wz_dir = wz_lib.parent().expect("cdylib has a parent");

    let ref_out = work.path().join("zenohc");
    let wz_out = work.path().join("wz_capi_c");
    std::fs::create_dir_all(&ref_out).expect("build dir");
    std::fs::create_dir_all(&wz_out).expect("build dir");
    let reference = compile_zenoh_c_example(
        "inline_probe",
        &ref_out,
        &include,
        &src,
        reference_dir,
        "zenohc",
    )
    .unwrap_or_else(|d| panic!("the probe does not link against the REAL libzenohc.so\n{d}"));
    let wz = compile_zenoh_c_example("inline_probe", &wz_out, &include, &src, wz_dir, "wz_capi_c")
        .unwrap_or_else(|d| panic!("§5.27 api-compat-c: the probe does NOT link against wz\n{d}"));

    let oracle = run(&reference, reference_dir);
    assert_eq!(
        oracle, EXPECTED,
        "the REAL library's order is not the one this file expects"
    );
    let got = run(&wz, wz_dir);
    assert_eq!(
        got, oracle,
        "§5.27 api-compat-c: a delivery wz's session makes to itself does not run where the real \
         library's does\n  libzenohc {oracle}\n  wz        {got}"
    );
}
