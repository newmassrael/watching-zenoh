// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` — the CANCELLATION TOKEN plane on the zenoh-c ABI,
//! adjudicated by the real `libzenohc.so`.
//!
//! ## The residual this closes
//!
//! Until R2949 the zenoh-c ABI declared the token family (new / cancel /
//! is_cancelled / clone / drop) over a bare shared flag, and the three option
//! structs that carry a token — `z_get_options_t`, `z_querier_get_options_t`,
//! `z_liveliness_get_options_t` — typed the slot `void *` and ignored it. A C
//! program could build a token, hand it to a get, cancel it, and the get ran on
//! as if nothing had happened, with every call reporting success. The pico ABI
//! had the real plane; R2949 moved it into `wz-capi-core` and put both ABIs on
//! it.
//!
//! ## What upstream does, read rather than inferred
//!
//! * A get registers an on-cancel handler and a notifier on the token BEFORE it
//!   is sent; a token whose cancel has started refuses the registration and the
//!   get fails with "Query was cancelled"
//!   (`zenoh/src/api/session.rs` @ `bail!("Query was cancelled")`), which
//!   zenoh-c reports as `Z_EGENERIC`. The callback is dropped on that path, so
//!   its `drop(context)` runs.
//! * `z_cancellation_token_cancel` runs the handlers — which drop the get's
//!   callback — and "blocks until execution of callback is finished".
//!
//! ## The legs
//!
//! Two sessions in one process: a serving one that LISTENS and declares the
//! queryable, and an asking one that CONNECTS to it.
//!
//! - **legB** — an ALREADY-cancelled token on `z_get`: the rc, whether the
//!   reply closure's drop ran, and whether the moved handle was consumed.
//! - **legC** — a LIVE token cancelled while the get is outstanding. The
//!   serving session's queryable clones the query it receives and does not
//!   answer, so the get cannot end for any reason other than the cancel. The
//!   drop count is read either side of the cancel, then once more after the
//!   held query is finally answered (the reply must have nowhere to land).
//!
//!   Why not ONE session with a session-local queryable, which would be
//!   simpler: this probe was first written that way, and wz ended the get
//!   BEFORE the cancel while zenoh-c kept it open — wz's local get finalises
//!   its local leg before a C queryable that holds the query has run
//!   (open-debt item 836). That is a divergence of the local query plane, not of
//!   cancellation, so legC must not stand on it.
//! - **legD** — `z_querier_get`, already-cancelled: the second reader of the
//!   field, at a different offset.
//! - **legE** — `z_liveliness_get`, already-cancelled: the third reader.
//!
//! The drop COUNT is the observable because it is the one signal that tells a
//! cancelled get from a timed-out one and from one never issued: it is the
//! completion signal on every path on both implementations.
//!
//! Each session opens with ONE endpoint in ONE role, the intersection of what
//! both ABIs open (see `zenoh_c_local_queryable_matching_twice_and_diff`).

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

static const char *KE = "acdemo/cancel/thing";

/* One counter per leg: the reply closure's drop increments its own. */
static int dropped_b = 0;
static int dropped_c = 0;
static int dropped_d = 0;
static int dropped_e = 0;

static void reply_call(z_loaned_reply_t *reply, void *ctx) {
    (void)reply;
    (void)ctx;
}

static void reply_drop(void *ctx) {
    int *slot = (int *)ctx;
    (*slot)++;
}

/* legC's queryable HOLDS the query it receives, so the get stays pending.
   `volatile`: the queryable runs on the serving session's own thread. */
static z_owned_query_t held_query;
static volatile int held = 0;

static void on_query(z_loaned_query_t *query, void *ctx) {
    (void)ctx;
    if (!held) {
        z_query_clone(&held_query, query);
        held = 1;
    }
}

static void legB(const z_loaned_session_t *s, const z_loaned_keyexpr_t *ke) {
    z_owned_cancellation_token_t t;
    if (z_cancellation_token_new(&t) != Z_OK) { printf("legB.token_new=FAILED\n"); return; }
    printf("legB.cancel.rc=%d\n", (int)z_cancellation_token_cancel(z_cancellation_token_loan_mut(&t)));
    printf("legB.is_cancelled=%d\n", (int)z_cancellation_token_is_cancelled(z_cancellation_token_loan(&t)));

    z_owned_closure_reply_t closure;
    z_closure_reply(&closure, reply_call, reply_drop, (void *)&dropped_b);
    z_get_options_t g;
    z_get_options_default(&g);
    g.cancellation_token = z_cancellation_token_move(&t);
    printf("legB.get.rc=%d\n", (int)z_get(s, ke, "", z_move(closure), &g));
    printf("legB.dropped=%d\n", dropped_b);
    printf("legB.token_spent=%d\n", (int)(!z_internal_cancellation_token_check(&t)));
    z_cancellation_token_drop(z_cancellation_token_move(&t));
}

static void legC(const z_loaned_session_t *s, const z_loaned_keyexpr_t *ke) {
    z_owned_cancellation_token_t t;
    if (z_cancellation_token_new(&t) != Z_OK) { printf("legC.token_new=FAILED\n"); return; }
    z_owned_cancellation_token_t keep;
    z_cancellation_token_clone(&keep, z_cancellation_token_loan(&t));

    z_owned_closure_reply_t closure;
    z_closure_reply(&closure, reply_call, reply_drop, (void *)&dropped_c);
    z_get_options_t g;
    z_get_options_default(&g);
    g.timeout_ms = 60000;
    g.cancellation_token = z_cancellation_token_move(&t);
    printf("legC.get.rc=%d\n", (int)z_get(s, ke, "", z_move(closure), &g));

    /* The queryable (on the OTHER session) must have taken the query, or the get
       was never pending and the transition below would be measuring nothing. It
       crosses a link, so it is waited for rather than read at once. */
    for (int i = 0; i < 300 && !held; i++) { z_sleep_ms(10); }
    printf("legC.held=%d\n", held);
    printf("legC.dropped_before_cancel=%d\n", dropped_c);
    printf("legC.cancel.rc=%d\n", (int)z_cancellation_token_cancel(z_cancellation_token_loan_mut(&keep)));
    printf("legC.dropped_after_cancel=%d\n", dropped_c);
    printf("legC.is_cancelled=%d\n", (int)z_cancellation_token_is_cancelled(z_cancellation_token_loan(&keep)));

    if (held) {
        z_owned_bytes_t body;
        z_bytes_copy_from_str(&body, "too-late");
        z_query_reply(z_query_loan(&held_query), ke, z_move(body), NULL);
        z_query_drop(z_query_move(&held_query));
    }
    printf("legC.dropped_after_reply=%d\n", dropped_c);
    z_cancellation_token_drop(z_cancellation_token_move(&keep));
}

static void legD(const z_loaned_session_t *s, const z_loaned_keyexpr_t *ke) {
    z_owned_querier_t querier;
    if (z_declare_querier(s, &querier, ke, NULL) != Z_OK) { printf("legD.declare=FAILED\n"); return; }
    z_owned_cancellation_token_t t;
    z_cancellation_token_new(&t);
    z_cancellation_token_cancel(z_cancellation_token_loan_mut(&t));

    z_owned_closure_reply_t closure;
    z_closure_reply(&closure, reply_call, reply_drop, (void *)&dropped_d);
    z_querier_get_options_t g;
    z_querier_get_options_default(&g);
    g.cancellation_token = z_cancellation_token_move(&t);
    printf("legD.get.rc=%d\n", (int)z_querier_get(z_querier_loan(&querier), "", z_move(closure), &g));
    printf("legD.dropped=%d\n", dropped_d);
    printf("legD.token_spent=%d\n", (int)(!z_internal_cancellation_token_check(&t)));
    z_querier_drop(z_querier_move(&querier));
}

static void legE(const z_loaned_session_t *s, const z_loaned_keyexpr_t *ke) {
    z_owned_cancellation_token_t t;
    z_cancellation_token_new(&t);
    z_cancellation_token_cancel(z_cancellation_token_loan_mut(&t));

    z_owned_closure_reply_t closure;
    z_closure_reply(&closure, reply_call, reply_drop, (void *)&dropped_e);
    z_liveliness_get_options_t g;
    z_liveliness_get_options_default(&g);
    g.cancellation_token = z_cancellation_token_move(&t);
    printf("legE.get.rc=%d\n", (int)z_liveliness_get(s, ke, z_move(closure), &g));
    printf("legE.dropped=%d\n", dropped_e);
    printf("legE.token_spent=%d\n", (int)(!z_internal_cancellation_token_check(&t)));
}

/* One endpoint, one role per session: the serving session LISTENS, the asking
   one CONNECTS — the shape both ABIs open (wz refuses listen+connect together). */
static int open_session(z_owned_session_t *s, const char *key, const char *endpoint) {
    z_owned_config_t config;
    if (z_config_default(&config) != Z_OK) { return -1; }
    if (zc_config_insert_json5(z_config_loan_mut(&config),
                               "scouting/multicast/enabled", "false") != Z_OK) {
        return -1;
    }
    char value[256];
    snprintf(value, sizeof value, "[\"%s\"]", endpoint);
    if (zc_config_insert_json5(z_config_loan_mut(&config), key, value) != Z_OK) { return -1; }
    return z_open(s, z_move(config), NULL) == Z_OK ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: probe <listen-endpoint>\n"); return 2; }

    z_owned_session_t srv;
    if (open_session(&srv, "listen/endpoints", argv[1]) < 0) { printf("open.srv=FAILED\n"); return 1; }
    z_view_keyexpr_t ke;
    if (z_view_keyexpr_from_str(&ke, KE) != Z_OK) { printf("ke=FAILED\n"); return 1; }
    z_owned_closure_query_t qcallback;
    z_closure_query(&qcallback, on_query, NULL, NULL);
    z_owned_queryable_t queryable;
    if (z_declare_queryable(z_loan(srv), &queryable, z_loan(ke), z_move(qcallback), NULL) != Z_OK) {
        printf("queryable=FAILED\n"); return 1;
    }

    z_owned_session_t cli;
    if (open_session(&cli, "connect/endpoints", argv[1]) < 0) { printf("open.cli=FAILED\n"); return 1; }
    /* Let the queryable's declaration reach the asking session. */
    z_sleep_ms(1000);

    legB(z_loan(cli), z_loan(ke));
    legC(z_loan(cli), z_loan(ke));
    legD(z_loan(cli), z_loan(ke));
    legE(z_loan(cli), z_loan(ke));

    z_queryable_drop(z_queryable_move(&queryable));
    z_session_drop(z_session_move(&cli));
    z_session_drop(z_session_move(&srv));
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
    std::fs::write(src_dir.join("wz_cancellation.c"), PROBE).expect("write the probe source");

    let lib = wz_capi_c_cdylib();
    let wz_libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_zenoh_c_example(
        "wz_cancellation",
        dir.path(),
        include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!(
            "§5.27 api-compat-c: the cancellation probe does NOT link against wz's cdylib.\n{diag}"
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
        "wz_cancellation",
        &ref_dir,
        include,
        &src_dir,
        &libdir_ref,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("the cancellation probe does not link against the REAL libzenohc.so\n{diag}")
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
        "the cancellation probe exited non-zero on wz's C ABI.\n\
         --- stdout on wz ---\n{wz_stdout}\n--- reference printed ---\n{ref_stdout}"
    );
    (wz_stdout, ref_stdout)
}

/// THE GATE: a cancellation token stops the gets it was handed, on all three
/// readers, and wz answers what zenoh's own library answers.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "opens a session and reads a zenoh-c oracle; run by run-ci Layer C1cc \
            (which builds the matching ABI arm this needs)"]
fn a_cancellation_token_stops_a_get_identically_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    // The token family and the three option fields exist only in the unstable
    // arm, upstream's and wz's alike, so an oracle built without it has nothing
    // to adjudicate. READ from the oracle's own configure header, the file
    // Layer C1cc derives its build arm from.
    let configure = std::fs::read_to_string(include.join("zenoh_configure.h")).unwrap_or_default();
    if !configure
        .lines()
        .any(|l| l.trim() == "#define Z_FEATURE_UNSTABLE_API")
    {
        eprintln!(
            "skip: this zenoh-c oracle is built WITHOUT Z_FEATURE_UNSTABLE_API, where \
             cancellation tokens do not exist on either implementation."
        );
        return;
    }
    assert_zenoh_c_arm_pairing(&include);
    let (wz_stdout, ref_stdout) = run_both_arms(&include);

    // The ORACLE first and in full: two identical failures diff clean.
    assert!(
        ref_stdout.contains("done"),
        "the reference arm did not reach the end of the probe:\n{ref_stdout}"
    );
    assert!(
        ref_stdout.contains("legC.held=1"),
        "the reference's local queryable did not take the query, so legC's get was \
         never outstanding and its transition measures nothing:\n{ref_stdout}"
    );
    assert!(
        ref_stdout.contains("legC.dropped_before_cancel=0")
            && ref_stdout.contains("legC.dropped_after_cancel=1"),
        "the reference does not end a live get at cancel at this pin, so the claim \
         this leg holds wz to is not upstream's:\n{ref_stdout}"
    );

    assert_eq!(
        wz_stdout, ref_stdout,
        "§5.27 api-compat-c: wz's C ABI and libzenohc disagree about what a \
         cancellation token does to a get.\n--- wz ---\n{wz_stdout}--- libzenohc ---\n{ref_stdout}"
    );
}
