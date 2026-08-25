// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-pico` — the CANCELLATION TOKEN plane, adjudicated by a real
//! `libzenohpico.so`.
//!
//! ## The residual this closes
//!
//! The debt ledger carried `cancellation_token` as "ACCEPTED FOR LAYOUT AND
//! NEVER READ" on `z_get_options_t` and `z_querier_get_options_t`: wz had the
//! token TYPE (`z_cancellation_token_new` / `_cancel` / `_is_cancelled` /
//! `_clone`) and no plane behind it, so a C program could build a token, hand it
//! to a get, and get back a query nothing could cancel — with the call reporting
//! success. R311y574 measured that the only assignment in the tree was the
//! default writer's `= null_mut()`.
//!
//! Two further defects sat inside that one, and neither is visible from the
//! struct:
//!
//! * The field is a `z_moved_cancellation_token_t *` — an ownership TRANSFER
//!   upstream consumes unconditionally (`z_cancellation_token_drop(
//!   opt.cancellation_token)`, `vendor/zenoh-pico/src/api/api.c:1783`). Reading
//!   it as an opaque pointer and dropping it on the floor leaked one token per
//!   get and left the caller's owned struct non-null.
//! * `z_liveliness_get_options_t` carries the same field, and wz declared that
//!   struct at 8 B against a reference header that makes it 16 B. See
//!   `pico_abi_option_layout.rs`, where the type is now pinned; this file
//!   measures the CONSEQUENCE that a layout gate cannot see.
//!
//! ## What upstream actually does, and why each leg is deterministic
//!
//! Read out of the vendored source, not inferred from the API's shape:
//!
//! * `_z_pending_query_register_cancellation` installs an on-cancel handler
//!   whose body is `_z_unregister_pending_query(zn, qid)`
//!   (`src/session/query.c:290-334`), and `_z_pending_query_clear` runs the
//!   query's `_dropper` (`src/session/query.c:29-41`). So cancelling is not a
//!   distinct delivery state: the pending query stops existing and the reply
//!   closure's DROP fires, synchronously, on the cancelling thread.
//! * `_z_cancellation_token_add_on_cancel_handler` answers `Z_ERR_CANCELLED`
//!   (`-69`, `utils/result.h:98`) once cancel has started
//!   (`src/session/cancellation.c:171-181`), and `_z_query` returns that after
//!   unregistering — WITHOUT sending a Query
//!   (`src/net/primitives.c:606-629`). So an already-cancelled token makes the
//!   get FAIL, and the failure is a specific code a program can branch on.
//!
//! That gives five legs with no sleep and no scheduler dependence:
//!
//! - **legA** — the DEFAULT writer's tail. Poison the options struct, call
//!   `z_liveliness_get_options_default`, ask whether the token slot was
//!   written. This is the observable half of the 8-vs-16 byte defect: a build
//!   that stops at `timeout_ms` leaves a caller's stack garbage where upstream
//!   writes NULL.
//! - **legB** — an ALREADY-CANCELLED token on `z_get`. The return code and
//!   whether the reply closure's drop fired.
//! - **legC** — a LIVE token cancelled while the get is outstanding, against a
//!   queryable that never replies. The drop count is read before and after the
//!   cancel, so the leg measures a TRANSITION rather than an end state.
//! - **legD / legE** — the same already-cancelled token through
//!   `z_querier_get` and `z_liveliness_get`.
//!
//! ## Why legD and legE exist when the seam is shared
//!
//! All three entry points funnel into ONE issue seam inside wz, so it is
//! tempting to call legB's result a measurement of all three. R311y572 is the
//! standing correction to that: a shared seam is a CLAIM until the senders and
//! the readers are counted. Here there is one sender and **three readers** — the
//! field sits at a different offset in each of the three option structs
//! (64 / 24 / 8), and upstream declares the `source_info` /
//! `cancellation_token` pair in OPPOSITE orders in two of them. R311y562's
//! defect was exactly an offset, so a leg per reader is a leg per thing that can
//! be wrong. Each of the five legs was damage-probed separately and each fails on
//! its own lines.
//!
//! ## Why the drop COUNT and not a delivery
//!
//! A cancelled get has nothing to deliver, so "no reply arrived" is true of a
//! cancelled get, a timed-out get and a get that was never issued alike. The
//! reply closure's `drop(context)` is the one signal that distinguishes them:
//! it is this tree's completion signal on every path and upstream's `_dropper`
//! on every path, so a count read either side of the cancel says exactly when
//! the get ended.

use std::path::{Path, PathBuf};
use std::process::Command;

use wz_integration_tests::common::{
    compile_pico_source, wz_capi_pico_cdylib, zenoh_pico_include_dirs, zenoh_pico_library_dir,
    zenoh_pico_shared_library, PortReservation,
};

/// Three legs over one session pair. Written here rather than patched into
/// `vendor/zenoh-pico` for the reason the sibling adjudicators give: a patched
/// submodule is a reference nobody can trust twice.
const PROBE: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zenoh-pico.h"

/* One counter per leg. The reply closure's drop increments its own, so a leg's
   completion is a number rather than a wait. */
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

/* `key` is `uint8_t`, not `const char *`: pico's config keys are small integer
   constants (`Z_CONFIG_LISTEN_KEY` is `0x42`) and `zp_config_insert` takes a
   `uint8_t`. */
static int open_session(z_owned_session_t *out, uint8_t key, const char *endpoint) {
    z_owned_config_t config;
    z_config_default(&config);
    if (zp_config_insert(z_loan_mut(config), Z_CONFIG_MODE_KEY, "peer") < 0) return -1;
    if (zp_config_insert(z_loan_mut(config), key, endpoint) < 0) return -1;
    if (z_open(out, z_move(config), NULL) < 0) return -1;
    if (zp_start_read_task(z_loan_mut(*out), NULL) < 0) return -1;
    if (zp_start_lease_task(z_loan_mut(*out), NULL) < 0) return -1;
    return 0;
}

/* legA -- the DEFAULT writer's tail, on the struct whose size was wrong.
   The whole struct is poisoned first, so "the default wrote this slot" is
   distinguishable from "the slot happened to be zero". */
static void legA(void) {
    z_liveliness_get_options_t o;
    memset(&o, 0xAA, sizeof(o));
    /* Printed so a build compiled against a DIFFERENT header shows the
       disagreement here rather than as an unexplained tail difference. Same on
       both arms by construction (one header, two links), which is what makes it
       an anchor rather than a measurement. */
    printf("legA.sizeof=%zu\n", sizeof(z_liveliness_get_options_t));
    z_result_t rc = z_liveliness_get_options_default(&o);
    printf("legA.default.rc=%d\n", (int)rc);
    printf("legA.timeout_written=%d\n", (int)(o.timeout_ms == 0));
#ifdef Z_FEATURE_UNSTABLE_API
    /* NOT the pointer value: an address would differ run to run. Whether the
       slot was WRITTEN is the property, and 0xAA poison makes "unwritten"
       distinguishable from "written NULL". */
    printf("legA.token_written=%d\n", (int)(o.cancellation_token == NULL));
#else
    printf("legA.token_written=absent\n");
#endif
}

/* legB -- an ALREADY-CANCELLED token handed to z_get. */
static void legB(const z_loaned_session_t *cli, const z_loaned_keyexpr_t *ke) {
    z_owned_cancellation_token_t t;
    if (z_cancellation_token_new(&t) < 0) { printf("legB.token_new=FAILED\n"); return; }
    printf("legB.cancel.rc=%d\n", (int)z_cancellation_token_cancel(z_cancellation_token_loan_mut(&t)));
    printf("legB.is_cancelled=%d\n", (int)z_cancellation_token_is_cancelled(z_cancellation_token_loan(&t)));

    z_owned_closure_reply_t rclosure;
    if (z_closure_reply(&rclosure, reply_call, reply_drop, (void *)&dropped_b) < 0) {
        printf("legB.closure=FAILED\n"); return;
    }

    z_get_options_t g;
    z_get_options_default(&g);
    /* A long timeout so no sweep can be mistaken for the cancellation. */
    g.timeout_ms = 60000;
    g.cancellation_token = z_cancellation_token_move(&t);

    z_result_t rc = z_get(cli, ke, "", z_move(rclosure), &g);
    /* THE LEG. Z_ERR_CANCELLED is -69; the raw number is printed rather than
       compared to a constant here, so the diff decides and this file asserts
       nothing about the answer in advance. */
    printf("legB.get.rc=%d\n", (int)rc);
    /* The get is over either way -- the question is whether the CALLEE said so
       by running the drop. */
    printf("legB.dropped=%d\n", dropped_b);
    /* The moved token must be spent: the callee owns it now, on both ABIs. */
    printf("legB.token_spent=%d\n", (int)(!z_internal_cancellation_token_check(&t)));
    z_drop(z_move(t));
}

/* legC -- a LIVE token cancelled while the get is outstanding.
   The queryable receives the query and never replies, so the get cannot end for
   any reason other than the cancel. */
static void legC(const z_loaned_session_t *cli,
                 const z_loaned_fifo_handler_query_t *qhandler,
                 const z_loaned_keyexpr_t *ke) {
    z_owned_cancellation_token_t t;
    if (z_cancellation_token_new(&t) < 0) { printf("legC.token_new=FAILED\n"); return; }

    z_owned_closure_reply_t rclosure;
    if (z_closure_reply(&rclosure, reply_call, reply_drop, (void *)&dropped_c) < 0) {
        printf("legC.closure=FAILED\n"); return;
    }

    z_get_options_t g;
    z_get_options_default(&g);
    g.timeout_ms = 60000;
    z_owned_cancellation_token_t held;
    /* A CLONE is kept so the get can be cancelled after the moved handle is
       consumed -- the refcounted-value semantics the type exists for. */
    if (z_cancellation_token_clone(&held, z_cancellation_token_loan(&t)) < 0) {
        printf("legC.clone=FAILED\n"); return;
    }
    g.cancellation_token = z_cancellation_token_move(&t);

    z_result_t rc = z_get(cli, ke, "", z_move(rclosure), &g);
    printf("legC.get.rc=%d\n", (int)rc);

    /* Receiving the query is what proves the get is really outstanding: without
       it, a zero-peer session would complete the get immediately and the
       transition below would be measuring nothing. */
    z_owned_query_t q;
    printf("legC.query.recv.rc=%d\n", (int)z_recv(qhandler, &q));
    printf("legC.dropped_before_cancel=%d\n", dropped_c);

    printf("legC.cancel.rc=%d\n", (int)z_cancellation_token_cancel(z_cancellation_token_loan_mut(&held)));
    /* THE LEG: the TRANSITION. An end state alone could not tell a cancelled get
       apart from one that was never issued. */
    printf("legC.dropped_after_cancel=%d\n", dropped_c);

    /* The query is answered only AFTER the cancel, so the reply has nowhere to
       land. Printed because a divergence here would be a divergence in what
       cancellation removed, not in whether it happened. */
    z_owned_bytes_t body;
    z_bytes_copy_from_str(&body, "too-late");
    printf("legC.reply.rc=%d\n", (int)z_query_reply(z_loan(q), ke, z_move(body), NULL));
    z_drop(z_move(q));
    printf("legC.dropped_after_reply=%d\n", dropped_c);
    z_drop(z_move(held));
}

/* legD -- the SECOND reader of the field: `z_querier_get_options_t`.
   `z_get` and `z_querier_get` share one issue seam inside wz, so their
   cancellation SEMANTICS cannot diverge -- but they do not share the option
   STRUCT, and `cancellation_token` sits at a different offset in each (24 here,
   64 in `z_get_options_t`, and upstream declares the pair in opposite orders in
   the two structs). R311y562's whole defect was an offset, so a leg that only
   drove `z_get` would leave this read unmeasured and call the seam a
   measurement. An already-cancelled token is the discriminator: a build that
   read the wrong 8 bytes cannot answer -69. */
static void legD(const z_loaned_session_t *cli, const z_loaned_keyexpr_t *ke) {
    z_owned_querier_t querier;
    if (z_declare_querier(cli, &querier, ke, NULL) < 0) { printf("legD.declare=FAILED\n"); return; }

    z_owned_cancellation_token_t t;
    if (z_cancellation_token_new(&t) < 0) { printf("legD.token_new=FAILED\n"); return; }
    z_cancellation_token_cancel(z_cancellation_token_loan_mut(&t));

    z_owned_closure_reply_t rclosure;
    if (z_closure_reply(&rclosure, reply_call, reply_drop, (void *)&dropped_d) < 0) {
        printf("legD.closure=FAILED\n"); return;
    }

    z_querier_get_options_t g;
    z_querier_get_options_default(&g);
    g.cancellation_token = z_cancellation_token_move(&t);

    printf("legD.get.rc=%d\n", (int)z_querier_get(z_loan(querier), "", z_move(rclosure), &g));
    printf("legD.dropped=%d\n", dropped_d);
    printf("legD.token_spent=%d\n", (int)(!z_internal_cancellation_token_check(&t)));
    z_drop(z_move(t));
    z_drop(z_move(querier));
}

/* legE -- the THIRD reader: `z_liveliness_get_options_t`, at offset 8.
   This is the struct whose SIZE was wrong, so legA (the default writer) and this
   leg cover its two halves: that the tail is written, and that it is read. */
static void legE(const z_loaned_session_t *cli, const z_loaned_keyexpr_t *ke) {
    z_owned_cancellation_token_t t;
    if (z_cancellation_token_new(&t) < 0) { printf("legE.token_new=FAILED\n"); return; }
    z_cancellation_token_cancel(z_cancellation_token_loan_mut(&t));

    z_owned_closure_reply_t rclosure;
    if (z_closure_reply(&rclosure, reply_call, reply_drop, (void *)&dropped_e) < 0) {
        printf("legE.closure=FAILED\n"); return;
    }

    z_liveliness_get_options_t g;
    z_liveliness_get_options_default(&g);
#ifdef Z_FEATURE_UNSTABLE_API
    g.cancellation_token = z_cancellation_token_move(&t);
#endif
    printf("legE.get.rc=%d\n", (int)z_liveliness_get(cli, ke, z_move(rclosure), &g));
    printf("legE.dropped=%d\n", dropped_e);
    printf("legE.token_spent=%d\n", (int)(!z_internal_cancellation_token_check(&t)));
    z_drop(z_move(t));
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: probe <endpoint>\n"); return 2; }

    legA();

    z_owned_session_t srv;
    if (open_session(&srv, Z_CONFIG_LISTEN_KEY, argv[1]) < 0) { printf("open.srv=FAILED\n"); return 1; }

    z_view_keyexpr_t ke;
    if (z_view_keyexpr_from_str(&ke, "wz/pico/cancel/probe") < 0) { printf("keyexpr=FAILED\n"); return 1; }

    z_owned_closure_query_t qclosure;
    z_owned_fifo_handler_query_t qhandler;
    if (z_fifo_channel_query_new(&qclosure, &qhandler, 4) < 0) { printf("query_channel=FAILED\n"); return 1; }
    z_owned_queryable_t qable;
    if (z_declare_queryable(z_loan(srv), &qable, z_loan(ke), z_move(qclosure), NULL) < 0) {
        printf("declare_queryable=FAILED\n"); return 1;
    }

    z_owned_session_t cli;
    if (open_session(&cli, Z_CONFIG_CONNECT_KEY, argv[1]) < 0) { printf("open.cli=FAILED\n"); return 1; }

    legB(z_loan(cli), z_loan(ke));
    legC(z_loan(cli), z_loan(qhandler), z_loan(ke));
    legD(z_loan(cli), z_loan(ke));
    legE(z_loan(cli), z_loan(ke));

    z_drop(z_move(qable));
    z_drop(z_move(qhandler));
    z_drop(z_move(cli));
    z_drop(z_move(srv));
    printf("done\n");
    return 0;
}
"#;

/// Compile once, link twice, run both, return the two stdouts.
fn run_both_arms() -> (String, String) {
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src = dir.path().join("wz_pico_cancellation_token.c");
    std::fs::write(&src, PROBE).expect("write the probe source");
    let includes = zenoh_pico_include_dirs();

    let cdylib = wz_capi_pico_cdylib();
    let wz_libdir = cdylib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_pico_source(&src, dir.path(), &includes, &wz_libdir, "wz_capi_pico")
        .unwrap_or_else(|diag| {
            panic!(
                "§5.27 api-compat-pico: the cancellation-token probe does NOT link \
                 against wz's pico cdylib. A missing symbol here is a program upstream \
                 can write and wz cannot run.\n{diag}"
            )
        });

    // Through the REGISTERED resolver, not a path join: Layer A4 reads a test's
    // foreign class off the resolver functions its call graph names.
    let reference = zenoh_pico_shared_library();
    assert!(
        reference.is_file(),
        "the reference libzenohpico.so vanished between resolution and use"
    );
    let ref_libdir = zenoh_pico_library_dir();
    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let on_ref = compile_pico_source(&src, &ref_dir, &includes, &ref_libdir, "zenohpico")
        .unwrap_or_else(|diag| {
            panic!(
                "the cancellation-token probe does not link against the REAL \
                 libzenohpico.so\n{diag}"
            )
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
    let (wz_ok, wz_stdout) = run(&on_wz, &wz_libdir);
    let (ref_ok, ref_stdout) = run(&on_ref, &ref_libdir);
    assert!(
        ref_ok,
        "the REFERENCE arm failed, so this machine's oracle cannot serve as one here \
         — the comparison below would be meaningless.\n{ref_stdout}"
    );
    assert!(
        wz_ok,
        "the wz arm exited non-zero. Its stdout up to the failure:\n{wz_stdout}"
    );
    (wz_stdout, ref_stdout)
}

/// The oracle, or `None` with a LOUD note naming what to do about it.
fn oracle_or_note() -> Option<PathBuf> {
    let lib = zenoh_pico_library_dir().join("libzenohpico.so");
    if lib.is_file() {
        return Some(lib);
    }
    eprintln!(
        "skip: the zenoh-pico ORACLE is absent. This leg needs the CMake-built \
         libzenohpico.so and its generated config.h — run \
         scripts/build-zenoh-pico-cli.sh. Hosted CI provisions it before the \
         sweep that runs this, so a skip here is a LOCAL gap, not a passing run."
    );
    None
}

/// The lines that must appear on EITHER arm before the two are compared.
///
/// R311y570: a diff gate is an EQUALITY, and two arms that both ignored the
/// token entirely would print identical stdouts and diff clean. Every anchor
/// below is therefore derived from OUTSIDE the program — the vendored source and
/// the reference header — and not from either arm's output.
///
/// R311y572: the anchor was CALIBRATED against the oracle before being written
/// here, because the first anchor of a round has been backwards before.
///
/// Deliberately NOT anchored: `legB.get.rc` and `legC.dropped_after_cancel`.
/// Those are the measurements; pinning them here would make this file assert the
/// answer it was written to find out. The two anchored `legC` lines below are the
/// preconditions of that measurement, not the measurement.
fn anchors() -> Vec<&'static str> {
    vec![
        // 16 B, `cancellation_token` at 8, MEASURED against the reference
        // headers — the flag `Z_FEATURE_UNSTABLE_API` is defined in
        // `target/zenoh-pico-build/zenohpico/include/zenoh-pico/config.h:35`, so
        // a build that reads it as absent would print `absent` below and fail
        // here rather than silently make legA vacuous.
        "legA.sizeof=16",
        "legA.default.rc=0",
        "legA.timeout_written=1",
        // The get was ISSUED and the queryable RECEIVED it. Without both, the
        // drop-count transition legC measures would be measuring an empty
        // session rather than a cancellation.
        "legC.get.rc=0",
        "legC.query.recv.rc=0",
        "legC.dropped_before_cancel=0",
        "done",
    ]
}

fn assert_anchored(arm: &str, stdout: &str) {
    let lines: Vec<&str> = stdout.lines().collect();
    let missing: Vec<&str> = anchors()
        .into_iter()
        .filter(|want| !lines.contains(want))
        .collect();
    assert!(
        missing.is_empty(),
        "the {arm} arm is missing {} anchored line(s), so it never reached the state \
         this probe measures.\nmissing: {missing:?}\n--- stdout ---\n{stdout}",
        missing.len(),
    );
}

/// THE ADJUDICATOR: the cancellation-token plane behaves identically on wz's
/// pico ABI and on the real `libzenohpico.so` — the default writer's tail, an
/// already-cancelled token's return code, and the drop-count transition a live
/// cancel produces.
// wz-proves: api-compat-pico wz->pico partial
// legE drives `z_liveliness_get`'s own option struct and its own cancellation
// registration against the real library, so this file is a SECOND, differently
// shaped foreign witness for that atom — the debt ledger carries `liveliness-get`
// in its 61 single-adjudicator list, and a second witness there is the point of
// keeping that list. `partial`: this leg adjudicates the CANCELLATION surface of
// the snapshot get, not its delivery, which the atom's other witness covers.
// wz-proves: liveliness-get wz->pico partial
#[test]
#[ignore = "links the CMake-built libzenohpico.so oracle; run by run-ci Layer E, \
            whose ignored-test sweep carries no --skip token this file matches"]
fn cancellation_token_stops_a_get_identically_on_wz_and_libzenohpico() {
    if oracle_or_note().is_none() {
        return;
    }
    let (wz_stdout, ref_stdout) = run_both_arms();

    assert_anchored("REFERENCE", &ref_stdout);
    assert_anchored("wz", &wz_stdout);

    let wz: Vec<&str> = wz_stdout.lines().collect();
    let reference: Vec<&str> = ref_stdout.lines().collect();
    let mut differing: Vec<String> = Vec::new();
    for (i, expected) in reference.iter().enumerate() {
        match wz.get(i) {
            Some(actual) if actual == expected => {}
            Some(actual) => differing.push(format!("  wz: {actual}\n  ref: {expected}")),
            None => differing.push(format!("  wz: <missing>\n  ref: {expected}")),
        }
    }
    if wz.len() > reference.len() {
        for extra in &wz[reference.len()..] {
            differing.push(format!("  wz: {extra}\n  ref: <missing>"));
        }
    }
    assert!(
        differing.is_empty(),
        "{} of {} probe line(s) differ between wz's pico ABI and the real \
         libzenohpico:\n{}",
        differing.len(),
        reference.len(),
        differing.join("\n")
    );
}
