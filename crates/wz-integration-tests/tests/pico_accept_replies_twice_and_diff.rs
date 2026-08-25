// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-pico` — `accept_replies`, and the first program that VARIES it.
//!
//! ## The residual this closes
//!
//! R311y562 found a live ABI defect by measurement: `z_get_options_t` was
//! missing the `source_info` / `cancellation_token` pair, which sit BEFORE
//! `accept_replies` in upstream's declaration, so the field a C program wrote at
//! offset 72 landed at 56 in wz's struct. The fix is gated by an offset assert
//! (`get.rs:704`).
//!
//! The debt ledger has carried what that fix did NOT buy ever since: "the
//! `accept_replies` displacement was fixed but its CONSEQUENCE was never
//! observed — no test shows a program reading the wrong policy, because no
//! upstream example varies it". `get.rs:655` says the same thing in the source.
//!
//! An offset assert is a claim about a STRUCT. It cannot tell you that the value
//! at that offset changes what the session does, and a struct can be laid out
//! perfectly while the field is read into nothing. So this probe varies the
//! field across two otherwise identical gets and measures the difference in
//! DELIVERY — on wz's pico ABI and on the real `libzenohpico.so`.
//!
//! ## What `accept_replies` does, and how a reply is made to violate it
//!
//! `Z_REPLY_KEYEXPR_MATCHING_QUERY` (the default, `get.rs:760`) says: only
//! accept replies whose keyexpr intersects the query's. `Z_REPLY_KEYEXPR_ANY`
//! lifts that. It is not a wire field of its own — pico transmits it as the
//! `_anyke` selector parameter (`get.rs:998-1011`), which is why a probe that
//! only inspected the struct would learn nothing about it.
//!
//! To make the setting observable, the queryable must reply on a keyexpr that
//! does NOT intersect the query's. Upstream's `z_queryable.c` always replies on
//! the query's own keyexpr, which is exactly why no upstream example can witness
//! this and why the probe is written here.
//!
//! ## What the probe therefore also measures, without being asked
//!
//! This tree carries a recorded non-claim: wz's replier does not enforce the
//! `_anyke` intersect guard that zenoh (`queryable.rs:278-287`) and pico apply
//! on the REPLYING side. That guard fires on exactly the call this probe makes —
//! a `z_query_reply` on a non-intersecting keyexpr — so `legD1.reply.rc` and
//! `legD2.reply.rc` are the first measurement of it on this ABI. The diff
//! decides; nothing here asserts an outcome in advance.

use std::path::{Path, PathBuf};
use std::process::Command;

use wz_integration_tests::common::{
    compile_pico_source, wz_capi_pico_cdylib, zenoh_pico_include_dirs, zenoh_pico_library_dir,
    zenoh_pico_shared_library, PortReservation,
};

/// Two gets that differ in ONE field, each answered on a non-intersecting
/// keyexpr.
///
/// Written here rather than patched into `vendor/zenoh-pico` for the reason the
/// sibling adjudicators give: a patched submodule is a reference nobody can
/// trust twice.
const PROBE: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zenoh-pico.h"

/* `key` is `uint8_t`, not `const char *`: pico's config keys are small integer
   constants (`Z_CONFIG_LISTEN_KEY` is `0x42`) and `zp_config_insert` takes a
   `uint8_t`. Typing the parameter as a pointer round-trips only because a
   SysV-x86-64 truncation happens to be lossless for values that small. */
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

/* One get, answered on `other_ke`, under the caller's `accept_replies` policy.
   Everything is received on the main thread through a FIFO channel, so the two
   arms' stdouts are line-comparable rather than scheduler-dependent. */
static void one_leg(const char *tag,
                    const z_loaned_session_t *cli,
                    const z_loaned_fifo_handler_query_t *qhandler,
                    const z_loaned_keyexpr_t *query_ke,
                    const z_loaned_keyexpr_t *other_ke,
                    z_reply_keyexpr_t policy) {
    z_owned_closure_reply_t rclosure;
    z_owned_fifo_handler_reply_t rhandler;
    if (z_fifo_channel_reply_new(&rclosure, &rhandler, 4) < 0) {
        printf("%s.reply_channel=FAILED\n", tag);
        return;
    }

    z_get_options_t gopts;
    z_get_options_default(&gopts);
    /* THE ONE FIELD THIS PROBE EXISTS FOR. Printed as well as set, so that a
       build whose struct put it somewhere else shows the disagreement here
       rather than as an unexplained delivery difference below. */
    gopts.accept_replies = policy;
    printf("%s.accept_replies=%d\n", tag, (int)gopts.accept_replies);

    z_result_t get_rc = z_get(cli, query_ke, "", z_move(rclosure), &gopts);
    printf("%s.get.rc=%d\n", tag, (int)get_rc);
    if (get_rc < 0) { return; }

    z_owned_query_t q;
    z_result_t q_rc = z_recv(qhandler, &q);
    printf("%s.query.recv.rc=%d\n", tag, (int)q_rc);
    if (q_rc != Z_OK) { return; }

    /* THE FAR SIDE of the same field. `accept_replies` is not a wire field --
       pico transmits it as the `_anyke` selector parameter -- and this accessor
       is how upstream says a queryable is meant to read it back. Printing it
       here is what separates "wz set a struct field" from "the policy crossed
       the link". */
    printf("%s.query.accepts_replies=%d\n", tag, (int)z_query_accepts_replies(z_loan(q)));

    /* The reply goes out on a keyexpr that does NOT intersect the query's. That
       is the whole mechanism: upstream's own queryable always answers on the
       query's keyexpr, so no upstream program can reach this state. */
    z_owned_bytes_t body;
    z_bytes_copy_from_str(&body, "off-key-reply");
    z_query_reply_options_t ropts;
    z_query_reply_options_default(&ropts);
    z_result_t reply_rc = z_query_reply(z_loan(q), other_ke, z_move(body), &ropts);
    printf("%s.reply.rc=%d\n", tag, (int)reply_rc);
    z_drop(z_move(q));

    /* No timeout and no sleep: the get terminates on the queryable's final, so
       the channel closes on its own and this recv answers either way. */
    z_owned_reply_t reply;
    z_result_t r_rc = z_recv(z_loan(rhandler), &reply);
    /* The RAW code is deliberately not printed. Z_CHANNEL_DISCONNECTED is an
       enum value, and printing it would make this leg assert a constant when
       what it means to assert is DELIVERED-or-NOT. */
    printf("%s.delivered=%d\n", tag, r_rc == Z_OK);
    if (r_rc == Z_OK) {
        const z_loaned_reply_t *lr = z_loan(reply);
        printf("%s.reply.is_ok=%d\n", tag, (int)z_reply_is_ok(lr));
        if (z_reply_is_ok(lr)) {
            const z_loaned_sample_t *sm = z_reply_ok(lr);
            z_view_string_t ke_str;
            z_keyexpr_as_view_string(z_sample_keyexpr(sm), &ke_str);
            printf("%s.reply.keyexpr=%.*s\n", tag,
                   (int)z_string_len(z_loan(ke_str)), z_string_data(z_loan(ke_str)));
        }
        z_drop(z_move(reply));
    }
    z_drop(z_move(rhandler));
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: probe <endpoint>\n"); return 2; }

    z_owned_session_t srv;
    if (open_session(&srv, Z_CONFIG_LISTEN_KEY, argv[1]) < 0) { printf("open.srv=FAILED\n"); return 1; }

    z_view_keyexpr_t qke, oke;
    if (z_view_keyexpr_from_str(&qke, "wz/pico/anyke/asked") < 0) { printf("keyexpr=FAILED\n"); return 1; }
    if (z_view_keyexpr_from_str(&oke, "wz/pico/anyke/answered") < 0) { printf("keyexpr2=FAILED\n"); return 1; }

    z_owned_closure_query_t qclosure;
    z_owned_fifo_handler_query_t qhandler;
    if (z_fifo_channel_query_new(&qclosure, &qhandler, 4) < 0) { printf("query_channel=FAILED\n"); return 1; }
    z_owned_queryable_t qable;
    if (z_declare_queryable(z_loan(srv), &qable, z_loan(qke), z_move(qclosure), NULL) < 0) {
        printf("declare_queryable=FAILED\n"); return 1;
    }

    z_owned_session_t cli;
    if (open_session(&cli, Z_CONFIG_CONNECT_KEY, argv[1]) < 0) { printf("open.cli=FAILED\n"); return 1; }

    /* The DEFAULT policy first, then the lifted one. Two legs that differ in
       exactly one field is what makes the difference between them attributable
       to that field. */
    one_leg("legD1", z_loan(cli), z_loan(qhandler), z_loan(qke), z_loan(oke),
            Z_REPLY_KEYEXPR_MATCHING_QUERY);
    one_leg("legD2", z_loan(cli), z_loan(qhandler), z_loan(qke), z_loan(oke),
            Z_REPLY_KEYEXPR_ANY);

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
    let src = dir.path().join("wz_pico_accept_replies.c");
    std::fs::write(&src, PROBE).expect("write the probe source");
    let includes = zenoh_pico_include_dirs();

    let cdylib = wz_capi_pico_cdylib();
    let wz_libdir = cdylib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_pico_source(&src, dir.path(), &includes, &wz_libdir, "wz_capi_pico")
        .unwrap_or_else(|diag| {
            panic!(
                "§5.27 api-compat-pico: the accept_replies probe does NOT link against \
                 wz's pico cdylib. A missing symbol here is a program upstream can \
                 write and wz cannot run.\n{diag}"
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
                "the accept_replies probe does not link against the REAL \
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
/// R311y570: a diff gate is an EQUALITY, and two arms that both ignored
/// `accept_replies` entirely would print identical stdouts and diff clean. These
/// anchor the parts of the run that are true regardless of what the policy does
/// — the query arrived, the field read back as it was written — so an arm that
/// never got that far fails by name.
///
/// Deliberately NOT anchored: whether either leg DELIVERS. That is the thing
/// being measured, and pinning it here from the outside would be this file
/// asserting the answer it was written to find out.
fn anchors() -> Vec<&'static str> {
    vec![
        // `z_reply_keyexpr_t`: ANY = 0, MATCHING_QUERY = 1
        // (`api/constants.h:288-292`) — and the FIRST run of this probe had
        // these backwards, which is the whole argument for calibrating an
        // anchor against the oracle instead of writing it from the name.
        // Read back off the struct, so a build that placed the field elsewhere
        // fails here rather than as an unexplained delivery difference.
        "legD1.accept_replies=1",
        "legD1.get.rc=0",
        "legD1.query.recv.rc=0",
        "legD2.accept_replies=0",
        "legD2.get.rc=0",
        "legD2.query.recv.rc=0",
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

/// THE ADJUDICATOR: two gets that differ only in `accept_replies`, each answered
/// on a non-intersecting keyexpr, behave identically on wz's pico ABI and on the
/// real `libzenohpico.so`.
///
/// This is the first program in the tree that varies the field at all, which is
/// what makes it the first evidence that the R311y562 offset fix has a
/// consequence rather than only a correct layout.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "links the CMake-built libzenohpico.so oracle; run by run-ci Layer E, \
            whose ignored-test sweep carries no --skip token this file matches"]
fn accept_replies_changes_delivery_identically_on_wz_and_libzenohpico() {
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
