// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.4 `session-matching` — a SESSION-LOCAL queryable is a match, and the
//! FOREIGN ADJUDICATOR for that is zenoh-c answering the same program.
//!
//! ## The residual this closes, and why it was not a witness gap
//!
//! The atom's reason carried "no foreign witness exists for a matching status
//! computed over a session-local queryable" on its STILL-PARTIAL list. R2579
//! built the witness and it did not merely fill a gap — it RED. wz's C ABI
//! answered `false` where zenoh-c answered `true`, so the clause was a
//! behavioural divergence wearing a proof obligation's clothes.
//!
//! ## The defect, and why no existing fixture could see it
//!
//! `WzFaces::declare_queryable` registers on every face session AND on the
//! face-independent local plane. `has_matching_queryable` read
//! `face_sessions()`, which is the faces alone. The plane is therefore
//! REDUNDANT whenever a face exists — the same declaration sits on that face's
//! session too, and the poll finds it there — and load-bearing only when the
//! face set is EMPTY.
//!
//! MEASURED both ways before the repair, with this same program:
//!
//! ```text
//! peer connected, one face : BEFORE=false  AFTER=true   <- masked
//! no peer, zero faces      : BEFORE=false  AFTER=false  <- the defect
//! ```
//!
//! So the leg runs with NOTHING connected, and that is not incidental: an
//! interop fixture connects something by definition, which is precisely why
//! every existing one walked past this. A future edit that gives this probe a
//! peer would make it pass while measuring nothing.
//!
//! ## Why a compile-once-link-twice differential rather than a wz assertion
//!
//! The question is what the matching verdict OUGHT to be for a session-local
//! declaration, and wz asserting its own answer cannot settle that. zenoh-c is
//! the same API answered by the reference implementation, so one program linked
//! against both turns the question into a diff. `zenoh_c_source_info_twice_and_diff`
//! records the rule this follows: "'No upstream example does X' is a claim about
//! a PROGRAM, not about the API" — no shipped example holds a queryable and a
//! querier on one session, so the program is written here.
//!
//! ## The shape both ABIs accept, measured rather than assumed
//!
//! wz's `z_open` REFUSES a config with neither endpoint (`wz-capi-c`'s
//! `session.rs` says so in as many words: a scouting open is not implemented)
//! and refuses listen+connect together, while zenoh-c opens all three. The
//! probe therefore sets exactly ONE listen endpoint, and the differential runs
//! on the INTERSECTION of the two ABIs rather than on the oracle's superset.
//! A probe written to the oracle's tolerance would fail on wz for a reason that
//! is not the claim.

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

/// One session, one querier, one SESSION-LOCAL queryable, two reads.
///
/// The BEFORE read is the anti-vacuity arm and it is not decoration: without it
/// an implementation that answered `true` unconditionally would pass, and
/// "matching" is exactly the kind of verdict a stub returns affirmatively.
const PROBE: &str = r#"#include <stdio.h>
#include <string.h>
#include "zenoh.h"

static const char *QUERYABLE_KE = "acdemo/local/**";
static const char *QUERIER_KE = "acdemo/local/thing";

static void on_query(z_loaned_query_t *query, void *context) {
    (void)query;
    (void)context;
}

static int read_status(const z_owned_querier_t *querier, const char *phase) {
    z_matching_status_t status;
    memset(&status, 0, sizeof(status));
    if (z_querier_get_matching_status(z_loan(*querier), &status) != Z_OK) {
        printf("%s=ERR\n", phase);
        return -1;
    }
    printf("%s=%s\n", phase, status.matching ? "true" : "false");
    return status.matching ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: probe <listen-endpoint>\n"); return 2; }

    z_owned_config_t config;
    if (z_config_default(&config) != Z_OK) { printf("config=FAILED\n"); return 1; }
    /* Nothing may reach this probe: the only possible match is session-local. */
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
    z_result_t open_rc = z_open(&session, z_move(config), NULL);
    if (open_rc != Z_OK) { printf("open.rc=%d\n", (int)open_rc); return 1; }

    z_view_keyexpr_t querier_ke;
    if (z_view_keyexpr_from_str(&querier_ke, QUERIER_KE) != Z_OK) {
        printf("querier.ke=FAILED\n"); return 1;
    }
    z_owned_querier_t querier;
    if (z_declare_querier(z_loan(session), &querier, z_loan(querier_ke), NULL) != Z_OK) {
        printf("querier=FAILED\n"); return 1;
    }

    int before = read_status(&querier, "before");

    z_view_keyexpr_t queryable_ke;
    if (z_view_keyexpr_from_str(&queryable_ke, QUERYABLE_KE) != Z_OK) {
        printf("queryable.ke=FAILED\n"); return 1;
    }
    z_owned_closure_query_t callback;
    z_closure_query(&callback, on_query, NULL, NULL);
    z_owned_queryable_t queryable;
    if (z_declare_queryable(z_loan(session), &queryable, z_loan(queryable_ke),
                            z_move(callback), NULL) != Z_OK) {
        printf("queryable=FAILED\n"); return 1;
    }

    int after = read_status(&querier, "after");
    printf("verdict=%s\n", (before == 0 && after == 1) ? "satisfies" : "does-not-satisfy");
    printf("done\n");
    return 0;
}
"#;

/// Compile the probe once and run it against each library, each on its own
/// reserved port — both arms LISTEN, so one port would make the second fail to
/// bind for a reason that is neither implementation's.
fn run_both_arms(include: &Path) -> (String, String) {
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("probe source dir");
    std::fs::write(src_dir.join("wz_local_matching.c"), PROBE).expect("write the probe source");

    let lib = wz_capi_c_cdylib();
    let wz_libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_zenoh_c_example(
        "wz_local_matching",
        dir.path(),
        include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!(
            "§5.4 session-matching: the local-queryable probe does NOT link against \
             wz's C-ABI cdylib.\n{diag}"
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
        "wz_local_matching",
        &ref_dir,
        include,
        &src_dir,
        &libdir_ref,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("the local-queryable probe does not link against the REAL libzenohc.so\n{diag}")
    });

    let run = |exe: &Path, libdir: &Path| -> (bool, String) {
        // Held across the child's whole run: the guard is what keeps the next
        // reservation from racing this listener, and the child binds at once.
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
        "the REFERENCE arm failed, so this machine's oracle cannot serve as one \
         here — the comparison below would be meaningless.\n{ref_stdout}"
    );
    assert!(
        wz_ok,
        "the local-queryable probe exited non-zero on wz's C ABI.\n\
         --- stdout on wz ---\n{wz_stdout}\n--- reference printed ---\n{ref_stdout}"
    );
    (wz_stdout, ref_stdout)
}

/// THE GATE: a queryable declared on a session with NO peer satisfies that
/// session's own querier, and wz answers what zenoh's own library answers.
///
/// `partial`: it covers the QUERYABLE plane's local half on one ABI. The
/// subscriber plane rides the same repair (`WzFaces::has_matching` reads the
/// same enumerator) and the matching LISTENER does not yet — see that method's
/// own note.
// wz-proves: session-matching zenoh-c->wz partial
#[test]
#[ignore = "opens a session and reads a zenoh-c oracle; run by run-ci Layer C1cc \
            (which builds the matching ABI arm this needs)"]
fn a_session_local_queryable_satisfies_its_own_querier_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    assert_zenoh_c_arm_pairing(&include);
    let (wz_stdout, ref_stdout) = run_both_arms(&include);

    // The ORACLE is asserted first and in full, BEFORE the diff. Two identical
    // failures diff clean, and "both printed nothing" is the shape a broken
    // harness produces — so what the reference must have said is stated here
    // rather than inferred from what the two happened to share.
    assert!(
        ref_stdout.contains("done"),
        "the reference arm did not reach the end of the probe:\n{ref_stdout}"
    );
    assert!(
        ref_stdout.contains("before=false"),
        "the reference arm reported a match BEFORE anything was declared, so its \
         `after` says nothing about the queryable:\n{ref_stdout}"
    );
    assert!(
        ref_stdout.contains("after=true"),
        "the reference implementation does NOT count a session-local queryable at \
         this pin, so the claim this leg exists to hold wz to is not upstream's. \
         Re-read the residual before changing wz:\n{ref_stdout}"
    );

    assert_eq!(
        wz_stdout, ref_stdout,
        "§5.4 session-matching: wz's C ABI and libzenohc disagree about whether a \
         SESSION-LOCAL queryable satisfies a querier on the same session.\n\
         --- wz ---\n{wz_stdout}--- libzenohc ---\n{ref_stdout}"
    );
}
