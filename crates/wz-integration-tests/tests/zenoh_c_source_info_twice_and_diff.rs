// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` — the `source_info` FOREIGN ADJUDICATOR.
//!
//! ## The gap this closes, named by the debt ledger as the largest on this axis
//!
//! R311y561, y562 and y563 built the `source_info` plane on both C ABIs — the
//! owned family, the six option folds, the sample accessor — and every witness
//! any of them produced is wz driving wz, with damage probes standing in for a
//! second opinion. The reason was recorded each round and was true each round:
//! **no stock example on either side sets the field**, so there was no program
//! to compile twice.
//!
//! "No upstream example does X" is a claim about a PROGRAM, not about the API
//! (this workspace has the note filed under exactly that name). The remedy it
//! prescribes is to PATCH one — take upstream's own source, add the calls, and
//! compile the result against both libraries. That is what this file does, and
//! the patched program is written here rather than edited into the clone so the
//! oracle checkout stays pristine.
//!
//! ## Why a SESSION probe rather than an accessor probe
//!
//! `source_info` is not a pure function: the interesting claim is that the
//! `(zid, eid, sn)` a publisher sets is the `(zid, eid, sn)` a subscriber reads,
//! which needs a live session on each arm. Both libraries can do that alone — a
//! peer session delivers to its own subscriber — so the probe stays
//! single-process and the two arms differ only in which implementation answers.
//!
//! The subscriber uses a RING CHANNEL rather than a callback, which is what
//! makes the leg deterministic: `z_ring_handler_sample_recv` blocks until the
//! sample arrives instead of sleeping and hoping. A callback probe would be a
//! rate measurement wearing a boolean's clothes.
//!
//! ## What a difference here would mean
//!
//! The `zid` is per-session and CANNOT match across the two arms — each library
//! mints its own. So the probe prints the entity id, the sequence number, and
//! whether the id ROUND-TRIPS (the sample's zid equals the one the program put
//! in), never the zid bytes themselves. Printing the zid would make the diff
//! fail for the one reason that is not a defect.

use std::path::{Path, PathBuf};
use std::process::Command;

use wz_integration_tests::common::{
    compile_zenoh_c_example, wz_capi_c_cdylib, zenoh_c_oracle, zenoh_c_shared_library,
    PortReservation,
};

/// Refuse to run when the cdylib on disk is not the arm this oracle's header is.
///
/// MEASURED, not anticipated: the first run of this leg reported `put.rc=-5` on
/// wz against a clean reference, which reads exactly like a wz defect. It was
/// not — the cdylib was the unstable arm and the header the no-unstable one, so
/// the C program wrote a `z_put_options_t` smaller than wz read and every
/// pointer past the short prefix was garbage. A harness that reports an ARM
/// MISMATCH as a behavioural divergence is worse than no harness, so the pairing
/// is asserted rather than assumed. Layer C1cc builds the matching arm; a
/// standalone `cargo test` does not, which is precisely when this fires.
fn assert_arm_pairing(include: &Path) {
    let configure = std::fs::read_to_string(include.join("zenoh_configure.h"))
        .expect("the oracle ships zenoh_configure.h");
    let oracle_is_unstable = configure.contains("#define Z_FEATURE_UNSTABLE_API");
    // `z_source_info_new` is unstable-gated in BOTH libraries, so its presence
    // in wz's exports names the arm the cdylib was built for.
    let out = Command::new("nm")
        .arg("-D")
        .arg("--defined-only")
        .arg(wz_capi_c_cdylib())
        .output()
        .expect("nm reads the cdylib's dynamic symbols");
    let wz_is_unstable = String::from_utf8_lossy(&out.stdout).contains("z_source_info_new");
    assert_eq!(
        wz_is_unstable, oracle_is_unstable,
        "ABI ARM MISMATCH: the cdylib on disk is the {} arm and this oracle's header          is the {} one. Every field past the short prefix of a feature-conditional          options struct would be read at the wrong offset, and the diff below would          report that as a behavioural divergence. Build the matching arm          (`cargo build -p wz-capi-c{}`) or run Layer C1cc, which does it for you.",
        if wz_is_unstable { "unstable" } else { "no-unstable" },
        if oracle_is_unstable { "unstable" } else { "no-unstable" },
        if oracle_is_unstable {
            ""
        } else {
            " --features zenoh-c-no-unstable-api"
        },
    );
}

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

/// upstream's `z_pub.c` + `z_sub.c`, fused and PATCHED to carry a source info.
///
/// The whole `source_info` half sits behind the header's own
/// `#if defined(Z_FEATURE_UNSTABLE_API)`, so on a no-unstable oracle the probe
/// compiles to the same program without it and both arms agree on the reduced
/// output — which is correct, and is why the test asserts what the ORACLE'S
/// configure header says it should have printed rather than a fixed line count.
const PROBE: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zenoh.h"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: probe <listen-endpoint>\n"); return 2; }

    z_owned_config_t config;
    z_config_default(&config);
    if (zc_config_insert_json5(z_config_loan_mut(&config), "mode", "\"peer\"") != 0) {
        printf("config.mode=FAILED\n"); return 1;
    }
    char listen[256];
    snprintf(listen, sizeof listen, "[\"%s\"]", argv[1]);
    if (zc_config_insert_json5(z_config_loan_mut(&config), "listen/endpoints", listen) != 0) {
        printf("config.listen=FAILED\n"); return 1;
    }

    z_owned_session_t session;
    if (z_open(&session, z_config_move(&config), NULL) != 0) {
        printf("open=FAILED\n"); return 1;
    }

    /* A RING channel, so the read below BLOCKS rather than sleeps. */
    z_owned_closure_sample_t callback;
    z_owned_ring_handler_sample_t handler;
    z_ring_channel_sample_new(&callback, &handler, 4);

    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, (char *)"wz/source_info/probe");
    z_owned_subscriber_t sub;
    if (z_declare_subscriber(z_session_loan(&session), &sub, z_view_keyexpr_loan(&ke),
                             z_closure_sample_move(&callback), NULL) != 0) {
        printf("declare_subscriber=FAILED\n"); return 1;
    }

    z_owned_bytes_t payload;
    printf("bytes.rc=%d\n", (int)z_bytes_copy_from_str(&payload, "source-info"));
    printf("bytes.check=%d\n", (int)z_internal_bytes_check(&payload));
    z_put_options_t opts;
    z_put_options_default(&opts);

    z_id_t id = z_info_zid(z_session_loan(&session));
#if defined(Z_FEATURE_UNSTABLE_API)
    /* THE PATCH: upstream's z_pub.c never touches this field.
       `z_entity_global_id_t` is OPAQUE with accessors and NO constructor, so the
       only way a C program obtains one is to ask an entity for its own — which
       is why this declares a publisher it would otherwise not need. The oracle's
       header is what said so; the first cut of this probe invented a four-
       argument `z_source_info_new(&info, &zid, eid, sn)` and the reference
       refused to compile it. */
    z_owned_publisher_t pub_;
    if (z_declare_publisher(z_session_loan(&session), &pub_,
                            z_view_keyexpr_loan(&ke), NULL) != 0) {
        printf("declare_publisher=FAILED\n"); return 1;
    }
    z_entity_global_id_t gid = z_publisher_id(z_publisher_loan(&pub_));
    z_owned_source_info_t info;
    z_result_t si_rc = z_source_info_new(&info, &gid, 28784u);
    printf("source_info.new.rc=%d\n", (int)si_rc);
    printf("source_info.check=%d\n", (int)z_internal_source_info_check(&info));
    /* The id a publisher reports must round-trip through the source info the
       program builds from it. The zid halves are per-session, so only the
       AGREEMENT is printed, never the bytes. */
    z_entity_global_id_t back = z_source_info_id(z_source_info_loan(&info));
    z_id_t back_zid = z_entity_global_id_zid(&back);
    z_id_t gid_zid = z_entity_global_id_zid(&gid);
    printf("source_info.zid_matches_publisher=%d\n",
           memcmp(&back_zid, &gid_zid, sizeof gid_zid) == 0);
    printf("source_info.zid_matches_session=%d\n",
           memcmp(&back_zid, &id, sizeof id) == 0);
    printf("source_info.eid_round_trips=%d\n",
           z_entity_global_id_eid(&back) == z_entity_global_id_eid(&gid));
    printf("source_info.sn=%u\n", (unsigned)z_source_info_sn(z_source_info_loan(&info)));
    opts.source_info = z_source_info_move(&info);
#endif

    z_result_t put_rc = z_put(z_session_loan(&session), z_view_keyexpr_loan(&ke),
                              z_bytes_move(&payload), &opts);
    printf("put.rc=%d\n", (int)put_rc);
    if (put_rc != 0) { return 1; }
#if defined(Z_FEATURE_UNSTABLE_API)
    /* A MOVED field is consumed on return: the caller's value is a gravestone. */
    printf("source_info.check_after_put=%d\n", (int)z_internal_source_info_check(&info));
#endif

    z_owned_sample_t sample;
    z_result_t rc = z_ring_handler_sample_recv(z_ring_handler_sample_loan(&handler), &sample);
    printf("recv.rc=%d\n", (int)rc);
    if (rc == 0) {
        z_view_string_t ke_str;
        z_keyexpr_as_view_string(z_sample_keyexpr(z_sample_loan(&sample)), &ke_str);
        printf("sample.keyexpr=%.*s\n",
               (int)z_string_len(z_view_string_loan(&ke_str)),
               z_string_data(z_view_string_loan(&ke_str)));
#if defined(Z_FEATURE_UNSTABLE_API)
        const z_loaned_source_info_t *got = z_sample_source_info(z_sample_loan(&sample));
        printf("sample.source_info_present=%d\n", got != NULL);
        if (got != NULL) {
            z_entity_global_id_t sample_gid = z_source_info_id(got);
            z_id_t got_zid = z_entity_global_id_zid(&sample_gid);
            printf("sample.sn=%u\n", (unsigned)z_source_info_sn(got));
            /* The zid and the eid are both per-session / per-publisher and
               cannot match ACROSS arms, so only the ROUND TRIPS are printed. */
            printf("sample.zid_round_trips=%d\n",
                   memcmp(&got_zid, &id, sizeof id) == 0);
            printf("sample.eid_round_trips=%d\n",
                   z_entity_global_id_eid(&sample_gid) == z_entity_global_id_eid(&gid));
        }
#endif
        z_sample_drop(z_sample_move(&sample));
    }

#if defined(Z_FEATURE_UNSTABLE_API)
    z_undeclare_publisher(z_publisher_move(&pub_));
#endif
    z_undeclare_subscriber(z_subscriber_move(&sub));
    z_ring_handler_sample_drop(z_ring_handler_sample_move(&handler));
    z_close(z_session_loan_mut(&session), NULL);
    z_session_drop(z_session_move(&session));
    printf("done\n");
    return 0;
}
"#;

/// Compile once, link twice, run both, return the two stdouts.
fn run_both_arms(include: &Path) -> (String, String) {
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("probe source dir");
    std::fs::write(src_dir.join("wz_source_info.c"), PROBE).expect("write the probe source");

    let lib = wz_capi_c_cdylib();
    let wz_libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_zenoh_c_example(
        "wz_source_info",
        dir.path(),
        include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!(
            "§5.27 api-compat-c: the patched source-info probe does NOT link against \
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
        "wz_source_info",
        &ref_dir,
        include,
        &src_dir,
        &libdir_ref,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("the patched source-info probe does not link against the REAL libzenohc.so\n{diag}")
    });

    // A port each: the two arms both LISTEN, so sharing one would make the
    // second arm fail to bind for a reason that has nothing to do with either
    // implementation.
    let run = |exe: &Path, libdir: &Path| -> (bool, String) {
        // Held across the child`s whole run: the guard is what keeps the next
        // reservation from racing this listener, and the child binds immediately.
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
        "the patched source-info probe exited non-zero on wz's C ABI.\n\
         --- stdout on wz ---\n{wz_stdout}\n--- reference printed ---\n{ref_stdout}"
    );
    (wz_stdout, ref_stdout)
}

/// THE GATE: the `source_info` a publisher sets is the one a subscriber reads,
/// and wz answers what zenoh's own library answers.
///
/// `partial`: it covers the PUT plane's `source_info` on one ABI. The get,
/// querier and reply folds carry the same field through the same seam and are
/// not driven here.
// wz-proves: api-compat-c wz->zenoh-c partial
#[test]
#[ignore = "opens a session and reads a zenoh-c oracle; run by run-ci Layer C1ce \
            (which has the UNSTABLE oracle this needs to measure source_info at \
            all) and by Layer C1cc (delivery half + the arm-pairing refusal)"]
fn a_patched_upstream_put_carries_source_info_identically_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    assert_arm_pairing(&include);
    let (wz_stdout, ref_stdout) = run_both_arms(&include);

    // Asserted BEFORE the diff: two empty captures are equal, and the UNSTABLE
    // half of this probe sits behind the header's own `#if`, so on a
    // no-unstable oracle it compiles to nothing. Which half to expect is read
    // from `zenoh_configure.h` rather than inferred from what happened to print
    // — otherwise the leg would report its strongest result having measured the
    // keyexpr and nothing else.
    let configure = std::fs::read_to_string(include.join("zenoh_configure.h"))
        .expect("the oracle ships zenoh_configure.h");
    let unstable = configure.contains("#define Z_FEATURE_UNSTABLE_API");
    assert!(
        ref_stdout.contains("done"),
        "the reference arm did not reach the end of the probe:\n{ref_stdout}"
    );
    assert!(
        ref_stdout.contains("recv.rc=0"),
        "the reference arm never received its own sample, so nothing downstream \
         of the put was measured:\n{ref_stdout}"
    );
    if unstable {
        for expected in [
            "source_info.new.rc=0",
            "source_info.zid_matches_publisher=1",
            "source_info.eid_round_trips=1",
            "sample.source_info_present=1",
            "sample.sn=28784",
            "sample.zid_round_trips=1",
            "sample.eid_round_trips=1",
        ] {
            assert!(
                ref_stdout.contains(expected),
                "the oracle declares Z_FEATURE_UNSTABLE_API but its own arm did not \
                 print `{expected}`, so the source-info half measured nothing:\n{ref_stdout}"
            );
        }
    } else {
        assert!(
            !ref_stdout.contains("sample.source_info_present"),
            "the oracle declares no Z_FEATURE_UNSTABLE_API yet the probe reached the \
             source-info half:\n{ref_stdout}"
        );
        eprintln!(
            "NOTE: this oracle is a NO-UNSTABLE build, so the source_info half of the \
             probe compiled to nothing. The keyexpr / delivery half is still compared. \
             Provision an unstable oracle to measure the field itself."
        );
    }

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
        "{} of {} probe line(s) differ between wz's C ABI and the real libzenohc:\n{}",
        differing.len(),
        reference.len(),
        differing.join("\n")
    );
}
