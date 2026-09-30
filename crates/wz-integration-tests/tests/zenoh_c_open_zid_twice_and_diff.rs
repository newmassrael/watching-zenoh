// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` — the session's own zid is the config's `id`, on the C ABI
//! that stands for zenoh-c.
//!
//! ## The gap this closes
//!
//! `z_open` minted a fresh random zid for every session and never read the
//! config's `id`, so a program that names its node by a configured id got a
//! session standing on another identity, and `z_info_zid` reported that other
//! one. The key was already in the config reader's table and already honoured
//! by `z_scout` and by the command line; the one door that opens a session was
//! the one that ignored it.
//!
//! ## What is compared, and what cannot be
//!
//! An id given to `z_open` must come back from `z_info_zid` byte for byte, and
//! that is a comparison between the two arms because zenoh-c's answer is the
//! spelling rule itself: the text is a `ZenohId` as zenoh PRINTS it, the 16-byte
//! little-endian id read as a `u128` in hex, so `c11e47c11e49` is the bytes
//! `49 1e c1 47 1e c1` followed by ten zeros. A rule read off wz's own model
//! would be the model grading itself, so the expected bytes are also derived
//! here, once, from the documented reading (`u128::from_str_radix` and
//! `to_le_bytes`) and asserted against BOTH arms before they are compared with
//! each other: two arms that agreed on the wrong bytes would otherwise pass.
//!
//! The refusals are compared by the code each arm returns when the id is
//! inserted, one case per rule zenoh states: uppercase, a leading zero (which is
//! how the id zero is refused), empty, non-hex, more than sixteen bytes, and the
//! two that are ACCEPTED and look like they should not be, a leading `+` and an
//! odd number of digits.
//!
//! A session that is given NO id still gets a fresh one, and a zid a random
//! source drew cannot match across the arms, so the probe prints only that it is
//! non-zero and differs from the configured one.

use std::path::{Path, PathBuf};
use std::process::Command;

use wz_integration_tests::common::{
    assert_zenoh_c_arm_pairing, compile_zenoh_c_example, wz_capi_c_cdylib, zenoh_c_oracle,
    zenoh_c_shared_library, PortReservation,
};

/// The id the open case configures: six bytes, so the session's zid is shorter
/// than the sixteen `z_id_t` holds and the zero padding is part of the answer.
const CONFIGURED: &str = "c11e47c11e49";

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

/// One program, compiled once and linked twice.
///
/// Every line is a fact both arms must print identically, so nothing here prints
/// a value a random source drew.
const PROBE: &str = r#"#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "zenoh.h"

/* Insert `id` alone into a fresh default config and print the code. The config
   is dropped again: only the refusal is being asked about. */
static void insert_case(const char *label, const char *json) {
    z_owned_config_t config;
    if (z_config_default(&config) != Z_OK) { printf("insert.%s.rc=NOCONFIG\n", label); return; }
    z_result_t rc = zc_config_insert_json5(z_config_loan_mut(&config), "id", json);
    printf("insert.%s.rc=%d\n", label, (int)rc);
    z_config_drop(z_config_move(&config));
}

/* The same question asked of a whole DOCUMENT, which is a second door onto the
   same config and must give the same answer. */
static void document_case(const char *label, const char *text) {
    z_owned_config_t config;
    z_result_t rc = zc_config_from_str(&config, text);
    printf("document.%s.rc=%d\n", label, (int)rc);
    if (rc == Z_OK) { z_config_drop(z_config_move(&config)); }
}

static void print_zid(const char *label, z_id_t id) {
    printf("%s.zid=", label);
    for (int i = 0; i < 16; i++) { printf("%02x", (unsigned)id.id[i]); }
    printf("\n");
}

/* Open a peer that reaches nothing, with `id` (or none) and the listener the
   caller reserved, and print the session's own zid. */
static int open_case(const char *label, const char *id_json, const char *endpoint,
                     z_id_t *out) {
    z_owned_config_t config;
    if (z_config_default(&config) != Z_OK) { printf("%s.config=FAILED\n", label); return 1; }
    if (zc_config_insert_json5(z_config_loan_mut(&config),
                               "scouting/multicast/enabled", "false") != Z_OK) {
        printf("%s.config.scouting=FAILED\n", label); return 1;
    }
    char listen[256];
    snprintf(listen, sizeof listen, "[\"%s\"]", endpoint);
    if (zc_config_insert_json5(z_config_loan_mut(&config), "listen/endpoints", listen) != Z_OK) {
        printf("%s.config.listen=FAILED\n", label); return 1;
    }
    if (id_json != NULL) {
        z_result_t rc = zc_config_insert_json5(z_config_loan_mut(&config), "id", id_json);
        if (rc != Z_OK) { printf("%s.config.id=%d\n", label, (int)rc); return 1; }
    }
    z_owned_session_t session;
    z_result_t rc = z_open(&session, z_config_move(&config), NULL);
    printf("%s.open.rc=%d\n", label, (int)rc);
    if (rc != Z_OK) { return 1; }
    *out = z_info_zid(z_session_loan(&session));
    z_close(z_session_loan_mut(&session), NULL);
    z_session_drop(z_session_move(&session));
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: probe <endpoint> <endpoint>\n"); return 2; }

    /* What the config accepts and refuses as an `id`. */
    insert_case("short", "\"1\"");
    insert_case("six_bytes", "\"c11e47c11e49\"");
    insert_case("odd_digits", "\"abc\"");
    insert_case("sixteen_bytes", "\"ffffffffffffffffffffffffffffffff\"");
    insert_case("leading_plus", "\"+1\"");
    insert_case("empty", "\"\"");
    insert_case("zero", "\"0\"");
    insert_case("leading_zero", "\"01\"");
    insert_case("leading_zero_pair", "\"0a0b\"");
    insert_case("uppercase", "\"ABC\"");
    insert_case("not_hex", "\"zz\"");
    insert_case("seventeen_bytes", "\"1ffffffffffffffffffffffffffffffff\"");
    insert_case("not_a_string", "123");

    document_case("valid", "{\"id\":\"c11e47c11e49\"}");
    document_case("short", "{\"id\":\"1\"}");
    document_case("uppercase", "{\"id\":\"ABC\"}");
    document_case("leading_zero", "{\"id\":\"01\"}");
    document_case("empty", "{\"id\":\"\"}");
    document_case("not_a_string", "{\"id\":123}");

    /* A session opened with an id stands on it. */
    z_id_t configured;
    memset(&configured, 0, sizeof configured);
    if (open_case("with_id", "\"c11e47c11e49\"", argv[1], &configured) != 0) { return 1; }
    print_zid("with_id", configured);

    /* A session opened without one is still given one of its own. */
    z_id_t fresh;
    memset(&fresh, 0, sizeof fresh);
    if (open_case("without_id", NULL, argv[2], &fresh) != 0) { return 1; }
    int nonzero = 0;
    for (int i = 0; i < 16; i++) { nonzero |= fresh.id[i] != 0; }
    printf("without_id.zid_nonzero=%d\n", nonzero);
    printf("without_id.zid_differs_from_configured=%d\n",
           memcmp(&fresh, &configured, sizeof fresh) != 0);
    printf("done\n");
    return 0;
}
"#;

/// Compile the probe once and run it on each arm, returning `(wz, reference)`.
fn run_both_arms(include: &Path) -> (String, String) {
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("probe source dir");
    std::fs::write(src_dir.join("wz_open_zid.c"), PROBE).expect("write the probe source");

    let lib = wz_capi_c_cdylib();
    let wz_libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_zenoh_c_example(
        "wz_open_zid",
        dir.path(),
        include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!(
            "§5.27 api-compat-c: the open-zid probe does NOT link against wz's C-ABI \
             cdylib.\n{diag}"
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
        "wz_open_zid",
        &ref_dir,
        include,
        &src_dir,
        &libdir_ref,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("the open-zid probe does not link against the REAL libzenohc.so\n{diag}")
    });

    // Two ports each, held across the child's whole run, and never shared between
    // the arms: both listen, so a shared port would make the second arm fail to
    // bind for a reason that has nothing to do with either implementation.
    let run = |exe: &Path, libdir: &Path| -> (bool, String) {
        // ONE acquisition for both: a second `pick` on this thread would re-enter
        // the process-global lock and block until the job was killed.
        let (first, second) = PortReservation::pick_pair();
        let out = Command::new(exe)
            .arg(format!("tcp/127.0.0.1:{}", first.port()))
            .arg(format!("tcp/127.0.0.1:{second}"))
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
        "the open-zid probe exited non-zero on wz's C ABI.\n\
         --- stdout on wz ---\n{wz_stdout}\n--- reference printed ---\n{ref_stdout}"
    );
    (wz_stdout, ref_stdout)
}

/// The sixteen bytes `z_info_zid` must report for [`CONFIGURED`], as hex.
///
/// Derived from the documented reading and from nothing in this workspace: the
/// text is the id as a `u128` in big-endian hex, and `z_id_t` holds its
/// little-endian bytes.
fn expected_zid_hex() -> String {
    let id = u128::from_str_radix(CONFIGURED, 16).expect("the configured id is hex");
    id.to_le_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// THE GATE: a session opened with an `id` stands on it, the config refuses what
/// zenoh refuses, and wz answers what zenoh's own library answers.
///
/// `partial`: it covers the config's `id` at `z_open` on the zenoh-c ABI. The
/// zenoh-pico ABI reads its zid through a numeric key with its own spelling and
/// is not driven here.
// wz-proves: api-compat-c wz->zenoh-c partial
#[test]
#[ignore = "opens sessions and reads a zenoh-c oracle; run by run-ci Layer C1cc"]
fn an_open_stands_on_its_configured_id_identically_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    assert_zenoh_c_arm_pairing(&include);
    let (wz_stdout, ref_stdout) = run_both_arms(&include);

    // Asserted BEFORE the diff: two arms that both never reached the end, or that
    // both reported the wrong bytes, are equal to each other.
    assert!(
        ref_stdout.contains("done"),
        "the reference arm did not reach the end of the probe:\n{ref_stdout}"
    );
    let expected = format!("with_id.zid={}", expected_zid_hex());
    assert!(
        ref_stdout.lines().any(|l| l == expected),
        "the ORACLE reported another zid than the documented reading of `{CONFIGURED}` \
         ({expected}), so the derivation in this test is wrong:\n{ref_stdout}"
    );
    assert!(
        wz_stdout.lines().any(|l| l == expected),
        "wz's session did not stand on the configured id `{CONFIGURED}` \
         (expected `{expected}`):\n--- wz ---\n{wz_stdout}\n--- reference ---\n{ref_stdout}"
    );
    for line in [
        "without_id.zid_nonzero=1",
        "without_id.zid_differs_from_configured=1",
    ] {
        assert!(
            ref_stdout.lines().any(|l| l == line) && wz_stdout.lines().any(|l| l == line),
            "a session with no id must still get one of its own (`{line}`):\n\
             --- wz ---\n{wz_stdout}\n--- reference ---\n{ref_stdout}"
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
