// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` — the zenoh-ext families ADJUDICATED, not merely linked.
//!
//! R311y573 implemented `ze_publication_cache` and `ze_querying_subscriber`, the
//! 18 symbols that were the smaller of the two planes the symbol census had left
//! on the `unstable-shm` arm. The census measured 83 -> 65 the moment they
//! existed, and that number says only that the symbols are DEFINED.
//!
//! A link census is not a proof — this tree has a whole memory note about the
//! difference. So this probe drives both families end to end and compares wz's
//! stdout against the real `libzenohc.so`, which is the only witness that can
//! tell "wz exports 18 symbols" from "wz exports 18 symbols that do what
//! upstream's do".
//!
//! ## What the probe exercises
//!
//! - `ze_publication_cache` storing session-local publications and answering a
//!   later `z_get` from its ring, with `history` bounding the ring.
//! - `ze_querying_subscriber` fetching that same history at DECLARATION time
//!   through its own query, then receiving a live publication.
//! - `ze_querying_subscriber_get` issuing an ADDITIONAL query afterwards.
//!
//! ## No upstream example can do this
//!
//! zenoh-c ships 29 examples and none uses either family — they are deprecated,
//! so upstream's own corpus is silent about them. That is precisely why the
//! drop-in corpus could never have caught a defect here, and why the probe is
//! written rather than borrowed.
//!
//! ## This lane needs an UNSTABLE oracle
//!
//! Both families sit behind `Z_FEATURE_UNSTABLE_API`, so the oracle has to be
//! a build that carries that axis. Two of the four arms do, and both are
//! provisioned: the published archive is the `unstable-shm` build (R2278
//! measured it, at both pins) and Layer C1cc runs against it, while R2281
//! re-aimed Layer C1ce at the `unstable` arm — which carries the axis without
//! shared memory, and is what `wz-capi-c`'s default features model. This header
//! named only a second oracle until R2278, on a reading that has never been
//! true of the archive at any measured pin: it is the `unstable-shm` build.

use std::path::{Path, PathBuf};
use std::process::Command;

use wz_integration_tests::common::{
    wz_capi_c_cdylib, zenoh_c_oracle, zenoh_c_shared_library, PortReservation,
};

/// One program, both families, everything received on the main thread.
const PROBE: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zenoh.h"

#define KE "wz/ext/plane/data"

static void put_str(const z_loaned_session_t *s, const char *body) {
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, KE);
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, body);
    z_put_options_t opts;
    z_put_options_default(&opts);
    z_result_t rc = z_put(s, z_loan(ke), z_move(payload), &opts);
    printf("put[%s].rc=%d\n", body, (int)rc);
}

/* Drain a reply channel to exhaustion, printing each OK reply's payload. The
   channel closes on the query's own final, so this terminates without a timeout
   and without a sleep. */
static int drain_replies(const char *tag, const z_loaned_fifo_handler_reply_t *h) {
    int n = 0;
    for (;;) {
        z_owned_reply_t reply;
        if (z_recv(h, &reply) != Z_OK) break;
        if (z_reply_is_ok(z_loan(reply))) {
            const z_loaned_sample_t *sm = z_reply_ok(z_loan(reply));
            z_owned_string_t body;
            z_bytes_to_string(z_sample_payload(sm), &body);
            printf("%s.reply[%d]=%.*s\n", tag, n,
                   (int)z_string_len(z_loan(body)), z_string_data(z_loan(body)));
            z_drop(z_move(body));
            n++;
        }
        z_drop(z_move(reply));
    }
    printf("%s.replies=%d\n", tag, n);
    return n;
}

static int sub_hits = 0;
static void on_sample(z_loaned_sample_t *sample, void *ctx) {
    (void)ctx;
    z_owned_string_t body;
    z_bytes_to_string(z_sample_payload(sample), &body);
    printf("qsub.sample[%d]=%.*s\n", sub_hits,
           (int)z_string_len(z_loan(body)), z_string_data(z_loan(body)));
    z_drop(z_move(body));
    sub_hits++;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: probe <endpoint>\n"); return 2; }

    z_owned_config_t config;
    z_config_default(&config);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MODE_KEY, "\"peer\"");
    /* A JSON5 ARRAY, as upstream's own examples write it. The first draft passed
       argv[1] bare; that is not a JSON5 value, both parsers refused it, and only
       wz turned the refusal into a failed open — upstream opens an endpointless
       peer and scouts. The probe was wrong, not wz. */
    char listen_json[256];
    snprintf(listen_json, sizeof listen_json, "[\"%s\"]", argv[1]);
    z_result_t listen_rc =
        zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_LISTEN_KEY, listen_json);
    printf("config.listen.rc=%d\n", (int)listen_rc);
    /* UPSTREAM REQUIREMENT, found by running the reference arm rather than by
       reading: `PublicationCache::new` BAILS when the session has no HLC
       (`zenoh-ext/src/publication_cache.rs` @ `impl fmt::Debug for PublicationCache`),
   and the first draft of
       this probe got rc=-128 on libzenohc for exactly that reason. A cache
       stores TIMESTAMPED samples, so a session that stamps nothing cannot back
       one. */
    z_result_t ts_rc = zc_config_insert_json5(z_loan_mut(config), "timestamping",
                           "{\"enabled\":{\"router\":true,\"peer\":true,\"client\":true}}");
    printf("config.timestamping.rc=%d\n", (int)ts_rc);
    z_owned_session_t s;
    z_result_t open_rc = z_open(&s, z_move(config), NULL);
    printf("open.rc=%d\n", (int)open_rc);
    if (open_rc < 0) { return 1; }

    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, KE);

    /* ---- the PUBLICATION CACHE ------------------------------------------ */
    ze_publication_cache_options_t copts;
    ze_publication_cache_options_default(&copts);
    /* Read the defaults back: upstream's history is 1, not 0, and a probe that
       did not print it could not tell a defaulted struct from a zeroed one. */
    printf("cache.default.history=%d\n", (int)copts.history);
    printf("cache.default.complete=%d\n", (int)copts.queryable_complete);
    printf("cache.default.resources_limit=%d\n", (int)copts.resources_limit);
    copts.history = 3;
    ze_owned_publication_cache_t cache;
    z_result_t crc = ze_declare_publication_cache(z_loan(s), &cache, z_loan(ke), &copts);
    printf("cache.declare.rc=%d\n", (int)crc);
    printf("cache.check=%d\n", (int)ze_internal_publication_cache_check(&cache));
    if (crc < 0) { return 1; }

    z_view_string_t cke;
    z_keyexpr_as_view_string(ze_publication_cache_keyexpr(ze_publication_cache_loan(&cache)), &cke);
    printf("cache.keyexpr=%.*s\n",
           (int)z_string_len(z_loan(cke)), z_string_data(z_loan(cke)));

    /* FOUR publications into a THREE-deep ring: the oldest must fall out, which
       is what makes `history` observable rather than merely accepted. */
    put_str(z_loan(s), "one");
    put_str(z_loan(s), "two");
    put_str(z_loan(s), "three");
    put_str(z_loan(s), "four");

    /* ---- the QUERYING SUBSCRIBER ---------------------------------------- */
    /* Declared AFTER the puts, so everything it reports as history came from the
       cache's queryable rather than from live delivery. */
    z_owned_closure_sample_t sub_closure;
    z_closure(&sub_closure, on_sample, NULL, NULL);
    ze_querying_subscriber_options_t qopts;
    ze_querying_subscriber_options_default(&qopts);
    printf("qsub.default.timeout_ms=%d\n", (int)qopts.query_timeout_ms);
    ze_owned_querying_subscriber_t qsub;
    z_result_t qrc = ze_declare_querying_subscriber(z_loan(s), &qsub, z_loan(ke),
                                                    z_move(sub_closure), &qopts);
    printf("qsub.declare.rc=%d\n", (int)qrc);
    printf("qsub.check=%d\n", (int)ze_internal_querying_subscriber_check(&qsub));
    if (qrc < 0) { return 1; }

    /* ---- a DIRECT get at the cache, drained deterministically ------------ */
    z_owned_closure_reply_t rclosure;
    z_owned_fifo_handler_reply_t rhandler;
    z_fifo_channel_reply_new(&rclosure, &rhandler, 16);
    z_get_options_t gopts;
    z_get_options_default(&gopts);
    /* R311y837 — NAME the mode. This get exists to observe the whole ring, and
       a get that names nothing resolves to Latest on BOTH implementations,
       which keeps one reply per keyexpr; all four publications share one
       keyexpr, so the ring collapses to its newest sample and the depth this
       probe varies becomes unobservable. zenoh-ext's own cache-facing GETs pin
       None at every call site for exactly this reason. Measured: with the
       default this printed `get.replies=1` while the querying subscriber, which
       pins None itself, still saw all three. */
    gopts.consolidation = z_query_consolidation_none();
    z_result_t grc = z_get(z_loan(s), z_loan(ke), "", z_move(rclosure), &gopts);
    printf("get.rc=%d\n", (int)grc);
    drain_replies("get", z_loan(rhandler));
    z_drop(z_move(rhandler));

    /* ---- the ADDITIONAL query the family exists to offer ----------------- */
    z_result_t arc_ = ze_querying_subscriber_get(ze_querying_subscriber_loan(&qsub),
                                                 z_loan(ke), NULL);
    printf("qsub.get.rc=%d\n", (int)arc_);

    z_drop(z_move(qsub));
    z_drop(z_move(cache));
    printf("cache.check_after_drop=%d\n", (int)ze_internal_publication_cache_check(&cache));
    printf("qsub.check_after_drop=%d\n", (int)ze_internal_querying_subscriber_check(&qsub));
    z_drop(z_move(s));
    printf("done\n");
    return 0;
}
"#;

/// The SHM-feature oracle's `(include, libdir)`, or `None` with a note naming
/// the script.
///
/// Resolved through the REGISTERED `zenoh_c_oracle` / `zenoh_c_shared_library`
/// rather than by joining a path, and the naming is load-bearing rather than
/// stylistic: Layer A4 derives a test's foreign class from the resolver
/// FUNCTIONS its call graph names, so a library reached through a local
/// `prefix.join("lib/libzenohc.so")` is one the audit cannot see is foreign.
/// The first draft of this file did exactly that and A4-3 rejected its
/// `wz->zenoh-c` claim as a wz-vs-wz test — which is the invariant working.
fn oracle_prefix() -> Option<(PathBuf, PathBuf)> {
    if let Some((include, libdir, _examples)) = zenoh_c_oracle() {
        let lib = zenoh_c_shared_library();
        if lib.is_some() {
            return Some((include, libdir));
        }
    }
    eprintln!(
        "skip: no zenoh-c oracle is installed. Both families sit behind \
         Z_FEATURE_UNSTABLE_API, so the oracle must be a build that carries it — \
         run scripts/install-zenoh-c.sh for the published package, or \
         scripts/install-zenoh-c-arm.sh unstable for the arm Layer C1ce provisions."
    );
    None
}

fn compile(
    src: &Path,
    out: &Path,
    include: &Path,
    libdir: &Path,
    link: &str,
) -> Result<PathBuf, String> {
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let exe = out.join(format!("ext_probe_on_{link}"));
    let output = Command::new(&cc)
        .arg(src)
        .arg(format!("-I{}", include.display()))
        .arg("-o")
        .arg(&exe)
        .arg(format!("-L{}", libdir.display()))
        .arg(format!("-l{link}"))
        .arg(format!("-Wl,-rpath,{}", libdir.display()))
        .output()
        .unwrap_or_else(|e| panic!("spawn {cc}: {e}"));
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(exe)
}

fn run_both_arms(include: &Path, ref_libdir: &Path) -> (String, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("wz_ext_families.c");
    std::fs::write(&src, PROBE).expect("write probe");

    let cdylib = wz_capi_c_cdylib();
    let wz_libdir = cdylib.parent().expect("cdylib parent").to_path_buf();
    let on_wz = compile(&src, dir.path(), include, &wz_libdir, "wz_capi_c").unwrap_or_else(|d| {
        panic!(
            "§5.27 api-compat-c: the zenoh-ext probe does NOT link against wz's \
             cdylib. A missing symbol here is a program upstream can write and wz \
             cannot run.\n{d}"
        )
    });

    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference dir");
    let on_ref = compile(&src, &ref_dir, include, ref_libdir, "zenohc")
        .unwrap_or_else(|d| panic!("the probe does not link against the REAL libzenohc\n{d}"));

    let run = |exe: &Path, libdir: &Path| -> (bool, String) {
        let port = PortReservation::pick();
        let out = Command::new(exe)
            .arg(format!("tcp/127.0.0.1:{}", port.port()))
            .env("LD_LIBRARY_PATH", libdir)
            .output()
            .unwrap_or_else(|e| panic!("spawn {}: {e}", exe.display()));
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    };
    let (wz_ok, wz_out) = run(&on_wz, &wz_libdir);
    let (ref_ok, ref_out) = run(&on_ref, ref_libdir);
    assert!(
        ref_ok,
        "the REFERENCE arm failed, so the comparison below would be meaningless.\n{ref_out}"
    );
    assert!(wz_ok, "the wz arm exited non-zero:\n{wz_out}");
    (wz_out, ref_out)
}

/// Lines that must appear on EITHER arm before the two are compared.
///
/// R311y570: a diff gate is an EQUALITY. Two arms that both refused to declare
/// anything would print identical stdouts and diff clean, so the parts that are
/// true regardless of what the cache returns are anchored from HERE — outside
/// the C program that prints them.
const ANCHORS: &[&str] = &[
    // Upstream's `ze_publication_cache_options_default` sets history to 1, and a
    // zeroed struct would set it to 0. This line is what tells them apart.
    "cache.default.history=1",
    "cache.default.complete=0",
    "cache.default.resources_limit=0",
    "cache.declare.rc=0",
    "cache.check=1",
    "cache.keyexpr=wz/ext/plane/data",
    "put[one].rc=0",
    "put[four].rc=0",
    "qsub.default.timeout_ms=0",
    "qsub.declare.rc=0",
    "qsub.check=1",
    "get.rc=0",
    "qsub.get.rc=0",
    // A moved handle must gravestone, on both families.
    "cache.check_after_drop=0",
    "qsub.check_after_drop=0",
    "done",
];

fn assert_anchored(arm: &str, stdout: &str) {
    let lines: Vec<&str> = stdout.lines().collect();
    let missing: Vec<&&str> = ANCHORS.iter().filter(|w| !lines.contains(w)).collect();
    assert!(
        missing.is_empty(),
        "the {arm} arm is missing {} anchored line(s), so it never reached the state \
         this probe measures.\nmissing: {missing:?}\n--- stdout ---\n{stdout}",
        missing.len(),
    );
}

/// THE ADJUDICATOR: both zenoh-ext families behave identically on wz's cdylib
/// and on the real `libzenohc.so`.
// wz-proves: api-compat-c wz->zenoh-c partial
#[test]
#[ignore = "links the shared-memory zenoh-c oracle; run by run-ci Layer C1ce"]
fn the_zenoh_ext_families_behave_identically_on_wz_and_libzenohc() {
    let Some((include, ref_libdir)) = oracle_prefix() else {
        return;
    };
    let (wz_out, ref_out) = run_both_arms(&include, &ref_libdir);

    assert_anchored("REFERENCE", &ref_out);
    assert_anchored("wz", &wz_out);

    // ADJUDICATED vs REPORTED, and the split is a MEASUREMENT rather than a
    // convenience. Upstream's publication cache stores through a background task
    // with no completion signal (`zenoh-ext/src/publication_cache.rs`
    // @ `let mut local_sub`),
    // so how many of the four publications have landed when the query arrives is
    // a RACE on the reference arm: the first run of this probe saw
    // `get.replies=1` there against wz's 3, and re-running moved the number.
    // Diffing that would be diffing a scheduler.
    //
    // So the diff covers the lines whose value is DETERMINED — the option
    // defaults, every rc, the keyexpr accessor and the post-move gravestones —
    // and the delivery lines are printed on both arms but adjudicated by neither.
    // That is a NAMED NON-CLAIM, not a silent exclusion: what this file proves is
    // that the 18 symbols exist and their ABI surface behaves as upstream's does,
    // and what it explicitly does not prove is that a cached sample reaches a
    // querier in the same WINDOW on both implementations.
    let adjudicated = |line: &str| {
        !(line.starts_with("qsub.sample[")
            || line.starts_with("get.reply[")
            || line.starts_with("get.replies="))
    };
    let wz: Vec<&str> = wz_out.lines().filter(|l| adjudicated(l)).collect();
    let reference: Vec<&str> = ref_out.lines().filter(|l| adjudicated(l)).collect();
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
        "{} of {} probe line(s) differ between wz's zenoh-c ABI and the real \
         libzenohc:\n{}",
        differing.len(),
        reference.len(),
        differing.join("\n")
    );

    // The wz-side claim the diff above deliberately does not make, asserted HERE
    // and labelled as wz-only: FOUR publications into a THREE-deep ring leave
    // exactly three, oldest evicted. Upstream cannot be held to it in the same
    // run for the timing reason above, so this is a claim about wz's cache
    // semantics rather than a differential — and saying so is the point.
    assert!(
        wz_out.contains("get.replies=3"),
        "wz's publication cache did not answer with its whole 3-deep ring. \
         `history` is the one cache option this probe varies, so a wrong count \
         here means the bound is not being applied.\n{wz_out}"
    );
    assert!(
        !wz_out.contains("=one"),
        "wz's cache still holds `one`, the publication a 3-deep ring must have \
         evicted when the fourth arrived — the ring is not bounded.\n{wz_out}"
    );
}
