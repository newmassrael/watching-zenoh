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
    /* Scouting off, as zenoh's own tests state it: a session that scouts connects to every
       zenoh node on the default group, and this one is to talk to the endpoint it is given. */
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MULTICAST_SCOUTING_KEY, "false");
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

/// Compile `probe` once and run it against wz's cdylib and against the real
/// libzenohc, returning `(wz stdout, reference stdout)`.
fn run_both_arms(probe: &str, include: &Path, ref_libdir: &Path) -> (String, String) {
    run_both_arms_with(probe, include, ref_libdir, &[], 1)
}

/// [`run_both_arms`] for a probe that takes `leading` arguments and then `ports` loopback
/// endpoints, each a port reserved for the run.
fn run_both_arms_with(
    probe: &str,
    include: &Path,
    ref_libdir: &Path,
    leading: &[&str],
    ports: usize,
) -> (String, String) {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("wz_ext_families.c");
    std::fs::write(&src, probe).expect("write probe");

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
        // ONE reservation for all of them: picking `ports` times on a thread deadlocks.
        let (_reservation, reserved) = PortReservation::pick_many(ports);
        let out = Command::new(exe)
            .args(leading)
            .args(reserved.iter().map(|port| format!("tcp/127.0.0.1:{port}")))
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
    let (wz_out, ref_out) = run_both_arms(PROBE, &include, &ref_libdir);

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

/// One program that fills a publication cache and asks it for its contents under
/// every `_time` selector worth telling apart, printing which publications came
/// back.
///
/// The selectors are built FROM THE CACHED SAMPLES' OWN TIMESTAMPS, read off an
/// unfiltered reply, so a boundary can sit on a sample's exact nanosecond, one
/// nanosecond either side of it, or a zone/fraction spelling away from it. A
/// range written in relative time (`now(-1h)`) could only say "all" or "none"
/// of samples this fresh; it cannot say which side of a boundary a sample is.
///
/// Every case is chosen so that a parser that REJECTED the selector would answer
/// differently from one that read it: a valid range that holds nothing against
/// one that does not parse and so filters nothing. That is what makes a pass here
/// mean "read the same", where a case answering "all" either way would pass for a
/// parser that read nothing.
const TIME_RANGE_PROBE: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "zenoh.h"

#define KE "wz/timerange/data"
#define KE_WILD "wz/timerange/*"
#define N 4

static const char *BODY[N] = {"p0", "p1", "p2", "p3"};

static void nap_ms(long ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

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

/* One get. Returns a bitmask of the publications that came back, and when
   `stamps` is given, the NTP64 word each reply carried. The channel closes on the
   query's own final, so this drains without a timeout. */
static unsigned ask(const z_loaned_session_t *s, const char *ke_str, const char *params,
                    uint64_t stamps[N]) {
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, ke_str);
    z_owned_closure_reply_t closure;
    z_owned_fifo_handler_reply_t handler;
    z_fifo_channel_reply_new(&closure, &handler, 16);
    z_get_options_t gopts;
    z_get_options_default(&gopts);
    gopts.consolidation = z_query_consolidation_none();
    z_result_t rc = z_get(s, z_loan(ke), params, z_move(closure), &gopts);
    unsigned mask = 0;
    if (rc < 0) {
        printf("get.rc=%d\n", (int)rc);
        z_drop(z_move(handler));
        return 0;
    }
    for (;;) {
        z_owned_reply_t reply;
        if (z_recv(z_loan(handler), &reply) != Z_OK) break;
        if (z_reply_is_ok(z_loan(reply))) {
            const z_loaned_sample_t *sm = z_reply_ok(z_loan(reply));
            z_owned_string_t body;
            z_bytes_to_string(z_sample_payload(sm), &body);
            for (int i = 0; i < N; i++) {
                size_t len = strlen(BODY[i]);
                if (z_string_len(z_loan(body)) == len &&
                    memcmp(z_string_data(z_loan(body)), BODY[i], len) == 0) {
                    mask |= 1u << i;
                    const z_timestamp_t *ts = z_sample_timestamp(sm);
                    if (ts && stamps) stamps[i] = z_timestamp_ntp64_time(ts);
                }
            }
            z_drop(z_move(body));
        }
        z_drop(z_move(reply));
    }
    z_drop(z_move(handler));
    return mask;
}

static void report(const char *label, unsigned mask) {
    printf("sel[%s]=", label);
    int n = 0;
    for (int i = 0; i < N; i++) {
        if (mask & (1u << i)) {
            printf("%s%s", n ? "," : "", BODY[i]);
            n++;
        }
    }
    if (!n) printf("none");
    printf("\n");
}

/* The RFC3339 spelling of the instant an NTP64 word names, shifted by `delta_ns`,
   to `digits` fractional digits, with `zone` appended. The fraction becomes
   nanoseconds the way uhlc reads it, rounded UP, so a spelling at 9 digits is
   the sample's own instant. */
static void instant(uint64_t ntp, long delta_ns, int digits, const char *zone, char *out,
                    size_t cap) {
    uint64_t frac = ntp & 0xFFFFFFFFull;
    int64_t secs = (int64_t)(ntp >> 32);
    int64_t nanos = (int64_t)((frac * 1000000000ull + 0xFFFFFFFFull) >> 32) + delta_ns;
    while (nanos >= 1000000000) { nanos -= 1000000000; secs++; }
    while (nanos < 0) { nanos += 1000000000; secs--; }
    time_t t = (time_t)secs;
    struct tm tm;
    gmtime_r(&t, &tm);
    char nine[16];
    snprintf(nine, sizeof nine, "%09ld", (long)nanos);
    nine[digits] = 0;
    if (digits > 0) {
        snprintf(out, cap, "%04d-%02d-%02dT%02d:%02d:%02d.%s%s", tm.tm_year + 1900,
                 tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, nine, zone);
    } else {
        snprintf(out, cap, "%04d-%02d-%02dT%02d:%02d:%02d%s", tm.tm_year + 1900,
                 tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, zone);
    }
}

#define SEL(label, ke, ...)                                  \
    do {                                                     \
        snprintf(sel, sizeof sel, __VA_ARGS__);              \
        report(label, ask(loan_s, ke, sel, NULL));           \
    } while (0)

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: probe <endpoint>\n"); return 2; }

    z_owned_config_t config;
    z_config_default(&config);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MULTICAST_SCOUTING_KEY, "false");
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MODE_KEY, "\"peer\"");
    char listen_json[256];
    snprintf(listen_json, sizeof listen_json, "[\"%s\"]", argv[1]);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_LISTEN_KEY, listen_json);
    /* A cache stores TIMESTAMPED samples, so a session that stamps nothing cannot
       back one (`PublicationCache::new` bails without an HLC). */
    zc_config_insert_json5(z_loan_mut(config), "timestamping",
                           "{\"enabled\":{\"router\":true,\"peer\":true,\"client\":true}}");
    z_owned_session_t s;
    z_result_t open_rc = z_open(&s, z_move(config), NULL);
    printf("open.rc=%d\n", (int)open_rc);
    if (open_rc < 0) { return 1; }
    const z_loaned_session_t *loan_s = z_loan(s);

    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, KE);
    ze_publication_cache_options_t copts;
    ze_publication_cache_options_default(&copts);
    copts.history = 8;
    ze_owned_publication_cache_t cache;
    z_result_t crc = ze_declare_publication_cache(loan_s, &cache, z_loan(ke), &copts);
    printf("cache.declare.rc=%d\n", (int)crc);
    if (crc < 0) { return 1; }

    /* Four publications, a few milliseconds apart so their HLC stamps are far
       enough apart that no spelling below can straddle two of them by accident. */
    for (int i = 0; i < N; i++) {
        put_str(loan_s, BODY[i]);
        nap_ms(4);
    }

    /* Upstream's cache stores through a background task with no completion signal,
       so the publications land when they land. Ask until all four are there. */
    uint64_t stamps[N] = {0, 0, 0, 0};
    unsigned seen = 0;
    for (int tries = 0; tries < 500 && seen != 0xFu; tries++) {
        seen = ask(loan_s, KE, "", stamps);
        if (seen != 0xFu) nap_ms(10);
    }
    printf("settled=%d\n", seen == 0xFu);
    if (seen != 0xFu) { return 1; }
    int increasing = 1;
    for (int i = 0; i + 1 < N; i++) if (!(stamps[i] < stamps[i + 1])) increasing = 0;
    printf("stamps.increasing=%d\n", increasing);

    char t1[64], t2[64], t1p[64], t1m[64], t1z[64], t1f[64], sel[512];
    instant(stamps[1], 0, 9, "Z", t1, sizeof t1);
    instant(stamps[2], 0, 9, "Z", t2, sizeof t2);
    instant(stamps[1], 1, 9, "Z", t1p, sizeof t1p);
    instant(stamps[1], -1, 9, "Z", t1m, sizeof t1m);
    instant(stamps[1], 0, 9, "+00:00", t1z, sizeof t1z);
    /* Five fractional digits: a spelling that is EARLIER than the sample by up to
       ten microseconds, so it still holds the sample and drops the one before. */
    instant(stamps[1], 0, 5, "Z", t1f, sizeof t1f);

    /* ---- a boundary on a sample's own instant, and one nanosecond either side - */
    SEL("all", KE, "_time=[..]");
    SEL("from1-in", KE, "_time=[%s..]", t1);
    SEL("from1-ex", KE, "_time=]%s..]", t1);
    SEL("to2-in", KE, "_time=[..%s]", t2);
    SEL("to2-ex", KE, "_time=[..%s[", t2);
    SEL("span-in", KE, "_time=[%s..%s]", t1, t2);
    SEL("span-ex", KE, "_time=]%s..%s[", t1, t2);
    SEL("from1-plus1ns", KE, "_time=[%s..]", t1p);
    SEL("from1-minus1ns", KE, "_time=[%s..]", t1m);
    SEL("to1-minus1ns", KE, "_time=[..%s]", t1m);
    /* ---- the spellings humantime's weak parser accepts ------------------------ */
    SEL("zone-offset", KE, "_time=[%s..]", t1z);
    SEL("frac-5-digits", KE, "_time=[%s..]", t1f);
    SEL("old-date-space", KE, "_time=[..2000-01-01 00:00:00]");
    SEL("old-date-zoneless", KE, "_time=[..2000-01-01T00:00:00]");
    SEL("epoch-end", KE, "_time=[..1970-01-01T00:00:00Z]");
    SEL("year-9999-leap", KE, "_time=[9999-12-31T23:59:60Z..]");
    /* ---- relative time, every unit -------------------------------------------- */
    SEL("future-hour", KE, "_time=[now(1h)..]");
    SEL("plus-sign", KE, "_time=[now(+1h)..]");
    SEL("past-hour-end", KE, "_time=[..now(-1h)]");
    SEL("recent-hour", KE, "_time=[now(-1h)..]");
    SEL("until-hour", KE, "_time=[..now(1h)]");
    SEL("unit-u", KE, "_time=[..now(-3600000000u)]");
    SEL("unit-ms", KE, "_time=[..now(-3600000ms)]");
    SEL("unit-s", KE, "_time=[..now(-3600s)]");
    SEL("unit-m", KE, "_time=[..now(-60m)]");
    SEL("unit-h", KE, "_time=[..now(-0.5h)]");
    SEL("unit-d", KE, "_time=[..now(-1d)]");
    SEL("unit-w", KE, "_time=[..now(-1w)]");
    SEL("unit-bare", KE, "_time=[..now(-3600)]");
    /* An offset no instant can hold is an UNBOUNDED end, not a clamp. */
    SEL("offset-overflow-end", KE, "_time=[..now(-1e300d)]");
    SEL("offset-overflow-start", KE, "_time=[now(1e300d)..]");
    /* ---- values upstream's parser rejects: no filter, every publication ------- */
    SEL("duration-form", KE, "_time=[%s;1h]", t1);
    SEL("bogus", KE, "_time=bogus");
    SEL("too-short", KE, "_time=[..");
    SEL("date-only", KE, "_time=[..2020-11-05]");
    SEL("pre-epoch", KE, "_time=[..1969-12-31T23:59:59Z]");
    SEL("year-10000", KE, "_time=[..10000-01-01T00:00:00Z]");
    /* ---- where the key sits in the parameter list, and the wildcard branch ---- */
    SEL("first-key-wins", KE, "_time=[%s..];_time=[..]", t2);
    SEL("surrounded", KE, "x=1;_time=]%s..];y=2", t2);
    SEL("wildcard-key", KE_WILD, "_time=[%s..]", t1);

    z_drop(z_move(cache));
    z_drop(z_move(s));
    printf("done\n");
    return 0;
}
"#;

/// Lines that must appear on the REFERENCE arm, written from zenoh-util's
/// `TimeRange` and zenoh-ext's `PublicationCache` rather than copied from a run.
/// A diff is an equality, and two arms that both ignored `_time` would print the
/// same four publications for every selector; these are what tell a filter from
/// its absence.
const TIME_RANGE_EXPECTED: &[&str] = &[
    "cache.declare.rc=0",
    "put[p0].rc=0",
    "put[p3].rc=0",
    "settled=1",
    "stamps.increasing=1",
    "sel[all]=p0,p1,p2,p3",
    "sel[from1-in]=p1,p2,p3",
    "sel[from1-ex]=p2,p3",
    "sel[to2-in]=p0,p1,p2",
    "sel[to2-ex]=p0,p1",
    "sel[span-in]=p1,p2",
    "sel[span-ex]=none",
    "sel[from1-plus1ns]=p2,p3",
    "sel[from1-minus1ns]=p1,p2,p3",
    "sel[to1-minus1ns]=p0",
    "sel[zone-offset]=p1,p2,p3",
    "sel[frac-5-digits]=p1,p2,p3",
    "sel[old-date-space]=none",
    "sel[old-date-zoneless]=none",
    "sel[epoch-end]=none",
    "sel[year-9999-leap]=none",
    "sel[future-hour]=none",
    "sel[plus-sign]=none",
    "sel[past-hour-end]=none",
    "sel[recent-hour]=p0,p1,p2,p3",
    "sel[until-hour]=p0,p1,p2,p3",
    "sel[unit-u]=none",
    "sel[unit-ms]=none",
    "sel[unit-s]=none",
    "sel[unit-m]=none",
    "sel[unit-h]=none",
    "sel[unit-d]=none",
    "sel[unit-w]=none",
    "sel[unit-bare]=none",
    "sel[offset-overflow-end]=p0,p1,p2,p3",
    "sel[offset-overflow-start]=p0,p1,p2,p3",
    "sel[duration-form]=p0,p1,p2,p3",
    "sel[bogus]=p0,p1,p2,p3",
    "sel[too-short]=p0,p1,p2,p3",
    "sel[date-only]=p0,p1,p2,p3",
    "sel[pre-epoch]=p0,p1,p2,p3",
    "sel[year-10000]=p0,p1,p2,p3",
    "sel[first-key-wins]=p2,p3",
    "sel[surrounded]=p3",
    "sel[wildcard-key]=p1,p2,p3",
    "done",
];

/// THE ADJUDICATOR for the publication cache's `_time` filter: every selector
/// answers the same set on wz's cdylib and on the real `libzenohc.so`.
///
/// NOT CLAIMED: a sample with no timestamp (a cache cannot be built without an
/// HLC, so the C API cannot make one), and a cache answering while the wall
/// clock moves under a relative bound.
// wz-proves: api-compat-c wz->zenoh-c partial
#[test]
#[ignore = "links the shared-memory zenoh-c oracle; run by run-ci Layer C1ce"]
fn the_publication_cache_filters_by_the_querys_time_range_identically_on_wz_and_libzenohc() {
    let Some((include, ref_libdir)) = oracle_prefix() else {
        return;
    };
    let (wz_out, ref_out) = run_both_arms(TIME_RANGE_PROBE, &include, &ref_libdir);

    for (arm, stdout) in [("REFERENCE", &ref_out), ("wz", &wz_out)] {
        let lines: Vec<&str> = stdout.lines().collect();
        let missing: Vec<&&str> = TIME_RANGE_EXPECTED
            .iter()
            .filter(|w| !lines.contains(w))
            .collect();
        assert!(
            missing.is_empty(),
            "the {arm} arm answered {} selector(s) differently from what zenoh's own \
             `TimeRange` and `PublicationCache` say it must.\nmissing: {missing:?}\n\
             --- stdout ---\n{stdout}",
            missing.len(),
        );
    }

    let wz: Vec<&str> = wz_out.lines().filter(|l| l.starts_with("sel[")).collect();
    let reference: Vec<&str> = ref_out.lines().filter(|l| l.starts_with("sel[")).collect();
    assert_eq!(
        wz, reference,
        "wz's publication cache and the real libzenohc answer some `_time` selector \
         differently"
    );
    assert!(
        wz.len() >= 40,
        "only {} selector line(s) were compared; the probe stopped early:\n{wz_out}",
        wz.len()
    );
}

/// One program that holds a querying subscriber's query OPEN while samples arrive,
/// then answers it, and prints what the subscriber's callback saw and when.
///
/// The queryable keeps a CLONE of the query it is handed and answers it from the main
/// thread later, so the order of events is the program's, not a scheduler's: no
/// sleep decides which comes first. While the initial query is held open the program
/// publishes two live samples, checks the callback has seen nothing, then answers with
/// replies out of order, one repeated timestamp, one reply that repeats a live
/// sample's timestamp, and one with no timestamp at all. A second round does the
/// same through `ze_querying_subscriber_get`.
const MERGE_PROBE: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include "zenoh.h"

#define KE "wz/merge/data"
#define MAXLOG 32

static pthread_mutex_t LOCK = PTHREAD_MUTEX_INITIALIZER;
static char LOG_NAME[MAXLOG][16];
static int LOG_TS[MAXLOG];
static int LOG_N = 0;

static z_owned_query_t HELD[4];
static int HELD_N = 0;

static void nap_ms(long ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static void on_sample(z_loaned_sample_t *sample, void *ctx) {
    (void)ctx;
    z_owned_string_t body;
    z_bytes_to_string(z_sample_payload(sample), &body);
    pthread_mutex_lock(&LOCK);
    if (LOG_N < MAXLOG) {
        size_t n = z_string_len(z_loan(body));
        if (n > 15) n = 15;
        memcpy(LOG_NAME[LOG_N], z_string_data(z_loan(body)), n);
        LOG_NAME[LOG_N][n] = 0;
        LOG_TS[LOG_N] = z_sample_timestamp(sample) != NULL;
        LOG_N++;
    }
    pthread_mutex_unlock(&LOCK);
    z_drop(z_move(body));
}

static void on_query(z_loaned_query_t *query, void *ctx) {
    (void)ctx;
    pthread_mutex_lock(&LOCK);
    if (HELD_N < 4) {
        z_query_clone(&HELD[HELD_N], query);
        HELD_N++;
    }
    pthread_mutex_unlock(&LOCK);
}

static int log_count(void) {
    pthread_mutex_lock(&LOCK);
    int n = LOG_N;
    pthread_mutex_unlock(&LOCK);
    return n;
}

static int held_count(void) {
    pthread_mutex_lock(&LOCK);
    int n = HELD_N;
    pthread_mutex_unlock(&LOCK);
    return n;
}

static void log_clear(void) {
    pthread_mutex_lock(&LOCK);
    LOG_N = 0;
    pthread_mutex_unlock(&LOCK);
}

/* Poll `f` until it reaches `want` or `ms` pass. The program decides what happens
   next from what it saw, so a wait is a wait for a fact. */
static int wait_for(int (*f)(void), int want, int ms) {
    for (int waited = 0; waited < ms; waited += 5) {
        if (f() >= want) return 1;
        nap_ms(5);
    }
    return f() >= want;
}

static void print_round(const char *tag) {
    pthread_mutex_lock(&LOCK);
    printf("%s.order=", tag);
    for (int i = 0; i < LOG_N; i++) printf("%s%s", i ? "," : "", LOG_NAME[i]);
    if (!LOG_N) printf("none");
    printf("\n%s.count=%d\n%s.timestamps=", tag, LOG_N, tag);
    for (int i = 0; i < LOG_N; i++) printf("%s%d", i ? "," : "", LOG_TS[i]);
    if (!LOG_N) printf("none");
    printf("\n");
    pthread_mutex_unlock(&LOCK);
}

static void put_ts(const z_loaned_session_t *s, const char *body, z_timestamp_t *ts) {
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, KE);
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, body);
    z_put_options_t opts;
    z_put_options_default(&opts);
    opts.timestamp = ts;
    z_result_t rc = z_put(s, z_loan(ke), z_move(payload), &opts);
    printf("put[%s].rc=%d\n", body, (int)rc);
}

static void reply_with(const z_loaned_query_t *q, const char *body, z_timestamp_t *ts) {
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, KE);
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, body);
    z_query_reply_options_t ro;
    z_query_reply_options_default(&ro);
    ro.timestamp = ts;
    z_result_t rc = z_query_reply(q, z_loan(ke), z_move(payload), &ro);
    printf("reply[%s].rc=%d\n", body, (int)rc);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: probe <endpoint>\n"); return 2; }

    z_owned_config_t config;
    z_config_default(&config);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MULTICAST_SCOUTING_KEY, "false");
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MODE_KEY, "\"peer\"");
    char listen_json[256];
    snprintf(listen_json, sizeof listen_json, "[\"%s\"]", argv[1]);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_LISTEN_KEY, listen_json);
    zc_config_insert_json5(z_loan_mut(config), "timestamping",
                           "{\"enabled\":{\"router\":true,\"peer\":true,\"client\":true}}");
    z_owned_session_t s;
    z_result_t open_rc = z_open(&s, z_move(config), NULL);
    printf("open.rc=%d\n", (int)open_rc);
    if (open_rc < 0) { return 1; }
    const z_loaned_session_t *ls = z_loan(s);

    /* Seven stamps in the order they are minted: the replies A < B < C, the live
       L1 < L2, then the second round's history H2 < live M1. */
    z_timestamp_t tA, tB, tC, tL1, tL2, tH2, tM1;
    z_timestamp_t *all[7] = {&tA, &tB, &tC, &tL1, &tL2, &tH2, &tM1};
    int minted = 1;
    uint64_t last = 0;
    for (int i = 0; i < 7; i++) {
        if (z_timestamp_new(all[i], ls) < 0) minted = 0;
        uint64_t now = z_timestamp_ntp64_time(all[i]);
        if (i > 0 && !(last < now)) minted = 0;
        last = now;
    }
    printf("stamps.increasing=%d\n", minted);

    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, KE);

    z_owned_closure_query_t qclosure;
    z_closure(&qclosure, on_query, NULL, NULL);
    z_owned_queryable_t qbl;
    z_result_t brc = z_declare_queryable(ls, &qbl, z_loan(ke), z_move(qclosure), NULL);
    printf("queryable.rc=%d\n", (int)brc);
    if (brc < 0) { return 1; }

    z_owned_closure_sample_t sclosure;
    z_closure(&sclosure, on_sample, NULL, NULL);
    ze_querying_subscriber_options_t qopts;
    ze_querying_subscriber_options_default(&qopts);
    ze_owned_querying_subscriber_t qsub;
    z_result_t qrc = ze_declare_querying_subscriber(ls, &qsub, z_loan(ke),
                                                    z_move(sclosure), &qopts);
    printf("qsub.declare.rc=%d\n", (int)qrc);
    if (qrc < 0) { return 1; }

    /* ---- round 1: the INITIAL query ------------------------------------------ */
    printf("phase1.query_held=%d\n", wait_for(held_count, 1, 3000));
    put_ts(ls, "L1", &tL1);
    put_ts(ls, "L2", &tL2);
    nap_ms(200);
    /* The initial query is still open. A live sample that arrived now is parked. */
    printf("phase1.before_reply=%d\n", log_count());
    reply_with(z_loan(HELD[0]), "B", &tB);
    reply_with(z_loan(HELD[0]), "A", &tA);
    reply_with(z_loan(HELD[0]), "Adup", &tA);
    reply_with(z_loan(HELD[0]), "C", &tC);
    reply_with(z_loan(HELD[0]), "L1dup", &tL1);
    reply_with(z_loan(HELD[0]), "U", NULL);
    nap_ms(200);
    /* Replies are parked as well: the query has not ended, so nothing is out yet. */
    printf("phase1.before_end=%d\n", log_count());
    z_drop(z_move(HELD[0]));
    wait_for(log_count, 6, 3000);
    nap_ms(200);
    print_round("phase1");

    /* ---- round 2: a LATER query ---------------------------------------------- */
    log_clear();
    z_result_t grc = ze_querying_subscriber_get(ze_querying_subscriber_loan(&qsub),
                                                z_loan(ke), NULL);
    printf("qsub.get.rc=%d\n", (int)grc);
    printf("phase2.query_held=%d\n", wait_for(held_count, 2, 3000));
    put_ts(ls, "M1", &tM1);
    nap_ms(200);
    printf("phase2.before_reply=%d\n", log_count());
    reply_with(z_loan(HELD[1]), "H2", &tH2);
    z_drop(z_move(HELD[1]));
    wait_for(log_count, 2, 3000);
    nap_ms(200);
    print_round("phase2");

    z_drop(z_move(qsub));
    z_drop(z_move(qbl));
    z_drop(z_move(s));
    printf("done\n");
    return 0;
}
"#;

/// What the reference arm must print, written from zenoh-ext's `FetchingSubscriber`
/// (`MergeQueue`, `register_handler`, `RepliesHandler`) rather than copied from a run.
/// A diff is an equality, and an arm that delivered everything on arrival would print
/// the same six names in a different order: these lines are the order.
const MERGE_EXPECTED: &[&str] = &[
    "stamps.increasing=1",
    "queryable.rc=0",
    "qsub.declare.rc=0",
    // Held open, a live sample waits: nothing reached the callback.
    "phase1.query_held=1",
    "phase1.before_reply=0",
    "reply[B].rc=0",
    "reply[U].rc=0",
    // Replies wait too, until the query ends.
    "phase1.before_end=0",
    // No timestamp first, then oldest first; the repeated A and the repeat of L1
    // are the same instant as one already parked, and are not delivered.
    "phase1.order=U,A,B,C,L1,L2",
    "phase1.count=6",
    "phase1.timestamps=0,1,1,1,1,1",
    "qsub.get.rc=0",
    "phase2.query_held=1",
    "phase2.before_reply=0",
    "phase2.order=H2,M1",
    "phase2.count=2",
    "phase2.timestamps=1,1",
    "done",
];

/// THE ADJUDICATOR for the querying subscriber's merge: what its callback sees, in what
/// order and when, is the same on wz's cdylib and on the real `libzenohc.so`.
///
/// NOT CLAIMED: a live sample that carries no timestamp (stamped on arrival upstream),
/// which a single session cannot make because its own puts are stamped; and a query that
/// ends by timeout rather than by its final.
// wz-proves: api-compat-c wz->zenoh-c partial
#[test]
#[ignore = "links the shared-memory zenoh-c oracle; run by run-ci Layer C1ce"]
fn a_querying_subscriber_merges_replies_and_live_samples_identically_on_wz_and_libzenohc() {
    let Some((include, ref_libdir)) = oracle_prefix() else {
        return;
    };
    let (wz_out, ref_out) = run_both_arms(MERGE_PROBE, &include, &ref_libdir);

    for (arm, stdout) in [("REFERENCE", &ref_out), ("wz", &wz_out)] {
        let lines: Vec<&str> = stdout.lines().collect();
        let missing: Vec<&&str> = MERGE_EXPECTED
            .iter()
            .filter(|w| !lines.contains(w))
            .collect();
        assert!(
            missing.is_empty(),
            "the {arm} arm did not merge as zenoh-ext's FetchingSubscriber does.\n\
             missing: {missing:?}\n--- stdout ---\n{stdout}",
        );
    }
    let wz: Vec<&str> = wz_out.lines().collect();
    let reference: Vec<&str> = ref_out.lines().collect();
    assert_eq!(
        wz, reference,
        "wz's querying subscriber and the real libzenohc's differ in what the callback \
         saw"
    );
}

/// One program, two sessions in one process joined by a link, an advanced publisher
/// with a cache and an advanced subscriber with history on each side of the link.
/// It prints how many times each subscriber's callback ran and for which samples.
///
/// A C session in wz is a plane plus one wz session per link, and an advanced
/// subscriber is declared on each. The plane's startup history GET is pinned to the
/// session; a face's is not, and whether a face's GET reaches that face's own copies
/// of the cache and answers a second time is the question: the real library has ONE
/// subscriber and one cache, so it hears each cached sample once. The link is what
/// makes a face exist, so the link is the variable and the count is the answer.
const FACE_PROBE: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include "zenoh.h"

#define KE "wz/face/data"
#define MAXLOG 32

static pthread_mutex_t LOCK = PTHREAD_MUTEX_INITIALIZER;
static char NAMES_1[MAXLOG][16];
static char NAMES_2[MAXLOG][16];
static int N_1 = 0;
static int N_2 = 0;

static void nap_ms(long ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static void record(char names[MAXLOG][16], int *n, z_loaned_sample_t *sample) {
    z_owned_string_t body;
    z_bytes_to_string(z_sample_payload(sample), &body);
    pthread_mutex_lock(&LOCK);
    if (*n < MAXLOG) {
        size_t len = z_string_len(z_loan(body));
        if (len > 15) len = 15;
        memcpy(names[*n], z_string_data(z_loan(body)), len);
        names[*n][len] = 0;
        (*n)++;
    }
    pthread_mutex_unlock(&LOCK);
    z_drop(z_move(body));
}

static void on_sample_1(z_loaned_sample_t *sample, void *ctx) { (void)ctx; record(NAMES_1, &N_1, sample); }
static void on_sample_2(z_loaned_sample_t *sample, void *ctx) { (void)ctx; record(NAMES_2, &N_2, sample); }

static void on_peer(const z_id_t *id, void *ctx) {
    (void)id;
    (*(int *)ctx)++;
}

static int peers_of(const z_loaned_session_t *s) {
    int n = 0;
    z_owned_closure_zid_t closure;
    z_closure(&closure, on_peer, NULL, &n);
    z_info_peers_zid(s, z_move(closure));
    return n;
}

static int by_name(const void *a, const void *b) { return strcmp((const char *)a, (const char *)b); }

static void report(const char *tag, char names[MAXLOG][16], int n) {
    pthread_mutex_lock(&LOCK);
    qsort(names, (size_t)n, 16, by_name);
    printf("%s.count=%d\n%s.names=", tag, n, tag);
    for (int i = 0; i < n; i++) printf("%s%s", i ? "," : "", names[i]);
    if (!n) printf("none");
    printf("\n");
    pthread_mutex_unlock(&LOCK);
}

static z_result_t open_peer(z_owned_session_t *s, const char *key, const char *endpoint) {
    z_owned_config_t config;
    z_config_default(&config);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MULTICAST_SCOUTING_KEY, "false");
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MODE_KEY, "\"peer\"");
    char json[256];
    snprintf(json, sizeof json, "[\"%s\"]", endpoint);
    zc_config_insert_json5(z_loan_mut(config), key, json);
    zc_config_insert_json5(z_loan_mut(config), "timestamping",
                           "{\"enabled\":{\"router\":true,\"peer\":true,\"client\":true}}");
    return z_open(s, z_move(config), NULL);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: probe <endpoint>\n"); return 2; }

    z_owned_session_t s1, s2;
    z_result_t rc1 = open_peer(&s1, Z_CONFIG_LISTEN_KEY, argv[1]);
    printf("open1.rc=%d\n", (int)rc1);
    if (rc1 < 0) { return 1; }
    z_result_t rc2 = open_peer(&s2, Z_CONFIG_CONNECT_KEY, argv[1]);
    printf("open2.rc=%d\n", (int)rc2);
    if (rc2 < 0) { return 1; }
    const z_loaned_session_t *l1 = z_loan(s1);
    const z_loaned_session_t *l2 = z_loan(s2);

    /* The link is the variable: wait for it from BOTH ends before anything is declared. */
    int up = 0;
    for (int waited = 0; waited < 8000 && !up; waited += 20) {
        up = peers_of(l1) >= 1 && peers_of(l2) >= 1;
        if (!up) nap_ms(20);
    }
    printf("link.up=%d\n", up);
    if (!up) { return 1; }

    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, KE);

    ze_advanced_publisher_options_t popts;
    ze_advanced_publisher_options_default(&popts);
    ze_advanced_publisher_cache_options_default(&popts.cache);
    popts.cache.max_samples = 8;
    ze_owned_advanced_publisher_t pub;
    z_result_t prc = ze_declare_advanced_publisher(l1, &pub, z_loan(ke), &popts);
    printf("pub.rc=%d\n", (int)prc);
    if (prc < 0) { return 1; }

    const char *bodies[3] = {"p1", "p2", "p3"};
    for (int i = 0; i < 3; i++) {
        z_owned_bytes_t payload;
        z_bytes_copy_from_str(&payload, bodies[i]);
        ze_advanced_publisher_put_options_t put_opts;
        ze_advanced_publisher_put_options_default(&put_opts);
        z_result_t rc = ze_advanced_publisher_put(ze_advanced_publisher_loan(&pub), z_move(payload), &put_opts);
        printf("put[%s].rc=%d\n", bodies[i], (int)rc);
    }
    nap_ms(300);

    /* A subscriber with history on the publisher's own side of the link ... */
    ze_advanced_subscriber_options_t sopts1;
    ze_advanced_subscriber_options_default(&sopts1);
    ze_advanced_subscriber_history_options_default(&sopts1.history);
    z_owned_closure_sample_t c1;
    z_closure(&c1, on_sample_1, NULL, NULL);
    ze_owned_advanced_subscriber_t sub1;
    z_result_t src1 = ze_declare_advanced_subscriber(l1, &sub1, z_loan(ke), z_move(c1), &sopts1);
    printf("sub1.rc=%d\n", (int)src1);

    /* ... and one on the other side, whose history GET crosses the link. */
    ze_advanced_subscriber_options_t sopts2;
    ze_advanced_subscriber_options_default(&sopts2);
    ze_advanced_subscriber_history_options_default(&sopts2.history);
    z_owned_closure_sample_t c2;
    z_closure(&c2, on_sample_2, NULL, NULL);
    ze_owned_advanced_subscriber_t sub2;
    z_result_t src2 = ze_declare_advanced_subscriber(l2, &sub2, z_loan(ke), z_move(c2), &sopts2);
    printf("sub2.rc=%d\n", (int)src2);

    /* History arrives by a GET that completes on its own; give both time to finish and
       then to show a late duplicate if there is one. */
    nap_ms(2500);
    report("s1.history", NAMES_1, N_1);
    report("s2.history", NAMES_2, N_2);

    z_drop(z_move(sub1));
    z_drop(z_move(sub2));
    z_drop(z_move(pub));
    z_drop(z_move(s2));
    z_drop(z_move(s1));
    printf("done\n");
    return 0;
}
"#;

/// What the reference arm must print: a cached sample is heard ONCE by each
/// subscriber, whichever side of the link it sits on.
const FACE_EXPECTED: &[&str] = &[
    "open1.rc=0",
    "open2.rc=0",
    "link.up=1",
    "pub.rc=0",
    "put[p3].rc=0",
    "sub1.rc=0",
    "sub2.rc=0",
    "s1.history.count=3",
    "s1.history.names=p1,p2,p3",
    "s2.history.count=3",
    "s2.history.names=p1,p2,p3",
    "done",
];

/// THE ADJUDICATOR for the face session's history destination: with a link up, a
/// subscriber with history hears each cached sample as many times on wz's cdylib as on
/// the real `libzenohc.so`.
// wz-proves: api-compat-c wz->zenoh-c partial
#[test]
#[ignore = "links the shared-memory zenoh-c oracle; run by run-ci Layer C1ce"]
fn a_history_subscriber_hears_each_cached_sample_once_with_a_link_up_on_wz_and_libzenohc() {
    let Some((include, ref_libdir)) = oracle_prefix() else {
        return;
    };
    let (wz_out, ref_out) = run_both_arms(FACE_PROBE, &include, &ref_libdir);

    for (arm, stdout) in [("REFERENCE", &ref_out), ("wz", &wz_out)] {
        let lines: Vec<&str> = stdout.lines().collect();
        let missing: Vec<&&str> = FACE_EXPECTED
            .iter()
            .filter(|w| !lines.contains(w))
            .collect();
        assert!(
            missing.is_empty(),
            "the {arm} arm did not hear the cache once per subscriber.\n\
             missing: {missing:?}\n--- stdout ---\n{stdout}",
        );
    }
    let wz: Vec<&str> = wz_out.lines().collect();
    let reference: Vec<&str> = ref_out.lines().collect();
    assert_eq!(
        wz, reference,
        "wz's history subscribers and the real libzenohc's hear the cache a different \
         number of times"
    );
}

/// Five sessions in a chain A - B - C - D - E, one program, the nodes' gossip configured by
/// the first argument. Only A dials what gossip names; the rest hold the links they were
/// given. It prints which nodes each one is linked to once the links have stopped changing.
///
/// `scouting/gossip/multihop` is the variable: the default config says gossip information
/// "are propagated multiple hops to all nodes in the local network" when it is on and "only
/// propagated to the next hop" when it is off. So A, the only node that dials, should come to
/// hold a link to the far end of the chain only with the key on. Which nodes A links to with
/// the key off is the real library's to say.
const GOSSIP_PROBE: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "zenoh.h"

#define N 5

static const char NAME[N] = {'A', 'B', 'C', 'D', 'E'};
static z_id_t ZIDS[N];

static void nap_ms(long ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static void on_peer(const z_id_t *id, void *ctx) {
    unsigned *mask = (unsigned *)ctx;
    for (int i = 0; i < N; i++) {
        if (memcmp(id->id, ZIDS[i].id, sizeof id->id) == 0) *mask |= 1u << i;
    }
}

static unsigned links_of(const z_loaned_session_t *s) {
    unsigned mask = 0;
    z_owned_closure_zid_t closure;
    z_closure(&closure, on_peer, NULL, &mask);
    z_info_peers_zid(s, z_move(closure));
    return mask;
}

static z_result_t open_node(z_owned_session_t *s, const char *multihop, int dials,
                            const char *listen, const char *connect) {
    z_owned_config_t config;
    z_config_default(&config);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MULTICAST_SCOUTING_KEY, "false");
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MODE_KEY, "\"peer\"");
    zc_config_insert_json5(z_loan_mut(config), "scouting/gossip/multihop", multihop);
    if (!dials) {
        zc_config_insert_json5(z_loan_mut(config), "scouting/gossip/autoconnect",
                               "{\"router\":[],\"peer\":[]}");
    }
    char json[256];
    snprintf(json, sizeof json, "[\"%s\"]", listen);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_LISTEN_KEY, json);
    if (connect) {
        snprintf(json, sizeof json, "[\"%s\"]", connect);
        zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_CONNECT_KEY, json);
    }
    return z_open(s, z_move(config), NULL);
}

static void print_links(unsigned masks[N]) {
    for (int i = 0; i < N; i++) {
        printf("%c.links=", NAME[i]);
        int n = 0;
        for (int j = 0; j < N; j++) {
            if (masks[i] & (1u << j)) {
                printf("%s%c", n ? "," : "", NAME[j]);
                n++;
            }
        }
        if (!n) printf("none");
        printf("\n");
    }
}

int main(int argc, char **argv) {
    if (argc < 1 + 1 + N) { fprintf(stderr, "usage: probe <multihop> <5 endpoints>\n"); return 2; }
    const char *multihop = argv[1];
    const char *ep[N];
    for (int i = 0; i < N; i++) ep[i] = argv[2 + i];

    /* The chain, each node opened once the node it dials is listening: A dials B, C dials B,
       D dials C, E dials D. B holds A and C; C holds B and D; D holds C and E. */
    z_owned_session_t s[N];
    int order[N] = {1, 0, 2, 3, 4};
    int dial[N] = {1, -1, 1, 2, 3};
    for (int k = 0; k < N; k++) {
        int i = order[k];
        z_result_t rc = open_node(&s[i], multihop, i == 0, ep[i], dial[i] >= 0 ? ep[dial[i]] : NULL);
        printf("open[%c].rc=%d\n", NAME[i], (int)rc);
        if (rc < 0) return 1;
        ZIDS[i] = z_info_zid(z_loan(s[i]));
        nap_ms(150);
    }

    /* Wait for the links to stop changing: a gossip dial is a link opening on its own time. */
    unsigned last[N] = {0};
    int quiet = 0;
    for (int waited = 0; waited < 12000 && quiet < 3000; waited += 100) {
        unsigned now[N];
        int same = 1;
        for (int i = 0; i < N; i++) {
            now[i] = links_of(z_loan(s[i]));
            if (now[i] != last[i]) same = 0;
        }
        quiet = same ? quiet + 100 : 0;
        memcpy(last, now, sizeof last);
        nap_ms(100);
    }
    print_links(last);

    for (int i = N - 1; i >= 0; i--) z_drop(z_move(s[i]));
    printf("done\n");
    return 0;
}
"#;

/// THE ADJUDICATOR for `scouting/gossip/multihop`: a chain of five peers, only the first
/// dialling what gossip names, ends up with the same links on wz's cdylib as on the real
/// `libzenohc.so`, with the key off and with it on.
// wz-proves: api-compat-c wz->zenoh-c partial
#[test]
#[ignore = "links the shared-memory zenoh-c oracle; run by run-ci Layer C1ce"]
fn gossip_multihop_links_the_chain_identically_on_wz_and_libzenohc() {
    let Some((include, ref_libdir)) = oracle_prefix() else {
        return;
    };
    let mut by_setting: Vec<(&str, String)> = Vec::new();
    for multihop in ["false", "true"] {
        let (wz_out, ref_out) =
            run_both_arms_with(GOSSIP_PROBE, &include, &ref_libdir, &[multihop], 5);
        assert!(
            ref_out.lines().any(|line| line == "done"),
            "the reference arm never finished.\n{ref_out}"
        );
        assert_eq!(
            wz_out, ref_out,
            "with scouting/gossip/multihop = {multihop}, wz's chain of five peers holds \
             different links from the real libzenohc's.\n--- wz ---\n{wz_out}\n--- reference \
             ---\n{ref_out}"
        );
        by_setting.push((multihop, ref_out));
    }
    // What the real library does with the key in a chain, stated once both settings are in
    // hand. Printed whole when it is not what is asserted, because the assertion is a claim
    // about the library and the library has the last word.
    assert_eq!(
        by_setting[0].1, by_setting[1].1,
        "the key changes the links of the real library's chain.\n--- off ---\n{}\n--- on \
         ---\n{}",
        by_setting[0].1, by_setting[1].1
    );
}
