// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! wz <-> zenoh-ext ADVANCED-PUBSUB cross-impl interop (R311y442).
//!
//! The `@adv` plane had no foreign witness at all before this file. Every
//! advanced-pubsub test in the tree was wz<->wz, and that is not a coverage gap
//! of the ordinary kind — a wz<->wz pair AGREES on a selector dialect even when
//! the dialect is one no zenoh or zenoh-pico peer can read, because the same
//! wrong spelling is on both ends. Two such divergences were live, and R311y441
//! found them by reading rather than by testing, which is the shape of defect
//! this file exists to make observable.
//!
//! ## Why the oracle is an EXAMPLE binary and not zenohd
//!
//! Every other cross-impl leg in this tree witnesses against `zenohd` or the
//! zenoh-pico CLI. Neither can serve here: zenohd is a ROUTER and holds no
//! `AdvancedCache`, and zenoh-pico has no advanced-pubsub plane whatsoever. The
//! cache is a library object that only exists inside an APPLICATION built on
//! `zenoh-ext` — so upstream's own `z_advanced_pub` / `z_advanced_sub` examples
//! are the oracle, provisioned by `scripts/build-zenohd.sh` from the same pinned
//! checkout as zenohd itself.
//!
//! `zenoh-ext-examples` pulls `zenoh-ext` with `unstable`, and that is
//! load-bearing rather than incidental: `Query::_reply_sample` only consults
//! `_anyke` under `zenoh/unstable` (a `zcondfeat!`), so an oracle built without
//! it would refuse every `@adv` reply regardless of what the querier sent, and a
//! conformant wz would be indistinguishable from a broken one.
//!
//! ## The two defects, and why they COMPOUND rather than add
//!
//! 1. **The list separator.** zenoh's `Parameters` is `;`-separated
//!    (`commons/zenoh-protocol/src/core/parameters.rs:32`) and zenoh-pico agrees
//!    (`query_params.h:34`). wz joined and split on `&`.
//! 2. **`_anyke`.** An advanced cache replies under the CACHED SAMPLE's own
//!    keyexpr, which does not intersect the `@adv` KE the GET is addressed to.
//!    zenoh's responder refuses such a reply unless the querier set `_anyke`
//!    (`zenoh/src/api/queryable.rs:278-287`), which zenoh-ext's own subscriber
//!    does on every GET (`zenoh-ext/src/advanced_subscriber.rs:807` and six
//!    siblings). wz's runtime path never set it — though wz's C-API path did
//!    (`wz-capi-pico/src/get.rs:820-835`), so the rule was known here and lost.
//!
//! They are not independent, and the measurement is what shows it. Under `&` a
//! selector reads to zenoh as ONE parameter keyed `_max`, whose value swallows
//! the rest of the string — INCLUDING the `_anyke` token. So the separator
//! defect DESTROYS `_anyke` in every multi-parameter selector, and no arm of
//! this file can vary one while holding the other fixed. Measured during
//! authoring: with the `_anyke` fix in place but the separator reverted to `&`,
//! history recovery is 0 of 5, not the "cap dropped, all 5 returned" that
//! treating the two as independent would predict.
//!
//! ## The legs
//!
//! 1. **PROOF (ask side).** A `z_advanced_pub` cache holds 5 samples published
//!    BEFORE wz exists. A wz `AdvancedSubscriber` then joins and its startup
//!    history GET recovers exactly those 5, byte-exact, ahead of any live
//!    sample — and the oracle logs ZERO reply refusals.
//! 2. **SEPARATOR witness.** The same fixture with `--history-max 2
//!    --history-max-age N`, i.e. a TWO-parameter selector, is capped to 2 by the
//!    foreign cache. What this adds over leg 1 is a POSITIVE CONFORMANCE
//!    observation — the parameters after the first are genuinely parsed as list
//!    elements — which a one-parameter selector cannot show, since it reads the
//!    same under either separator.
//!
//!    It is NOT a second independent RED, and the first draft of this file said it
//!    was. Measured (REVIEWER 2): reverting the separator alone, the `_anyke`
//!    alone, or both, produces the SAME failure shape in this leg as in leg 1 —
//!    an empty recovery. The over-return shape the cap is supposed to discriminate
//!    against is unreachable on the pre-fix wire, because `&` swallows `_anyke`
//!    before the cap ever matters. The cap assertion still guards a real
//!    regression (a future change that drops the second parameter while keeping
//!    `_anyke`), just not one the pre-fix tree could exhibit.
//! 3. **DISCRIMINATOR.** A GET on the SAME cache KE carrying no `_anyke` at all
//!    gets zero replies while the oracle logs refusals. This is what makes leg
//!    1's zero-refusal assertion a discriminator instead of a tautology: same
//!    oracle, same cache, same keyexpr, and the only difference is the token.
//!    The vehicle is the pico `z_get` CLI, whose selector parameters are
//!    hardcoded empty (`examples/unix/c11/z_get.c:98` passes `""`), so it sends
//!    the exact shape wz used to send, without needing a build variant.
//! 4. **ANSWER side.** The mirror: a wz `AdvancedPublisher` bursts into its own
//!    `@adv` cache, then upstream's own `z_advanced_sub` joins late and recovers
//!    all of it. This is the only leg that exercises wz's cache as a RESPONDER
//!    to a real zenoh querier, so it is what binds `ext-pubsub-advanced-cache`
//!    and `-advanced-publisher` rather than the subscriber-side atoms.
//!
//!    It is SEPARATOR-BLIND, and that bound is worth stating. `z_advanced_sub`
//!    hardcodes `HistoryConfig::default()`, so its selector carries no
//!    `key=value` parameter at all — only the bare `_anyke` — and wz's cache-side
//!    read returns `None` under either separator. Confirmed by measurement: leg 4
//!    passes on the pre-fix wire too. The cache half of the separator fix has no
//!    foreign witness and cannot get one from this oracle.
//!
//! Opt-in (`#[ignore]`, run-ci Layer Z): zenohd, the zenoh-ext examples and the
//! pico CLI are all external binaries. wz-ap-demo must be built `--features
//! advanced`; without it the demo logs `INERT` and declares nothing, which the
//! legs assert against explicitly rather than reading as an empty result.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    read_captured, spawn_zenohd_on_ephemeral_tcp, wait_for_substring, wz_ap_demo_binary,
    zenoh_ext_example_binary, zenoh_pico_cli_binary, ChildGuard,
};

/// How long a leg waits for a marker line before declaring the fixture dead.
const MARKER_TIMEOUT: Duration = Duration::from_secs(20);

/// Samples the oracle publishes into its cache before wz joins. Small enough to
/// keep the leg quick, large enough that a `_max=2` cap is a real cut.
const CACHED_SAMPLES: usize = 5;

/// `z_advanced_pub` publishes once a second, so the fixture must wait at least
/// this long to be sure the cache holds `CACHED_SAMPLES`.
const BURST_SETTLE: Duration = Duration::from_millis(6_500);

fn tempfile() -> std::fs::File {
    tempfile::tempfile().expect("tempfile for captured child output")
}

/// Spawn upstream's `z_advanced_pub` as a CLIENT of `port`, publishing on
/// `keyexpr` with a cache deep enough to hold the whole burst.
///
/// `RUST_LOG=warn` is not cosmetic: it is what makes the responder's own reply
/// refusal (`AdvancedCache{} Error replying to query: ... does not intersect
/// ...`) visible. That line is the mechanism under test stated by the foreign
/// implementation itself, which is far stronger evidence than counting an
/// absence of deliveries on the wz side.
fn spawn_zenoh_advanced_pub(port: u16, keyexpr: &str, value: &str) -> (ChildGuard, std::fs::File) {
    let bin = zenoh_ext_example_binary("z_advanced_pub");
    // ONE capture for both streams, deliberately. The example prints its `Put
    // Data` progress with `println!` while `tracing` writes the reply-refusal
    // WARN through its own subscriber, and which stream each lands on is not
    // this file's business to know. Splitting them is how the first draft of leg
    // 1 came to count refusals on a stream that never carries them, asserting
    // `== 0` vacuously — the discriminator leg is what surfaced it.
    let output = tempfile();
    let stdout_writer = output.try_clone().expect("dup z_advanced_pub stdout");
    let writer = output.try_clone().expect("dup z_advanced_pub stderr");
    let child = ChildGuard::wrap(
        "z_advanced_pub (zenoh-ext oracle)",
        Command::new(&bin)
            .arg("--mode")
            .arg("client")
            .arg("-e")
            .arg(format!("tcp/127.0.0.1:{port}"))
            .arg("--no-multicast-scouting")
            .arg("-k")
            .arg(keyexpr)
            .arg("-i")
            .arg("16")
            .arg("-v")
            .arg(value)
            .env("RUST_LOG", "warn")
            .stdout(Stdio::from(stdout_writer))
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn z_advanced_pub"),
    );
    (child, output)
}

/// Run a wz advanced SUBSCRIBER against `port` and return its captured stderr.
/// `history_max` / `history_max_age` map to `_max` / `_time` on the startup GET.
fn run_wz_advanced_subscriber(
    port: u16,
    keyexpr: &str,
    history_max: Option<usize>,
    history_max_age: Option<u32>,
    run_for: Duration,
) -> String {
    let demo = wz_ap_demo_binary();
    let stderr = tempfile();
    let writer = stderr.try_clone().expect("dup wz-ap-demo stderr");
    let mut reader = stderr;
    let mut cmd = Command::new(&demo);
    cmd.arg("--connect")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--advanced-subscribe")
        .arg(keyexpr);
    if let Some(max) = history_max {
        cmd.arg("--history-max").arg(max.to_string());
    }
    if let Some(age) = history_max_age {
        cmd.arg("--history-max-age").arg(age.to_string());
    }
    let _child = ChildGuard::wrap(
        "wz-ap-demo (--advanced-subscribe)",
        cmd.env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo advanced subscriber"),
    );

    // The declare marker is the fixture's liveness check. Its ABSENCE has two
    // very different causes — a demo built without `advanced` (which logs INERT)
    // and a session that never established — so assert on it rather than letting
    // an empty sample list stand in for either.
    let captured = wait_for_substring(&mut reader, "DECLARED ADVANCED SUBSCRIBER", MARKER_TIMEOUT)
        .unwrap_or_else(|snapshot| {
            panic!(
                "wz-ap-demo never declared an advanced subscriber. If this says INERT, \
             the demo was built without `--features advanced`.\n--- captured ---\n{snapshot}"
            )
        });
    assert!(
        !captured.contains("is INERT"),
        "wz-ap-demo reports --advanced-subscribe INERT; build it with \
         `--features advanced`.\n--- captured ---\n{captured}"
    );

    std::thread::sleep(run_for);
    read_captured(&mut reader)
}

/// The burst index of every `ADVANCED SAMPLE` line, in delivery order.
///
/// Both publishers emit `[{idx:4}] {value}`, so the index is the sample's
/// position in the burst — which is what distinguishes a RECOVERED sample from a
/// live one without depending on wall-clock timing.
fn delivered_indices(captured: &str) -> Vec<usize> {
    captured
        .lines()
        .filter(|l| l.contains("ADVANCED SAMPLE"))
        .filter_map(|l| {
            let start = l.find("payload='[")? + "payload='[".len();
            let rest = &l[start..];
            let end = rest.find(']')?;
            rest[..end].trim().parse::<usize>().ok()
        })
        .collect()
}

/// How many samples the oracle has published so far, read off its own log.
///
/// R311y442 review (REVIEWER 2, finding 1) — the FIRST version of these legs read
/// this once, before wz started, and then asserted the recovered set was exactly
/// `[pb-N .. pb)`. That is a claim about the cache at GET time made from a
/// PRE-JOIN reading, and the oracle keeps publishing at 1 Hz throughout: one more
/// sample landing before the GET slides the `_max=N` window by one and the
/// assertion fails with a message that reads like a dialect regression. The
/// budget was measured at ~513 ms on an idle 32-core box and is a sawtooth in the
/// oracle's own session-open delay, so on a slower runner it can approach zero —
/// a PERSISTENT red on that machine, which is worse than a flake.
///
/// The legs now BRACKET the run: `pb` before wz starts, `pa` after it ends, and
/// the assertion is the invariant that holds for every cache state in between
/// (see [`assert_capped_recovery`]).
fn published_so_far(captured: &str) -> usize {
    captured.lines().filter(|l| l.contains("Put Data")).count()
}

/// Assert that `delivered` is a contiguous ascending run whose head is the newest
/// `cap` samples the foreign cache held when it answered — without needing to know
/// WHICH state that was.
///
/// The cache replies its newest `cap` samples, so `delivered[0] == k - cap + 1`
/// where `k` is the newest cached index at GET time. `k` is not observable, but it
/// is BOUNDED: it cannot be older than the last sample published before wz existed
/// (`pb - 1`) nor newer than the last one published by the time wz stopped
/// (`pa - 1`). So `pb - cap <= delivered[0] <= pa - cap`, and that bracket is
/// exactly as discriminating as the identity form was:
///
///   - cap DROPPED (the separator failure's over-return shape) → the cache replies
///     its whole ring, `delivered[0]` collapses toward 0, below `pb - cap`.
///   - NOTHING recovered (the `_anyke` failure's shape) → `delivered[0]` is the
///     live cursor, at or above `pb`, which exceeds `pa - cap` for any real run.
fn assert_capped_recovery(delivered: &[usize], cap: usize, pb: usize, pa: usize, ctx: &str) {
    assert!(!delivered.is_empty(), "no samples delivered at all\n{ctx}");
    for w in delivered.windows(2) {
        assert_eq!(
            w[1],
            w[0] + 1,
            "delivered indices are not contiguous ({:?}) — the subscriber dropped or \
             reordered a sample\n{ctx}",
            delivered
        );
    }
    let first = delivered[0];
    let lo = pb.saturating_sub(cap);
    let hi = pa.saturating_sub(cap);
    assert!(
        first >= lo && first <= hi,
        "recovery window starts at {first}, outside the bracket [{lo}, {hi}] implied by \
         a `_max={cap}` reply against a cache that held between {pb} and {pa} samples. \
         Below the bracket means the cap never reached the cache as its own list \
         element; above it means nothing was recovered and only live samples arrived.\
         \ndelivered={delivered:?}\n{ctx}"
    );
}

/// Count the oracle's own reply-refusal lines.
fn refusal_count(captured: &str) -> usize {
    captured
        .lines()
        .filter(|l| l.contains("does not intersect with query"))
        .count()
}

/// Leg 1 — the PROOF. wz's startup history GET drains a real zenoh-ext
/// `AdvancedCache` of samples published before wz existed.
// The direction names who PRODUCES the artifact under test, per the convention at
// wz_zenohd_storage_replication.rs:582-588 and wz_fragment_rx_zenohd_interop.rs:371.
// wz builds the selector, so history is wz->; the ORDERING atom consumes the
// foreign publisher's SourceInfo, so it is zenoh-ext->.
// wz-proves: ext-pubsub-advanced-history wz->zenoh-ext
// wz-proves: ext-pubsub-advanced-subscriber zenoh-ext->wz
#[test]
#[ignore = "external binaries: zenohd + zenoh-ext examples; run-ci Layer Z"]
fn wz_advanced_history_recovers_a_real_zenoh_ext_cache() {
    let (_zenohd, port) = spawn_zenohd_on_ephemeral_tcp(tempfile);
    let (_oracle, mut oracle_out) = spawn_zenoh_advanced_pub(port, "demo/example/adv", "ORACLEVAL");
    std::thread::sleep(BURST_SETTLE);

    // Bracket the run: `pb` is what the oracle had published before wz existed,
    // `pa` what it had published by the time wz stopped. Neither is the cache
    // state at GET time; together they BOUND it.
    let published_before = published_so_far(&read_captured(&mut oracle_out));
    assert!(
        published_before >= CACHED_SAMPLES,
        "oracle only published {published_before} samples before wz joined; \
         the fixture needs at least {CACHED_SAMPLES}"
    );

    let captured = run_wz_advanced_subscriber(
        port,
        "demo/example/**",
        Some(CACHED_SAMPLES),
        None,
        Duration::from_secs(4),
    );
    let published_after = published_so_far(&read_captured(&mut oracle_out));
    let indices = delivered_indices(&captured);
    let ctx = format!("pb={published_before} pa={published_after}\n--- captured ---\n{captured}");
    assert_capped_recovery(
        &indices,
        CACHED_SAMPLES,
        published_before,
        published_after,
        &ctx,
    );

    // Byte-exactness, not just arrival: the recovered payloads are the oracle's
    // own strings, at whichever indices the bracket admitted.
    for idx in indices.iter().take(CACHED_SAMPLES) {
        let needle = format!("payload='[{idx:4}] ORACLEVAL'");
        assert!(
            captured.contains(&needle),
            "recovered sample {idx} did not arrive byte-exact (looking for {needle})\n{ctx}"
        );
    }

    // Read AFTER the 4s run, so the oracle's rx thread has long since written any
    // refusal it was going to. Unlike leg 3's polled positive assertion, a late
    // write here would bias toward PASSING — but this assertion can never be the
    // first to fire: a refused reply means nothing was recovered, and
    // `assert_capped_recovery` above fails on that first.
    let oracle_log = read_captured(&mut oracle_out);
    assert_eq!(
        refusal_count(&oracle_log),
        0,
        "the zenoh-ext cache refused replies to wz's history GET; \
         `_anyke` is missing from the selector\n--- oracle ---\n{oracle_log}"
    );
}

/// Leg 2 — the SEPARATOR witness. A TWO-parameter selector (`_max` + `_time`)
/// is honoured by the foreign cache, which is only possible if the parameters
/// after the first are being read as list elements.
///
/// Leg 1 cannot make this claim: a single-parameter selector parses identically
/// under either separator. And the `&` spelling does not merely drop the cap —
/// it swallows `_anyke` into `_max`'s value, so the whole GET is refused and the
/// recovered set is EMPTY rather than uncapped. Both failure shapes are excluded
/// below.
// The `_max` / `_time` selector plane specifically, which leg 1 cannot bound:
// a one-parameter selector reads identically under either list separator.
// wz-proves: ext-pubsub-advanced-history wz->zenoh-ext
#[test]
#[ignore = "external binaries: zenohd + zenoh-ext examples; run-ci Layer Z"]
fn wz_advanced_history_max_is_honoured_by_the_zenoh_ext_cache() {
    let (_zenohd, port) = spawn_zenohd_on_ephemeral_tcp(tempfile);
    let (_oracle, mut oracle_out) = spawn_zenoh_advanced_pub(port, "demo/example/adv", "CAPVAL");
    std::thread::sleep(BURST_SETTLE);

    const CAP: usize = 2;
    let published_before = published_so_far(&read_captured(&mut oracle_out));
    assert!(
        published_before > CAP,
        "oracle published {published_before} samples; the cap of {CAP} would not cut"
    );

    let captured = run_wz_advanced_subscriber(
        port,
        "demo/example/**",
        Some(CAP),
        // A generous age bound: its job is to make the selector carry a SECOND
        // parameter, not to filter anything out.
        Some(3_600),
        Duration::from_secs(4),
    );
    let published_after = published_so_far(&read_captured(&mut oracle_out));
    let indices = delivered_indices(&captured);
    let ctx = format!(
        "pb={published_before} pa={published_after} cap={CAP}\n--- captured ---\n{captured}"
    );
    assert_capped_recovery(&indices, CAP, published_before, published_after, &ctx);

    let oracle_log = read_captured(&mut oracle_out);
    assert_eq!(
        refusal_count(&oracle_log),
        0,
        "the cache refused replies even with `_anyke` present\n--- oracle ---\n{oracle_log}"
    );
}

/// Leg 3 — the DISCRIMINATOR. The same cache, the same keyexpr, a GET WITHOUT
/// `_anyke`: zero replies, and the oracle says why.
///
/// Without this arm, leg 1's `refusal_count == 0` would be consistent with a
/// cache that never refuses anything. The pico `z_get` CLI is the vehicle
/// because its selector parameters are hardcoded empty, so it reproduces the
/// pre-fix wz shape exactly without a second wz build.
// wz-proves: none -- the DISCRIMINATOR for the two legs above. No wz code runs
// on the query path at all: a pico z_get (whose selector parameters are
// hardcoded empty) asks the same oracle cache the same keyexpr, and is refused.
// It witnesses that the `_anyke` gate is LIVE on this oracle, which is what
// stops leg 1's `refusals == 0` from being a property of a permissive fixture.
// Claiming an atom here would credit wz for a foreign implementation's refusal.
#[test]
#[ignore = "external binaries: zenohd + zenoh-ext examples + pico CLI; run-ci Layer Z"]
fn zenoh_ext_cache_refuses_a_get_without_anyke() {
    let (_zenohd, port) = spawn_zenohd_on_ephemeral_tcp(tempfile);
    let (_oracle, mut oracle_out) = spawn_zenoh_advanced_pub(port, "demo/example/adv", "REFUSEVAL");
    std::thread::sleep(BURST_SETTLE);

    let z_get = zenoh_pico_cli_binary("z_get");
    let stdout = tempfile();
    let writer = stdout.try_clone().expect("dup z_get stdout");
    let mut reader = stdout;
    let child = ChildGuard::wrap(
        "pico z_get (no _anyke)",
        Command::new(&z_get)
            .arg("-m")
            .arg("client")
            .arg("-e")
            .arg(format!("tcp/127.0.0.1:{port}"))
            .arg("-k")
            // Addressed at the cache itself, which is where the replies would come
            // from — the same KE family wz's history GET uses.
            .arg("demo/example/adv/@adv/**")
            .env("RUST_LOG", "error")
            .stdout(Stdio::from(writer))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn pico z_get"),
    );
    let _ = wait_for_substring(&mut reader, "query final notification", MARKER_TIMEOUT);
    // ChildGuard kills on Drop; drop explicitly so the read below sees a settled
    // process rather than one still appending.
    drop(child);

    let get_out = read_captured(&mut reader);
    // NOT a bare `">> Received"` match: pico prints `">> Received query final
    // notification"` from its drop handler on every completed GET, so the loose
    // needle matches the SUCCESS path of a query that returned nothing. A reply
    // line is `">> Received <KIND> ('<ke>': '<payload>')"`.
    let reply_lines: Vec<&str> = get_out
        .lines()
        .filter(|l| l.starts_with(">> Received") && !l.contains("query final notification"))
        .collect();
    assert!(
        reply_lines.is_empty(),
        "a GET without `_anyke` received replies {reply_lines:?}; the reply-keyexpr \
         gate is not active on this oracle, so leg 1 proves nothing\n\
         --- z_get ---\n{get_out}"
    );
    // The GET must actually have COMPLETED — otherwise "no replies" would just
    // mean the query never reached the cache, and the leg would pass vacuously.
    assert!(
        get_out.contains("query final notification"),
        "the pico GET never terminated, so its empty reply set says nothing about \
         the `_anyke` gate\n--- z_get ---\n{get_out}"
    );

    // POLLED, not read once: the refusal is written by the oracle's rx thread as
    // it processes the query, which can trail the querier's own termination.
    // Reading a single snapshot here raced that write and saw an empty log.
    let oracle_log = wait_for_substring(
        &mut oracle_out,
        "does not intersect with query",
        MARKER_TIMEOUT,
    )
    .unwrap_or_else(|snapshot| {
        panic!(
            "the cache logged no reply refusal for a non-`_anyke` GET, so its \
             `_anyke` gate is not the thing leg 1 depends on\n--- oracle ---\n{snapshot}"
        )
    });
    assert!(
        refusal_count(&oracle_log) > 0,
        "refusal marker matched but the counter read zero\n--- oracle ---\n{oracle_log}"
    );
}

/// Leg 4 — the ANSWER side. A wz `AdvancedPublisher`'s cache, drained by
/// upstream's own `z_advanced_sub` joining after the burst.
///
/// This is the direction that binds the cache and publisher atoms: it is wz's
/// `@adv` queryable parsing a REAL zenoh selector and wz's `SourceInfo`
/// sequencing being legible to a real zenoh reorder buffer.
// The REVERSE direction: wz is the responder, so this is the only leg that
// exercises wz's `@adv` queryable against a real zenoh selector and wz's
// SourceInfo sequencing against a real zenoh reorder buffer.
// wz is the RESPONDER here, so wz produces both artifacts: the cache's replies and
// the SourceInfo-sequenced samples. Same shape as the storage-replication leg,
// where wz declares the queryable and the claims read wz->zenohd.
// wz-proves: ext-pubsub-advanced-cache wz->zenoh-ext
// wz-proves: ext-pubsub-advanced-publisher wz->zenoh-ext
#[test]
#[ignore = "external binaries: zenohd + zenoh-ext examples; run-ci Layer Z"]
fn zenoh_ext_advanced_sub_recovers_a_wz_cache() {
    let (_zenohd, port) = spawn_zenohd_on_ephemeral_tcp(tempfile);

    let demo = wz_ap_demo_binary();
    let demo_stderr = tempfile();
    let demo_writer = demo_stderr.try_clone().expect("dup wz-ap-demo stderr");
    let mut demo_reader = demo_stderr;
    let _demo = ChildGuard::wrap(
        "wz-ap-demo (--advanced-publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--advanced-publish")
            .arg("demo/wzadv/x")
            .arg("--value")
            .arg("WZCACHE")
            .arg("--advanced-publish-count")
            .arg(CACHED_SAMPLES.to_string())
            .arg("--cache-max")
            .arg("16")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_writer))
            .spawn()
            .expect("spawn wz-ap-demo advanced publisher"),
    );

    // Wait for the burst to FINISH. The subject is what a late joiner can still
    // retrieve once publishing has stopped, so a subscriber that raced the burst
    // would be witnessing live delivery instead of the cache.
    let demo_log = wait_for_substring(&mut demo_reader, "ADVANCED BURST COMPLETE", MARKER_TIMEOUT)
        .unwrap_or_else(|snapshot| {
            panic!(
                "wz-ap-demo never completed its advanced burst. If this says INERT, \
             the demo was built without `--features advanced`.\n--- captured ---\n{snapshot}"
            )
        });
    assert!(
        !demo_log.contains("is INERT"),
        "wz-ap-demo reports --advanced-publish INERT; build it with \
         `--features advanced`.\n--- captured ---\n{demo_log}"
    );

    let sub = zenoh_ext_example_binary("z_advanced_sub");
    let sub_stdout = tempfile();
    let sub_writer = sub_stdout.try_clone().expect("dup z_advanced_sub stdout");
    let mut sub_reader = sub_stdout;
    let sub_child = ChildGuard::wrap(
        "z_advanced_sub (zenoh-ext oracle)",
        Command::new(&sub)
            .arg("--mode")
            .arg("client")
            .arg("-e")
            .arg(format!("tcp/127.0.0.1:{port}"))
            .arg("--no-multicast-scouting")
            .arg("-k")
            .arg("demo/wzadv/**")
            .env("RUST_LOG", "error")
            .stdout(Stdio::from(sub_writer))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn z_advanced_sub"),
    );
    let last = format!("[{:4}] WZCACHE", CACHED_SAMPLES - 1);
    let sub_out =
        wait_for_substring(&mut sub_reader, &last, MARKER_TIMEOUT).unwrap_or_else(|snapshot| {
            panic!(
                "z_advanced_sub never recovered the wz cache's last sample \
                 ({last})\n--- z_advanced_sub ---\n{snapshot}\n--- wz ---\n{demo_log}"
            )
        });
    drop(sub_child);

    for idx in 0..CACHED_SAMPLES {
        let expected = format!("('demo/wzadv/x': '[{idx:4}] WZCACHE')");
        assert!(
            sub_out.contains(&expected),
            "a real zenoh advanced subscriber did not recover wz cache sample \
             {idx} byte-exact (looking for {expected})\n--- z_advanced_sub ---\n{sub_out}"
        );
    }
}
