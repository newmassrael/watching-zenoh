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
//! 5. **RECOVERY (R311y443).** The retransmission path, which none of the four
//!    legs above can reach: it engages only on LOSS, and two healthy peers on a
//!    loopback link never lose anything. A relay between zenohd and wz DELETES
//!    one of the oracle's samples from the wire; wz sees the hole in the next
//!    sample's sequence number and refills it with an `_sn=last+1..` GET against
//!    the foreign publisher's own `@adv` cache, delivering it in order.
//! 6. **RECOVERY CONTROL.** Leg 5 with `--advanced-recovery` omitted and nothing
//!    else changed: the sample stays missing and wz reports a `Miss` of exactly
//!    one. This is what makes leg 5 a statement about wz rather than about the
//!    fixture — "the sample arrived" is otherwise equally consistent with a
//!    needle that stopped matching or a link that re-sent the batch.
//! 7. **BEACON (R311y444).** The publisher-side half of miss detection, which is
//!    a DIFFERENT ATOM from legs 5/6 and in the opposite direction. Every one of
//!    `ext-pubsub-sample-miss-detection`'s 19 cfg sites is in
//!    `advanced_publisher.rs` — the beacon EMIT — while the subscriber-side
//!    heartbeat TRIGGER belongs to `ext-pubsub-advanced-recovery`
//!    (`advanced_subscriber.rs:220` says so outright). So a leg where wz consumes
//!    a foreign beacon would compile none of this atom and prove something else.
//!
//!    Here the relay removes the LAST sample of a wz burst. wz then stops
//!    publishing, so no later sequence number can ever expose the hole and the
//!    oracle's sample-driven trigger has nothing to fire on — by construction,
//!    not by timing. What remains is wz's beacon, and upstream's `z_advanced_sub`
//!    recovers the sample from wz's own `@adv` cache through it.
//! 8. **BEACON CONTROL.** Leg 7 with the beacon unarmed and nothing else changed:
//!    the sample stays gone. The oracle arms its heartbeat trigger and both its
//!    history GETs identically in both legs, so every other path that could refill
//!    the hole is present here too.
//!
//!    Falsified further by DAMAGING THE ATOM'S OWN WIRE ARTIFACT rather than the
//!    flag that gates it (the R311y443-review standard): with `emit_heartbeat`
//!    publishing `z_serialize::<u32>(&0)` instead of the last sn
//!    (`advanced_publisher.rs:440`), leg 7 goes RED and leg 8 stays GREEN. A
//!    beacon that arrives but lies is indistinguishable from no beacon to the
//!    oracle, which is the property the leg actually depends on.
//! 9. **HEARTBEAT TRIGGER (R311y444).** The third of `-advanced-recovery`'s three
//!    triggers, which legs 5/6 left unarmed on purpose. It cannot be judged by
//!    whether the gap was refilled: wz's sample-driven trigger is implied by
//!    recovering at all and cannot be switched off, and the oracle publishes at
//!    1 Hz forever, so both arms end with the hole filled. The observable is the
//!    SELECTOR — heartbeat asks for a BOUNDED `_sn=a..b`
//!    (`advanced_subscriber.rs:709-726`), sample-driven for an OPEN `_sn=a..`
//!    (`:605-613`) — read out of the ORACLE's `zenoh_ext=trace`, so it is the
//!    receiving peer that reports what wz put on the wire.
//! 10. **HEARTBEAT TRIGGER CONTROL.** Same fixture, trigger unarmed: no bounded
//!     range, and the open one still present. That second half is the parser's
//!     calibration — without it, a parser that matched nothing would satisfy the
//!     negative vacuously.
//!
//!    These two subscribe on a CONCRETE keyexpr rather than `demo/example/**`.
//!    The heartbeat trigger declares a second subscriber on `<ke>/@adv/pub/**`,
//!    which under a `**`-tailed base composes to the `**`+literal+`*` shape wz's
//!    R300 gate refuses for SIGABRTing zenoh-pico (`keyexpr_canon.rs:383-394`).
//!    Upstream emits it regardless, so wz is the safer side here — but in wz the
//!    heartbeat trigger and a `**`-tailed base are not composable.
//!
//! ## The naming obligation (R311y443)
//!
//! Every test fn in this file MUST carry the `zenoh_ext` token. run-ci's Layer E
//! catch-all sweep skips by that substring, because it runs a wz-ap-demo built
//! WITHOUT `--features advanced`, where every `--advanced-*` flag is inert. A
//! leg named for what it does rather than for its oracle silently rejoins that
//! sweep and fails there with a correct diagnosis in the wrong lane.
//!
//! Opt-in (`#[ignore]`, run-ci Layer Z): zenohd, the zenoh-ext examples and the
//! pico CLI are all external binaries. wz-ap-demo must be built `--features
//! advanced`; without it the demo logs `INERT` and declares nothing, which the
//! legs assert against explicitly rather than reading as an empty result.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_codecs::wire_const::T_MID_FRAME;
use wz_integration_tests::common::{
    read_captured, spawn_counting_relay, spawn_zenohd_on_ephemeral_tcp, wait_for_substring,
    wz_ap_demo_binary, zenoh_ext_example_binary, zenoh_pico_cli_binary, ChildGuard, RelayFault,
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
    spawn_zenoh_advanced_pub_with_log(port, keyexpr, value, "warn")
}

/// [`spawn_zenoh_advanced_pub`] with the oracle's `RUST_LOG` chosen by the caller.
///
/// R311y444 — the heartbeat-trigger legs need `zenoh_ext=trace`, because what
/// distinguishes the trigger they test is not WHETHER the gap was refilled but
/// which SELECTOR asked for it, and the only implementation that logs the
/// selector wz actually put on the wire is the foreign one receiving it.
fn spawn_zenoh_advanced_pub_with_log(
    port: u16,
    keyexpr: &str,
    value: &str,
    rust_log: &str,
) -> (ChildGuard, std::fs::File) {
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
            .env("RUST_LOG", rust_log)
            .stdout(Stdio::from(stdout_writer))
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn z_advanced_pub"),
    );
    (child, output)
}

/// Spawn a wz advanced SUBSCRIBER against `port` and return once its declare
/// marker is on the log — the child, its still-open capture, and the snapshot
/// taken at declare time.
///
/// Split out of [`run_wz_advanced_subscriber`] by R311y443, which needs the
/// moment of declaration as an OBSERVABLE rather than just a barrier: the
/// recovery legs read the oracle's own publish count right here, to bound what
/// the startup history GET could possibly have carried.
///
/// `history_max` / `history_max_age` map to `_max` / `_time` on that startup
/// GET; `recovery` arms sample-driven retransmission.
fn spawn_wz_advanced_subscriber(
    port: u16,
    keyexpr: &str,
    history_max: Option<usize>,
    history_max_age: Option<u32>,
    recovery: bool,
    recovery_heartbeat: bool,
) -> (ChildGuard, std::fs::File, String) {
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
    if recovery {
        cmd.arg("--advanced-recovery");
    }
    if recovery_heartbeat {
        cmd.arg("--advanced-recovery-heartbeat");
    }
    let child = ChildGuard::wrap(
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
    // The declare line reports the options it was built with, so a flag that
    // silently failed to parse is caught here rather than being read downstream
    // as the behaviour under test being absent.
    assert!(
        captured.contains(&format!("recovery={recovery}")),
        "wz-ap-demo declared with recovery != {recovery}; the --advanced-recovery \
         flag did not take\n--- captured ---\n{captured}"
    );
    assert!(
        captured.contains(&format!("recovery_heartbeat={recovery_heartbeat}")),
        "wz-ap-demo declared with recovery_heartbeat != {recovery_heartbeat}; the \
         --advanced-recovery-heartbeat flag did not take\n--- captured ---\n{captured}"
    );
    (child, reader, captured)
}

/// Run a wz advanced SUBSCRIBER against `port` for `run_for` and return its
/// captured stderr. `history_max` / `history_max_age` map to `_max` / `_time` on
/// the startup GET.
fn run_wz_advanced_subscriber(
    port: u16,
    keyexpr: &str,
    history_max: Option<usize>,
    history_max_age: Option<u32>,
    run_for: Duration,
) -> String {
    let (_child, mut reader, _at_declare) =
        spawn_wz_advanced_subscriber(port, keyexpr, history_max, history_max_age, false, false);
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

/// The `nb` of every `ADVANCED MISS` the subscriber reported, in order.
///
/// A `Miss` is what wz emits for a forward gap it did NOT fill, so this is the
/// recovery legs' negative observable: present in the control, absent in the
/// proof.
fn miss_counts(captured: &str) -> Vec<usize> {
    captured
        .lines()
        .filter(|l| l.contains("ADVANCED MISS"))
        .filter_map(|l| {
            let start = l.find("missed=")? + "missed=".len();
            l[start..].trim().parse::<usize>().ok()
        })
        .collect()
}

/// The burst index the recovery legs remove from the wire.
///
/// Late enough that wz is certainly established and has a `last_delivered`
/// baseline before the oracle reaches it (the oracle publishes at 1 Hz, so this
/// is ~8 s of slack, and the leg MEASURES that rather than assuming it), and
/// early enough that the run outlasts it with room for the recovery round trip.
const GAP_INDEX: usize = 8;

/// How long the recovery legs let the subscriber run after it declares. Must
/// outlast the oracle reaching `GAP_INDEX + 1` — the successor whose arrival is
/// what makes the gap visible — plus the recovery GET's round trip.
const RECOVERY_RUN: Duration = Duration::from_secs(15);

/// The shared fixture for legs 5 and 6: an oracle publishing through a healthy
/// link into zenohd, and a wz subscriber reaching zenohd through a relay that
/// removes exactly one sample on the way IN.
///
/// Returns the subscriber's captured log, how many samples the oracle had
/// published when wz DECLARED, how many it had published by the END of the run,
/// and how many batches the relay dropped.
///
/// R311y443-review (REVIEWER 2, finding 7) — the closing count is not
/// diagnostic decoration. It is what separates the two causes of a missing
/// `GAP_INDEX + 1`: an oracle that never got there (fixture) from a recovery GET
/// that never completed, leaving the successor stuck in the reorder buffer
/// (a genuine failure of the path under test). See [`assert_gap_fixture_held`].
fn run_gap_fixture(recovery: bool, value: &str) -> (String, usize, usize, usize) {
    let (_zenohd, port) = spawn_zenohd_on_ephemeral_tcp(tempfile);
    // The ORACLE dials zenohd directly: its own link must stay lossless, or the
    // `@adv` cache it answers recovery GETs from would be missing the very
    // sample under test. Only wz's link carries the fault.
    let (_oracle, mut oracle_out) = spawn_zenoh_advanced_pub(port, "demo/example/adv", value);
    let needle = format!("[{GAP_INDEX:4}] {value}");
    let relay = spawn_counting_relay(
        port,
        T_MID_FRAME,
        RelayFault::DropFirstAcceptorToDialer {
            needle: needle.clone().into_bytes(),
        },
    );

    let (_demo, mut reader, _at_declare) =
        spawn_wz_advanced_subscriber(relay.port(), "demo/example/**", None, None, recovery, false);
    // READ AT DECLARE, and this reading is load-bearing rather than diagnostic.
    // It is what excludes the startup history GET as the path by which
    // `GAP_INDEX` could reach wz: that GET goes out with the declare, so it can
    // only carry samples the oracle had already published by this instant.
    let published_at_declare = published_so_far(&read_captured(&mut oracle_out));

    std::thread::sleep(RECOVERY_RUN);
    let captured = read_captured(&mut reader);
    let published_after = published_so_far(&read_captured(&mut oracle_out));
    (
        captured,
        published_at_declare,
        published_after,
        relay.dropped_count(),
    )
}

/// The preconditions both recovery legs share, asserted rather than assumed.
///
/// Each one turns a fixture that drifted into a NAMED failure. Without them a
/// slow runner, a stale oracle or a needle that stopped matching would all
/// surface as "the sample is missing", which reads as a recovery regression —
/// the exact mis-diagnosis R311y442's review caught in the first version of
/// legs 1 and 2.
fn assert_gap_fixture_held(
    delivered: &[usize],
    published_at_declare: usize,
    published_after: usize,
    dropped: usize,
    ctx: &str,
) {
    assert_eq!(
        dropped, 1,
        "the relay removed {dropped} batches, not 1; with 0 the leg proves nothing \
         (nothing was ever lost, so an intact stream is not evidence of recovery) \
         and with more than 1 the induced fault is not the one described\n{ctx}"
    );
    // R311y443-review (REVIEWER 2, finding 6) — this bounds the GET's ISSUE
    // instant, and the reply's content is fixed when the CACHE PROCESSES the
    // query, a moment later. So the exclusion rests on one further premise: the
    // cache answers before the oracle's next publish. Measured at the boundary
    // this assertion permits (a joined-8-samples-late variant): the reply landed
    // 1.2 s ahead of index 8 being published. Deliberately NOT tightened to
    // `== 0` — that would cut late-join tolerance from ~8 s to ~1 s and rebuild
    // the persistent-red shape R311y442's review removed. The needle is what
    // makes the leg sound even if this premise ever fails: a history reply
    // carrying index 8 also carries index 7, so removing it reds the baseline
    // assertion below instead of passing.
    assert!(
        published_at_declare <= GAP_INDEX,
        "the oracle had already published {published_at_declare} samples (up to index \
         {}) when wz declared, so its startup history GET could have carried index \
         {GAP_INDEX} itself and the recovery path would not be the only way back. \
         wz joined too late — the fixture, not the code under test\n{ctx}",
        published_at_declare.saturating_sub(1)
    );
    assert!(
        delivered.contains(&(GAP_INDEX - 1)),
        "index {} never arrived, so wz had no in-order baseline before the gap and \
         no forward gap could be detected at all\n{ctx}",
        GAP_INDEX - 1
    );
    // R311y443-review (REVIEWER 2, finding 7) — a missing successor has TWO
    // causes and the first version of this message named only the fixture one.
    // With recovery armed the successor is BUFFERED on arrival
    // (`advanced_subscriber.rs:586`) and released only by `finish_recovery` ->
    // `flush_sequenced`, so a recovery GET that never completes leaves it
    // undelivered for a reason that has nothing to do with the run being short —
    // and "extend RECOVERY_RUN" would send the next reader at the wrong thing.
    // The oracle's own closing count separates them.
    assert!(
        delivered.contains(&(GAP_INDEX + 1)),
        "index {} never arrived. {}\n{ctx}",
        GAP_INDEX + 1,
        if published_after < GAP_INDEX + 2 {
            format!(
                "The oracle published only {published_after} samples in the whole run, \
                 so it never reached that index and the run ended before the successor \
                 that makes the gap observable — extend RECOVERY_RUN. This is the \
                 fixture, not the code under test."
            )
        } else {
            format!(
                "The oracle DID publish it ({published_after} samples in the run), so \
                 this is not a short run: the successor arrived and is stuck in the \
                 reorder buffer, which means the recovery GET never completed. That is \
                 a failure of the path under test."
            )
        }
    );
}

/// Leg 5 — the PROOF for `ext-pubsub-advanced-recovery`. A relay deletes one of
/// the oracle's samples from the wire; wz notices the hole from the NEXT
/// sample's sequence number and refills it out of the foreign publisher's own
/// `@adv` cache.
///
/// ## Why a fault had to be injected at all
///
/// Every other leg in this file witnesses a path both peers exercise by simply
/// running. Retransmission is different: it engages only on LOSS, and two
/// healthy peers on a loopback TCP link never lose anything. Before this leg,
/// wz's recovery path was covered only wz<->wz, where the same reorder buffer
/// sits on both ends of the claim — and the `@adv` selector defects R311y441
/// found are exactly what that arrangement cannot see. The relay is what makes
/// the gap real, and it is the same one R311y438 built to COUNT the wire,
/// taught to remove one batch from it.
///
/// ## What makes this attributable to recovery
///
/// There are FOUR ways index `GAP_INDEX` could reach wz — R311y443 first wrote
/// three and R311y443-review (REVIEWER 2) found the fourth. A count is a
/// citation here, so they are enumerated rather than summarised:
///
///   * the LIVE push — removed by the relay, which reports `dropped == 1`;
///   * the STARTUP HISTORY GET — issued at declare time, and the leg reads the
///     oracle's publish count at that instant to prove the sample did not yet
///     exist to be carried (see the premise noted at
///     [`assert_gap_fixture_held`]);
///   * the LATE-PUBLISHER GET (`issue_late_publisher_query`,
///     `advanced_subscriber.rs:1103-1139`) — an UNBOUNDED per-publisher history
///     GET fired from the `<ke>/@adv/pub/**` liveliness callback, whose replies
///     feed the same `ingest_sequenced`. Absent by construction:
///     `HistoryConfig::detect_late_publishers` defaults to `false`
///     (`advanced_subscriber.rs:385`), the trigger is gated on it
///     (`:1609`), and wz-ap-demo never calls the setter — so the liveliness
///     subscriber is never declared. A future flag exposing it reopens this;
///   * the PERIODIC / HEARTBEAT triggers — not armed. `--advanced-recovery` is
///     sample-driven only, which matters here because upstream's oracle DOES
///     beacon (`MissDetectionConfig::default().heartbeat(500ms)`,
///     `zenoh-ext/examples/examples/z_advanced_pub.rs:36`), so a subscriber with
///     the heartbeat trigger armed would recover the gap without the gap ever
///     having been the reason.
///
/// What is left is the sample-driven `_sn=last+1..` GET, answered by a real
/// zenoh-ext `AdvancedCache`. Leg 6 is its twin: same fixture, same drop, flag
/// omitted, and the sample stays missing — and it is the STRONGER half of the
/// argument, because every non-recovery-gated path above is present identically
/// in both legs, so leg 6 closes them empirically whether or not this list is
/// complete. The enumeration that must be exhaustive is the small one: the three
/// recovery triggers (`advanced_subscriber.rs:605`, `:696`, `:724`), of which
/// `RecoveryConfig::new()` arms only the first.
// wz issues the recovery GET and consumes the replies, so the recovering half is
// wz->; the sequence numbers it detects the gap in are the foreign publisher's
// SourceInfo, which is the zenoh-ext-> direction.
// wz-proves: ext-pubsub-advanced-recovery wz->zenoh-ext
#[test]
#[ignore = "external binaries: zenohd + zenoh-ext examples; run-ci Layer Z"]
fn wz_advanced_recovery_refills_a_gap_from_the_zenoh_ext_cache() {
    let (captured, published_at_declare, published_after, dropped) =
        run_gap_fixture(true, "GAPVAL");
    let delivered = delivered_indices(&captured);
    let ctx = format!(
        "gap_index={GAP_INDEX} published_at_declare={published_at_declare} \
         published_after={published_after} dropped={dropped} delivered={delivered:?}\n\
         --- captured ---\n{captured}"
    );
    assert_gap_fixture_held(
        &delivered,
        published_at_declare,
        published_after,
        dropped,
        &ctx,
    );

    assert!(
        delivered.contains(&GAP_INDEX),
        "index {GAP_INDEX} was removed from the wire and never came back; the \
         sample-driven `_sn={}..` recovery GET did not refill it from the \
         zenoh-ext cache\n{ctx}",
        GAP_INDEX
    );
    // Byte-exact, not merely present: a recovered sample is the publisher's own
    // bytes replayed out of its cache, and an index alone cannot carry that.
    let needle = format!("payload='[{GAP_INDEX:4}] GAPVAL'");
    assert!(
        captured.contains(&needle),
        "index {GAP_INDEX} was recovered but not byte-exact (looking for \
         {needle})\n{ctx}"
    );
    // Ordering, not just arrival. The recovered sample is delivered from the
    // reorder buffer in sn order, so the whole run is contiguous — which is the
    // difference between refilling a hole and appending a late duplicate.
    for w in delivered.windows(2) {
        assert_eq!(
            w[1],
            w[0] + 1,
            "delivered indices are not contiguous ({delivered:?}); the recovered \
             sample was not reinserted in sequence\n{ctx}"
        );
    }
    // CALIBRATED BY LEG 6, which asserts `vec![1]` through this same parser on
    // this same fixture (R311y443-review, REVIEWER 2). That matters because this
    // is a `== 0` over a hand-rolled `missed=` reader whose `filter_map` drops
    // anything it cannot parse: on its own, a log-format drift would make it
    // pass vacuously. If leg 6 is ever deleted or weakened, this assertion
    // becomes a tautology and needs its own calibration.
    assert!(
        miss_counts(&captured).is_empty(),
        "the subscriber reported {:?} misses; a gap the recovery filled must not \
         also surface as a Miss at flush\n{ctx}",
        miss_counts(&captured)
    );
}

/// Leg 6 — the CONTROL twin of leg 5. Same oracle, same relay, same removed
/// sample, `--advanced-recovery` omitted: the hole stays a hole.
///
/// This is what stops leg 5 from being a statement about the fixture instead of
/// about wz. Without it, "index 8 arrived" is equally consistent with a relay
/// whose needle silently stopped matching, a zenohd that re-sent the batch, or
/// any other path that quietly repairs the stream — none of which involve wz's
/// recovery code. Here the ONLY difference is one flag on one binary, and the
/// sample does not arrive.
///
/// It also pins the no-recovery behaviour itself, which is a real branch rather
/// than an absence: wz reports a `Miss` carrying the number of skipped samples
/// and delivers PAST the hole (`advanced_subscriber.rs:587-596`), rather than
/// stalling on it.
// wz-proves: none -- the CONTROL for leg 5. It is wz's no-retransmission branch
// that runs here, and asserting a sample does NOT arrive credits no atom; its
// job is to bind leg 5's positive result to the recovery path specifically.
#[test]
#[ignore = "external binaries: zenohd + zenoh-ext examples; run-ci Layer Z"]
fn wz_without_recovery_keeps_a_gap_the_zenoh_ext_cache_could_fill() {
    let (captured, published_at_declare, published_after, dropped) =
        run_gap_fixture(false, "NOGAPVAL");
    let delivered = delivered_indices(&captured);
    let ctx = format!(
        "gap_index={GAP_INDEX} published_at_declare={published_at_declare} \
         published_after={published_after} dropped={dropped} delivered={delivered:?}\n\
         --- captured ---\n{captured}"
    );
    assert_gap_fixture_held(
        &delivered,
        published_at_declare,
        published_after,
        dropped,
        &ctx,
    );

    assert!(
        !delivered.contains(&GAP_INDEX),
        "index {GAP_INDEX} arrived at a subscriber with NO recovery armed. The \
         relay removed it from the wire, so something other than wz's \
         retransmission path is repairing the stream — and leg 5's positive \
         result cannot be attributed to recovery until that is explained\n{ctx}"
    );
    assert_eq!(
        miss_counts(&captured),
        vec![1],
        "expected exactly one Miss of exactly one sample — the hole the relay \
         made. A different count means the drop did not remove the sample this \
         leg thinks it did\n{ctx}"
    );
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

/// The `_sn=` ranges the oracle's own trace shows wz asking for, as
/// `(from, to)` with `to == None` for an OPEN range.
///
/// R311y444 — this is the heartbeat-trigger legs' whole observable, because
/// recovery SUCCESS cannot separate the two triggers. wz's sample-driven trigger
/// cannot be switched off (it is implied by recovering at all,
/// `advanced_subscriber.rs:195-197`) and the oracle publishes at 1 Hz forever, so
/// the successor that fires it always arrives. What differs is the SELECTOR:
/// sample-driven sends `to_sn: None` (`:605-613`) and heartbeat sends
/// `to_sn: Some(hb_sn)` (`:709-726`), so a bounded range is the beacon path's
/// signature and nothing else in wz emits one.
///
/// Parsed from the FOREIGN implementation's log rather than wz's, deliberately:
/// wz does not log its own selector, and a claim about what crossed the wire is
/// worth more when the peer that received it is the one reporting.
fn requested_sn_ranges(oracle_trace: &str) -> Vec<(u32, Option<u32>)> {
    let mut out = Vec::new();
    for line in oracle_trace.lines() {
        let mut rest = line;
        while let Some(pos) = rest.find("_sn=") {
            rest = &rest[pos + "_sn=".len()..];
            let end = rest
                .find(|c: char| c == ';' || c == '"' || c == '\'' || c.is_whitespace())
                .unwrap_or(rest.len());
            let (val, tail) = rest.split_at(end);
            if let Some((from, to)) = val.split_once("..") {
                if let Ok(from) = from.trim().parse::<u32>() {
                    let to = to.trim();
                    // R311y444-review (REVIEWER 2, NIT) — an UNPARSABLE upper
                    // bound must not silently become `None`, which is the shape
                    // leg 10 calibrates on as healthy AND leg 9 reads as "no
                    // bounded range". Unreachable today (the bound is a u32
                    // rendered by wz), but a corruption must not disguise itself
                    // as the good case, so it panics instead.
                    let to = if to.is_empty() {
                        None
                    } else {
                        Some(to.parse::<u32>().unwrap_or_else(|_| {
                            panic!("unparsable `_sn` upper bound {to:?} in the oracle trace")
                        }))
                    };
                    out.push((from, to));
                }
            }
            rest = tail;
        }
    }
    out
}

/// The shared fixture for legs 9 and 10: leg 5's gap fixture with the oracle
/// tracing, and wz's heartbeat trigger armed or not.
///
/// Returns wz's log, the oracle's trace, and the relay's drop count.
///
/// wz subscribes on the CONCRETE `demo/example/adv`, not the `demo/example/**`
/// every other leg here uses, and that is forced rather than stylistic. The
/// heartbeat trigger declares a SECOND subscriber on `<ke>/@adv/pub/**`, which
/// with a `**`-tailed base composes to `demo/example/**/@adv/pub/**` — a `**`
/// chunk, then literal chunks, then a `*`-shape chunk, which is exactly what
/// wz's R300 outbound gate refuses because it SIGABRTs zenoh-pico's canon
/// (`keyexpr_canon.rs:383-394`, R299 bug #3). Upstream emits that keyexpr anyway
/// (the oracle runs `-k demo/example/**` with its own heartbeat armed), so this
/// is wz declining to put a pico-crashing keyexpr on the wire rather than a
/// defect — but the composition limit is real: in wz the heartbeat trigger and a
/// `**`-tailed base cannot be used together, and a fixture that ignored it would
/// fail at declare with the trigger never armed at all.
fn run_heartbeat_trigger_fixture(heartbeat: bool, value: &str) -> (String, String, usize) {
    let (_zenohd, port) = spawn_zenohd_on_ephemeral_tcp(tempfile);
    let (_oracle, mut oracle_out) =
        spawn_zenoh_advanced_pub_with_log(port, "demo/example/adv", value, "warn,zenoh_ext=trace");
    let needle = format!("[{GAP_INDEX:4}] {value}");
    let relay = spawn_counting_relay(
        port,
        T_MID_FRAME,
        RelayFault::DropFirstAcceptorToDialer {
            needle: needle.into_bytes(),
        },
    );
    let (_demo, mut reader, _at_declare) = spawn_wz_advanced_subscriber(
        relay.port(),
        "demo/example/adv",
        None,
        None,
        true,
        heartbeat,
    );
    std::thread::sleep(RECOVERY_RUN);
    (
        read_captured(&mut reader),
        read_captured(&mut oracle_out),
        relay.dropped_count(),
    )
}

/// The burst the beacon legs publish. Its LAST index is the one the relay
/// removes, so the burst has to be long enough that the oracle is certainly
/// established with an in-order baseline well before the fixture reaches it.
const BEACON_BURST: usize = 20;

/// The beacon period wz is armed with. Matches upstream's own default in
/// `z_advanced_pub` (`MissDetectionConfig::default().heartbeat(500ms)`,
/// `zenoh-ext/examples/examples/z_advanced_pub.rs:36`), so the leg witnesses the
/// cadence a real deployment would run rather than one tuned to pass.
const BEACON_PERIOD_MS: u64 = 500;

/// How long the beacon legs let the oracle run AFTER wz's burst has completed.
///
/// This window is the whole point of the fixture: publishing has STOPPED, so
/// nothing but the beacon can still tell the oracle that a sample it never saw
/// exists. At [`BEACON_PERIOD_MS`] it is ~16 beacons, and the recovery GET round
/// trip was measured under 100 ms in R311y443-review.
const BEACON_RUN: Duration = Duration::from_secs(8);

/// Spawn upstream's `z_advanced_sub` against `port` and return once it has
/// DECLARED — the child and its still-open capture.
///
/// Waiting for the declare marker is what makes the beacon legs' ordering real
/// rather than hoped for: the oracle must be subscribed BEFORE wz publishes
/// anything, or its startup history GET could carry the very sample the relay is
/// about to remove.
///
/// The oracle needs no flags to arm what these legs test. `z_advanced_sub`
/// hard-codes `.recovery(RecoveryConfig::default().heartbeat())` (`:33`) and
/// declares a `sample_miss_listener` (`:38`), so the heartbeat trigger and the
/// miss report are always live — there is no arming knob to get wrong.
fn spawn_zenoh_advanced_sub(port: u16, keyexpr: &str) -> (ChildGuard, std::fs::File) {
    let bin = zenoh_ext_example_binary("z_advanced_sub");
    let output = tempfile();
    let writer = output.try_clone().expect("dup z_advanced_sub stdout");
    let mut reader = output;
    let child = ChildGuard::wrap(
        "z_advanced_sub (zenoh-ext oracle)",
        Command::new(&bin)
            .arg("--mode")
            .arg("client")
            .arg("-e")
            .arg(format!("tcp/127.0.0.1:{port}"))
            .arg("--no-multicast-scouting")
            .arg("-k")
            .arg(keyexpr)
            .env("RUST_LOG", "error")
            .stdout(Stdio::from(writer))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn z_advanced_sub"),
    );
    wait_for_substring(&mut reader, "Declaring AdvancedSubscriber", MARKER_TIMEOUT).unwrap_or_else(
        |snapshot| {
            panic!(
                "z_advanced_sub never declared its subscriber; the oracle never \
                 reached the fixture\n--- z_advanced_sub ---\n{snapshot}"
            )
        },
    );
    (child, reader)
}

/// Spawn a wz advanced PUBLISHER against `port`, optionally with its heartbeat
/// beacon armed, and return once its burst has COMPLETED.
///
/// Returns the child, its still-open capture, and the log at burst completion.
fn spawn_wz_advanced_publisher(
    port: u16,
    keyexpr: &str,
    value: &str,
    heartbeat: bool,
) -> (ChildGuard, std::fs::File, String) {
    let demo = wz_ap_demo_binary();
    let stderr = tempfile();
    let writer = stderr.try_clone().expect("dup wz-ap-demo stderr");
    let mut reader = stderr;
    let mut cmd = Command::new(&demo);
    cmd.arg("--connect")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--advanced-publish")
        .arg(keyexpr)
        .arg("--value")
        .arg(value)
        .arg("--advanced-publish-count")
        .arg(BEACON_BURST.to_string())
        .arg("--cache-max")
        .arg("32");
    if heartbeat {
        cmd.arg("--advanced-publish-heartbeat")
            .arg(BEACON_PERIOD_MS.to_string());
    }
    let child = ChildGuard::wrap(
        "wz-ap-demo (--advanced-publish)",
        cmd.env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo advanced publisher"),
    );

    let captured = wait_for_substring(&mut reader, "ADVANCED BURST COMPLETE", MARKER_TIMEOUT)
        .unwrap_or_else(|snapshot| {
            panic!(
                "wz-ap-demo never completed its advanced burst. If this says INERT, \
                 the demo was built without `--features advanced`.\n--- captured ---\n{snapshot}"
            )
        });
    assert!(
        !captured.contains("is INERT"),
        "wz-ap-demo reports --advanced-publish INERT; build it with \
         `--features advanced`.\n--- captured ---\n{captured}"
    );
    // The declare line reports the option it was built with, so a flag that
    // silently failed to parse is caught HERE rather than downstream, where a
    // beacon that was never armed reads exactly like a beacon that was armed and
    // did not work — the same guard the recovery legs put on `recovery=`.
    let expected = if heartbeat {
        format!("heartbeat_ms=Some({BEACON_PERIOD_MS})")
    } else {
        "heartbeat_ms=None".to_string()
    };
    assert!(
        captured.contains(&expected),
        "wz-ap-demo did not declare with {expected}; the \
         --advanced-publish-heartbeat flag did not take\n--- captured ---\n{captured}"
    );
    // wz emitting fewer samples than asked would ALSO leave the last index
    // missing, which is the control leg's expected observation and the proof
    // leg's failure — so the two would be indistinguishable without this.
    //
    // R311y444-review (REVIEWER 2, DEFECT) — filtered on `ADVANCED PUT keyexpr=`,
    // not on `ADVANCED PUT`. The demo logs BOTH outcomes with that shorter
    // substring (`tasks.rs:213` on Ok, `:217` "ADVANCED PUT failed:" on Err), so
    // the loose filter counted a FAILED put of the last index as a success —
    // defeating the exact vacuity this guard exists to close.
    assert!(
        !captured.contains("ADVANCED PUT failed"),
        "a wz put FAILED during the burst, so a missing sample downstream is the \
         publisher's error and not the wire fault under test\n--- captured ---\n{captured}"
    );
    let puts = captured
        .lines()
        .filter(|l| l.contains("ADVANCED PUT keyexpr="))
        .count();
    assert_eq!(
        puts, BEACON_BURST,
        "wz published {puts} samples, not {BEACON_BURST}; the burst itself is \
         short, so nothing downstream is a statement about the beacon\n--- captured ---\n{captured}"
    );
    (child, reader, captured)
}

/// The shared fixture for legs 7 and 8: a wz advanced publisher bursting into
/// zenohd over a healthy link, and upstream's `z_advanced_sub` reaching zenohd
/// through a relay that removes the burst's LAST sample on the way in.
///
/// Returns the oracle's captured output, wz's log, and the relay's drop count.
fn run_beacon_fixture(heartbeat: bool, value: &str) -> (String, String, usize) {
    let (_zenohd, port) = spawn_zenohd_on_ephemeral_tcp(tempfile);
    // The fault rides the ORACLE's link, which is the reverse of the recovery
    // legs and follows from which side is the receiver here. wz dials zenohd
    // DIRECTLY: its own link must stay lossless, or the `@adv` cache that answers
    // the recovery GET would be missing the very sample under test.
    let needle = format!("[{:4}] {value}", BEACON_BURST - 1);
    let relay = spawn_counting_relay(
        port,
        T_MID_FRAME,
        RelayFault::DropFirstAcceptorToDialer {
            needle: needle.into_bytes(),
        },
    );

    // ORDER IS LOAD-BEARING. The oracle subscribes BEFORE wz exists, which closes
    // its two history paths — but they are closed in DIFFERENT ways, and the
    // first version of this comment claimed both were structural:
    //
    //   * its STARTUP history GET (`<ke>/@adv/**`, issued at declare) is closed
    //     STRUCTURALLY — it goes out while there is no wz process, so no cache
    //     exists to answer it;
    //   * its LATE-PUBLISHER GET — armed, since `z_advanced_sub` sets
    //     `HistoryConfig::default().detect_late_publishers()` (`:32`) — is closed
    //     by a MARGIN, not by construction. It fires when the oracle OBSERVES
    //     wz's `@adv` liveliness token, and a networked GET is answered from the
    //     cache state at ARRIVAL, not at issue. Nothing structurally bounds that
    //     instant.
    //
    // R311y444-review (REVIEWERS 1 and 2, independently) — the margin was then
    // measured rather than argued: the late-publisher GET lands ~90ms after the
    // token while the burst runs BEACON_BURST * 200ms ~= 3.8s, and it was
    // observed carrying source_sn 0. That is ~42x, and it is a WALL-CLOCK burst
    // so a faster machine does not shrink it. It is also fail-loud: if that GET
    // ever carried the last index, LEG 8 REDS — which is to say leg 8, not this
    // ordering, is what ultimately closes the path.
    let (_sub, mut sub_out) = spawn_zenoh_advanced_sub(relay.port(), "demo/wzadv/**");
    let (_demo, _demo_reader, demo_log) =
        spawn_wz_advanced_publisher(port, "demo/wzadv/x", value, heartbeat);

    // Publishing has stopped. Everything that arrives from here on is the beacon
    // path or nothing.
    std::thread::sleep(BEACON_RUN);
    (read_captured(&mut sub_out), demo_log, relay.dropped_count())
}

/// The precondition both beacon legs share: the fault actually landed, and the
/// stream was otherwise intact.
fn assert_beacon_fixture_held(sub_out: &str, dropped: usize, value: &str, ctx: &str) {
    assert_eq!(
        dropped, 1,
        "the relay removed {dropped} batches, not 1; with 0 nothing was ever lost, \
         so neither leg is a statement about the beacon\n{ctx}"
    );
    // Everything BEFORE the removed sample must have arrived live. Without this,
    // a fixture that lost the whole tail would satisfy the control leg's
    // assertion for entirely the wrong reason.
    for idx in 0..BEACON_BURST - 1 {
        let expected = format!("('demo/wzadv/x': '[{idx:4}] {value}')");
        assert!(
            sub_out.contains(&expected),
            "the oracle never received sample {idx}, which the relay did NOT \
             remove — the fixture lost more than the one batch it meant to\n{ctx}"
        );
    }
}

/// Leg 7 — the PROOF for `ext-pubsub-sample-miss-detection`. wz's heartbeat
/// beacon is what tells a real zenoh-ext subscriber that a sample it never saw
/// exists, and the subscriber then recovers it from wz's own `@adv` cache.
///
/// ## Why the LAST sample, specifically
///
/// The recovery legs (5 and 6) remove a sample from the MIDDLE of a stream, and
/// there the successor's sequence number is what reveals the hole. That is a
/// different atom: it witnesses the subscriber's sample-driven trigger, and
/// upstream's oracle would have recovered the gap with or without a beacon.
///
/// Removing the burst's LAST sample closes that path BY CONSTRUCTION rather than
/// by timing. wz stops publishing when the burst completes, so no later sample
/// can ever carry the sequence number that would expose the gap, and
/// `z_advanced_sub`'s sample-driven trigger has nothing to fire on. What remains
/// is the beacon — a `z_serialize::<u32>` of wz's last sn, republished every
/// [`BEACON_PERIOD_MS`] on the publisher's own `@adv` KE
/// (`advanced_publisher.rs:440`), which is byte-identical to what upstream emits
/// from `advanced_publisher.rs:390-395`.
///
/// ## What binds this to the atom's own code
///
/// `ext-pubsub-sample-miss-detection` has 19 cfg sites and every one of them is
/// in `advanced_publisher.rs` — the beacon EMIT. The subscriber-side heartbeat
/// trigger is a different atom (`ext-pubsub-advanced-recovery`, and
/// `advanced_subscriber.rs:220` says so). So the direction matters: a leg where
/// wz CONSUMES a foreign beacon would compile none of this atom's code. Here wz
/// produces the beacon and the foreign implementation consumes it, which is what
/// makes leg 8 — the same fixture with the beacon off — a discriminator on the
/// atom rather than on the flag that gates it.
// wz-proves: ext-pubsub-sample-miss-detection wz->zenoh-ext
#[test]
#[ignore = "external binaries: zenohd + zenoh-ext examples; run-ci Layer Z"]
fn zenoh_ext_advanced_sub_recovers_a_lost_last_sample_from_the_wz_heartbeat() {
    let value = "WZBEAT";
    let (sub_out, demo_log, dropped) = run_beacon_fixture(true, value);
    let ctx = format!("--- z_advanced_sub ---\n{sub_out}\n--- wz ---\n{demo_log}");
    assert_beacon_fixture_held(&sub_out, dropped, value, &ctx);

    let last = format!("('demo/wzadv/x': '[{:4}] {value}')", BEACON_BURST - 1);
    assert!(
        sub_out.contains(&last),
        "the relay removed the burst's LAST sample and it never came back. \
         Publishing had stopped, so no live sample could reveal the gap: the \
         beacon was the only path, and a real zenoh-ext subscriber did not \
         recover through it (looking for {last})\n{ctx}"
    );
}

/// Leg 8 — the CONTROL twin of leg 7. Same fixture, same removed sample, beacon
/// NOT armed, and the sample stays gone.
///
/// This is the half that makes leg 7 a statement about the beacon rather than
/// about the oracle's recovery machinery: `z_advanced_sub` arms its heartbeat
/// trigger and its history GETs identically in both legs, so everything that
/// could refill the hole for another reason is present here too. The only
/// difference on the wire is whether wz emits the beacon at all.
// wz-proves: none -- the CONTROL for leg 7. It is the beacon-off branch, and it
// is what binds leg 7's positive result to the beacon specifically.
#[test]
#[ignore = "external binaries: zenohd + zenoh-ext examples; run-ci Layer Z"]
fn zenoh_ext_advanced_sub_cannot_recover_a_lost_last_sample_without_the_wz_heartbeat() {
    let value = "NOBEAT";
    let (sub_out, demo_log, dropped) = run_beacon_fixture(false, value);
    let ctx = format!("--- z_advanced_sub ---\n{sub_out}\n--- wz ---\n{demo_log}");
    assert_beacon_fixture_held(&sub_out, dropped, value, &ctx);

    let last = format!("('demo/wzadv/x': '[{:4}] {value}')", BEACON_BURST - 1);
    assert!(
        !sub_out.contains(&last),
        "without the beacon the oracle recovered the removed last sample anyway, \
         so leg 7's positive result is NOT attributable to the beacon — some \
         other path (a history GET, a late-publisher GET) is refilling the \
         hole\n{ctx}"
    );
}

/// Leg 9 — the PROOF for `ext-pubsub-advanced-recovery`'s HEARTBEAT trigger, the
/// third of its three and the one legs 5/6 deliberately left unarmed.
///
/// ## Why this leg cannot be judged by whether the gap was refilled
///
/// Legs 5 and 6 separate "recovered" from "not recovered" by toggling recovery
/// itself. That is unavailable here: wz's sample-driven trigger is implied by
/// recovering at all (`advanced_subscriber.rs:195-197`) and cannot be switched
/// off, and upstream's `z_advanced_pub` publishes at 1 Hz forever — so the
/// successor that fires the sample-driven GET always arrives, and BOTH arms of a
/// heartbeat-on/heartbeat-off pair end with the hole filled. Judging by delivery
/// would make the two legs indistinguishable, which is the trap this leg is
/// built around rather than into.
///
/// What separates them is the SELECTOR the two triggers put on the wire:
///
///   * sample-driven issues `to_sn: None` → an OPEN `_sn=last+1..`
///     (`advanced_subscriber.rs:605-613`);
///   * heartbeat issues `to_sn: Some(hb_sn)` → a BOUNDED `_sn=last+1..hb`
///     (`:709-726`), because the beacon states exactly how far the publisher has
///     got and there is no reason to ask past it.
///
/// A bounded `_sn` range is emitted by nothing else in wz, so its presence in
/// the FOREIGN implementation's own trace is the beacon path having fired. Leg 10
/// is the control: same fixture, trigger unarmed, and the bounded range is absent
/// while the open one is still there — which is also what keeps the parser
/// honest, since a parser that matched nothing would satisfy leg 10 vacuously.
///
/// ## The one undocumented margin (R311y444-review, REVIEWER 2)
///
/// The beacon's 500ms period must beat the oracle's next 1 Hz sample. If a live
/// sample arrived first, the sample-driven trigger would take the
/// `pending_queries` slot (`advanced_subscriber.rs:605`, `:719` both gate on
/// `pending_queries == 0`) and no bounded GET would ever be issued. That is a 2x
/// margin — the tightest in this file, and the only one not stated where it is
/// relied on. Measured healthy: the GET fires between the oracle's `Put Data [8]`
/// and `Put Data [9]`.
// wz-proves: ext-pubsub-advanced-recovery zenoh-ext->wz
#[test]
#[ignore = "external binaries: zenohd + zenoh-ext examples; run-ci Layer Z"]
fn zenoh_ext_heartbeat_beacon_drives_a_bounded_wz_recovery_get() {
    let value = "HBTRIG";
    let (captured, oracle_trace, dropped) = run_heartbeat_trigger_fixture(true, value);
    let delivered = delivered_indices(&captured);
    let ranges = requested_sn_ranges(&oracle_trace);
    let ctx = format!(
        "delivered={delivered:?} sn_ranges={ranges:?}\n--- wz ---\n{captured}\n\
         --- oracle trace ---\n{oracle_trace}"
    );
    // R311y444-review (REVIEWER 1, NIT) — the first version said "no trigger of
    // any kind had a reason to fire", which is false: `handle_heartbeat` fires
    // whenever a beacon reports past `last_delivered`, which ordinary in-flight
    // latency produces with no induced gap at all. What the drop is load-bearing
    // for is the BOUND asserted below being the gap's index.
    assert_eq!(
        dropped, 1,
        "the relay removed {dropped} batches, not 1; with 0 there is no gap at \
         index {GAP_INDEX}, so the bound asserted below is not the beacon's \
         report about a real loss\n{ctx}"
    );

    let bounded: Vec<_> = ranges.iter().filter(|(_, to)| to.is_some()).collect();
    assert!(
        !bounded.is_empty(),
        "the oracle's trace shows no BOUNDED `_sn=a..b` selector, so wz never \
         issued the heartbeat trigger's GET. Every range it did ask for is open, \
         which is the sample-driven trigger — the beacon path did not fire\n{ctx}"
    );
    // THE BOUND MUST BE THE BEACON'S REPORTED SN, and this assertion is what
    // makes the leg a statement about the zenoh-ext -> wz direction at all.
    //
    // R311y444-review (REVIEWER 2, BLOCKER; REVIEWER 1 reached the same place
    // from the other side) — the first version asserted only `to >= from`, which
    // is a TAUTOLOGY: `handle_heartbeat` requests only when `!caught_up`, i.e.
    // `hb_sn > last_delivered` (`advanced_subscriber.rs:715-726`), and
    // `from = last_delivered + 1`, so `to >= from` holds by construction and
    // asserts nothing about the beacon. Falsified by damaging the atom's own
    // wire artifact rather than the flag: byte-swapping the beacon decode at
    // `advanced_subscriber.rs:1549` made wz emit `_sn=8..134217728` at 2 Hz and
    // ALL FOUR legs stayed green. Pinning the VALUE is what closes it — wz must
    // have decoded the foreign beacon correctly to ask for exactly this range.
    let expected = GAP_INDEX as u32;
    assert!(
        bounded
            .iter()
            .any(|(from, to)| *from == expected && *to == Some(expected)),
        "wz issued a bounded recovery GET, but none asked for exactly \
         _sn={expected}..{expected} — the range the publisher's beacon reports \
         after the relay removed index {expected}. A bounded range with any \
         other bound means wz did not decode the foreign beacon correctly, \
         which is the zenoh-ext -> wz half this leg exists to witness\n{ctx}"
    );
}

/// Leg 10 — the CONTROL twin of leg 9. Same fixture, same induced gap, heartbeat
/// trigger unarmed: wz still recovers (the sample-driven trigger fires on the
/// successor) but every `_sn` range it asks for is OPEN.
///
/// This is what makes leg 9's bounded range attributable to the beacon rather
/// than to wz's recovery machinery in general — and it doubles as the parser's
/// calibration, since the open range it asserts PRESENT is read by the same
/// function that reads the bounded one. Without that arm, a parser that silently
/// matched nothing would satisfy the "no bounded range" assertion vacuously.
// wz-proves: none -- the CONTROL for leg 9.
#[test]
#[ignore = "external binaries: zenohd + zenoh-ext examples; run-ci Layer Z"]
fn zenoh_ext_wz_recovery_get_stays_unbounded_without_the_heartbeat_trigger() {
    let value = "HBCTRL";
    let (captured, oracle_trace, dropped) = run_heartbeat_trigger_fixture(false, value);
    let delivered = delivered_indices(&captured);
    let ranges = requested_sn_ranges(&oracle_trace);
    let ctx = format!(
        "delivered={delivered:?} sn_ranges={ranges:?}\n--- wz ---\n{captured}\n\
         --- oracle trace ---\n{oracle_trace}"
    );
    assert_eq!(
        dropped, 1,
        "the relay removed {dropped} batches, not 1\n{ctx}"
    );

    // CALIBRATION, and it has to come first: this is the same parser leg 9 leans
    // on, so a run where it matched nothing at all must fail HERE rather than
    // pass the negative below.
    assert!(
        ranges.iter().any(|(_, to)| to.is_none()),
        "the oracle's trace shows no OPEN `_sn=a..` selector either, so wz issued \
         no recovery GET the parser could see — the negative asserted below would \
         hold vacuously and leg 9's bounded-range assertion is uncalibrated\n{ctx}"
    );
    let bounded: Vec<_> = ranges.iter().filter(|(_, to)| to.is_some()).collect();
    assert!(
        bounded.is_empty(),
        "wz issued a BOUNDED recovery GET {bounded:?} with the heartbeat trigger \
         unarmed. Only the heartbeat path sets `to_sn`, so leg 9's bounded range \
         is not attributable to the beacon\n{ctx}"
    );
}
