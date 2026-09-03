// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.15 routing / §5.9 query — CROSS-IMPL validation that the wz `--router`
//! HONOURS a query's `QueryTarget` rather than relaying it, against real zenoh
//! (Rust) clients.
//!
//! R311y840 gave the wz `--router` a query plane and fanned every `Request` out
//! to EVERY matching queryable, recording the target as relayed-verbatim. That
//! is not what a zenoh router does. `compute_final_route`
//! (`zenoh/src/net/routing/dispatcher/queries.rs:205-266`) branches three ways:
//!
//!   - `All` — every matching queryable.
//!   - `AllComplete` — only those that declared `complete` AND cover the query.
//!   - `BestMatching` — the single NEAREST such queryable, falling back to `All`
//!     when none qualifies.
//!
//! `BestMatching` is the DEFAULT, so the divergence sat on the path a plain
//! `z_get` takes: a querier that stock zenoh answers from one queryable was
//! answered from all of them, and every non-authoritative peer was woken for a
//! question the authoritative one already covered.
//!
//! WHY THESE ORACLES AND NOT THE ONES ALREADY PROVISIONED. The decision is made
//! on COMPLETENESS, and neither existing foreign counterparty can express it.
//! `zenohd` is a router and declares no queryable of its own. zenoh-pico's
//! `z_queryable` example takes `z_queryable_options_default()`, whose `complete`
//! is hardcoded `false` (`_Z_QUERYABLE_COMPLETE_DEFAULT`,
//! `vendor/zenoh-pico/include/zenoh-pico/session/queryable.h:42`) with no flag to
//! change it — so a pico pair can only ever witness the fallback arm. Upstream's
//! own `z_queryable --complete` and `z_get --target` are the only foreign
//! binaries that can drive both sides, which is why
//! `scripts/build-zenohd.sh` now provisions them (R311y841).
//!
//! THE DISCRIMINATOR IS A COUNT, NOT A PRESENCE. All three legs below leave the
//! querier satisfied — the complete queryable answers every one of them — so
//! "a reply came back" cannot tell the three targets apart, and neither can the
//! querier's own stdout: zenoh's `z_get` consolidates by key expression, and
//! both queryables reply on the SAME `demo/**` pattern, so even the `All` leg
//! prints ONE line. What separates them is how many queries the INCOMPLETE
//! queryable was asked, and that is measured on its stdout, leg by leg. Under
//! the pre-R311y841 table its count rises by one every leg; under this one it
//! rises only on `All`.
//!
//! Requires: `wz-ap-demo` built with `--features routing-routes` AND the core
//! zenoh example binaries (`scripts/build-zenohd.sh` ->
//! `target/zenohd/zenoh_z_queryable`, `zenoh_z_get`). run-ci's Layer E5 builds
//! the demo with the feature and SKIPs this leg when the examples are absent.
//! The `wz_router_` fn prefix keeps the default Layer E sweep's
//! `--skip wz_router` from running it against an arbitrary-feature binary.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, graceful_terminate, read_captured,
    run_query_until_answered, spawn_on_ephemeral_port, wz_ap_demo_binary,
    zenoh_core_example_binary, QueryAttempts,
};

/// The keyexpr both queryables cover and the querier asks INSIDE of. The
/// queryables declare the pattern and the query names a concrete key, so
/// `demo/query-target/**` COVERS `demo/query-target/x` — the `includes`
/// relation zenoh's per-query completeness is computed from
/// (`hat/router/queries.rs:1464`). Distinct from every other Layer E keyexpr so
/// parallel runs never cross-match.
const QABL_KEY: &str = "demo/query-target/**";
const QUERY_KEY: &str = "demo/query-target/x";

/// Distinct payloads so a received line names WHICH queryable answered.
const COMPLETE_ANSWER: &str = "answer-from-the-complete-queryable";
const PARTIAL_ANSWER: &str = "answer-from-the-incomplete-queryable";

/// zenoh `z_queryable`'s ready marker and its per-query marker.
const QABL_READY: &str = "Declaring Queryable on";
const QABL_RECEIVED: &str = ">> [Queryable ] Received Query";

/// The querier's per-reply marker.
const GET_RECEIVED: &str = ">> Received (";

/// The `z_get -o` deadline, in milliseconds, and the wall-clock the harness
/// allows on top.
///
/// MEASURED, NOT CHOSEN — the R311y840 rule, which applies here in the same
/// shape: zenoh's `z_get` gives every query its own timeout (default 10000ms,
/// `examples/examples/z_get.rs` @ `.timeout(timeout)`), and when it expires the
/// reply channel closes
/// and the process exits with exactly the status a router-terminated query
/// produces. A generous deadline therefore reads "the router answered" and
/// "the router ignored me" as one value. Three seconds is two hundred times a
/// loopback round trip and well under upstream's own default, so an exit at the
/// deadline is a failure of wz rather than a slow success.
const GET_TIMEOUT_MS: &str = "3000";
const GET_WALL_CLOCK: Duration = Duration::from_secs(15);

/// Spawn the wz `--router` (`routing-routes`) on an ephemeral port; returns its
/// guard + stderr reader + the `tcp/...` endpoint the zenoh clients dial.
fn spawn_wz_router() -> (
    wz_integration_tests::common::ChildGuard,
    std::fs::File,
    String,
) {
    let demo = wz_ap_demo_binary();
    // The demo prints the same feature banner whether or not it carries the
    // change under test, so a router built before the target arms landed would
    // read as "wz does not honour QueryTarget" and send the diagnosis somewhere
    // else. R311y774 -> R311y776 spent two rounds on exactly that.
    assert_demo_binary_newer_than_sources(&demo);
    let router_stderr = tempfile::tempfile().expect("tempfile for router stderr");
    let (guard, reader, port) = spawn_on_ephemeral_port(
        &demo,
        &["--router", "127.0.0.1:0"],
        "router: listening on 127.0.0.1:",
        "router",
        router_stderr,
    );
    (guard, reader, format!("tcp/127.0.0.1:{port}"))
}

/// Spawn a real zenoh `z_queryable` as a CLIENT of `endpoint`, returning once it
/// has opened its session and declared. Same retry-on-transient-open-failure
/// shape as the pico spawn helpers, for the same reason: a session that fails to
/// open is a flake, not a finding.
fn spawn_declared_zenoh_queryable(
    z_queryable: &std::path::Path,
    payload: &str,
    complete: bool,
    endpoint: &str,
) -> (wz_integration_tests::common::ChildGuard, std::fs::File) {
    const ATTEMPTS: usize = 6;
    for attempt in 1..=ATTEMPTS {
        let out = tempfile::tempfile().expect("tempfile for z_queryable stdout");
        let out_writer = out.try_clone().expect("dup z_queryable stdout handle");
        let mut out_reader = out;
        let mut cmd = Command::new("stdbuf");
        cmd.args(["-oL", "-eL"]).arg(z_queryable).args([
            "-k",
            QABL_KEY,
            "-p",
            payload,
            "-m",
            "client",
            "-e",
            endpoint,
            "--no-multicast-scouting",
        ]);
        if complete {
            cmd.arg("--complete");
        }
        let mut child = wz_integration_tests::common::ChildGuard::wrap(
            "z_queryable (zenoh)",
            cmd.stderr(Stdio::from(
                out_writer.try_clone().expect("dup stderr handle"),
            ))
            .stdout(Stdio::from(out_writer))
            .spawn()
            .expect("spawn z_queryable via stdbuf"),
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let cap = read_captured(&mut out_reader);
            if cap.contains(QABL_READY) {
                return (child, out_reader);
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = child.child_mut().kill();
        let _ = child.child_mut().wait();
        eprintln!("z_queryable open attempt {attempt}/{ATTEMPTS} did not declare; retrying");
    }
    panic!("zenoh z_queryable failed to declare against the wz --router after {ATTEMPTS} attempts");
}

/// Run one `z_get` leg to completion and return its stdout. `target` is `None`
/// for the WIRE DEFAULT — upstream's own default is `BEST_MATCHING` and passing
/// it explicitly would test a different byte sequence than a plain `z_get`
/// emits, which is exactly the path this file exists to pin.
fn spawn_zget(
    z_get: &std::path::Path,
    endpoint: &str,
    target: Option<&str>,
) -> (wz_integration_tests::common::ChildGuard, std::fs::File) {
    let out = tempfile::tempfile().expect("tempfile for z_get stdout");
    let out_writer = out.try_clone().expect("dup z_get stdout handle");
    let out_reader = out;
    let mut cmd = Command::new("stdbuf");
    cmd.args(["-oL", "-eL"]).arg(z_get).args([
        "-s",
        QUERY_KEY,
        "-o",
        GET_TIMEOUT_MS,
        "-m",
        "client",
        "-e",
        endpoint,
        "--no-multicast-scouting",
    ]);
    if let Some(t) = target {
        cmd.args(["-t", t]);
    }
    let child = wz_integration_tests::common::ChildGuard::wrap(
        "z_get (zenoh)",
        cmd.stderr(Stdio::from(
            out_writer.try_clone().expect("dup stderr handle"),
        ))
        .stdout(Stdio::from(out_writer))
        .spawn()
        .expect("spawn z_get via stdbuf"),
    );
    (child, out_reader)
}

/// Run one `z_get` leg and return its stdout, once it has been answered.
///
/// R2311 (open-debt item 645) — ASKED EXACTLY ONCE, AND THAT IS A DECISION.
/// The generic hazard this routes through [`run_query_until_answered`] is a
/// query that beats the queryable's declaration to the router; here the caller
/// has ALREADY closed that window, by polling the wz router's own stderr until
/// it has logged both queryables before the first leg runs. Retrying on top of
/// that would break the measurement the file exists for: leg 3 asserts the
/// complete queryable was asked EXACTLY three times, so a fourth query — even
/// a well-meant one — is a wrong answer rather than a slow one.
fn run_zget(z_get: &std::path::Path, endpoint: &str, target: Option<&str>) -> String {
    let (mut child, mut reader, _) = run_query_until_answered(
        "zenoh z_get through the wz router",
        QueryAttempts::Once {
            because: "the caller polls the router's own stderr until both \
                      queryables are declared, and leg 3 counts the complete \
                      queryable's queries exactly",
        },
        GET_RECEIVED,
        GET_WALL_CLOCK,
        || spawn_zget(z_get, endpoint, target),
    )
    .unwrap_or_else(|captured| {
        panic!("zenoh z_get was not answered within {GET_WALL_CLOCK:?}; captured:\n{captured}")
    });
    // The legs read the WHOLE reply line (target and payload both), so the
    // capture is taken after the child has finished rather than at the instant
    // the reply marker appeared.
    let deadline = std::time::Instant::now() + GET_WALL_CLOCK;
    loop {
        match child.child_mut().try_wait().expect("try_wait on z_get") {
            Some(_) => break,
            None if std::time::Instant::now() >= deadline => {
                panic!(
                    "zenoh z_get did not finish within {GET_WALL_CLOCK:?}; captured so far:\n{}",
                    read_captured(&mut reader)
                );
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    read_captured(&mut reader)
}

/// How many queries has this queryable been asked, over its whole life so far?
fn queries_seen(reader: &mut std::fs::File) -> usize {
    read_captured(reader).matches(QABL_RECEIVED).count()
}

/// THE CROSS-IMPL HEADLINE. Two real zenoh `z_queryable`s — one `--complete`,
/// one not — sit behind a wz `--router`, and a real zenoh `z_get` queries them
/// three times, once per `QueryTarget`. All three legs come back answered; what
/// separates them is WHO was asked, measured on the incomplete queryable's own
/// stdout.
///
/// The three targets are legs of ONE test rather than three tests because the
/// discriminating quantity is a DIFFERENCE between legs against the same pair of
/// queryables — splitting them would leave each leg asserting an absolute count
/// that a different fixture could produce for a different reason.
// wz-proves: routing-routes wz->zenoh partial
// wz-proves: declare-queryable wz->zenoh partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-routes + zenoh z_queryable/z_get); Layer E5z runs via --ignored"]
fn wz_router_honours_the_query_target_against_real_zenoh_queryables() {
    let z_queryable = zenoh_core_example_binary("z_queryable");
    let z_get = zenoh_core_example_binary("z_get");
    let (mut router, mut router_reader, endpoint) = spawn_wz_router();

    let (mut whole, mut whole_reader) =
        spawn_declared_zenoh_queryable(&z_queryable, COMPLETE_ANSWER, true, &endpoint);
    let (mut partial, mut partial_reader) =
        spawn_declared_zenoh_queryable(&z_queryable, PARTIAL_ANSWER, false, &endpoint);
    // Both declarations have to have REACHED the router before the first query,
    // or leg 1 would be measuring a race rather than a routing decision.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if read_captured(&mut router_reader)
            .matches("queryable")
            .count()
            >= 2
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(500));

    assert_eq!(
        queries_seen(&mut partial_reader),
        0,
        "nothing has been queried yet"
    );

    // ---- LEG 1: the WIRE DEFAULT (BestMatching) ----
    let best = run_zget(&z_get, &endpoint, None);
    assert!(
        best.contains(GET_RECEIVED) && best.contains(COMPLETE_ANSWER),
        "a default-target z_get is answered by the COMPLETE queryable through the wz router; got:\n{best}"
    );
    let partial_after_best = queries_seen(&mut partial_reader);
    assert_eq!(
        partial_after_best,
        0,
        "BestMatching selects the single complete queryable, so the INCOMPLETE one \
         is never asked; its stdout so far:\n{}",
        read_captured(&mut partial_reader)
    );

    // ---- LEG 2: explicit ALL — the control that keeps leg 1 honest ----
    let all = run_zget(&z_get, &endpoint, Some("ALL"));
    assert!(
        all.contains(GET_RECEIVED),
        "an ALL-target z_get is answered too; got:\n{all}"
    );
    let partial_after_all = queries_seen(&mut partial_reader);
    assert_eq!(
        partial_after_all, 1,
        "an EXPLICIT All target reaches the incomplete queryable — which is what \
         makes leg 1's zero a routing decision rather than a broken face"
    );

    // ---- LEG 3: explicit ALL_COMPLETE ----
    let all_complete = run_zget(&z_get, &endpoint, Some("ALL_COMPLETE"));
    assert!(
        all_complete.contains(COMPLETE_ANSWER),
        "an ALL_COMPLETE z_get is answered by the complete queryable; got:\n{all_complete}"
    );
    assert_eq!(
        queries_seen(&mut partial_reader),
        partial_after_all,
        "ALL_COMPLETE filters the incomplete queryable out, so its count does not move"
    );

    // The complete queryable was asked by every one of the three legs — the
    // other half of the count, and what rules out a router that simply stopped
    // routing after leg 1.
    assert_eq!(
        queries_seen(&mut whole_reader),
        3,
        "the complete queryable answered all three targets; its stdout:\n{}",
        read_captured(&mut whole_reader)
    );

    graceful_terminate(partial.child_mut(), Duration::from_secs(5));
    graceful_terminate(whole.child_mut(), Duration::from_secs(5));
    graceful_terminate(router.child_mut(), Duration::from_secs(5));
}
