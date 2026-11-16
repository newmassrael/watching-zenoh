// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311qc/qd — router data-plane FORWARDING e2e: `wz-ap-demo --router` (built
//! with `--features routing-routes`) forwards a Put received on one peer face to
//! another peer face that declared a matching subscriber — the `routing-routes`
//! catalog atom on top of the `routing-router` accept-and-hold foundation.
//!
//! Topology: one `--router` + a `--key` consumer + a `--publish` producer, all
//! distinct processes (no co-located loopback). The consumer declares a routed
//! subscriber on `demo/route-fwd`; the producer publishes a Put on the same
//! keyexpr. Neither peer can hear the other directly (they each hold a single
//! link to the router); the consumer firing its subscriber callback is therefore
//! a definitive witness that the ROUTER forwarded the Put across faces — a
//! property the `routing-router` hold-only foundation (which routes nothing)
//! cannot produce. The router's shutdown summary independently reports
//! `forwarded N sample(s)` with `N >= 1`.
//!
//! Two scenarios share one orchestration ([`run_router_forward_e2e`]):
//!  - literal: the producer publishes a literal-keyexpr Put (forwarded verbatim);
//!  - aliased (R311qd): the producer `--declare-id 9` sends a DeclareKeyexpr then
//!    an id-only Put, which the router RE-LITERALIZES for the literal subscriber
//!    (the destination never saw the producer's expr-id mapping).
//!
//! A third leg runs the QUERY plane through the same router with wz on every
//! side (`wz_router_routes_a_wz_query_to_a_wz_queryable_on_another_face`).
//!
//! Requires the binary built with `--features routing-routes` (the forwarding
//! router; `--features routing-router` alone holds faces but routes nothing, so
//! the consumer would never fire). run-ci's Layer E5 builds it with the feature
//! and runs these on the `--ignored` lane.

use std::fs::File;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, run_query_until_answered, wait_for_substring,
    wz_ap_demo_binary, ChildGuard, PortReservation, QueryAttempts,
};

/// The keyexpr both peers agree on — distinct from the other router e2e's
/// `demo/router-test` so parallel Layer E runs never cross-match.
const KEYEXPR: &str = "demo/route-fwd";

/// Drive the producer -> router -> consumer forwarding scenario and assert the
/// core witnesses (consumer SUBSCRIBER FIRED on the agreed keyexpr + full
/// payload, router forwarded >= 1). `producer_extra` is appended to the
/// producer's args so a caller can opt into the DeclareKeyexpr-aliased publish
/// (`--declare-id N`). Returns the captured (router, consumer, producer) stderr
/// for any scenario-specific assertion the caller adds.
fn run_router_forward_e2e(producer_extra: &[&str]) -> (String, String, String) {
    let demo = wz_ap_demo_binary();
    let (mut router_guard, mut router_reader, addr) = spawn_router(&demo);

    // ── consumer: declare a routed subscriber and idle. The router records the
    //    subscription only when its own poll of this face yields the Declare
    //    frame — asynchronous to the consumer logging "DECLARED" — so we do NOT
    //    rely on a strict declare-before-publish ordering. What guarantees the
    //    overlap is the producer's 5-Put / 200ms burst (tasks.rs): even if the
    //    first Put loses the race to the route being recorded, a later one wins,
    //    and one forwarded Put satisfies the witnesses below. ──
    let consumer_stderr = tempfile::tempfile().expect("tempfile for consumer stderr");
    let consumer_writer = consumer_stderr
        .try_clone()
        .expect("dup consumer stderr handle");
    let mut consumer_reader = consumer_stderr;
    let mut consumer_guard = ChildGuard::wrap(
        "wz-ap-demo consumer (--key)",
        Command::new(&demo)
            .arg("--connect")
            .arg(&addr)
            .arg("--key")
            .arg(KEYEXPR)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(consumer_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect --key"),
    );

    // The consumer reached the router (face 0) and declared its subscriber; the
    // router has held face 0 and (on its next poll) recorded the route.
    let declared = wait_for_substring(
        &mut consumer_reader,
        "DECLARED ROUTED SUBSCRIBER",
        Duration::from_secs(5),
    );
    let face0 = wait_for_substring(&mut router_reader, "face 0 UP", Duration::from_secs(10));

    // ── producer: publish a Put on the same keyexpr (a finite burst), plus any
    //    scenario-specific args (e.g. --declare-id for the aliased path). ──
    let producer_stderr = tempfile::tempfile().expect("tempfile for producer stderr");
    let producer_writer = producer_stderr
        .try_clone()
        .expect("dup producer stderr handle");
    let mut producer_reader = producer_stderr;
    let mut producer_guard = ChildGuard::wrap(
        "wz-ap-demo producer (--publish)",
        Command::new(&demo)
            .arg("--connect")
            .arg(&addr)
            .arg("--publish")
            .arg(KEYEXPR)
            .arg("--value")
            .arg("forwarded-payload")
            .args(producer_extra)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(producer_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect --publish"),
    );

    let emitted = wait_for_substring(
        &mut producer_reader,
        "PUBLISHER EMITTED",
        Duration::from_secs(10),
    );

    // The witness: the consumer's subscriber callback fired, which can only
    // happen if the router forwarded the producer's Put across faces.
    let fired = wait_for_substring(
        &mut consumer_reader,
        "SUBSCRIBER FIRED",
        Duration::from_secs(10),
    );

    // Graceful shutdown the router → it logs its accept-loop + forward summary.
    graceful_terminate(router_guard.child_mut(), Duration::from_secs(5));
    let router_captured = read_captured(&mut router_reader);

    // Reap the peers (the router shutdown closed their sockets).
    let _ = producer_guard.child_mut().kill();
    let _ = producer_guard.child_mut().wait();
    let _ = consumer_guard.child_mut().kill();
    let _ = consumer_guard.child_mut().wait();

    let consumer_captured = read_captured(&mut consumer_reader);
    let producer_captured = read_captured(&mut producer_reader);
    eprintln!("--- router stderr ---\n{router_captured}");
    eprintln!("--- consumer stderr ---\n{consumer_captured}");
    eprintln!("--- producer stderr ---\n{producer_captured}");

    // Diagnostics first (surface captured output on any failure), then assert.
    declared.unwrap_or_else(|c| {
        panic!("consumer did not log 'DECLARED ROUTED SUBSCRIBER' within 5s\n--- consumer ---\n{c}\n--- router ---\n{router_captured}")
    });
    face0.unwrap_or_else(|c| {
        panic!("router did not log 'face 0 UP' within 10s\n--- router ---\n{c}")
    });
    emitted.unwrap_or_else(|c| {
        panic!("producer did not log 'PUBLISHER EMITTED' within 10s\n--- producer ---\n{c}\n--- router ---\n{router_captured}")
    });
    let fired_log = fired.unwrap_or_else(|c| {
        panic!(
            "consumer never fired its subscriber within 10s — the router did NOT forward \
             the Put across faces\n--- consumer ---\n{c}\n--- router ---\n{router_captured}"
        )
    });

    // The fired sample must carry the agreed keyexpr (not some stray match)
    // AND the full payload — "forwarded-payload" is 17 bytes, so a forward that
    // dropped or truncated the body would fail here even though the keyexpr
    // matched (the verbatim-clone payload-survival witness the unit suite, which
    // routes on keyexpr alone, cannot give).
    assert!(
        fired_log.contains(&format!("keyexpr='{KEYEXPR}'")),
        "consumer fired on the wrong keyexpr (expected {KEYEXPR})\n--- consumer ---\n{fired_log}"
    );
    assert!(
        fired_log.contains("payload_len=17"),
        "the forwarded sample must preserve the full 17-byte payload\n--- consumer ---\n{fired_log}"
    );

    // The router's own summary independently confirms it forwarded at least one
    // sample (a non-zero count — `forwarded 0 sample(s)` would mean the consumer
    // fired off a path other than the router, which the topology forbids).
    // R2886 — `--router` is the router hat, whose summary counts the pushes the
    // router took in (open-debt item 827 records that its label says
    // "forwarded"); the delivery at the consumer above is what proves transit.
    assert!(
        router_captured.contains("data push(es) forwarded")
            && !router_captured.contains(" 0 data push(es) forwarded"),
        "router summary must report a non-zero push count\n--- router stderr ---\n{router_captured}"
    );

    (router_captured, consumer_captured, producer_captured)
}

/// Spawn `wz-ap-demo --router` (bind once, hold faces, forward with
/// `routing-routes`) on a reserved loopback port, and return once it listens:
/// its guard, its stderr capture and the address the peers dial.
fn spawn_router(demo: &Path) -> (ChildGuard, File, String) {
    let port_res = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", port_res.port());

    let router_stderr = tempfile::tempfile().expect("tempfile for router stderr");
    let router_writer = router_stderr.try_clone().expect("dup router stderr handle");
    let mut router_reader = router_stderr;
    let mut router_guard = ChildGuard::wrap(
        "wz-ap-demo router (--router, routing-routes)",
        Command::new(demo)
            .arg("--router")
            .arg(&addr)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(router_writer))
            .spawn()
            .expect("spawn wz-ap-demo --router"),
    );

    let bound = wait_for_substring(
        &mut router_reader,
        "router-hat: listening on",
        Duration::from_secs(5),
    );
    if let Err(captured) = &bound {
        let _ = router_guard.child_mut().kill();
        let _ = router_guard.child_mut().wait();
        panic!(
            "wz-ap-demo --router did not log 'listening on' within 5s (is the binary \
             built with --features routing-routes?)\n--- router stderr ---\n{captured}"
        );
    }
    // Router bound — release the port-alloc mutex for parallel Layer E tests.
    drop(port_res);
    (router_guard, router_reader, addr)
}

/// The keyexpr a querier asks and the pattern the queryable answers, distinct
/// from `KEYEXPR` so the query leg cannot be answered by the Push legs'
/// processes.
const QUERY_KEYEXPR: &str = "demo/route-q/x";
const QUERYABLE_PATTERN: &str = "demo/route-q/**";
/// The queryable's reply, checked byte for byte at the querier.
const QUERY_REPLY: &str = "answered-across-the-router";
/// How many one-shot queries the declaration-propagation window may eat: the
/// router records the queryable's declaration on its own poll of that face, so
/// a query can still find an empty route after the queryable logged its
/// declaration. A query that misses is finalized at once and retried.
const QUERY_ATTEMPTS: usize = 6;

/// The QUERY plane through the same router, with wz on every side: a wz querier
/// and a wz queryable that each hold one link to the router, so the reply can
/// only reach the querier if the router carried the query to the queryable's
/// face and the reply back. The foreign-pair legs (pico, zenoh) are stronger
/// witnesses, and they SKIP where their oracle is not installed; this one needs
/// nothing but the demo, so a build without either oracle still runs the query
/// plane end to end.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-routes); Layer E5 runs via --ignored"]
fn wz_router_routes_a_wz_query_to_a_wz_queryable_on_another_face() {
    let demo = wz_ap_demo_binary();
    let (mut router_guard, mut router_reader, addr) = spawn_router(&demo);

    let qabl_stderr = tempfile::tempfile().expect("tempfile for queryable stderr");
    let qabl_writer = qabl_stderr
        .try_clone()
        .expect("dup queryable stderr handle");
    let mut qabl_reader = qabl_stderr;
    let mut qabl_guard = ChildGuard::wrap(
        "wz-ap-demo queryable (--queryable)",
        Command::new(&demo)
            .arg("--connect")
            .arg(&addr)
            .arg("--queryable")
            .arg(QUERYABLE_PATTERN)
            .arg("--reply")
            .arg(QUERY_REPLY)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(qabl_writer))
            .spawn()
            .expect("spawn wz-ap-demo --connect --queryable"),
    );
    let declared = wait_for_substring(
        &mut qabl_reader,
        "DECLARED ROUTED QUERYABLE",
        Duration::from_secs(10),
    );
    let face0 = wait_for_substring(&mut router_reader, "face 0 UP", Duration::from_secs(10));

    let spawn_querier = || {
        let out = tempfile::tempfile().expect("tempfile for querier stderr");
        let writer = out.try_clone().expect("dup querier stderr handle");
        let guard = ChildGuard::wrap(
            "wz-ap-demo querier (--query)",
            Command::new(&demo)
                .arg("--connect")
                .arg(&addr)
                .arg("--query")
                .arg(QUERY_KEYEXPR)
                .arg("--on-query-reply-log")
                .arg("--on-query-final-log")
                .env("RUST_LOG", "info")
                .stdout(Stdio::null())
                .stderr(Stdio::from(writer))
                .spawn()
                .expect("spawn wz-ap-demo --connect --query"),
        );
        (guard, out)
    };
    let answered = run_query_until_answered(
        "wz querier through the wz router",
        QueryAttempts::UpTo(QUERY_ATTEMPTS),
        "REPLY RECEIVED",
        Duration::from_secs(15),
        spawn_querier,
    );
    let (mut querier, finalized) = match answered {
        Ok((guard, mut reader, _)) => {
            let finalized =
                wait_for_substring(&mut reader, "FINAL RECEIVED", Duration::from_secs(5));
            (Some(guard), finalized)
        }
        Err(captured) => (None, Err(captured)),
    };

    if let Some(guard) = querier.as_mut() {
        let _ = guard.child_mut().kill();
        let _ = guard.child_mut().wait();
    }
    let _ = qabl_guard.child_mut().kill();
    let _ = qabl_guard.child_mut().wait();
    graceful_terminate(router_guard.child_mut(), Duration::from_secs(5));
    let router_captured = read_captured(&mut router_reader);
    let qabl_captured = read_captured(&mut qabl_reader);
    eprintln!("--- router stderr ---\n{router_captured}");
    eprintln!("--- queryable stderr ---\n{qabl_captured}");

    declared.unwrap_or_else(|c| {
        panic!("the queryable did not log 'DECLARED ROUTED QUERYABLE' within 10s\n--- queryable ---\n{c}")
    });
    face0.unwrap_or_else(|c| {
        panic!("router did not log 'face 0 UP' within 10s\n--- router ---\n{c}")
    });
    assert!(
        qabl_captured.contains(&format!("QUERYABLE FIRED pattern='{QUERYABLE_PATTERN}'"))
            && qabl_captured.contains(&format!("keyexpr='{QUERY_KEYEXPR}'")),
        "the queryable never fired for {QUERY_KEYEXPR} — the router did not carry the \
         query to the queryable's face\n--- queryable ---\n{qabl_captured}\n--- router \
         ---\n{router_captured}"
    );
    let final_log = finalized.unwrap_or_else(|c| {
        panic!(
            "the querier saw no reply in {QUERY_ATTEMPTS} attempts, or no final within 5s of \
             it — the reply did not come back across the router, or the query was not \
             closed\n--- querier ---\n{c}\n--- queryable ---\n{qabl_captured}\n--- router \
             ---\n{router_captured}"
        )
    });
    let reply_line = final_log
        .lines()
        .find(|line| line.contains("REPLY RECEIVED"))
        .unwrap_or_default();
    assert!(
        reply_line.contains(&format!("keyexpr='{QUERY_KEYEXPR}'"))
            && reply_line.contains(&format!("payload=\"{QUERY_REPLY}\"")),
        "the querier's reply must carry the asked key and the queryable's value\n\
         --- querier ---\n{final_log}"
    );
}

/// Literal-keyexpr forwarding: the producer publishes a literal Put, the router
/// forwards it verbatim to the matching subscriber.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-routes); Layer E5 runs via --ignored"]
fn wz_router_forwards_put_to_a_matching_subscriber_on_another_face() {
    let _ = run_router_forward_e2e(&[]);
}

/// Aliased-keyexpr forwarding (R311qd): the producer `--declare-id 9` sends a
/// DeclareKeyexpr then an id-only Put; the router resolves the alias and
/// RE-LITERALIZES the Put for the literal subscriber (which never saw the
/// producer's mapping). The consumer firing is the proof the re-literalization
/// produced a frame the destination could decode.
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-routes); Layer E5 runs via --ignored"]
fn wz_router_re_literalizes_an_aliased_put_for_a_literal_subscriber() {
    let (_router, _consumer, producer) = run_router_forward_e2e(&["--declare-id", "9"]);
    // Confirm the producer actually exercised the DeclareKeyexpr-aliased path
    // (otherwise this would silently degenerate into the literal scenario).
    assert!(
        producer.contains("PUBLISHER DECLARED") && producer.contains("mapping_id=9"),
        "producer must have sent the DeclareKeyexpr alias (id=9)\n--- producer ---\n{producer}"
    );
}
