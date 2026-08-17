// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.15 routing — CROSS-IMPL validation of the wz `--router` data-plane
//! FORWARDING (`routing-routes`) against real zenoh-pico clients.
//!
//! `wz_router_forward.rs` proves `routing-routes` end to end, but with THREE wz
//! processes (router + wz consumer + wz producer) — SAME-impl, so it cannot
//! witness a foreign implementation (a wz<->wz e2e is not a cross-impl proof).
//! These tests replace BOTH endpoints with the embedded C stack: real pico
//! `z_pub` / `z_put` publish, the wz `--router` FORWARDS across faces, and a real
//! pico `z_sub` receives. Neither pico client knows the other's address (a STAR
//! through the wz router), so the pico subscriber firing is a definitive witness
//! that the wz ROUTER forwarded the sample between two foreign faces — the
//! `routing-routes` data-plane atom's cross-impl proof.
//!
//! Three facets, one per test:
//!
//!   1. `..._pub_to_pico_sub` — a pico `z_pub` (which declares a PUBLISHER, so
//!      pico installs an interest-based WRITE FILTER, `net/filtering.c`) publishes
//!      SUB-FIRST. The publisher's filter starts ACTIVE and drops every put
//!      locally until it receives a matching `DeclareSubscriber`; the wz router's
//!      RouteTable answers the publisher's CURRENT `Interest` with the
//!      subscription held on the sub's face (R311y373), releasing the filter.
//!      Before that fix a real pico publisher never interoperated with the wz
//!      `--router` at all (the router forwarded 0 — the RED this test surfaced).
//!
//!   2. `..._put_to_pico_sub` — a pico `z_put` (one-shot; declares a keyexpr RID
//!      then puts, NO publisher, so NO write filter) exercises the ALIASED
//!      forward path: the router records the `DeclareKeyexpr`, resolves the
//!      aliased Put through it, and re-literalizes it for the foreign subscriber.
//!
//!   3. `..._pub_before_sub` — the FUTURE half of the write-filter release: a
//!      pico `z_pub` publishes PUB-FIRST (its CURRENT interest finds no
//!      subscriber, so only a Final is returned and the filter stays ACTIVE);
//!      when the pico `z_sub` joins LATER the router PUSHES the new subscription
//!      to the waiting publisher face, releasing the filter mid-burst.
//!
//! Discriminator (binds to `routing-routes`, NOT the shared accept foundation):
//! a `wz-ap-demo` built with `routing-router` ALONE (no `routing-routes`) uses
//! the `NoOpForwarder` — it accepts and holds both pico faces but forwards
//! NOTHING and answers no interest, so the pico subscriber never fires and the
//! router's shutdown summary carries no `forwarded` clause. Only
//! `--features routing-routes` (`RoutingForwarder`) forwards, so a green receive
//! here is load-bearing on the forwarding atom, not on the `routing-router`
//! hold-only foundation both builds share.
//!
//! Requires: `wz-ap-demo` built with `--features routing-routes` AND the
//! zenoh-pico CLI (`scripts/build-zenoh-pico-cli.sh` -> `target/zenoh-pico-cli/`).
//! run-ci's Layer E5 builds the demo with the feature and SKIPs the pico leg if
//! the CLI is absent; the tests run on the `--ignored` lane like the other
//! binary-dep e2es. The `wz_router_` fn prefix keeps the default Layer E sweep's
//! `--skip wz_router` from running them against an arbitrary-feature binary.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, graceful_terminate, read_captured,
    spawn_on_ephemeral_port, spawn_publishing_zpub, spawn_subscribed_zsub, wait_for_substring,
    wz_ap_demo_binary, zenoh_pico_cli_binary,
};

/// The literal keyexpr the pico clients agree on — distinct per test so parallel
/// Layer E runs never cross-match.
const KEY_PUB: &str = "demo/pico-route-fwd";
const KEY_PUT: &str = "demo/pico-route-put";
const KEY_FUTURE: &str = "demo/pico-route-future";
/// A unique payload so the received line pins THIS producer's sample crossing the
/// router (a bare "Received" could be a stale artifact).
const VALUE_PUB: &str = "hello-pico-pub-via-wz-router";
const VALUE_PUT: &str = "hello-pico-put-via-wz-router";
const VALUE_FUTURE: &str = "hello-pico-future-via-wz-router";

/// The subscriber-side receive marker the pico `z_sub` prints per sample.
const RECEIVED: &str = ">> [Subscriber] Received";

/// Spawn the wz `--router` (`routing-routes`) on an ephemeral port; returns its
/// guard + stderr reader + the `tcp/...` endpoint the pico clients dial.
fn spawn_wz_router() -> (
    wz_integration_tests::common::ChildGuard,
    std::fs::File,
    String,
) {
    let demo = wz_ap_demo_binary();
    // R311y840 — every fixture in this file spawns THIS binary and every one of
    // them can be misled by a stale copy: the demo prints the same feature
    // banner whether or not it carries the change under test, so a router built
    // before the query plane landed would read as "the query plane does not
    // work" and send the diagnosis somewhere else. That is not hypothetical
    // (R311y774 -> R311y776 spent two rounds on exactly it), and it is sharpest
    // for the query legs below, whose whole subject is a code path the older
    // binary does not have.
    assert_demo_binary_newer_than_sources(&demo);
    let router_stderr = tempfile::tempfile().expect("tempfile for router stderr");
    let (guard, reader, port) = spawn_on_ephemeral_port(
        &demo,
        &["--router", "127.0.0.1:0"],
        "router: listening on 127.0.0.1:",
        "router",
        router_stderr,
    );
    let endpoint = format!("tcp/127.0.0.1:{port}");
    (guard, reader, endpoint)
}

/// Assert the routed sample carries BOTH the agreed keyexpr and the unique
/// payload — a green "Received" alone could be stale, but the unique value pins
/// THIS producer's sample crossing the wz router to the pico subscriber.
fn assert_routed(received_text: &str, key: &str, value: &str) {
    assert!(
        received_text.contains(key),
        "the pico subscriber received a sample, but not on the agreed keyexpr '{key}'\n--- \
         pico z_sub stdout ---\n{received_text}"
    );
    assert!(
        received_text.contains(value),
        "the pico subscriber received a sample, but not the producer's payload '{value}' — the \
         forwarded key/value did not match\n--- pico z_sub stdout ---\n{received_text}"
    );
}

/// Assert the wz router's OWN forward counter rose — the Put transited THROUGH
/// the router's `RoutingForwarder`, not around it. `forwarded 0 sample(s)` would
/// mean the pico sub fired off a path the star topology forbids; a
/// `routing-router`-only (`NoOpForwarder`) build emits no `forwarded` clause at
/// all (the discriminator).
fn assert_router_forwarded(router_stderr: &str) {
    assert!(
        router_stderr.contains("forwarded ") && !router_stderr.contains("forwarded 0 sample"),
        "the wz router summary must report a non-zero forward count — the routing-routes \
         RoutingForwarder did not carry the pico sample across faces\n--- router stderr ---\n{router_stderr}"
    );
}

/// pico `z_pub` -> wz `--router` (`routing-routes`) -> pico `z_sub`, SUB-FIRST:
/// the wz router answers the pico publisher's CURRENT write-filter Interest with
/// the matching subscription, releasing the filter, then forwards the Put across
/// faces to the foreign subscriber — the §5.15 forwarding atom's interest-driven
/// cross-impl (foreign<->foreign) data-plane proof.
// wz-proves: routing-routes wz->pico partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-routes + zenoh-pico z_pub/z_sub); Layer E5 runs via --ignored"]
fn wz_router_routes_pico_pub_to_pico_sub() {
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let (mut r_guard, mut r_reader, endpoint) = spawn_wz_router();

    // pico z_sub: a CLIENT of the wz router, subscribed and ready. Its declared
    // subscription is the route the router advertises back to the publisher's
    // interest and uses to forward the pico producer's Put.
    let (mut z_sub_child, mut z_sub_reader) =
        spawn_subscribed_zsub(&z_sub, KEY_PUB, &endpoint, "the wz --router", || {
            tempfile::tempfile().expect("tempfile for z_sub stdout")
        });

    // Ordering barrier (not a race): the sub's link reached Established on the
    // router (face 0 — the sub connected first). Its DeclareSubscriber is recorded
    // on the router's next poll; the publisher's CURRENT interest below then finds
    // it, releasing the write filter, and the burst covers the residual window.
    let face0 = wait_for_substring(&mut r_reader, "face 0 UP", Duration::from_secs(10));

    // pico z_pub: declares a PUBLISHER (installs the write filter) then bursts on
    // the same keyexpr. Its filter releases only once the router answers its
    // interest with the sub above; each subsequent Put is then forwarded.
    let mut pub_child = spawn_publishing_zpub(
        &z_pub,
        KEY_PUB,
        VALUE_PUB,
        &endpoint,
        "the wz --router",
        || tempfile::tempfile().expect("tempfile for z_pub stdout"),
    );

    let received = wait_for_substring(&mut z_sub_reader, RECEIVED, Duration::from_secs(15));

    let _ = pub_child.child_mut().kill();
    let _ = pub_child.child_mut().wait();
    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    graceful_terminate(r_guard.child_mut(), Duration::from_secs(5));

    let r_captured = read_captured(&mut r_reader);
    let z_sub_captured = read_captured(&mut z_sub_reader);
    eprintln!("--- wz router stderr ---\n{r_captured}");
    eprintln!("--- pico z_sub stdout ---\n{z_sub_captured}");

    face0.unwrap_or_else(|c| {
        panic!("wz router never logged 'face 0 UP' within 10s — the pico subscriber's link did not reach Established on the router\n--- router stderr ---\n{c}")
    });
    let received_text = received.unwrap_or_else(|c| {
        panic!(
            "pico z_sub never logged '{RECEIVED}' within 15s — the pico PUBLISHER's Put did not \
             route through the wz --router to the foreign pico subscriber (the write filter never \
             released?)\n--- pico z_sub stdout ---\n{c}\n--- wz router stderr ---\n{r_captured}"
        )
    });
    assert_routed(&received_text, KEY_PUB, VALUE_PUB);
    assert_router_forwarded(&r_captured);
}

/// pico `z_put` -> wz `--router` (`routing-routes`) -> pico `z_sub`: a one-shot
/// `z_put` (declares a keyexpr RID then puts an ALIASED Put, NO publisher so NO
/// write filter) exercises the router's aliased-forward path — it records the
/// `DeclareKeyexpr`, resolves the aliased Put through it, and re-literalizes it
/// for the foreign subscriber.
// wz-proves: routing-routes wz->pico partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-routes + zenoh-pico z_put/z_sub); Layer E5 runs via --ignored"]
fn wz_router_routes_pico_put_to_pico_sub() {
    let z_put = zenoh_pico_cli_binary("z_put");
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let (mut r_guard, mut r_reader, endpoint) = spawn_wz_router();

    let (mut z_sub_child, mut z_sub_reader) =
        spawn_subscribed_zsub(&z_sub, KEY_PUT, &endpoint, "the wz --router", || {
            tempfile::tempfile().expect("tempfile for z_sub stdout")
        });

    // Barrier: the sub's face is Established (face 0). Its DeclareSubscriber is
    // recorded before z_put — which is one-shot with NO burst — even connects: the
    // sub declared on open (before this barrier released) and z_put's own session
    // handshake latency covers the router's single poll to record the route (15x
    // reliability check clean).
    let face0 = wait_for_substring(&mut r_reader, "face 0 UP", Duration::from_secs(10));

    // pico z_put: one-shot literal-value Put via a declared keyexpr RID. Spawned
    // directly (no burst helper): open -> declare keyexpr -> put -> exit.
    let put_stdout = tempfile::tempfile().expect("tempfile for z_put stdout");
    let mut put_child = Command::new("stdbuf")
        .args(["-oL", "-eL"])
        .arg(&z_put)
        .args([
            "-k", KEY_PUT, "-v", VALUE_PUT, "-e", &endpoint, "-m", "client",
        ])
        .stdout(Stdio::from(
            put_stdout.try_clone().expect("dup stdout handle"),
        ))
        .stderr(Stdio::from(
            put_stdout.try_clone().expect("dup stderr handle"),
        ))
        .spawn()
        .expect("spawn z_put via stdbuf");

    let received = wait_for_substring(&mut z_sub_reader, RECEIVED, Duration::from_secs(15));

    let _ = put_child.kill();
    let _ = put_child.wait();
    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    graceful_terminate(r_guard.child_mut(), Duration::from_secs(5));

    let r_captured = read_captured(&mut r_reader);
    let z_sub_captured = read_captured(&mut z_sub_reader);
    eprintln!("--- wz router stderr ---\n{r_captured}");
    eprintln!("--- pico z_sub stdout ---\n{z_sub_captured}");

    face0.unwrap_or_else(|c| {
        panic!("wz router never logged 'face 0 UP' within 10s — the pico subscriber's link did not reach Established on the router\n--- router stderr ---\n{c}")
    });
    let received_text = received.unwrap_or_else(|c| {
        panic!(
            "pico z_sub never logged '{RECEIVED}' within 15s — the pico z_put's aliased Put did \
             not route through the wz --router to the foreign pico subscriber\n--- pico z_sub \
             stdout ---\n{c}\n--- wz router stderr ---\n{r_captured}"
        )
    });
    assert_routed(&received_text, KEY_PUT, VALUE_PUT);
    assert_router_forwarded(&r_captured);
}

/// pico `z_pub` -> wz `--router` (`routing-routes`) -> pico `z_sub`, PUB-FIRST:
/// the FUTURE half of the write-filter release. The publisher declares first, its
/// CURRENT interest finds no subscriber (only a Final is returned, the filter
/// stays ACTIVE), then the pico subscriber joins LATER — the router PUSHES the new
/// subscription to the waiting publisher face, releasing the filter, and the
/// remaining burst forwards to the foreign subscriber.
// wz-proves: routing-routes wz->pico partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-routes + zenoh-pico z_pub/z_sub); Layer E5 runs via --ignored"]
fn wz_router_routes_pico_pub_before_sub() {
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let (mut r_guard, mut r_reader, endpoint) = spawn_wz_router();

    // pico z_pub FIRST: declares a publisher (write filter ACTIVE) and begins
    // putting into the void — no subscriber exists yet, so the router returns only
    // a Final to its CURRENT interest and the filter drops these early puts.
    let mut pub_child = spawn_publishing_zpub(
        &z_pub,
        KEY_FUTURE,
        VALUE_FUTURE,
        &endpoint,
        "the wz --router",
        || tempfile::tempfile().expect("tempfile for z_pub stdout"),
    );

    // Barrier: the publisher's face is Established (face 0 — it connected first),
    // so its FUTURE interest is registered on the router before the sub joins.
    let face0 = wait_for_substring(&mut r_reader, "face 0 UP", Duration::from_secs(10));

    // pico z_sub joins LATER: the router pushes this new subscription to the
    // waiting publisher face (the FUTURE interest), releasing its write filter so
    // the remaining burst forwards.
    let (mut z_sub_child, mut z_sub_reader) =
        spawn_subscribed_zsub(&z_sub, KEY_FUTURE, &endpoint, "the wz --router", || {
            tempfile::tempfile().expect("tempfile for z_sub stdout")
        });

    let received = wait_for_substring(&mut z_sub_reader, RECEIVED, Duration::from_secs(20));

    let _ = pub_child.child_mut().kill();
    let _ = pub_child.child_mut().wait();
    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();
    graceful_terminate(r_guard.child_mut(), Duration::from_secs(5));

    let r_captured = read_captured(&mut r_reader);
    let z_sub_captured = read_captured(&mut z_sub_reader);
    eprintln!("--- wz router stderr ---\n{r_captured}");
    eprintln!("--- pico z_sub stdout ---\n{z_sub_captured}");

    face0.unwrap_or_else(|c| {
        panic!("wz router never logged 'face 0 UP' within 10s — the pico publisher's link did not reach Established on the router\n--- router stderr ---\n{c}")
    });
    let received_text = received.unwrap_or_else(|c| {
        panic!(
            "pico z_sub never logged '{RECEIVED}' within 20s — the router did not PUSH the later \
             subscription to the waiting pico publisher (the FUTURE interest never fired?)\n--- \
             pico z_sub stdout ---\n{c}\n--- wz router stderr ---\n{r_captured}"
        )
    });
    assert_routed(&received_text, KEY_FUTURE, VALUE_FUTURE);
    assert_router_forwarded(&r_captured);
}

// ─── R311y840 — the QUERY plane, cross-impl ─────────────────────────────
//
// The three legs above are the PUSH plane. Until this round a wz `--router`
// carried Push and nothing else, so a real `z_get` through one reached no
// queryable and — worse — got no `ResponseFinal` either, which is not a slow
// answer but a permanent hang: pico's `z_get` blocks on a condvar the reply
// DROPPER signals (`examples/unix/c11/z_get.c:101`), and the dropper runs when
// the query is finalized. Both legs below therefore have a hang as their
// failure mode rather than a wrong value, which is why each carries its own
// bounded `wait_for_substring` deadline.

/// The keyexpr / value the query legs agree on — distinct from the Push legs'
/// so a parallel Layer E run never cross-matches.
const KEY_QUERY: &str = "demo/pico-route-query";
const VALUE_QUERY: &str = "hello-pico-reply-via-wz-router";
/// A keyexpr NO queryable is declared on, for the empty-route leg.
const KEY_QUERY_UNMATCHED: &str = "demo/pico-route-query-nobody";

/// pico `z_get`'s per-reply marker and its terminator.
const GET_RECEIVED: &str = ">> Received PUT";
const GET_FINAL: &str = ">> Received query final notification";
/// How long the final may take before it stops being evidence about wz.
///
/// MEASURED, NOT CHOSEN. pico gives every `z_get` its OWN deadline —
/// `Z_GET_TIMEOUT_DEFAULT 10000` (`include/zenoh-pico/config.h.in:208`) — and
/// when it expires pico drops the pending query itself, which runs the reply
/// dropper and prints the SAME `GET_FINAL` line. So "the final appeared inside
/// 15s" is true whether the router closed the query or ignored it entirely, and
/// the first version of the empty-route leg below passed under a probe that
/// deleted the whole query plane. A router-sent final is a round trip over
/// loopback (milliseconds); pico's self-timeout is ten seconds. Five seconds
/// separates them with a factor of two of margin on the side that matters.
const GET_FINAL_BUDGET: Duration = Duration::from_secs(5);
/// pico `z_queryable`'s ready marker and its per-query marker.
const QABL_READY: &str = "Creating Queryable on";
const QABL_RECEIVED: &str = ">> [Queryable handler] Received Query";

/// Spawn a zenoh-pico `z_queryable` as a CLIENT of `endpoint`, returning once it
/// has opened its session and declared the queryable. Same retry-on-transient-
/// open-failure shape as `common::spawn_subscribed_zsub`, and for the same
/// reason: a session that fails to open is a flake, not a finding, and a fixture
/// that cannot tell them apart reports the wrong one.
fn spawn_declared_zqueryable(
    z_queryable: &std::path::Path,
    key: &str,
    value: &str,
    endpoint: &str,
) -> (wz_integration_tests::common::ChildGuard, std::fs::File) {
    const ATTEMPTS: usize = 6;
    for attempt in 1..=ATTEMPTS {
        let out = tempfile::tempfile().expect("tempfile for z_queryable stdout");
        let out_writer = out.try_clone().expect("dup z_queryable stdout handle");
        let mut out_reader = out;
        let mut child = wz_integration_tests::common::ChildGuard::wrap(
            "z_queryable (zenoh-pico)",
            Command::new("stdbuf")
                .args(["-oL", "-eL"])
                .arg(z_queryable)
                .args(["-k", key, "-v", value, "-e", endpoint, "-m", "client"])
                .stderr(Stdio::from(
                    out_writer.try_clone().expect("dup stderr handle"),
                ))
                .stdout(Stdio::from(out_writer))
                .spawn()
                .expect("spawn z_queryable via stdbuf"),
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        loop {
            let cap = read_captured(&mut out_reader);
            if cap.contains(QABL_READY) {
                return (child, out_reader);
            }
            if cap.contains("Unable to open session") || std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = child.child_mut().kill();
        let _ = child.child_mut().wait();
        eprintln!("z_queryable open attempt {attempt}/{ATTEMPTS} did not declare; retrying");
    }
    panic!("pico z_queryable failed to declare against the wz --router after {ATTEMPTS} attempts");
}

/// Spawn a zenoh-pico `z_get` as a CLIENT of `endpoint`. Returns as soon as the
/// process is up — unlike the queryable there is nothing to wait FOR, since the
/// query is the first thing it does and the whole point is what comes back.
fn spawn_zget(
    z_get: &std::path::Path,
    key: &str,
    endpoint: &str,
) -> (wz_integration_tests::common::ChildGuard, std::fs::File) {
    let out = tempfile::tempfile().expect("tempfile for z_get stdout");
    let out_writer = out.try_clone().expect("dup z_get stdout handle");
    let child = wz_integration_tests::common::ChildGuard::wrap(
        "z_get (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(z_get)
            .args(["-k", key, "-e", endpoint, "-m", "client"])
            .stderr(Stdio::from(
                out_writer.try_clone().expect("dup stderr handle"),
            ))
            .stdout(Stdio::from(out_writer))
            .spawn()
            .expect("spawn z_get via stdbuf"),
    );
    (child, out)
}

/// THE CROSS-IMPL HEADLINE. A real pico `z_get` reaches a real pico
/// `z_queryable` THROUGH a wz `--router`, and its reply comes back — two foreign
/// endpoints that cannot hear each other, joined only by wz. This is the query
/// half of what "wz replaces zenohd" has to mean, and before R311y840 it was
/// impossible: the router had no `Request` arm, so the query was dropped and the
/// pico querier blocked on its condvar until the harness killed it.
// wz-proves: routing-routes wz->pico partial
// wz-proves: declare-queryable wz->pico partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-routes + zenoh-pico z_get/z_queryable); Layer E5 runs via --ignored"]
fn wz_router_routes_a_pico_get_to_a_pico_queryable() {
    let z_get = zenoh_pico_cli_binary("z_get");
    let z_queryable = zenoh_pico_cli_binary("z_queryable");
    let (mut r_guard, mut r_reader, endpoint) = spawn_wz_router();

    let (mut qabl_child, mut qabl_reader) =
        spawn_declared_zqueryable(&z_queryable, KEY_QUERY, VALUE_QUERY, &endpoint);

    // Ordering barrier, not a race: the queryable's link is Established on the
    // router (face 0 — it connected first), so its DeclareQueryable is recorded
    // before the querier below exists. Without this the query can legitimately
    // find an empty route and be finalized at once, which is the OTHER leg's
    // subject and would pass this one for the wrong reason.
    let face0 = wait_for_substring(&mut r_reader, "face 0 UP", Duration::from_secs(10));

    let query_sent = std::time::Instant::now();
    let (mut get_child, mut get_reader) = spawn_zget(&z_get, KEY_QUERY, &endpoint);

    let received = wait_for_substring(&mut get_reader, GET_RECEIVED, Duration::from_secs(15));
    let finalized = wait_for_substring(&mut get_reader, GET_FINAL, GET_FINAL_BUDGET);
    let final_after = query_sent.elapsed();

    let _ = get_child.child_mut().kill();
    let _ = get_child.child_mut().wait();
    let _ = qabl_child.child_mut().kill();
    let _ = qabl_child.child_mut().wait();
    graceful_terminate(r_guard.child_mut(), Duration::from_secs(5));

    let r_captured = read_captured(&mut r_reader);
    let qabl_captured = read_captured(&mut qabl_reader);
    eprintln!("--- wz router stderr ---\n{r_captured}");
    eprintln!("--- pico z_queryable stdout ---\n{qabl_captured}");

    face0.unwrap_or_else(|c| {
        panic!(
            "wz router never logged 'face 0 UP' within 10s — the pico queryable's link did not \
             reach Established on the router\n--- router stderr ---\n{c}"
        )
    });
    assert!(
        qabl_captured.contains(QABL_RECEIVED),
        "the pico QUERYABLE never logged '{QABL_RECEIVED}' — the wz router did not carry the \
         foreign query across faces\n--- pico z_queryable stdout ---\n{qabl_captured}\n--- router \
         stderr ---\n{r_captured}"
    );
    let received_text = received.unwrap_or_else(|c| {
        panic!(
            "pico z_get never logged '{GET_RECEIVED}' within 15s — the foreign queryable's REPLY \
             did not come back through the wz router\n--- pico z_get stdout ---\n{c}\n--- pico \
             z_queryable stdout ---\n{qabl_captured}\n--- router stderr ---\n{r_captured}"
        )
    });
    assert!(
        received_text.contains(KEY_QUERY) && received_text.contains(VALUE_QUERY),
        "the pico querier received a reply, but not '{KEY_QUERY}' = '{VALUE_QUERY}' — the routed \
         reply's keyexpr or payload did not survive the relay\n--- pico z_get stdout \
         ---\n{received_text}"
    );
    finalized.unwrap_or_else(|c| {
        panic!(
            "pico z_get received its reply but never logged '{GET_FINAL}' within \
             {GET_FINAL_BUDGET:?} — the wz router did not close the query, and pico's z_get blocks \
             on its condvar until the reply dropper runs, so what follows is pico's own 10s \
             self-timeout rather than an answer\n--- pico z_get stdout ---\n{c}\n--- router \
             stderr ---\n{r_captured}"
        )
    });
    eprintln!("router-sent final arrived {final_after:?} after the query was sent");
}

/// The empty-route leg, and the one that makes the hang concrete. A real pico
/// `z_get` on a keyexpr NO queryable covers must still be CLOSED by the router —
/// zenoh's `route_query` sends the `ResponseFinal` itself when the route is
/// empty. Silence here is not "no answers"; it is a client that never returns.
// wz-proves: routing-routes wz->pico partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-routes + zenoh-pico z_get); Layer E5 runs via --ignored"]
fn wz_router_finalizes_a_pico_get_that_matches_no_queryable() {
    let z_get = zenoh_pico_cli_binary("z_get");
    let (mut r_guard, mut r_reader, endpoint) = spawn_wz_router();

    let query_sent = std::time::Instant::now();
    let (mut get_child, mut get_reader) = spawn_zget(&z_get, KEY_QUERY_UNMATCHED, &endpoint);

    // BOUNDED BY `GET_FINAL_BUDGET`, NOT BY PATIENCE. pico closes its own query
    // at ten seconds and prints the identical line, so a generous deadline here
    // makes the leg pass whether or not wz did anything — measured: the first
    // version of this test used 15s and stayed GREEN under the probe that
    // deletes `route_query` outright.
    let finalized = wait_for_substring(&mut get_reader, GET_FINAL, GET_FINAL_BUDGET);
    let final_after = query_sent.elapsed();
    let get_captured = read_captured(&mut get_reader);

    let _ = get_child.child_mut().kill();
    let _ = get_child.child_mut().wait();
    graceful_terminate(r_guard.child_mut(), Duration::from_secs(5));

    let r_captured = read_captured(&mut r_reader);
    eprintln!("--- wz router stderr ---\n{r_captured}");

    finalized.unwrap_or_else(|c| {
        panic!(
            "pico z_get on an unmatched keyexpr never logged '{GET_FINAL}' within \
             {GET_FINAL_BUDGET:?} — the wz router dropped the query instead of finalizing it, so \
             the client is left waiting out its own 10s timeout rather than being told there are \
             no queryables\n--- pico z_get stdout ---\n{c}\n--- router stderr ---\n{r_captured}"
        )
    });
    eprintln!("router-sent empty-route final arrived {final_after:?} after the query was sent");
    assert!(
        !get_captured.contains(GET_RECEIVED),
        "the querier was closed, but it also received a REPLY on a keyexpr no queryable was \
         declared on\n--- pico z_get stdout ---\n{get_captured}"
    );
}
