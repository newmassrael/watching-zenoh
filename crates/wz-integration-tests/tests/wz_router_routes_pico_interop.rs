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
    graceful_terminate, read_captured, spawn_on_ephemeral_port, spawn_publishing_zpub,
    spawn_subscribed_zsub, wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary,
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
        .stdout(Stdio::from(put_stdout))
        .stderr(Stdio::null())
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
