// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y140 — the FIRST cross-impl test that puts a foreign implementation on
//! wz's ROUTER-TIER link-state wire.
//!
//! Every prior wz <-> zenohd interop leg (`wz_to_zenohd_router.rs`) pairs wz as
//! a CLIENT (wire `WhatAmI::Client`) against the reference router — it exercises
//! the client-egress / peer data path, never the router-distinctive
//! `routers_net` link-state tier. The wz <-> wz federation
//! (`wz_router_hat_mesh.rs`) proves the dual-mesh `RouterForwarder` federates
//! with ITSELF, but a same-impl mesh cannot catch a wire divergence from the
//! canonical implementation. This file closes that gap: a wz `--router-hat`
//! node (the one wz run-mode that presents wire `WhatAmI::Router`) federates
//! with a real `zenohd` v1.5.0 over the `routers_net` link-state protocol —
//! zenoh's `OAM(OAM_LINKSTATE)` -> `LinkStateList` exchange (psid<->zid mapping,
//! sn-newest-wins, full dump on new link) — the true "zenohd-equivalent" acid
//! test for wz's router tier.
//!
//! Five legs, STAGED so a failure localises (topology before data before reverse
//! data before query before future-mode):
//!
//!   1. `wz_router_hat_federates_with_zenohd_at_router_tier` — the CONTROL-PLANE
//!      floor: wz `--router-hat --connect <zenohd>` dials the reference router;
//!      both present `WhatAmI::Router`, so zenohd files wz into its `routers_net`
//!      and each floods the other its `LinkStateList` OAM. TWO witnesses, which
//!      prove DIFFERENT things and are both asserted: `routers-net converged (2
//!      node(s))` proves the transport handshake + Router-tier CLASSIFICATION —
//!      but it fires on `add_link` from the INIT-derived zid+whatami with NO OAM
//!      ingest needed, so on its own it is handshake-satisfiable. The shutdown
//!      `learned mesh topology (ingested N)` witness (emitted only when
//!      `forwarder.ingested() > 0`) proves wz actually DECODED >=1 of zenohd's
//!      `LinkStateList` OAM floods — the cross-impl link-state WIRE-DECODE proof,
//!      and the reason this test exists: a same-impl mesh or a handshake-only
//!      witness could NOT catch a `LinkStateList` codec divergence from canonical
//!      zenoh. Deterministic: zenohd floods its full link-state on the new router
//!      link, which wz ingests before the 250 ms app tick that logs convergence.
//!
//!   2. `wz_router_hat_and_zenohd_federate_pico_data_across_the_backbone` — the
//!      DATA-PLANE acid test: a zenoh-pico `z_pub` (client of ZENOHD) publishes
//!      `demo/key`, and a zenoh-pico `z_sub` (client of the WZ router)
//!      subscribes to `demo/**`. The Put crosses the MIXED-VENDOR router
//!      backbone — pico -> zenohd -> [`routers_net` link-state] -> wz-router ->
//!      pico — so the subscriber behind wz receives data published behind
//!      zenohd. This exercises the whole chain the topology floor cannot: wz
//!      advertising a client subscriber's interest ACROSS the router backbone
//!      into zenohd's routing table, and zenohd routing matching data back over
//!      the cross-impl mesh. Every hop is cross-impl. Transit-pinned on wz's
//!      `forwarded mesh data` (it counts every inbound Push it routes) so a
//!      green receipt cannot be a direct pub<->sub link — the sub dials only wz,
//!      the pub only zenohd.
//!
//!   3. `wz_router_hat_and_zenohd_federate_pico_data_in_reverse` — the REVERSE
//!      data-plane acid test (R311y141): a zenoh-pico `z_pub` (client of the WZ
//!      router) publishes `demo/key`, a zenoh-pico `z_sub` (client of ZENOHD)
//!      subscribes `demo/**`. The Put crosses the backbone the OTHER way — pico
//!      -> wz-router -> [`routers_net` link-state] -> zenohd -> pico — which
//!      needs wz to ANSWER the pico publisher's declare-Interest (the zenoh-1.x
//!      write-filter handshake): without it the publisher's filter drops every
//!      Put LOCALLY. Barrier-gated on wz's `learned a mesh sub` (wz has ingested
//!      zenohd's sub off the mesh) so the CURRENT-mode reply is non-empty —
//!      i.e. the sub-before-pub ordering only (FUTURE-mode pub-first = leg 5).
//!
//!   4. `wz_router_hat_and_zenohd_federate_a_pico_query` — the QUERY-plane acid
//!      test (R311y147; the query twin of leg 3). A zenoh-pico `z_querier` (the
//!      PERSISTENT querier — the only pico CLI that installs a querier
//!      write-filter, unlike one-shot `z_get`) behind the WZ router queries
//!      `demo/key`; a zenoh-pico `z_queryable` behind ZENOHD answers. wz ANSWERS
//!      the querier's declare-Interest with the queryable it learned off the mesh
//!      from zenohd (the y141 qabl interest-dump), deactivating the querier's
//!      write-filter; the Query then routes querier -> wz -> [routers_net] ->
//!      zenohd -> queryable and the Reply returns in reverse — every hop
//!      cross-impl. Barrier-gated on wz's `learned a queryable` (an unscoped
//!      count, but effectively precise here — `demo/**` is the only queryable —
//!      so wz's CURRENT qabl dump answers the querier non-empty; the 30-get burst
//!      absorbs the reverse-route install slack; wz has NO qabl future-push).
//!      Transit-pinned on wz's `routed a query`. The default querier target is
//!      BEST_MATCHING so its filter is NON-complete — this exercises the
//!      intersects deactivation path, NOT the ALL_COMPLETE `complete && includes`
//!      fold (not CLI-drivable; stays unit-proven).
//!
//!   5. `wz_router_hat_pushes_a_future_subscriber_to_a_pico_publisher` — the
//!      FUTURE-mode pub-before-sub acid test (R311y147; the cross-impl closure of
//!      the R311y146 proactive-push work). Same topology as leg 3 (pub behind wz,
//!      sub behind zenohd) but the publisher declares BEFORE any subscriber, so
//!      wz's CURRENT interest dump is empty and the ONLY deactivation path is the
//!      y146 FUTURE push (wz stores the pub's f() interest, then pushes an
//!      unsolicited DeclareSubscriber once zenohd's sub floods across the mesh).
//!      Asserted via the `pushed a future subscriber` witness so the deactivation
//!      is provably the FUTURE push, not a raced CURRENT dump.
//!
//! SCOPE — what this does NOT yet cover (the cross-impl router tier is a large
//! surface; this is the first, deliberately-2-node slice, mirroring how the
//! wz<->wz mesh suite staged its own coverage):
//!   * FORWARD-direction query deferred — leg 4 covers the REVERSE query (querier
//!     behind wz, so wz answers the interest, the distinctive direction). A
//!     FORWARD query (querier behind zenohd, queryable behind wz — zenohd answers
//!     the interest, wz routes an INGRESS query to a local queryable + reply
//!     EGRESS) is the query twin of leg 2 and a re-openable follow-up.
//!   * ALL_COMPLETE querier fold deferred — leg 4's default z_querier is
//!     NON-complete; the `complete && includes` fold is not CLI-drivable (no
//!     target flag) and stays unit-proven.
//!   * qabl future-push + undeclare-push deferred — a queryable learned AFTER a
//!     querier's FUTURE interest (the query-plane analog of leg 5) and a sub/qabl
//!     WITHDRAWAL re-arming the filter are the R311y146 named deferrals, not
//!     covered here.
//!   * peer-tier FUTURE-push observability deferred — leg 5's `future_pushes`
//!     witness is on the ROUTER forwarder only; the peer `LinkstateForwarder`'s
//!     own `push_future_subscription` carries no counter yet (no peer-mode
//!     pub-before-sub e2e exists), a re-openable follow-up when one lands.
//!   * TWO routers on ONE direct face — each router is therefore the SOLE master
//!     of its own domain, so NO multi-hop spanning-tree route / non-master HRW
//!     election / transit-through-a-third-router is exercised (the R311y120
//!     router-native black-hole corner stays UNIT-proven). A 3+-router
//!     mixed-vendor topology where a non-master wz router must bridge is the real
//!     router-distinctive acid test beyond this direct-link slice.
//!   * CLIENT subscribers behind wz only — a router-NATIVE sub behind wz is not
//!     drivable by the OBSERVE-only demo router.
//!
//! These are the carry-forward follow-ups, in rough value order.
//!
//! Opt-in (`#[ignore]`, run-ci Layer Z) AND double binary-dep: needs the
//! external `zenohd` 1.5.0 build (`scripts/build-zenohd.sh`) AND `wz-ap-demo`
//! built with `--features router-hat-router` (the run-mode ACTIVE atom). Neither
//! is a default-sweep artifact, so this never gates the default test run.

use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_answering_zqueryable, spawn_on_ephemeral_port,
    spawn_publishing_zpub, spawn_querying_zquerier, spawn_subscribed_zsub, spawn_zenohd,
    wait_for_substring, wz_ap_demo_binary, zenoh_pico_cli_binary, PortReservation,
};

/// The router-tier convergence witness the wz `--router-hat` node logs once its
/// `routers_net` reaches two nodes (self + the federated peer). Shared by both
/// legs — leg 2 waits on it to gate client attach until the backbone is up.
const ROUTERS_NET_CONVERGED: &str = "router-hat: routers-net converged (2 node(s))";

/// The stderr/stdout tempfile factory the common spawn helpers require (the lib
/// crate cannot depend on the dev-only `tempfile`, so the caller supplies it).
fn tempfile() -> std::fs::File {
    tempfile::tempfile().expect("tempfile for child capture")
}

/// Spawn the wz `--router-hat` node dialing `zenohd_addr`, returned once it logs
/// its listen line (with the OS-assigned ephemeral port). Presents wire
/// `WhatAmI::Router`, so zenohd files it into `routers_net`.
fn spawn_router_hat_dialing(
    zenohd_addr: &str,
) -> (wz_integration_tests::common::ChildGuard, std::fs::File, u16) {
    spawn_on_ephemeral_port(
        &wz_ap_demo_binary(),
        &["--router-hat", "127.0.0.1:0", "--connect", zenohd_addr],
        "router-hat: listening on 127.0.0.1:",
        "wz-router-hat",
        tempfile(),
    )
}

/// Leg 1 — the router-tier topology floor. wz `--router-hat` dials zenohd and
/// converges its `routers_net` to 2, proving the cross-impl link-state exchange.
#[test]
#[ignore = "binary-dep e2e (zenohd + wz-ap-demo --features router-hat-router); run via Layer Z / --ignored"]
fn wz_router_hat_federates_with_zenohd_at_router_tier() {
    let port_res = PortReservation::pick();
    let zport = port_res.port();
    // zenohd defaults to mode=router (zenohd/src/main.rs) — a bare `-l` router.
    let _zenohd = spawn_zenohd(zport, tempfile);
    let zaddr = format!("127.0.0.1:{zport}");

    let (mut wz_guard, mut wz_reader, _wz_port) = spawn_router_hat_dialing(&zaddr);

    // `routers-net converged (2)` proves the transport handshake + Router-tier
    // CLASSIFICATION (it fires on `add_link` from the INIT-derived zid+whatami,
    // no OAM ingest needed) — necessary, but handshake-satisfiable on its own.
    let converged = wait_for_substring(
        &mut wz_reader,
        ROUTERS_NET_CONVERGED,
        Duration::from_secs(15),
    );

    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let wz_captured = read_captured(&mut wz_reader);
    eprintln!("--- wz-router-hat stderr ---\n{wz_captured}");

    converged.unwrap_or_else(|c| {
        panic!(
            "wz-router-hat never converged its router tier to 2 within 15s against \
             the reference zenohd — the two routers did not link at the router \
             tier\n--- wz-router-hat stderr ---\n{c}"
        )
    });
    // The cross-impl WIRE-DECODE proof (the acid test's real point): the shutdown
    // `learned mesh topology (ingested N)` witness is emitted ONLY when wz DECODED
    // >=1 of zenohd's `LinkStateList` OAM floods (`forwarder.ingested() > 0`,
    // runner.rs). Convergence above is handshake-satisfiable; THIS is what a
    // `LinkStateList` codec divergence from canonical zenoh would break. zenohd
    // floods its full link-state on the new router link, so wz ingests it before
    // the 250 ms app tick that logs convergence — deterministic ordering.
    assert!(
        wz_captured.contains("router-hat: learned mesh topology"),
        "wz-router-hat converged its router tier but never ingested a \
         `LinkStateList` OAM from zenohd (no 'learned mesh topology' shutdown \
         witness) — the tiers linked at the transport layer but wz did not DECODE \
         zenohd's routers_net link-state wire\n--- wz-router-hat stderr ---\n{wz_captured}"
    );
}

/// Leg 2 — the data-plane acid test. A pico Put crosses the mixed-vendor router
/// backbone (pico -> zenohd -> linkstate -> wz-router -> pico).
#[test]
#[ignore = "binary-dep e2e (zenohd + zenoh-pico z_pub/z_sub + wz-ap-demo --features router-hat-router); run via Layer Z / --ignored"]
fn wz_router_hat_and_zenohd_federate_pico_data_across_the_backbone() {
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let port_res = PortReservation::pick();
    let zport = port_res.port();
    let _zenohd = spawn_zenohd(zport, tempfile);
    let zaddr = format!("127.0.0.1:{zport}");

    // wz --router-hat dials zenohd; wait for the router backbone to converge
    // BEFORE attaching clients so the link-state mesh is established.
    let (mut wz_guard, mut wz_reader, wz_port) = spawn_router_hat_dialing(&zaddr);
    if wait_for_substring(
        &mut wz_reader,
        ROUTERS_NET_CONVERGED,
        Duration::from_secs(15),
    )
    .is_err()
    {
        let c = read_captured(&mut wz_reader);
        graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
        panic!("wz <-> zenohd router backbone never converged within 15s\n--- wz-router-hat stderr ---\n{c}");
    }

    // z_sub: a pico CLIENT of the WZ router, subscribing to demo/**. wz learns
    // the client sub and advertises its interest ACROSS the router backbone into
    // zenohd's routing table (the cross-tier client-subscriber advertise).
    let wz_endpoint = format!("tcp/127.0.0.1:{wz_port}");
    let (mut z_sub_guard, mut z_sub_reader) =
        spawn_subscribed_zsub(&z_sub, "demo/**", &wz_endpoint, "wz-router-hat", tempfile);

    // Gate the publish on wz DISPATCHING the cross-tier client-sub advertise (its
    // interest flooding toward zenohd; `client_subs_seen > 0` synchronously calls
    // advertise_client_cross_tier_sub). zenohd's route INSTALL completes shortly
    // after — dispatched != installed — so the 30-Put burst below absorbs that
    // residual gap rather than this gate guaranteeing it.
    let advertised = wait_for_substring(
        &mut wz_reader,
        "router-hat: learned a client sub",
        Duration::from_secs(10),
    );

    // z_pub: a pico CLIENT of ZENOHD, publishing demo/key as a 30-Put burst
    // (~30s, one Put/s), so delivery is self-healing across the route install.
    // pico's `-e` needs a SCHEME'd locator (`tcp/...`), unlike wz's `--connect`
    // which also accepts the bare `HOST:PORT` in `zaddr`.
    let z_pub_endpoint = format!("tcp/127.0.0.1:{zport}");
    let z_pub_guard = advertised.is_ok().then(|| {
        spawn_publishing_zpub(
            &z_pub,
            "demo/key",
            "router-tier-federation",
            &z_pub_endpoint,
            "zenohd",
            tempfile,
        )
    });

    // The acid test: the pico Put reaches the pico subscriber behind wz, having
    // crossed the cross-impl router backbone.
    let received = wait_for_substring(
        &mut z_sub_reader,
        "Received ('demo/key'",
        Duration::from_secs(15),
    );
    // Transit pin: wz forwarded the cross-backbone Push (it counts every inbound
    // Push it routes). By the time `received` fired the Put has transited wz, so
    // this line is already logged; wait a short window for it to flush.
    let transit = received.is_ok().then(|| {
        wait_for_substring(
            &mut wz_reader,
            "router-hat: forwarded mesh data",
            Duration::from_secs(5),
        )
    });

    if let Some(mut c) = z_pub_guard {
        let _ = c.child_mut().kill();
        let _ = c.child_mut().wait();
    }
    let _ = z_sub_guard.child_mut().kill();
    let _ = z_sub_guard.child_mut().wait();
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let wz_captured = read_captured(&mut wz_reader);
    let z_sub_captured = read_captured(&mut z_sub_reader);
    eprintln!("--- wz-router-hat stderr ---\n{wz_captured}");
    eprintln!("--- z_sub stdout ---\n{z_sub_captured}");

    advertised.unwrap_or_else(|c| {
        panic!(
            "wz-router-hat never advertised the client subscriber into the router \
             backbone within 10s — the cross-tier client-sub advertise did not \
             fire\n--- wz-router-hat stderr ---\n{c}"
        )
    });
    received.unwrap_or_else(|c| {
        panic!(
            "pico z_sub behind wz-router never received the Put published behind \
             zenohd within 15s — data did not cross the cross-impl router \
             backbone\n--- z_sub stdout ---\n{c}"
        )
    });
    // `transit` is Some(_) iff `received` was Ok (asserted just above), so the
    // inner Result is the transit witness.
    transit
        .expect("received implies transit was probed")
        .unwrap_or_else(|c| {
            panic!(
                "wz-router-hat never logged 'forwarded mesh data' — the pico Put \
                 reached the subscriber without transiting wz's router, so the \
                 delivery did not exercise the cross-backbone route\n--- \
                 wz-router-hat stderr ---\n{c}"
            )
        });
}

/// Leg 3 — the REVERSE data-plane acid test (the capstone of the R311y141
/// interest-handshake work). A pico Put crosses the mixed-vendor backbone in the
/// OPPOSITE direction to leg 2: pub-behind-WZ -> wz-router -> [`routers_net`
/// link-state] -> zenohd -> sub-behind-ZENOHD. This exercises what leg 2 could
/// not: wz ANSWERING a pico publisher's declare-`Interest` (the zenoh-1.x
/// write-filter handshake) with the remote subscription it learned from zenohd.
/// Without that answer a pico publisher's write-filter never deactivates and it
/// drops every Put LOCALLY (the reverse-data black-hole this round fixes) — so the
/// puts never even reach wz's wire.
///
/// Gated on wz's `learned a mesh sub` witness — wz has INGESTED zenohd's
/// subscriber off the router mesh, so it can answer the publisher's interest
/// NON-empty. This barrier (NOT leg 2's `learned a client sub`, of which there is
/// none in the reverse case) is what makes the leg deterministic: a Put burst
/// cannot rescue an already-active write filter (it emits zero wire traffic), so
/// the publisher must not spawn until wz provably holds the remote sub.
#[test]
#[ignore = "binary-dep e2e (zenohd + zenoh-pico z_pub/z_sub + wz-ap-demo --features router-hat-router); run via Layer Z / --ignored"]
fn wz_router_hat_and_zenohd_federate_pico_data_in_reverse() {
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let port_res = PortReservation::pick();
    let zport = port_res.port();
    let _zenohd = spawn_zenohd(zport, tempfile);
    let zaddr = format!("127.0.0.1:{zport}");

    // wz --router-hat dials zenohd; wait for the router backbone to converge
    // BEFORE attaching clients so the link-state mesh is established.
    let (mut wz_guard, mut wz_reader, wz_port) = spawn_router_hat_dialing(&zaddr);
    if wait_for_substring(
        &mut wz_reader,
        ROUTERS_NET_CONVERGED,
        Duration::from_secs(15),
    )
    .is_err()
    {
        let c = read_captured(&mut wz_reader);
        graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
        panic!("wz <-> zenohd router backbone never converged within 15s\n--- wz-router-hat stderr ---\n{c}");
    }

    // z_sub: a pico CLIENT of ZENOHD, subscribing demo/**. zenohd propagates the
    // sub across the router backbone into wz's routers_net (the direction leg 2's
    // wz->zenohd advertise proved works; here it is zenohd->wz).
    let z_sub_endpoint = format!("tcp/127.0.0.1:{zport}");
    let (mut z_sub_guard, mut z_sub_reader) =
        spawn_subscribed_zsub(&z_sub, "demo/**", &z_sub_endpoint, "zenohd", tempfile);

    // Barrier: wz has INGESTED zenohd's sub off the mesh, so it can now answer a
    // publisher's write-filter interest with a matching DeclareSubscriber.
    let learned = wait_for_substring(
        &mut wz_reader,
        "router-hat: learned a mesh sub",
        Duration::from_secs(10),
    );

    // z_pub: a pico CLIENT of WZ, publishing demo/key. Its write-filter interest is
    // answered by wz (the R311y141 fix), so it puts the 30-Put burst on the wire;
    // wz routes it across the backbone to zenohd, which delivers to z_sub.
    let z_pub_endpoint = format!("tcp/127.0.0.1:{wz_port}");
    let z_pub_guard = learned.is_ok().then(|| {
        spawn_publishing_zpub(
            &z_pub,
            "demo/key",
            "reverse-federation",
            &z_pub_endpoint,
            "wz-router-hat",
            tempfile,
        )
    });

    // The acid test: the pico Put published behind wz reaches the pico subscriber
    // behind zenohd, having crossed the cross-impl router backbone in REVERSE.
    let received = wait_for_substring(
        &mut z_sub_reader,
        "Received ('demo/key'",
        Duration::from_secs(15),
    );
    // Transit pin: wz forwarded the cross-backbone Push (it counts every inbound
    // Push it routes) — so the delivery genuinely transited wz, not a direct link.
    let transit = received.is_ok().then(|| {
        wait_for_substring(
            &mut wz_reader,
            "router-hat: forwarded mesh data",
            Duration::from_secs(5),
        )
    });

    if let Some(mut c) = z_pub_guard {
        let _ = c.child_mut().kill();
        let _ = c.child_mut().wait();
    }
    let _ = z_sub_guard.child_mut().kill();
    let _ = z_sub_guard.child_mut().wait();
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let wz_captured = read_captured(&mut wz_reader);
    let z_sub_captured = read_captured(&mut z_sub_reader);
    eprintln!("--- wz-router-hat stderr ---\n{wz_captured}");
    eprintln!("--- z_sub stdout ---\n{z_sub_captured}");

    learned.unwrap_or_else(|c| {
        panic!(
            "wz-router-hat never INGESTED zenohd's subscriber off the mesh within \
             10s (no 'learned a mesh sub') — the sub did not propagate across the \
             router backbone\n--- wz-router-hat stderr ---\n{c}"
        )
    });
    received.unwrap_or_else(|c| {
        panic!(
            "pico z_sub behind zenohd never received the Put published behind wz \
             within 15s — reverse data did not cross the cross-impl router backbone \
             (the publisher's write-filter never deactivated?)\n--- z_sub stdout \
             ---\n{c}"
        )
    });
    transit
        .expect("received implies transit was probed")
        .unwrap_or_else(|c| {
            panic!(
                "wz-router-hat never logged 'forwarded mesh data' — the Put reached \
                 the subscriber without transiting wz's router\n--- wz-router-hat \
                 stderr ---\n{c}"
            )
        });
}

/// Leg 4 — the QUERY-plane acid test (R311y147), the query twin of leg 3. A pico
/// `z_querier` (client of the WZ router) queries `demo/key`; a pico `z_queryable`
/// (client of ZENOHD) answers. The Query crosses the mixed-vendor backbone
/// querier -> wz-router -> [`routers_net` link-state] -> zenohd -> queryable and
/// the Reply returns in reverse. Uses the PERSISTENT `z_querier` (not one-shot
/// `z_get`, which installs no write-filter) so wz must ANSWER the querier's
/// declare-Interest with the queryable it learned off the mesh from zenohd (the
/// y141 qabl interest-dump) before the querier's write-filter deactivates — the
/// query-plane analog of leg 3's publisher handshake.
///
/// Gated on wz's `learned a queryable` witness — wz has INGESTED zenohd's
/// queryable off the routers_net. `queryables_seen()` is an unscoped count, but in
/// this 2-node topology `demo/**` is the ONLY queryable that ever exists, so the
/// barrier is effectively precise: by the time the querier spawns, wz's CURRENT
/// qabl dump (`dump_interest_qabls`) answers its declare-Interest non-empty and
/// deactivates the write-filter. Note wz has NO qabl future-push — it stores a
/// FUTURE interest only for subscribers (`su()`); a querier's `qa()` interest is
/// CURRENT-only, so the query-plane analog of leg 5's push is a named deferral,
/// NOT a safety net here. The `-n 30 -t 3000` get burst absorbs the residual
/// dispatched-!=-installed slack on the reverse route into zenohd. The primary
/// proof — the reply crossing the backbone (+ transit `routed a query` + the
/// foreign `Received Query`) — is independent of the deactivation timing.
#[test]
#[ignore = "binary-dep e2e (zenohd + zenoh-pico z_querier/z_queryable + wz-ap-demo --features router-hat-router); run via Layer Z / --ignored"]
fn wz_router_hat_and_zenohd_federate_a_pico_query() {
    let z_querier = zenoh_pico_cli_binary("z_querier");
    let z_queryable = zenoh_pico_cli_binary("z_queryable");
    let port_res = PortReservation::pick();
    let zport = port_res.port();
    let _zenohd = spawn_zenohd(zport, tempfile);
    let zaddr = format!("127.0.0.1:{zport}");

    // wz --router-hat dials zenohd; wait for the router backbone to converge
    // BEFORE attaching clients so the link-state mesh is established.
    let (mut wz_guard, mut wz_reader, wz_port) = spawn_router_hat_dialing(&zaddr);
    if wait_for_substring(
        &mut wz_reader,
        ROUTERS_NET_CONVERGED,
        Duration::from_secs(15),
    )
    .is_err()
    {
        let c = read_captured(&mut wz_reader);
        graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
        panic!("wz <-> zenohd router backbone never converged within 15s\n--- wz-router-hat stderr ---\n{c}");
    }

    // z_queryable: a pico CLIENT of ZENOHD, answering demo/**. zenohd floods the
    // queryable across the router backbone into wz's router_qabls (the query-plane
    // analog of the subscriber flood leg 3 relies on).
    let z_qabl_endpoint = format!("tcp/127.0.0.1:{zport}");
    let (mut z_qabl_guard, mut z_qabl_reader) = spawn_answering_zqueryable(
        &z_queryable,
        "demo/**",
        "query-federation",
        &z_qabl_endpoint,
        "zenohd",
        tempfile,
    );

    // Barrier: wz has INGESTED zenohd's queryable off the mesh, so it can answer a
    // querier's write-filter interest with a matching DeclareQueryable.
    let learned = wait_for_substring(
        &mut wz_reader,
        "router-hat: learned a queryable",
        Duration::from_secs(10),
    );

    // z_querier: a pico CLIENT of WZ, querying demo/key as a 30-get burst. Its
    // write-filter interest is answered by wz (the y141/y146 qabl handshake), so
    // it puts the get on the wire; wz routes it across the backbone to zenohd,
    // which dispatches to z_queryable; the reply returns the same path in reverse.
    let q_endpoint = format!("tcp/127.0.0.1:{wz_port}");
    let mut z_querier_pair = learned.is_ok().then(|| {
        spawn_querying_zquerier(
            &z_querier,
            "demo/key",
            &q_endpoint,
            "wz-router-hat",
            tempfile,
        )
    });

    // The acid test: the reply from z_queryable behind zenohd reaches the pico
    // querier behind wz, having crossed the cross-impl router backbone.
    let received = z_querier_pair.as_mut().map(|(_, reader)| {
        wait_for_substring(reader, ">> Received ('demo/key'", Duration::from_secs(20))
    });
    // Transit pin: the Query transited wz's router (`queries_seen` rose). By the
    // time `received` fired the Query has transited, so wait a short window for
    // the log to flush. `queries_seen` counts inbound Request(Query) only, so this
    // is unsatisfiable by a mere interest/declare round-trip.
    let transit = matches!(&received, Some(Ok(_))).then(|| {
        wait_for_substring(
            &mut wz_reader,
            "router-hat: routed a query",
            Duration::from_secs(5),
        )
    });

    let z_querier_captured = if let Some((mut child, mut reader)) = z_querier_pair {
        let _ = child.child_mut().kill();
        let _ = child.child_mut().wait();
        read_captured(&mut reader)
    } else {
        String::new()
    };
    let _ = z_qabl_guard.child_mut().kill();
    let _ = z_qabl_guard.child_mut().wait();
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let wz_captured = read_captured(&mut wz_reader);
    let z_qabl_captured = read_captured(&mut z_qabl_reader);
    eprintln!("--- wz-router-hat stderr ---\n{wz_captured}");
    eprintln!("--- z_querier stdout ---\n{z_querier_captured}");
    eprintln!("--- z_queryable stdout ---\n{z_qabl_captured}");

    learned.unwrap_or_else(|c| {
        panic!(
            "wz-router-hat never INGESTED zenohd's queryable off the mesh within \
             10s (no 'learned a queryable') — the queryable did not propagate \
             across the router backbone\n--- wz-router-hat stderr ---\n{c}"
        )
    });
    received
        .expect("learned implies the querier was spawned")
        .unwrap_or_else(|c| {
            panic!(
                "pico z_querier behind wz never received a reply to demo/key within \
                 20s — the query/reply did not complete over the cross-impl router \
                 backbone (the querier's write-filter never deactivated, the query \
                 was not routed to the queryable, or the reply was lost on the \
                 return path — the z_queryable stdout above shows which)\n--- \
                 z_querier stdout ---\n{c}"
            )
        });
    transit
        .expect("received implies transit was probed")
        .unwrap_or_else(|c| {
            panic!(
                "wz-router-hat never logged 'routed a query' — the reply reached the \
                 querier without a Query transiting wz's router\n--- wz-router-hat \
                 stderr ---\n{c}"
            )
        });
    // Foreign-side proof: the query reached the REAL cross-impl answerer, not a
    // wz-local synthesised reply (wz hosts no local queryable in this test).
    assert!(
        z_qabl_captured.contains("[Queryable handler] Received Query"),
        "z_queryable behind zenohd never logged 'Received Query' — the reply \
         z_querier saw did not originate at the real cross-impl answerer\n--- \
         z_queryable stdout ---\n{z_qabl_captured}"
    );
}

/// Leg 5 — FUTURE-mode pub-before-sub (R311y147), the cross-impl closure of the
/// R311y146 proactive subscriber push. Same topology as leg 3 (pub behind wz, sub
/// behind zenohd) but the publisher declares BEFORE any subscriber exists, so
/// wz's CURRENT interest dump is empty and the ONLY way the publisher's
/// write-filter deactivates is the y146 FUTURE push: wz stores the publisher's
/// `f()` interest, then — when zenohd's subscriber later floods across the mesh —
/// proactively pushes an unsolicited `DeclareSubscriber` to the publisher's face.
///
/// Asserted via the `pushed a future subscriber` witness so the deactivation is
/// provably the FUTURE push, not a raced CURRENT dump (both are otherwise silent
/// — `push_future_subscription` and the CURRENT interest reply log nothing on
/// success). The publisher spawns FIRST with NO barrier (a barrier would destroy
/// the pub-before-sub ordering that IS the discriminator); its `-n 30` burst is
/// self-healing across the push, so puts dropped while the filter was active are
/// followed by puts that flow once it deactivates.
#[test]
#[ignore = "binary-dep e2e (zenohd + zenoh-pico z_pub/z_sub + wz-ap-demo --features router-hat-router); run via Layer Z / --ignored"]
fn wz_router_hat_pushes_a_future_subscriber_to_a_pico_publisher() {
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let port_res = PortReservation::pick();
    let zport = port_res.port();
    let _zenohd = spawn_zenohd(zport, tempfile);
    let zaddr = format!("127.0.0.1:{zport}");

    // wz --router-hat dials zenohd; wait for the router backbone to converge
    // BEFORE attaching clients so the link-state mesh is established.
    let (mut wz_guard, mut wz_reader, wz_port) = spawn_router_hat_dialing(&zaddr);
    if wait_for_substring(
        &mut wz_reader,
        ROUTERS_NET_CONVERGED,
        Duration::from_secs(15),
    )
    .is_err()
    {
        let c = read_captured(&mut wz_reader);
        graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
        panic!("wz <-> zenohd router backbone never converged within 15s\n--- wz-router-hat stderr ---\n{c}");
    }

    // z_pub: a pico CLIENT of WZ, publishing demo/key — spawned FIRST, with NO
    // matching subscriber anywhere. Its write-filter is ACTIVE, so its early puts
    // drop LOCALLY; wz stores its f() interest (an empty CURRENT dump). The helper
    // returns once z_pub is looping ("Putting Data" prints regardless of the
    // filter dropping the put) — so the publisher's declare-Interest is on the wire
    // before the sub is spawned. That wz actually STORED it is proven downstream by
    // the `pushed a future subscriber` witness, which can only fire from a stored
    // future interest.
    let z_pub_endpoint = format!("tcp/127.0.0.1:{wz_port}");
    let mut z_pub_guard = spawn_publishing_zpub(
        &z_pub,
        "demo/key",
        "future-mode-federation",
        &z_pub_endpoint,
        "wz-router-hat",
        tempfile,
    );

    // z_sub: a pico CLIENT of ZENOHD, subscribing demo/** — spawned SECOND. zenohd
    // floods it across the router backbone to wz, which PUSHES an unsolicited
    // DeclareSubscriber to z_pub's stored future interest (y146), deactivating the
    // publisher's write-filter so its remaining burst flows.
    let z_sub_endpoint = format!("tcp/127.0.0.1:{zport}");
    let (mut z_sub_guard, mut z_sub_reader) =
        spawn_subscribed_zsub(&z_sub, "demo/**", &z_sub_endpoint, "zenohd", tempfile);

    // FUTURE-push proof: wz proactively pushed the subscriber to the publisher's
    // face — the ONLY deactivation path given the pub-before-sub ordering.
    let pushed = wait_for_substring(
        &mut wz_reader,
        "router-hat: pushed a future subscriber",
        Duration::from_secs(20),
    );

    // The acid test: the Put published behind wz reaches the subscriber behind
    // zenohd — which can only happen after the future push deactivated the pub.
    let received = wait_for_substring(
        &mut z_sub_reader,
        "Received ('demo/key'",
        Duration::from_secs(20),
    );
    let transit = received.is_ok().then(|| {
        wait_for_substring(
            &mut wz_reader,
            "router-hat: forwarded mesh data",
            Duration::from_secs(5),
        )
    });

    let _ = z_pub_guard.child_mut().kill();
    let _ = z_pub_guard.child_mut().wait();
    let _ = z_sub_guard.child_mut().kill();
    let _ = z_sub_guard.child_mut().wait();
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let wz_captured = read_captured(&mut wz_reader);
    let z_sub_captured = read_captured(&mut z_sub_reader);
    eprintln!("--- wz-router-hat stderr ---\n{wz_captured}");
    eprintln!("--- z_sub stdout ---\n{z_sub_captured}");

    pushed.unwrap_or_else(|c| {
        panic!(
            "wz-router-hat never PUSHED a future subscriber within 20s (no 'pushed \
             a future subscriber') — the y146 proactive push did not fire, so a \
             pub-before-sub publisher's write-filter would never deactivate\n--- \
             wz-router-hat stderr ---\n{c}"
        )
    });
    received.unwrap_or_else(|c| {
        panic!(
            "pico z_sub behind zenohd never received the Put published behind wz \
             within 20s — the FUTURE-mode pub-before-sub data did not cross the \
             backbone (the future push did not deactivate the publisher?)\n--- \
             z_sub stdout ---\n{c}"
        )
    });
    transit
        .expect("received implies transit was probed")
        .unwrap_or_else(|c| {
            panic!(
                "wz-router-hat never logged 'forwarded mesh data' — the Put reached \
                 the subscriber without transiting wz's router\n--- wz-router-hat \
                 stderr ---\n{c}"
            )
        });
}
