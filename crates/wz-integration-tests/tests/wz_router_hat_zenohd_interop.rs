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
//! Nine legs, STAGED so a failure localises (topology before data before reverse
//! data before query before future-mode before forward-query before future-query
//! before undeclare-re-arm before liveliness-token lifecycle):
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
//!   6. `wz_router_hat_and_zenohd_federate_a_pico_query_across_the_backbone` — the FORWARD
//!      QUERY-plane acid test (R311y149; the query twin of leg 2, OPPOSITE to leg
//!      4). A pico `z_queryable` behind the WZ router answers `demo/**`; a pico
//!      `z_querier` behind ZENOHD queries `demo/key`. wz ADVERTISES its client
//!      queryable across the routers_net (`advertise_client_cross_tier_qabl`) so
//!      zenohd routes the querier's Query toward wz; wz routes that INGRESS Query
//!      to its client queryable and the Reply EGRESS back — query-INGRESS /
//!      reply-EGRESS, the mirror of leg 4's query-EGRESS / reply-INGRESS.
//!      Barrier-gated on `learned a queryable` (an unscoped count; here it fires
//!      on wz's OWN client qabl, whose ingest synchronously dispatches the
//!      cross-tier advertise — the `-n 30 -t 3000` burst absorbs any imprecision);
//!      transit-pinned on `routed a query`.
//!
//!   7. `wz_router_hat_pushes_a_future_queryable_to_a_pico_querier` — the
//!      FUTURE-mode querier-before-queryable acid test (R311y156; the QUERY-plane
//!      twin of leg 5, cross-impl closure of the R311y150 proactive qabl push).
//!      Same topology as leg 4 (querier behind wz, queryable behind zenohd) but the
//!      QUERIER declares BEFORE any queryable, so wz's CURRENT dump is empty and the
//!      ONLY deactivation path is the y150 FUTURE push (wz stores the querier's f()
//!      queryable interest, then pushes an unsolicited DeclareQueryable once zenohd's
//!      queryable floods across the mesh). Asserted via the `pushed a future
//!      queryable` witness so the deactivation is provably the FUTURE push, not a
//!      raced CURRENT dump.
//!
//!   8. `wz_router_hat_undeclare_re_arms_a_pico_queriers_write_filter` — the
//!      UNDECLARE-RE-ARM acid test (R311y156; the QUERY-plane closure of R311y151).
//!      Same setup as leg 7 but the pico `z_querier` runs with `-a` (a matching
//!      listener), so its OWN write-filter state is a POSITIVE observable: "Querier
//!      has matching queryable." on the future-push deactivation, then — the acid
//!      test — "Querier has NO MORE matching queryables." after the queryable is
//!      KILLED and wz's y151 undeclare_push_qabls re-arms the filter cross-impl.
//!
//!   9. `wz_router_hat_token_lifecycle_reaches_a_pico_liveliness_subscriber` — the
//!      LIVELINESS-TOKEN lifecycle acid test (§5.21 routing-token-tables,
//!      R311y170-175; the token twin of legs 7 & 8 FOLDED into one subscriber
//!      lifecycle). A pico `z_sub_liveliness` (client of wz, FUTURE-only) is spawned
//!      before a pico `z_liveliness` (client of zenohd) declares a token; zenohd
//!      floods it over routers_net (a sourced full-flood, NOT interest-gated, the
//!      same mechanism as subs/qabls) and wz PROACTIVELY pushes it to the
//!      subscriber's stored future interest (slice-4 push_future_token) — proven the
//!      FUTURE push by the `pushed a future token` witness. The subscriber prints
//!      "New alive token"; then z_liveliness is KILLED and its socket close makes
//!      zenohd flood an UndeclareToken that wz undeclare_push_token's to the
//!      subscriber ("Dropped token", the slice-5 reconcile-notify closure). One
//!      test because the same subscriber prints both observables (no `-a`-style flag
//!      change is needed, unlike leg 8). Needs wz-ap-demo built with
//!      `routing-token-tables` (the Layer Z build opts in).
//!
//! SCOPE — what this does NOT yet cover (the cross-impl router tier is a large
//! surface; this is the first, deliberately-2-node slice, mirroring how the
//! wz<->wz mesh suite staged its own coverage):
//!   * ALL_COMPLETE querier fold deferred — legs 4 & 6's default z_querier is
//!     NON-complete; the `complete && includes` fold is not CLI-drivable (no
//!     target flag) and stays unit-proven.
//!   * qabl future-push + undeclare-re-arm CLOSED by legs 7 & 8 (R311y156) — a
//!     queryable learned AFTER a querier's FUTURE interest pushes an unsolicited
//!     DeclareQueryable (leg 7, the `pushed a future queryable` witness), and a
//!     queryable WITHDRAWAL re-arms the querier's write-filter (leg 8, the pico `-a`
//!     matching listener's "NO MORE matching queryables." positive observable — NOT
//!     a flaky negative). Both are also unit-proven on the forwarder.
//!   * peer-tier FUTURE-push observability CLOSED (R311y158 counter + R311y165 e2e):
//!     the peer `LinkstateForwarder` carries its own `future_pushes` counter
//!     (surfaced by run_peer as `pushed a future subscriber`), and the strong
//!     peer-mode pub-before-sub cross-impl e2e now lands in
//!     `wz_peer_future_push_pico_interop.rs` — a pico z_pub client of peer-A is
//!     pushed the future declare + its Put re-injected across the wz peer mesh to a
//!     pico z_sub client of peer-B (D4, R311y163/y164, wired the peer client data plane).
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
//! built with `--features router-hat-router` (the run-mode ACTIVE atom; leg 9
//! additionally needs `routing-token-tables`, which the Layer Z build opts into
//! and which pulls `router-hat-router`). Neither is a default-sweep artifact, so
//! this never gates the default test run.

use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_answering_zqueryable, spawn_liveliness_subscriber,
    spawn_liveliness_token, spawn_on_ephemeral_port, spawn_publishing_zpub,
    spawn_querying_zquerier, spawn_subscribed_zsub, spawn_zenohd, wait_for_substring,
    wz_ap_demo_binary, zenoh_pico_cli_binary, PortReservation,
};

/// The router-tier convergence witness the wz `--router-hat` node logs once its
/// `routers_net` reaches two nodes (self + the federated peer). Shared by all
/// legs — each waits on it to gate client attach until the backbone is up.
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
// R311y423 — and this leg is scouting-gossip's cross-impl witness. The atom is
// the link-state gossip flood (wz-routing-graph + linkstate_forward.rs,
// FOUNDATIONAL/always-on), and the assertion below is precisely that wz
// DECODED >=1 of zenohd's LinkStateList OAM floods -- `ingested() > 0`, not the
// handshake-satisfiable convergence tick. zenohd->wz only: wz's own flood
// reaching zenohd is not asserted here, so no wz->zenohd claim is made.
// A4-5 containment is exempt (FOUNDATIONAL names no cfg site), so this rests on
// that reading -- verified by hand at R311y423.
// R311y503 — and this leg is `router-orchestration`'s cross-impl witness. The
// atom is the ROUTER-SCOPED BOOTSTRAP, which R311y238 recorded as subsumed into
// this run-mode: `run_router_hat_until` binds the listen endpoint and then dials
// every `--connect` target as a router-tier face (runner.rs, the `dials` vector
// feeding `peer_loop`'s `FaceSources`). The dial half is what this leg turns on
// -- wz is the DIALER here, zenohd only accepts -- so the claim is wz->zenohd.
// Bound by damage, not by reading: clearing `dials` after the parse loop (so the
// bind and every other bootstrap step still runs) reds THIS leg and no other
// targeted leg. `routers-net converged (2 node(s))` cannot be reached without
// the router-scoped dial that the atom names.
// wz-proves: router-hat-router zenohd->wz
// wz-proves: router-hat-router wz->zenohd partial
// wz-proves: scouting-gossip zenohd->wz
// wz-proves: router-orchestration wz->zenohd
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
// wz-proves: declare-subscriber wz->zenohd
// wz-proves: codec-declare wz->zenohd
// wz-proves: router-hat-router wz->zenohd partial
// wz-proves: codec-frame zenohd->wz
// wz-proves: codec-push zenohd->wz
// wz-proves: router-hat-router zenohd->wz
// wz-proves: declare-subscriber pico->wz
// wz-proves: codec-declare pico->wz
// wz-proves: codec-frame wz->pico
// wz-proves: codec-push wz->pico
// R311y503 — and this leg is `routing-data-route-compute`'s cross-impl witness.
// The atom is the router `compute_data_route` fan (route_push's three blocks over
// the two mesh tiers plus the local client faces). This leg drives block 3 on a
// ROUTER-sourced Push: the Put enters wz over the zenohd link-state face and
// leaves through `deliver_to_client_subscribers` to a real pico z_sub, so the
// whole fan is cross-impl on both sides. Bound by damage: an early `return` at
// the head of `deliver_to_client_subscribers` -- leaving blocks 1/2 and the
// cross-mesh bridge intact -- reds THIS leg. Claimed `full` for wz->pico: the
// asserted receipt IS the computed route's egress.
// wz-proves: routing-data-route-compute wz->pico
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
// wz-proves: codec-frame wz->zenohd
// wz-proves: codec-push wz->zenohd
// wz-proves: router-hat-router wz->zenohd partial
// wz-proves: declare-subscriber zenohd->wz
// wz-proves: codec-declare zenohd->wz
// wz-proves: router-hat-router zenohd->wz
// wz-proves: declare-interest pico->wz
// wz-proves: codec-push pico->wz
// wz-proves: declare-subscriber wz->pico
// wz-proves: codec-declare wz->pico
// R311y503 — this leg carries TWO further cross-impl witnesses, each bound by its
// own damage rather than by reading:
//
//   `routing-interest-broker` (wz->pico). The atom is the router's interest
//   handshake -- the CURRENT-mode snapshot of matching remote declarations plus
//   the terminating DeclFinal, emitted by `respond_to_interest`. This leg is the
//   one that cannot proceed without it: the real pico publisher holds a WRITE
//   FILTER that emits zero wire bytes until wz answers its declare-Interest, so
//   the foreign process's own behaviour is the assertion. An early `return` at
//   the head of `respond_to_interest` reds exactly this leg.
//
//   `router-face-management` (pico->wz). The atom is the router-grade per-face
//   state; the part no sibling atom owns is `RouterFaceState`'s link-local
//   keyexpr-alias table (zenoh's FaceState `remote_mappings`, face.rs:63), fed by
//   `absorb_keyexpr_declaration` and read back by every `resolve_wireexpr` on the
//   inbound face. Damage attributed by TIER, which is what fixes the direction:
//   voiding the absorb for CLIENT-tier faces ONLY -- so zenohd's router-tier
//   aliases keep resolving -- still reds this leg, so the aliases that carry it
//   are the real pico's. wz DECODES a foreign alias table, hence pico->wz.
// wz-proves: routing-interest-broker wz->pico
// wz-proves: router-face-management pico->wz
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
// wz-proves: codec-request wz->zenohd
// wz-proves: router-hat-router wz->zenohd partial
// wz-proves: declare-queryable zenohd->wz
// wz-proves: codec-declare zenohd->wz
// wz-proves: codec-response zenohd->wz
// wz-proves: router-hat-router zenohd->wz
// wz-proves: declare-interest pico->wz
// wz-proves: codec-request pico->wz
// wz-proves: declare-queryable wz->pico
// wz-proves: codec-response wz->pico
// wz-proves: query-reply wz->pico
// R311y503 — and this leg is `routing-query-route-compute`'s cross-impl witness.
// The atom is the router's `compute_query_route` half: `route_request` picking the
// mesh block and the out-faces, with `PendingQueries` holding the reverse path the
// Response returns along. Here a real pico's Get enters wz, is routed onto the
// zenohd backbone, and the reply comes back down the recorded reverse path -- so
// both the forward decision and the reverse path are foreign-witnessed. Bound by
// damage: an early `return` at the head of `route_request` reds this leg (and the
// two sibling query legs) while every pubsub leg stays green, which is what
// distinguishes the query-route compute from the data-route compute above.
// wz-proves: routing-query-route-compute wz->zenohd
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
            false,
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
// wz-proves: declare-interest pico->wz partial
// wz-proves: declare-subscriber wz->pico
// wz-proves: codec-declare wz->pico
// wz-proves: codec-push pico->wz
// wz-proves: codec-frame wz->zenohd
// wz-proves: codec-push wz->zenohd
// wz-proves: router-hat-router wz->zenohd partial
// wz-proves: declare-subscriber zenohd->wz
// wz-proves: codec-declare zenohd->wz
// wz-proves: router-hat-router zenohd->wz
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

/// Leg 6 — the FORWARD QUERY-plane acid test (R311y149), the query twin of leg 2
/// (the OPPOSITE direction to leg 4). A pico `z_queryable` (client of the WZ
/// router) answers `demo/**`; a pico `z_querier` (client of ZENOHD) queries
/// `demo/key`. The Query crosses the backbone querier -> zenohd -> [`routers_net`
/// link-state] -> wz-router -> queryable and the Reply returns in reverse. This
/// exercises what leg 4 does NOT: wz ADVERTISING its client queryable across the
/// router backbone (`advertise_client_cross_tier_qabl`, the query twin of leg 2's
/// client-sub advertise) so zenohd routes a remote querier's Query toward wz, and
/// wz routing that INGRESS Query to its client queryable + the Reply EGRESS back —
/// query-INGRESS/reply-EGRESS, the mirror of leg 4's query-EGRESS/reply-INGRESS.
///
/// Gated on wz's `learned a queryable` witness — here it fires on wz ingesting its
/// OWN client queryable (`client_qabls`), which synchronously dispatches the
/// cross-tier advertise toward zenohd. zenohd's route install is the residual
/// dispatched-!=-installed gap the `z_querier -n 30 -t 3000` burst absorbs (the
/// querier's write-filter is answered by ZENOHD here, not wz). Transit-pinned on
/// wz's `routed a query`: the querier dials only zenohd and the queryable only wz,
/// so a reply implies the Query transited wz's router.
// wz-proves: declare-queryable wz->zenohd
// wz-proves: codec-declare wz->zenohd
// wz-proves: codec-response wz->zenohd
// wz-proves: query-reply wz->zenohd
// wz-proves: router-hat-router wz->zenohd partial
// wz-proves: codec-request zenohd->wz
// wz-proves: router-hat-router zenohd->wz
// wz-proves: declare-queryable pico->wz
// wz-proves: codec-response pico->wz
// wz-proves: codec-request wz->pico
#[test]
#[ignore = "binary-dep e2e (zenohd + zenoh-pico z_querier/z_queryable + wz-ap-demo --features router-hat-router); run via Layer Z / --ignored"]
fn wz_router_hat_and_zenohd_federate_a_pico_query_across_the_backbone() {
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

    // z_queryable: a pico CLIENT of WZ, answering demo/**. wz ingests it into
    // client_qabls and advertises the cross-tier queryable into the routers_net so
    // zenohd learns wz hosts a matching queryable.
    let z_qabl_endpoint = format!("tcp/127.0.0.1:{wz_port}");
    let (mut z_qabl_guard, mut z_qabl_reader) = spawn_answering_zqueryable(
        &z_queryable,
        "demo/**",
        "forward-query-federation",
        &z_qabl_endpoint,
        "wz-router-hat",
        tempfile,
    );

    // Barrier: wz has INGESTED its client queryable (and synchronously dispatched
    // the cross-tier advertise toward zenohd), so zenohd can answer a querier's
    // write-filter interest with a route toward wz.
    let learned = wait_for_substring(
        &mut wz_reader,
        "router-hat: learned a queryable",
        Duration::from_secs(10),
    );

    // z_querier: a pico CLIENT of ZENOHD, querying demo/key as a 30-get burst. Its
    // write-filter is answered by ZENOHD (which learned wz's advertised qabl off
    // the mesh); the Query routes zenohd -> wz, wz dispatches it to its client
    // queryable, and the reply returns the same path in reverse.
    let q_endpoint = format!("tcp/127.0.0.1:{zport}");
    let mut z_querier_pair = learned.is_ok().then(|| {
        spawn_querying_zquerier(
            &z_querier,
            "demo/key",
            &q_endpoint,
            "zenohd",
            false,
            tempfile,
        )
    });

    // The acid test: the reply from z_queryable behind wz reaches the pico querier
    // behind zenohd, having crossed the cross-impl router backbone in the forward
    // direction.
    let received = z_querier_pair.as_mut().map(|(_, reader)| {
        wait_for_substring(reader, ">> Received ('demo/key'", Duration::from_secs(20))
    });
    // Transit pin: the Query transited wz's router (`queries_seen` rose, counting
    // inbound Request(Query) only). By the time `received` fired the Query has
    // transited, so wait a short window for the log to flush.
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
            "wz-router-hat never INGESTED its client queryable within 10s (no \
             'learned a queryable') — the queryable's DeclareQueryable did not \
             reach wz\n--- wz-router-hat stderr ---\n{c}"
        )
    });
    received
        .expect("learned implies the querier was spawned")
        .unwrap_or_else(|c| {
            panic!(
                "pico z_querier behind zenohd never received a reply to demo/key \
                 within 20s — the query/reply did not complete over the cross-impl \
                 router backbone (wz did not advertise its client queryable to \
                 zenohd, the query was not routed to wz, or the reply was lost on \
                 the return path — the z_queryable stdout above shows which)\n--- \
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
    // Foreign-side proof: the query reached the REAL cross-impl answerer behind wz.
    assert!(
        z_qabl_captured.contains("[Queryable handler] Received Query"),
        "z_queryable behind wz never logged 'Received Query' — the reply z_querier \
         saw did not originate at the real cross-impl answerer\n--- z_queryable \
         stdout ---\n{z_qabl_captured}"
    );
}

/// Leg 7 — FUTURE-mode querier-before-queryable (R311y156), the QUERY-plane twin of
/// leg 5 and the cross-impl closure of the R311y150 proactive queryable push. Same
/// topology as leg 4 (querier behind wz, queryable behind zenohd) but the QUERIER
/// declares BEFORE any queryable exists, so wz's CURRENT interest dump is empty and
/// the ONLY way the querier's write-filter deactivates is the y150 FUTURE push: wz
/// stores the querier's `f()` queryable interest, then — when zenohd's queryable
/// later floods across the mesh — proactively pushes an unsolicited
/// `DeclareQueryable` to the querier's face (`push_future_queryable`).
///
/// Asserted via the `pushed a future queryable` witness so the deactivation is
/// provably the FUTURE push, not a raced CURRENT dump (both otherwise silent). The
/// querier spawns FIRST with NO barrier (a barrier would establish the
/// queryable-first ordering leg 4 uses, destroying the discriminator); its `-n 30`
/// burst is self-healing across the push, so gets dropped while the filter was active
/// are followed by gets that flow once it deactivates.
///
/// The UNDECLARE-RE-ARM half is NOT cross-impl assertable (the real pico `z_querier`
/// prints nothing when its write-filter re-arms, and the negative "gets stopped over
/// time" is inherently flaky), so it stays unit-proven on the forwarder — router
/// `withdrawing_the_last_backing_sub_undeclares_and_lets_a_re_declare_re_push`
/// (router_forward.rs) + the peer twins (linkstate_forward.rs
/// `peer_link_down_undeclares_to_the_client_querier`,
/// `peer_partial_qabl_withdrawal_downgrades_the_client_querier_same_id`).
// wz-proves: declare-interest pico->wz partial
// wz-proves: declare-queryable wz->pico
// wz-proves: codec-declare wz->pico
// wz-proves: codec-request wz->zenohd
// wz-proves: router-hat-router wz->zenohd partial
// wz-proves: declare-queryable zenohd->wz
// wz-proves: codec-declare zenohd->wz
// wz-proves: codec-response zenohd->wz
// wz-proves: router-hat-router zenohd->wz
// wz-proves: codec-request pico->wz
// wz-proves: codec-response wz->pico
// wz-proves: query-reply wz->pico
#[test]
#[ignore = "binary-dep e2e (zenohd + zenoh-pico z_querier/z_queryable + wz-ap-demo --features router-hat-router); run via Layer Z / --ignored"]
fn wz_router_hat_pushes_a_future_queryable_to_a_pico_querier() {
    let z_querier = zenoh_pico_cli_binary("z_querier");
    let z_queryable = zenoh_pico_cli_binary("z_queryable");
    let port_res = PortReservation::pick();
    let zport = port_res.port();
    let _zenohd = spawn_zenohd(zport, tempfile);
    let zaddr = format!("127.0.0.1:{zport}");

    // wz --router-hat dials zenohd; wait for the router backbone to converge BEFORE
    // attaching clients so the link-state mesh is established.
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

    // z_querier: a pico CLIENT of WZ, querying demo/key — spawned FIRST, with NO
    // matching queryable anywhere. Its write-filter is ACTIVE, so its early gets drop
    // LOCALLY; wz stores its f() queryable interest (an empty CURRENT dump). The
    // helper returns on "Declaring Querier on" — so the querier's declare-Interest is
    // on the wire before the queryable is spawned. That wz actually STORED it is
    // proven downstream by the `pushed a future queryable` witness, which can only
    // fire from a stored future interest.
    let q_endpoint = format!("tcp/127.0.0.1:{wz_port}");
    let (mut z_querier_guard, mut z_querier_reader) = spawn_querying_zquerier(
        &z_querier,
        "demo/key",
        &q_endpoint,
        "wz-router-hat",
        false,
        tempfile,
    );

    // z_queryable: a pico CLIENT of ZENOHD, answering demo/** — spawned SECOND. zenohd
    // floods it across the router backbone to wz, which PUSHES an unsolicited
    // DeclareQueryable to z_querier's stored future interest (y150), deactivating the
    // querier's write-filter so its remaining get burst flows.
    let z_qabl_endpoint = format!("tcp/127.0.0.1:{zport}");
    let (mut z_qabl_guard, mut z_qabl_reader) = spawn_answering_zqueryable(
        &z_queryable,
        "demo/**",
        "future-query-federation",
        &z_qabl_endpoint,
        "zenohd",
        tempfile,
    );

    // FUTURE-push proof: wz proactively pushed the queryable to the querier's face —
    // the ONLY deactivation path given the querier-before-queryable ordering.
    let pushed = wait_for_substring(
        &mut wz_reader,
        "router-hat: pushed a future queryable",
        Duration::from_secs(20),
    );

    // The acid test: the reply from z_queryable behind zenohd reaches the pico querier
    // behind wz — which can only happen after the future push deactivated the querier.
    let received = wait_for_substring(
        &mut z_querier_reader,
        ">> Received ('demo/key'",
        Duration::from_secs(20),
    );
    // Transit pin: the Query transited wz's router (`queries_seen` counts inbound
    // Request(Query) only, unsatisfiable by a mere interest/declare round-trip).
    let transit = received.is_ok().then(|| {
        wait_for_substring(
            &mut wz_reader,
            "router-hat: routed a query",
            Duration::from_secs(5),
        )
    });

    let _ = z_querier_guard.child_mut().kill();
    let _ = z_querier_guard.child_mut().wait();
    let _ = z_qabl_guard.child_mut().kill();
    let _ = z_qabl_guard.child_mut().wait();
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let wz_captured = read_captured(&mut wz_reader);
    let z_querier_captured = read_captured(&mut z_querier_reader);
    let z_qabl_captured = read_captured(&mut z_qabl_reader);
    eprintln!("--- wz-router-hat stderr ---\n{wz_captured}");
    eprintln!("--- z_querier stdout ---\n{z_querier_captured}");
    eprintln!("--- z_queryable stdout ---\n{z_qabl_captured}");

    pushed.unwrap_or_else(|c| {
        panic!(
            "wz-router-hat never PUSHED a future queryable within 20s (no 'pushed a \
             future queryable') — the y150 proactive push did not fire, so a \
             querier-before-queryable querier's write-filter would never deactivate \
             (or the real pico z_querier did not send a FUTURE-mode queryable \
             interest)\n--- wz-router-hat stderr ---\n{c}"
        )
    });
    received.unwrap_or_else(|c| {
        panic!(
            "pico z_querier behind wz never received a reply to demo/key within 20s — \
             the FUTURE-mode querier-before-queryable query did not complete over the \
             cross-impl router backbone (the future push did not deactivate the \
             querier, the query was not routed, or the reply was lost)\n--- z_querier \
             stdout ---\n{c}"
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
        "z_queryable behind zenohd never logged 'Received Query' — the reply z_querier \
         saw did not originate at the real cross-impl answerer\n--- z_queryable stdout \
         ---\n{z_qabl_captured}"
    );
}

/// Leg 8 — the UNDECLARE-RE-ARM cross-impl acid test (R311y156), the QUERY-plane
/// closure of the R311y151 undeclare-push. Same topology + future-push as leg 7, but
/// the pico `z_querier` runs with `-a` (a background matching listener), so its OWN
/// write-filter state is a POSITIVE observable: it prints "Querier has matching
/// queryable." when the y150 future push DEACTIVATES the filter, and — the acid test —
/// "Querier has NO MORE matching queryables." when the queryable WITHDRAWS and wz's
/// y151 `undeclare_push_qabls` pushes an `UndeclareQueryable` that RE-ARMS the filter.
///
/// This is the POSITIVE pico-side observable of the re-arm (`z_querier_get_matching_status`
/// = `!_z_write_filter_active`, zenoh-pico api.c), NOT the flaky negative "gets stopped
/// over time" — so the withdrawal half is proven on a REAL pico querier, not only on
/// the forwarder units (router_forward.rs
/// `withdrawing_the_last_backing_sub_undeclares_and_lets_a_re_declare_re_push`,
/// linkstate_forward.rs `peer_link_down_undeclares_to_the_client_querier`). Sequence:
/// querier (with -a) first → queryable second → "matching queryable" (future push
/// deactivated) → KILL the queryable → "NO MORE matching queryables" (undeclare
/// re-armed). The wz-side `pushed a future queryable` pins the deactivation was the
/// FUTURE push (querier-before-queryable), making this the full-lifecycle acid test.
// wz-proves: declare-undeclare wz->pico
// wz-proves: declare-undeclare zenohd->wz
// wz-proves: declare-queryable wz->pico
// wz-proves: declare-interest pico->wz partial
// wz-proves: codec-declare wz->pico
// wz-proves: codec-declare zenohd->wz
// wz-proves: router-hat-router zenohd->wz
#[test]
#[ignore = "binary-dep e2e (zenohd + zenoh-pico z_querier/z_queryable + wz-ap-demo --features router-hat-router); run via Layer Z / --ignored"]
fn wz_router_hat_undeclare_re_arms_a_pico_queriers_write_filter() {
    let z_querier = zenoh_pico_cli_binary("z_querier");
    let z_queryable = zenoh_pico_cli_binary("z_queryable");
    let port_res = PortReservation::pick();
    let zport = port_res.port();
    let _zenohd = spawn_zenohd(zport, tempfile);
    let zaddr = format!("127.0.0.1:{zport}");

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

    // z_querier WITH -a (matching listener): a pico CLIENT of WZ, querying demo/key —
    // spawned FIRST. Its write-filter starts ACTIVE; the y150 future push is the only
    // thing that deactivates it (querier-before-queryable, as in leg 7).
    let q_endpoint = format!("tcp/127.0.0.1:{wz_port}");
    let (mut z_querier_guard, mut z_querier_reader) = spawn_querying_zquerier(
        &z_querier,
        "demo/key",
        &q_endpoint,
        "wz-router-hat",
        true, // -a: observe the querier's own write-filter state
        tempfile,
    );

    // z_queryable: a pico CLIENT of ZENOHD, answering demo/** — spawned SECOND. zenohd
    // floods it across the backbone to wz, which future-pushes a DeclareQueryable to
    // the querier, deactivating its filter.
    let z_qabl_endpoint = format!("tcp/127.0.0.1:{zport}");
    let (mut z_qabl_guard, mut z_qabl_reader) = spawn_answering_zqueryable(
        &z_queryable,
        "demo/**",
        "undeclare-re-arm-federation",
        &z_qabl_endpoint,
        "zenohd",
        tempfile,
    );

    // Precondition (pico-side): the future push DEACTIVATED the querier's write-filter.
    let matched = wait_for_substring(
        &mut z_querier_reader,
        "Querier has matching queryable.",
        Duration::from_secs(20),
    );
    // wz-side cause: the deactivation was the y150 FUTURE push (querier-before-queryable).
    let pushed = matched.is_ok().then(|| {
        wait_for_substring(
            &mut wz_reader,
            "router-hat: pushed a future queryable",
            Duration::from_secs(5),
        )
    });

    // Withdraw the queryable: KILL z_queryable so zenohd floods an UndeclareQueryable
    // across the backbone to wz, whose y151 undeclare_push_qabls pushes an
    // UndeclareQueryable to the querier — re-arming its write-filter.
    if matched.is_ok() {
        let _ = z_qabl_guard.child_mut().kill();
        let _ = z_qabl_guard.child_mut().wait();
    }

    // THE ACID TEST (pico-side positive observable): the querier's write-filter
    // RE-ARMED — the withdrawal reached it via wz's undeclare-push.
    let rearmed = matched.is_ok().then(|| {
        wait_for_substring(
            &mut z_querier_reader,
            "Querier has NO MORE matching queryables.",
            Duration::from_secs(20),
        )
    });

    let _ = z_querier_guard.child_mut().kill();
    let _ = z_querier_guard.child_mut().wait();
    let _ = z_qabl_guard.child_mut().kill();
    let _ = z_qabl_guard.child_mut().wait();
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let wz_captured = read_captured(&mut wz_reader);
    let z_querier_captured = read_captured(&mut z_querier_reader);
    let z_qabl_captured = read_captured(&mut z_qabl_reader);
    eprintln!("--- wz-router-hat stderr ---\n{wz_captured}");
    eprintln!("--- z_querier stdout ---\n{z_querier_captured}");
    eprintln!("--- z_queryable stdout ---\n{z_qabl_captured}");

    matched.unwrap_or_else(|c| {
        panic!(
            "pico z_querier never observed 'Querier has matching queryable.' within 20s \
             — the y150 future push did not deactivate the querier's write-filter (the \
             re-arm test's precondition failed)\n--- z_querier stdout ---\n{c}"
        )
    });
    pushed
        .expect("matched implies the push was probed")
        .unwrap_or_else(|c| {
            panic!(
                "wz-router-hat never logged 'pushed a future queryable' — the querier's \
                 filter deactivated without the wz future push (a raced CURRENT dump?)\n\
                 --- wz-router-hat stderr ---\n{c}"
            )
        });
    rearmed
        .expect("matched implies the re-arm was probed")
        .unwrap_or_else(|c| {
            panic!(
                "pico z_querier never observed 'Querier has NO MORE matching \
                 queryables.' within 20s after the queryable was killed — the y151 \
                 undeclare-push did not re-arm the querier's write-filter cross-impl \
                 (zenohd did not flood the UndeclareQueryable, or wz did not push it to \
                 the querier)\n--- z_querier stdout ---\n{c}"
            )
        });
}

/// Leg 9 — the LIVELINESS-TOKEN cross-impl lifecycle acid test (§5.21
/// routing-token-tables, R311y170-175), the token twin of legs 7 & 8 folded into
/// one subscriber lifecycle. A pico `z_sub_liveliness` (client of the WZ router,
/// spawned FIRST) declares a FUTURE-only liveliness-token interest (no `-h`, pico
/// `InterestMode::Future`); a pico `z_liveliness` (client of ZENOHD, spawned
/// SECOND) declares a token `group1/zenoh-pico`. zenohd floods it over
/// `routers_net` as a sourced DeclareToken (zenohd hat/router/token.rs
/// `propagate_sourced_token` -> `send_sourced_token_to_net_clildren`: a full
/// link-state flood, NOT interest-gated — the SAME mechanism legs 2-8 prove for
/// subs/qabls), which wz `ingest_token`s and PROACTIVELY pushes to the
/// subscriber's stored future interest (slice-4 `push_future_token`) — the ONLY
/// delivery path given a FUTURE-only interest has no CURRENT dump to race. The
/// subscriber prints `New alive token`. Then — the slice-5 undeclare closure —
/// z_liveliness is KILLED; its socket close (it installs no signal handler) makes
/// zenohd flood an UndeclareToken, which wz `undeclare_push_token`s to the
/// subscriber, which prints `Dropped token`.
///
/// ONE test, not two: unlike legs 7/8 (leg 8 needs a DIFFERENT z_querier
/// invocation `-a` to make the write-filter re-arm a positive observable), the
/// SAME z_sub_liveliness process prints BOTH the declare (`New alive token`,
/// z_sub_liveliness.c PUT) and the undeclare (`Dropped token`, DELETE) — so the
/// token lifecycle is one continuous observable on one subscriber, and folding
/// saves a zenohd respawn. The wz-side `pushed a future token` witness pins the
/// declare delivery to the FUTURE push (not a raced dump); the exact keyexpr is
/// asserted on BOTH pico lines so an id-keyed undeclare black-hole (a wrong/empty
/// keyexpr) cannot pass. The CURRENT-mode token readiness leg (token-before-
/// subscriber, gating on a `learned a mesh token` witness) is deferred — it needs
/// `z_sub_liveliness -h` and a mesh-token readiness accessor no leg here consumes.
// wz-proves: routing-token-tables zenohd->wz
// wz-proves: routing-token-tables wz->pico
// wz-proves: declare-token zenohd->wz
// wz-proves: declare-token wz->pico
// wz-proves: declare-undeclare zenohd->wz
// wz-proves: declare-undeclare wz->pico
// wz-proves: declare-interest pico->wz partial
// wz-proves: codec-declare zenohd->wz
// wz-proves: codec-declare wz->pico
// wz-proves: router-hat-router zenohd->wz
#[test]
#[ignore = "binary-dep e2e (zenohd + zenoh-pico z_sub_liveliness/z_liveliness + wz-ap-demo --features router-hat-router,routing-token-tables); run via Layer Z / --ignored"]
fn wz_router_hat_token_lifecycle_reaches_a_pico_liveliness_subscriber() {
    let z_liveliness = zenoh_pico_cli_binary("z_liveliness");
    let z_sub_liveliness = zenoh_pico_cli_binary("z_sub_liveliness");
    let port_res = PortReservation::pick();
    let zport = port_res.port();
    let _zenohd = spawn_zenohd(zport, tempfile);
    let zaddr = format!("127.0.0.1:{zport}");

    // wz --router-hat dials zenohd; wait for the router backbone to converge BEFORE
    // attaching clients so the link-state token flood has a mesh to cross.
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
        panic!(
            "wz <-> zenohd router backbone never converged within 15s\n\
             --- wz-router-hat stderr ---\n{c}"
        );
    }

    // z_sub_liveliness: a pico CLIENT of WZ, subscribing group1/** — spawned FIRST,
    // with NO token declared anywhere. FUTURE-only (no -h), so wz stores its token
    // interest with an empty CURRENT dump; that wz stored it is proven downstream by
    // the `pushed a future token` witness (which can only fire from a stored future
    // interest). The token keyexpr group1/zenoh-pico intersects group1/**.
    let sub_endpoint = format!("tcp/127.0.0.1:{wz_port}");
    let (mut z_sub_guard, mut z_sub_reader) = spawn_liveliness_subscriber(
        &z_sub_liveliness,
        "group1/**",
        &sub_endpoint,
        "wz-router-hat",
        tempfile,
    );

    // z_liveliness: a pico CLIENT of ZENOHD, declaring token group1/zenoh-pico —
    // spawned SECOND. zenohd floods it over routers_net to wz, which pushes an
    // unsolicited DeclareToken to z_sub_liveliness's stored future interest.
    let token_endpoint = format!("tcp/127.0.0.1:{zport}");
    let (mut z_token_guard, mut z_token_reader) = spawn_liveliness_token(
        &z_liveliness,
        "group1/zenoh-pico",
        &token_endpoint,
        "zenohd",
        tempfile,
    );

    // FUTURE-push proof: wz proactively pushed the token to the subscriber's face —
    // the ONLY delivery path given the FUTURE-only interest (no CURRENT dump).
    let pushed = wait_for_substring(
        &mut wz_reader,
        "router-hat: pushed a future token",
        Duration::from_secs(20),
    );
    // Acid test (declare half): the token declared by z_liveliness behind zenohd
    // reaches the pico subscriber behind wz as a PUT — cross-impl, over the backbone.
    let alive = wait_for_substring(
        &mut z_sub_reader,
        "New alive token ('group1/zenoh-pico')",
        Duration::from_secs(20),
    );

    // Undeclare half (slice-5 reconcile-notify closure): kill z_liveliness. It
    // installs no signal handler, so its SOCKET CLOSE (not a graceful undeclare) is
    // what makes zenohd flood the UndeclareToken; wz undeclare_push_token's it to the
    // subscriber, which prints the DELETE. Only probed once the declare half arrived.
    let dropped = alive.is_ok().then(|| {
        let _ = z_token_guard.child_mut().kill();
        let _ = z_token_guard.child_mut().wait();
        wait_for_substring(
            &mut z_sub_reader,
            "Dropped token ('group1/zenoh-pico')",
            Duration::from_secs(20),
        )
    });

    let _ = z_sub_guard.child_mut().kill();
    let _ = z_sub_guard.child_mut().wait();
    let _ = z_token_guard.child_mut().kill();
    let _ = z_token_guard.child_mut().wait();
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let wz_captured = read_captured(&mut wz_reader);
    let z_sub_captured = read_captured(&mut z_sub_reader);
    let z_token_captured = read_captured(&mut z_token_reader);
    eprintln!("--- wz-router-hat stderr ---\n{wz_captured}");
    eprintln!("--- z_sub_liveliness stdout ---\n{z_sub_captured}");
    eprintln!("--- z_liveliness stdout ---\n{z_token_captured}");

    pushed.unwrap_or_else(|c| {
        panic!(
            "wz-router-hat never PUSHED a future token within 20s (no 'pushed a future \
             token') — the slice-4 proactive push did not fire, so a subscriber-before-\
             token liveliness subscriber would never receive the token (or the real pico \
             z_sub_liveliness did not send a FUTURE-mode token interest, or zenohd did not \
             flood the token over routers_net)\n--- wz-router-hat stderr ---\n{c}"
        )
    });
    alive.unwrap_or_else(|c| {
        panic!(
            "pico z_sub_liveliness behind wz never logged \"New alive token \
             ('group1/zenoh-pico')\" within 20s — the FUTURE-mode token push did not \
             deliver the token declared behind zenohd over the cross-impl router backbone \
             (the future push did not reach the subscriber, or the keyexpr drifted)\n\
             --- z_sub_liveliness stdout ---\n{c}"
        )
    });
    dropped
        .expect("alive implies the undeclare was probed")
        .unwrap_or_else(|c| {
            panic!(
                "pico z_sub_liveliness never logged \"Dropped token \
                 ('group1/zenoh-pico')\" within 20s after z_liveliness was killed — the \
                 slice-5 undeclare_push_token did not reach the subscriber cross-impl \
                 (zenohd did not flood the UndeclareToken on the socket close, wz did not \
                 push it, or the id-keyed undeclare resolved the wrong keyexpr)\n\
                 --- z_sub_liveliness stdout ---\n{c}"
            )
        });
    // Foreign-side proof: the token originated at the REAL cross-impl declarer
    // (z_liveliness behind zenohd), not a wz-local synthesis (wz declares no token).
    assert!(
        z_token_captured.contains("Declaring liveliness token 'group1/zenoh-pico'"),
        "z_liveliness behind zenohd never logged its token declaration — the token the \
         subscriber saw did not originate at the real cross-impl declarer\n\
         --- z_liveliness stdout ---\n{z_token_captured}"
    );
}

/// Leg 10 — the ROUTER-NATIVE cross-tier BRIDGE, cross-impl (the C4
/// [`bridge_push_cross_mesh`] acid test a foreign router uniquely enables).
///
/// Every prior data leg publishes from a pico CLIENT of a router (leg 2/3 take
/// the C3b `publish_client_push_into_meshes` re-inject) or from a wz peer into a
/// SAME-impl wz peer (`wz_router_hat_mesh` test #4). This leg puts a wz `--peer`
/// PUBLISHER behind the wz router and a pico `z_sub` behind ZENOHD: the
/// peer-source Put arrives on wz's `linkstatepeers_net`, so the ONLY path to the
/// subscriber is wz BRIDGING it cross-mesh into `routers_net` toward the sub
/// zenohd advertised as a ROUTER-NATIVE declaration (zenoh
/// `register_router_subscription`). That is the `router_subs -> peer-mesh`
/// direction the file header flags as UNIT-only — undrivable by the OBSERVE-only
/// wz demo router (it originates no router-native declare), but a single foreign
/// zenohd supplies one. wz is the sole master (`shared_nodes = {self}`) so the
/// master gate admits the bridge.
///
/// Discriminator (why this is not leg 2/3 nor test #4): the wz `--peer` publisher
/// knows only the wz router; the pico subscriber is zenohd's client — neither can
/// reach the other except through wz's cross-mesh bridge. Break
/// `bridge_push_cross_mesh` (or the router-native sub ingest) and the subscriber
/// receives nothing, while leg 2/3's within-tier / client re-inject route still
/// passes — so this witnesses the C4 bridge specifically. Barrier-gated on wz's
/// `learned a mesh sub` (wz provably holds zenohd's router-native sub) before the
/// peer publisher spawns, so a Put burst cannot outrun the mesh subscription.
// R311y503 — and this leg is `router-master-election`'s cross-impl witness, but
// only PARTIALLY, and the partial is measured rather than hedged. The atom is the
// HRW route-master election (`elect_router` / `shared_nodes` / `is_master`) that
// dedups delivery across routers. What this leg proves is that the master GATE is
// live and load-bearing on a foreign path: forcing `is_master` to `false` reds
// this leg (the peer->router bridge is the master-gated one) plus four others,
// against a real zenohd sub and a real pico sub. What it does NOT prove is the
// ELECTION discriminating between candidates -- inverting `elect_router`'s HRW
// comparison from MAX to MIN leaves all ten legs GREEN, because `shared_nodes` is
// `{self}` here and a one-candidate election has no order to invert. That matches
// zenoh: `shared_nodes` is only recomputed under `router_full_linkstate &&
// peer_full_linkstate` (hat/router/mod.rs:384) and a stock zenohd runs peers in
// gossip mode, so no foreign router joins wz's linkstatepeers_net. A `full` claim
// needs a topology where a foreign zid sits in BOTH nets; until then this stays
// partial.
// wz-proves: router-hat-router wz->zenohd partial
// wz-proves: router-master-election wz->zenohd partial
#[test]
#[ignore = "binary-dep e2e (zenohd + zenoh-pico z_sub + wz-ap-demo --features router-hat-router); run via Layer Z / --ignored"]
fn wz_router_hat_bridges_a_peer_publish_to_a_zenohd_router_native_sub() {
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let port_res = PortReservation::pick();
    let zport = port_res.port();
    let _zenohd = spawn_zenohd(zport, tempfile);
    let zaddr = format!("127.0.0.1:{zport}");

    // A pico z_sub behind ZENOHD subscribes demo/**; zenohd advertises it into
    // routers_net as a ROUTER-NATIVE subscription once the wz router links.
    let z_sub_endpoint = format!("tcp/127.0.0.1:{zport}");
    let (mut z_sub_guard, mut z_sub_reader) =
        spawn_subscribed_zsub(&z_sub, "demo/**", &z_sub_endpoint, "zenohd", tempfile);

    // wz --router-hat dials zenohd; converge the router backbone before attaching
    // the peer publisher.
    let (mut wz_guard, mut wz_reader, wz_port) = spawn_router_hat_dialing(&zaddr);
    if wait_for_substring(
        &mut wz_reader,
        ROUTERS_NET_CONVERGED,
        Duration::from_secs(15),
    )
    .is_err()
    {
        let c = read_captured(&mut wz_reader);
        let _ = z_sub_guard.child_mut().kill();
        graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
        panic!("wz <-> zenohd router backbone never converged within 15s\n--- wz-router-hat stderr ---\n{c}");
    }

    // Barrier: wz has INGESTED zenohd's router-native sub off routers_net, so it can
    // advertise it into the peer mesh (attract the peer publisher) AND bridge a
    // peer-source Push toward it. Gate the publisher's spawn on this witness.
    if wait_for_substring(
        &mut wz_reader,
        "router-hat: learned a mesh sub",
        Duration::from_secs(15),
    )
    .is_err()
    {
        let c = read_captured(&mut wz_reader);
        let _ = z_sub_guard.child_mut().kill();
        graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
        panic!("wz-router-hat never ingested zenohd's router-native sub within 15s — the router mesh did not carry the subscription\n--- wz-router-hat stderr ---\n{c}");
    }

    // The wz --peer PUBLISHER behind the wz router: whatami=Peer, so its Put arrives
    // on wz's linkstatepeers_net and takes the C4 cross-mesh bridge (NOT the C3b
    // client re-inject). It republishes each app tick, so delivery is self-healing.
    let r1_addr = format!("127.0.0.1:{wz_port}");
    let (mut peer_guard, mut peer_reader, _peer_port) = spawn_on_ephemeral_port(
        &wz_ap_demo_binary(),
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &r1_addr,
            "--publish",
            "demo/key",
        ],
        "peer: listening on 127.0.0.1:",
        "peer-pub",
        tempfile(),
    );

    // Acid test: the pico subscriber behind zenohd receives the wz peer's Put, having
    // crossed wz's cross-mesh bridge into routers_net and out through zenohd.
    let received = wait_for_substring(
        &mut z_sub_reader,
        "Received ('demo/key'",
        Duration::from_secs(20),
    );
    // Transit pin: wz forwarded the Push across the mesh (the peer -> router bridge).
    let transit = received.is_ok().then(|| {
        wait_for_substring(
            &mut wz_reader,
            "router-hat: forwarded mesh data",
            Duration::from_secs(5),
        )
    });

    let _ = peer_guard.child_mut().kill();
    let _ = peer_guard.child_mut().wait();
    let _ = z_sub_guard.child_mut().kill();
    let _ = z_sub_guard.child_mut().wait();
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let wz_captured = read_captured(&mut wz_reader);
    let peer_captured = read_captured(&mut peer_reader);
    let z_sub_captured = read_captured(&mut z_sub_reader);
    eprintln!("--- wz-router-hat stderr ---\n{wz_captured}");
    eprintln!("--- peer-pub stderr ---\n{peer_captured}");
    eprintln!("--- z_sub stdout ---\n{z_sub_captured}");

    received.unwrap_or_else(|c| {
        panic!(
            "pico z_sub behind zenohd never received the wz peer's Put within 20s — \
             the peer-source Put was not bridged cross-mesh (linkstatepeers_net -> \
             routers_net) toward zenohd's router-native sub\n--- z_sub stdout ---\n{c}"
        )
    });
    transit
        .expect("received implies transit was probed")
        .unwrap_or_else(|c| {
            panic!(
                "wz-router-hat never logged 'forwarded mesh data' — the Put reached \
                 the subscriber without transiting wz's router bridge\n--- \
                 wz-router-hat stderr ---\n{c}"
            )
        });
}
