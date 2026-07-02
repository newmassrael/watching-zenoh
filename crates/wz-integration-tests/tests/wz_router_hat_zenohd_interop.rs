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
//! Two legs, STAGED so a failure localises (topology before data):
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
//! SCOPE — what this does NOT yet cover (the cross-impl router tier is a large
//! surface; this is the first, deliberately-2-node slice, mirroring how the
//! wz<->wz mesh suite staged its own coverage):
//!   * ONE data direction — pub-behind-zenohd -> sub-behind-wz only; the reverse
//!     (pub behind wz -> sub behind zenohd) is untested.
//!   * DATA-push only — no cross-impl query/reply federation (the wz<->wz mesh
//!     has that as its test #6; the zenohd twin does not exist yet).
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
    graceful_terminate, read_captured, spawn_on_ephemeral_port, spawn_publishing_zpub,
    spawn_subscribed_zsub, spawn_zenohd, wait_for_substring, wz_ap_demo_binary,
    zenoh_pico_cli_binary, PortReservation,
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
