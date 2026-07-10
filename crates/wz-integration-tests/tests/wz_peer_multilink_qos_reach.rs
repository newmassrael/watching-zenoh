// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y220 (transport-qos demo reachability) — the DEMO-BINARY prioritized-publish
//! proof: a `--peer` mesh node built `--features transport-qos,transport-multilink`
//! and driven `--max-links 2 --qos --express-high` ORIGINATES its `--publish` data at
//! a non-DEFAULT QoS band (`RealTime`, the HIGH band) through the new
//! `LinkstateForwarder::publish_qos` app path, and the subscriber RECEIVES it over the
//! aggregated QoS multilink session. This makes the y217 `select_link` band routing +
//! y219a per-face band assignment reachable from a real binary — before y220 the
//! forwarder publish API hard-clamped `Priority::DEFAULT`, so an application could
//! never originate a banded Put.
//!
//! Topology (both binaries `--features transport-qos,transport-multilink`, ephemeral
//! ports read back from each peer's listen log):
//!   - peer B: `--peer 127.0.0.1:0 --subscribe demo/qos --max-links 2 --qos` — the
//!     ACCEPT-side subscriber. Aggregates the two INBOUND links A opens into ONE qos
//!     session and subscribes so the session carries real traffic.
//!   - peer A: `--peer 127.0.0.1:0 --connect <B>,<B> --publish demo/qos --max-links 2
//!     --qos --express-high` — the DIAL-side publisher. `--connect <B>,<B>` dials B
//!     TWICE so A aggregates two OUTBOUND links, negotiates qos (per-face priority
//!     bands installed by y219a), and originates its Put at `RealTime` via `publish_qos`.
//!
//! WITNESSES (all deterministic positive log lines, waited-on BEFORE shutdown — the
//! same happens-before the aggregate precedent uses, never a timing margin):
//!   1. both sides `live links now 2` — the aggregation into ONE qos session.
//!   2. peer-A `originating ExpressHigh Put via publish_qos` — proof the `--express-high`
//!      flag drove the NEW `publish_qos` branch (not the DEFAULT `publish` fall-through),
//!      so a green result cannot come from the pre-y220 path.
//!   3. peer-B `received mesh data` — the `RealTime` Put reached B's subscription over
//!      the aggregated qos session (reachability of the whole publish_qos -> fan_out_qos
//!      -> send_network_message_qos -> dispatch_push(priority) -> select_link chain).
//!
//! SCOPE BOUND (explicit, not silent — arbitrated by the pre-code review):
//!   - This e2e proves REACHABILITY of the publish_qos send PATH from the demo binary
//!     (the `--express-high` flag drives `publish_qos`, which drives `select_link`'s band
//!     routing, and the Put is delivered). It does NOT prove that band-based SELECTION was
//!     OBSERVED: a black-box subscriber cannot see which physical link carried a Put, and
//!     a DEFAULT Put over the same aggregated session delivers identically. Band-selection
//!     CORRECTNESS is asserted deterministically in-process by `session_multilink_deploy_e2e`
//!     (y219a, distinct faces) + the `select_link` unit tests.
//!   - Nor does a green result here distinguish qos-ON from qos-OFF: if QoS negotiation
//!     silently failed, the downstream `is_qos()` clamp forces DEFAULT, yet both the
//!     branch-taken witness (keyed off the CLI flag) and `received mesh data` (the
//!     DEFAULT-clamped delivery still succeeds) would still fire. That `is_qos`
//!     negotiation itself is covered by the `is_qos_negotiates_by_and_and_is_lowlatency_exclusive`
//!     lib unit test — this lane must not be read as proof that qos actually engaged.
//!   - It also does NOT prove the y219b joined-secondary DELIVERY fix. B's
//!     `received mesh data` witness is the `data_seen` counter, incremented UPSTREAM of
//!     the `faces.get(inbound)=None` drop gate y219b fixed
//!     (`linkstate_forward::forward_push` / `dispatch_local_subscribers`), so it fires
//!     whether or not the joined->primary resolution is present. The deterministic y219b
//!     guard is the library unit test
//!     `joined_link_inbound_delivers_to_primary_face_local_subscriber_after_register_joined`.
//!   - This 2-peer topology is single-hop, so it does not exercise TRANSIT band
//!     preservation. As of R311y221 a mesh/linkstate-peer relay DOES preserve the
//!     received band on re-forward (`forward_push` threads `FramePayload.priority`
//!     into `fan_out_qos`); the deterministic witness is the library unit test
//!     `forward_push_preserves_the_received_band_on_transit`. R311y224 extended the
//!     same preservation to the router-tier (`forward_push_tier` + the cross-mesh
//!     bridge / client->mesh reinject via `self_publish_into_tier`) and the
//!     switchboard (`RouteTable::forward_push`) transit re-forwards — deterministic
//!     witnesses are the `route_push_preserves_the_received_band_on_transit`
//!     (router) + `forward_push_preserves_the_received_band_on_transit` (switchboard)
//!     unit tests. Only the CLIENT-face egress (`deliver_to_client_subscribers`)
//!     still re-bands to DEFAULT — a named follow-up, deferred (NOT inert:
//!     `is_qos()` is whatami-agnostic, so a QoS-negotiated client would observe it).
//!
//! Requires the binary built `--features transport-qos,transport-multilink` (pulls
//! `routing-peer`, so `--peer` / `--publish` / `--subscribe` / `--qos` /
//! `--express-high` are all available). run-ci's qos-multilink demo lane builds it,
//! then runs this test via the `--ignored` gate like the other binary-dep e2es. The
//! `wz_peer_` fn prefix keeps the default Layer E sweep's `--skip wz_peer` from
//! double-running it on an arbitrary-feature binary. wz<->wz loopback (no pico/zenohd
//! prereq), so no SKIP guard.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, listen_port, read_captured, wait_for_substring, wz_ap_demo_binary,
    ChildGuard,
};

/// Spawn a `--peer` demo on an ephemeral port and wait until it binds, then read the
/// bound port back from its listen log. Returns the guard, its stderr reader, and the
/// port. (Mirrors the `spawn_peer` helper in `wz_peer_multilink_aggregate`.)
fn spawn_peer(label: &str, args: &[&str]) -> (ChildGuard, File, u16) {
    let stderr = tempfile::tempfile().expect("tempfile for peer stderr");
    let writer = stderr.try_clone().expect("dup peer stderr handle");
    let mut reader = stderr;
    let mut guard = ChildGuard::wrap(
        label.to_string(),
        Command::new(wz_ap_demo_binary())
            .args(args)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {label}: {e}")),
    );
    let captured = wait_for_substring(
        &mut reader,
        "peer: listening on 127.0.0.1:",
        Duration::from_secs(5),
    )
    .unwrap_or_else(|c| {
        let _ = guard.child_mut().kill();
        let _ = guard.child_mut().wait();
        panic!(
            "{label} did not bind within 5s (is the binary built with \
             --features transport-qos,transport-multilink?)\n--- {label} stderr ---\n{c}"
        );
    });
    let port = listen_port(&captured);
    (guard, reader, port)
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features transport-qos,transport-multilink); run-ci qos-multilink lane runs via --ignored"]
fn wz_peer_multilink_qos_express_high_publish_reaches_subscriber() {
    // B (accept-side qos subscriber, max_links=2) binds first so A can dial it twice.
    let (mut b_guard, mut b_reader, p_b) = spawn_peer(
        "peer-B",
        &[
            "--peer",
            "127.0.0.1:0",
            "--subscribe",
            "demo/qos",
            "--max-links",
            "2",
            "--qos",
        ],
    );
    let addr_b = format!("127.0.0.1:{p_b}");
    // A dials B TWICE (the same address, comma-separated, not deduped) so it opens two
    // outbound links to the one peer zid and aggregates them into a qos session, then
    // originates its Put at RealTime (the HIGH band) via `--express-high`.
    let dial_twice = format!("{addr_b},{addr_b}");
    let (mut a_guard, mut a_reader, _p_a) = spawn_peer(
        "peer-A",
        &[
            "--peer",
            "127.0.0.1:0",
            "--connect",
            &dial_twice,
            "--publish",
            "demo/qos",
            "--max-links",
            "2",
            "--qos",
            "--express-high",
        ],
    );

    // DETERMINISTIC sync on the witnesses THEMSELVES (each is a positive `log::info!`
    // waited-on before shutdown, so it is in the post-shutdown capture by construction).
    // A joined its two OUTBOUND dials into one qos session:
    let a_agg = wait_for_substring(&mut a_reader, "live links now 2", Duration::from_secs(15));
    // B joined the two INBOUND links (the accept-side twin):
    let b_agg = wait_for_substring(&mut b_reader, "live links now 2", Duration::from_secs(15));
    // A took the publish_qos branch (the `--express-high` flag drove it) — proof the new
    // path, not the DEFAULT `publish` fall-through, is exercised:
    let a_qos = wait_for_substring(
        &mut a_reader,
        "originating ExpressHigh Put via publish_qos",
        Duration::from_secs(15),
    );
    // B received the express-high Put over the aggregated qos session (this wait starts
    // past A's aggregation/publish lines; needs subscription convergence + a publish tick):
    let b_data = wait_for_substring(&mut b_reader, "received mesh data", Duration::from_secs(15));

    // Graceful-shutdown both, then read their FULL captured logs (seek-to-0) for the
    // diagnostics + the formal assertions.
    graceful_terminate(a_guard.child_mut(), Duration::from_secs(5));
    graceful_terminate(b_guard.child_mut(), Duration::from_secs(5));
    let a_captured = read_captured(&mut a_reader);
    let b_captured = read_captured(&mut b_reader);
    eprintln!("--- peer-A stderr ---\n{a_captured}");
    eprintln!("--- peer-B stderr ---\n{b_captured}");

    // Assert. An Err from a sync above means the witness never appeared within 15s — a
    // genuine failure of the qos-publish path, not a flake (each phrase is deterministic,
    // emitted once at establishment / first publish tick).
    a_agg.unwrap_or_else(|c| {
        panic!(
            "peer-A never aggregated its two outbound dials to B into one qos session \
             (no 'live links now 2')\n--- peer-A stderr ---\n{c}"
        )
    });
    b_agg.unwrap_or_else(|c| {
        panic!(
            "peer-B never aggregated the two inbound links from A into one qos session \
             (no 'live links now 2')\n--- peer-B stderr ---\n{c}"
        )
    });
    a_qos.unwrap_or_else(|c| {
        panic!(
            "peer-A never originated its Put via publish_qos — the --express-high flag \
             did not drive the qos-publish branch\n--- peer-A stderr ---\n{c}"
        )
    });
    b_data.unwrap_or_else(|c| {
        panic!(
            "peer-B never received A's express-high published data within 15s — the \
             publish_qos path did not deliver over the aggregated qos session\n\
             --- peer-B stderr ---\n{c}"
        )
    });
    // Belt-and-suspenders on the full capture: the distinctive markers are present on
    // the seek-to-0 capture (the waits above already gated on them; this re-checks so a
    // regression in either surface is caught).
    assert!(
        a_captured.contains("originating ExpressHigh Put via publish_qos"),
        "peer-A capture missing the publish_qos origination marker\n\
         --- peer-A stderr ---\n{a_captured}"
    );
    assert!(
        a_captured.contains("link AGGREGATED to zid"),
        "peer-A capture missing the aggregation marker\n--- peer-A stderr ---\n{a_captured}"
    );
    assert!(
        b_captured.contains("link AGGREGATED to zid"),
        "peer-B capture missing the aggregation marker\n--- peer-B stderr ---\n{b_captured}"
    );
}
