// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `scouting-autoconnect` cross-impl interop: a wz PEER learns a THIRD-PARTY
//! zenohd peer off a zenohd router's link-state flood and DIALS it, with the
//! third party's address never appearing in the wz process's argv.
//!
//! ## Why this needed a three-node topology, and why the earlier blocker was wrong
//!
//! The witness (`AcceptLoopSummary::gossip_dialed`, incremented only in the
//! `Step::Dial` arm reachable through a forwarder-emitted `DialIntent`) has
//! existed since R311y423, but no cross-impl leg drove it. That round recorded
//! the reason as a topology impossibility — "zenoh floods link-state on the
//! ROUTER tier, so a wz PEER attachment never receives a dialable third party" —
//! measured as a wz peer seeing only `peak 2 node(s)` beside a zenohd.
//!
//! The measurement was real; the explanation was not. zenoh's peer routing mode
//! is a SUBSYSTEM-WIDE setting, not a per-node one: `routing.peer.mode` selects
//! the whole hat (`zenoh/src/net/routing/hat/mod.rs:275-281` — `"linkstate"` ->
//! `linkstate_peer::HatCode`, otherwise `p2p_peer::HatCode`), and zenoh's own
//! config documents that it "needs to be set to the same value in all peers and
//! routers of the subsystem" (`DEFAULT_CONFIG.json5:240-241`). wz's
//! `LinkstateNetwork` ingest mirrors the FULL-linkstate path (`process_linkstates`
//! + edge rebuild + `remove_detached_nodes`, `wz-routing-graph/src/lib.rs`), i.e.
//! wz IS a `routing.peer.mode = "linkstate"` peer. The earlier spike put it in a
//! subsystem left at zenoh's `"peer_to_peer"` default, which zenoh's own rule
//! forbids mixing — so `peak 2 node(s)` was the documented consequence of a
//! non-uniform subsystem, not a wall in the demo's mode set. The fix is the
//! FIXTURE's configuration, and it needs no wz product code.
//!
//! ## The topology
//!
//! ```text
//!   R  zenohd, router mode, zid ff  <-- wz's only --connect target
//!   |\
//!   | \
//!   P  W    P = zenohd, mode=peer, zid 01, LISTENING on its own port
//!           W = wz-ap-demo --peer --autoconnect, zid 02
//! ```
//!
//! All three run `routing/peer/mode:"linkstate"`. W's argv names R's port and
//! nothing else; P's listen port reaches W only inside R's `LinkStateList`, and
//! the assertion below is that W's second face landed on exactly that port.
//!
//! JOIN ORDER IS NOT A PRECONDITION, and that was measured rather than assumed:
//! in full-linkstate mode `Network::add_link` sends the delta to every existing
//! link (`zenoh/src/net/protocol/network.rs:860-864` — the `whatami == Router`
//! narrowing applies only when `!full_linkstate`), so an already-attached peer is
//! told about a later joiner. Both orders were run and both produce one gossip
//! dial, so this test spawns P and W without an inter-node readiness gate.
//!
//! ## Why the zids are pinned
//!
//! The demo builds its policy with `AutoConnectStrategy::GreaterZid`
//! (`wz-ap-demo/src/runner.rs`), NOT zenoh's `always` default
//! (`DEFAULT_CONFIG.json5` `autoconnect_strategy`), so wz dials a discovered node
//! only when its own zid is the greater. Pinning `P=01 < W=02 < R=ff` makes the
//! candidate set exactly {P}: P is admitted, R is declined by the tie-break (and
//! is already connected anyway). Random zids would make the dial COUNT
//! order-of-magnitude flaky, which is why every id here is explicit.
//!
//! ## The three legs
//!
//!   1. positive — the gossip dial fires exactly once, onto P's LISTEN port.
//!   2. neuter (`--autoconnect` removed, topology untouched) — W still ingests
//!      the same flood and still meshes with P, but W initiates NO dial. This is
//!      the option-atom pair: the ONLY difference is the flag.
//!   3. control (`--autoconnect` kept, P absent) — nothing to discover, no dial.
//!      Separates "the flag emits a dial" from "a discovered peer emits a dial".
//!
//! Requires `wz-ap-demo` built with `--features routing-peer` and a `zenohd`
//! binary (`WZ_ZENOHD_BIN` or `scripts/build-zenohd.sh`). `#[ignore]` binary-dep
//! e2e; run via Layer Z / `--ignored`, `--test-threads=1` for per-leg zenohd
//! isolation.

use std::fs::File;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_substring, wait_for_tcp_accept_alive,
    wait_for_zenohd_handshake_ready, wz_ap_demo_binary, zenohd_binary, ChildGuard, PortReservation,
    ZENOHD_TCP_ACCEPT_BUDGET,
};

/// The three pinned zenoh ids. `GreaterZid` compares them, so their ORDER is the
/// fixture's control over which node is a dial candidate: W dials P (02 > 01) and
/// declines R (02 < ff). zenohd rejects a leading zero in `--id`, hence `1` and
/// not `01` — the byte on the wire is the same.
const ROUTER_ID: &str = "ff";
const PEER_ID: &str = "1";
const WZ_ZID: &str = "02";

/// The zid as wz PRINTS it for a remote face (zero-padded hex), which is what the
/// face-UP assertions match on. Distinct from [`PEER_ID`] because zenohd's CLI and
/// wz's log format disagree on leading zeros for the same 1-byte id.
const PEER_ZID_AS_LOGGED: &str = "01";

/// Spawn a zenohd participating in a `routing/peer/mode:"linkstate"` subsystem and
/// block until it is HANDSHAKE-ready.
///
/// `peer_mode` selects `mode:"peer"` over zenohd's `mode:"router"` default;
/// `dial_port`, when set, adds the `-e` seed link. Every instance pins `--id` (see
/// the module doc on `GreaterZid`) and carries the uniform peer-mode cfg — a
/// zenohd left at the `"peer_to_peer"` default would be a non-uniform subsystem,
/// which zenoh's own config forbids.
fn spawn_linkstate_zenohd(
    label: &'static str,
    port: u16,
    id: &str,
    peer_mode: bool,
    dial_port: Option<u16>,
) -> ChildGuard {
    let mut command = Command::new(zenohd_binary());
    command
        .arg("--id")
        .arg(id)
        .arg("-l")
        .arg(format!("tcp/127.0.0.1:{port}"))
        .arg("--no-multicast-scouting")
        .arg("--rest-http-port")
        .arg("none")
        // The `--cfg KEY:VALUE` VALUE is JSON5, so string values are quoted.
        .arg("--cfg")
        .arg("routing/peer/mode:\"linkstate\"");
    if peer_mode {
        command.arg("--cfg").arg("mode:\"peer\"");
    }
    if let Some(dial) = dial_port {
        command.arg("-e").arg(format!("tcp/127.0.0.1:{dial}"));
    }
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let mut guard = ChildGuard::wrap(label, command.spawn().expect("spawn zenohd"));
    if let Err(e) = wait_for_tcp_accept_alive(guard.child_mut(), port, ZENOHD_TCP_ACCEPT_BUDGET) {
        panic!("{label}: {e}");
    }
    // Close the TCP-accept-vs-handshake-ready gap with a real wz Client session
    // (the shared readiness SSOT); routing mode governs flooding, not Client
    // admission, so the anonymous probe reaches Established either way.
    wait_for_zenohd_handshake_ready(&format!("127.0.0.1:{port}"), || {
        tempfile::tempfile().expect("tempfile for zenohd readiness probe stderr")
    });
    guard
}

/// Spawn the wz peer: listen ephemeral, dial ONLY `router_port`, pin the zid, and
/// opt into gossip-autoconnect per `autoconnect`. Note what is absent from the
/// argv in every leg — P's port. Returns the guard plus the readable capture.
fn spawn_wz_peer(
    demo: &std::path::Path,
    router_port: u16,
    autoconnect: bool,
) -> (ChildGuard, File) {
    let stderr = tempfile::tempfile().expect("tempfile for wz peer stderr");
    let writer = stderr.try_clone().expect("dup wz peer stderr handle");
    let mut command = Command::new(demo);
    command
        .arg("--peer")
        .arg("127.0.0.1:0")
        .arg("--connect")
        .arg(format!("127.0.0.1:{router_port}"))
        .arg("--zid")
        .arg(WZ_ZID);
    if autoconnect {
        command.arg("--autoconnect");
    }
    let guard = ChildGuard::wrap(
        if autoconnect {
            "wz-ap-demo peer (--autoconnect)"
        } else {
            "wz-ap-demo peer (no --autoconnect)"
        },
        command
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo peer"),
    );
    (guard, stderr)
}

/// The demo's shutdown summary reports `dialed <n>, accepted <m>`. Both needles
/// are comma-bounded so `dialed 1,` cannot match inside `dialed 12,`.
fn assert_dial_ledger(captured: &str, dialed: u32, accepted: u32, why: &str) {
    let needle = format!("dialed {dialed}, accepted {accepted},");
    assert!(
        captured.contains(&needle),
        "{why}\nexpected the peer-loop summary to report '{needle}'\n\
         --- wz peer stderr ---\n{captured}"
    );
}

// wz-proves: scouting-autoconnect zenohd->wz
// wz-proves: scouting-autoconnect wz->zenohd
//
// BOTH directions, because both are asserted on the one exchange. `zenohd->wz`:
// the only way W can name P's listen port is by decoding R's LinkStateList, which
// carried P's zid + locators. `wz->zenohd`: W's own autoconnect policy admitted P
// and W OPENED the session — the face-UP line reports P's zid, so a foreign peer
// completed the handshake W initiated. Neither claim rests on the other's leg.
#[test]
#[ignore = "binary-dep e2e (2x zenohd + wz-ap-demo --features routing-peer); Layer Z runs via --ignored"]
fn wz_peer_gossip_autoconnects_to_a_zenohd_peer_discovered_through_a_zenohd_router() {
    let demo = wz_ap_demo_binary();
    let (port_res, peer_port) = PortReservation::pick_pair();
    let router_port = port_res.port();

    // R — the router W dials, and the only address in W's argv.
    let mut router = spawn_linkstate_zenohd(
        "zenohd (linkstate router)",
        router_port,
        ROUTER_ID,
        false,
        None,
    );
    // P — the THIRD PARTY: a zenohd peer that listens on `peer_port` and seeds
    // itself to R. W is never told this port.
    let mut peer = spawn_linkstate_zenohd(
        "zenohd (linkstate peer)",
        peer_port,
        PEER_ID,
        true,
        Some(router_port),
    );

    let (mut wz_guard, mut wz_reader) = spawn_wz_peer(&demo, router_port, true);
    drop(port_res);

    // Settle on the face to P — the post-dial barrier. Matching P's LISTEN port
    // here (not merely its zid) also makes the wait itself discriminating: a face
    // to P on any OTHER port would be P dialing W, which is not this atom.
    let face_needle = format!("UP (peer 127.0.0.1:{peer_port}, zid {PEER_ZID_AS_LOGGED})");
    let face_up = wait_for_substring(&mut wz_reader, &face_needle, Duration::from_secs(20));

    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let captured = read_captured(&mut wz_reader);
    let _ = peer.child_mut().kill();
    let _ = peer.child_mut().wait();
    let _ = router.child_mut().kill();
    let _ = router.child_mut().wait();
    eprintln!("--- wz peer stderr ---\n{captured}");

    // Diagnostics first, then assert.
    face_up.unwrap_or_else(|c| {
        panic!(
            "wz peer never brought up a face to the third-party zenohd peer on \
             127.0.0.1:{peer_port} within 20s — either R's LinkStateList did not carry \
             P's locators, or the autoconnect policy declined it.\n\
             --- wz peer stderr at deadline ---\n{c}"
        )
    });

    // THE witness: `gossip_dialed > 0`, incremented only in the `Step::Dial` arm a
    // forwarder-emitted `DialIntent` reaches. Exactly ONE dial — the zid pinning
    // makes P the only admitted candidate, so a second would mean the policy
    // admitted something it should not have.
    assert!(
        captured.contains("autoconnected to gossip-discovered peer(s) (1 dial(s))"),
        "wz peer must report exactly one gossip-autoconnect dial — the atom's own \
         counter, not the static --connect ledger.\n--- wz peer stderr ---\n{captured}"
    );
    // The DIRECTION: two outbound dials (R from argv, P from gossip) and zero
    // inbound accepts. This is what makes the claim `wz->zenohd`: had P dialed W
    // instead, the mesh would look the same to a liveness check but `accepted`
    // would be 1 and wz would have initiated nothing.
    assert_dial_ledger(
        &captured,
        2,
        0,
        "wz must have INITIATED both links; an accept here means the foreign peer \
         dialed wz and the gossip dial did not happen",
    );
}

// wz-proves: scouting-autoconnect zenohd->wz partial
//
// The option-atom PAIR for the leg above: identical fixture, `--autoconnect`
// removed. Claimed only `partial` and only in the discovery direction, because
// what this leg establishes is the ABSENCE of the dial, not a new capability.
#[test]
#[ignore = "binary-dep e2e (2x zenohd + wz-ap-demo --features routing-peer); Layer Z runs via --ignored"]
fn wz_peer_without_autoconnect_discovers_the_same_peer_and_dials_nothing() {
    let demo = wz_ap_demo_binary();
    let (port_res, peer_port) = PortReservation::pick_pair();
    let router_port = port_res.port();

    let mut router = spawn_linkstate_zenohd(
        "zenohd (linkstate router)",
        router_port,
        ROUTER_ID,
        false,
        None,
    );
    let mut peer = spawn_linkstate_zenohd(
        "zenohd (linkstate peer)",
        peer_port,
        PEER_ID,
        true,
        Some(router_port),
    );

    // The ONLY difference from the positive leg.
    let (mut wz_guard, mut wz_reader) = spawn_wz_peer(&demo, router_port, false);
    drop(port_res);

    // Settle on the INGEST, not on a face: the flood must have ARRIVED before the
    // teardown, or "no dial" would be a premature-shutdown false negative rather
    // than a policy decision.
    let ingested = wait_for_substring(
        &mut wz_reader,
        "ingested neighbour link-state",
        Duration::from_secs(20),
    );

    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let captured = read_captured(&mut wz_reader);
    let _ = peer.child_mut().kill();
    let _ = peer.child_mut().wait();
    let _ = router.child_mut().kill();
    let _ = router.child_mut().wait();
    eprintln!("--- wz peer stderr ---\n{captured}");

    ingested.unwrap_or_else(|c| {
        panic!(
            "wz peer never ingested a link-state within 20s — the flood did not arrive, \
             so this leg cannot distinguish 'policy declined' from 'nothing to decline'.\n\
             --- wz peer stderr at deadline ---\n{c}"
        )
    });

    // Discovery is UNCHANGED — the same flood, the same topology. Only the dial is
    // gone. Without this half the leg would not prove the flag is what moved.
    assert!(
        captured.contains("learned mesh topology"),
        "wz peer must still learn the topology without --autoconnect — discovery is \
         not what the flag gates.\n--- wz peer stderr ---\n{captured}"
    );
    assert!(
        !captured.contains("autoconnected to gossip-discovered"),
        "wz peer must report NO gossip-autoconnect dial without --autoconnect; if this \
         fires, the positive leg's witness is not bound to the policy.\n\
         --- wz peer stderr ---\n{captured}"
    );
    // Exactly the one static --connect dial. `accepted 1` is asserted too: P's own
    // zenoh autoconnect (whose default strategy IS `always`) dials W, so the mesh
    // still forms — the flag changed WHO dialed, not whether the mesh exists.
    assert_dial_ledger(
        &captured,
        1,
        1,
        "without --autoconnect wz must dial only its argv target and ACCEPT the \
         foreign peer's own autoconnect dial",
    );
}

// wz-proves: scouting-autoconnect zenohd->wz partial
//
// The second control: the flag is ON but there is no third party. Separates "the
// flag emits a dial" from "a DISCOVERED PEER emits a dial" — without it, a build
// that dialed on the flag alone would still pass the positive leg's counter.
#[test]
#[ignore = "binary-dep e2e (zenohd + wz-ap-demo --features routing-peer); Layer Z runs via --ignored"]
fn wz_peer_with_autoconnect_and_no_third_party_dials_nothing() {
    let demo = wz_ap_demo_binary();
    let port_res = PortReservation::pick();
    let router_port = port_res.port();

    // R alone — nothing for the policy to discover beyond the node wz already
    // dialed from argv (and `GreaterZid` declines it: 02 < ff).
    let mut router = spawn_linkstate_zenohd(
        "zenohd (linkstate router)",
        router_port,
        ROUTER_ID,
        false,
        None,
    );

    let (mut wz_guard, mut wz_reader) = spawn_wz_peer(&demo, router_port, true);
    drop(port_res);

    let ingested = wait_for_substring(
        &mut wz_reader,
        "ingested neighbour link-state",
        Duration::from_secs(20),
    );

    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let captured = read_captured(&mut wz_reader);
    let _ = router.child_mut().kill();
    let _ = router.child_mut().wait();
    eprintln!("--- wz peer stderr ---\n{captured}");

    ingested.unwrap_or_else(|c| {
        panic!(
            "wz peer never ingested R's link-state within 20s — with no flood at all \
             this leg proves nothing about the policy.\n\
             --- wz peer stderr at deadline ---\n{c}"
        )
    });

    assert!(
        !captured.contains("autoconnected to gossip-discovered"),
        "wz peer must report NO gossip-autoconnect dial when the flood carries no \
         admissible third party — the counter must bind to a DISCOVERED peer, not to \
         the --autoconnect flag.\n--- wz peer stderr ---\n{captured}"
    );
    assert_dial_ledger(
        &captured,
        1,
        0,
        "with no third party wz must dial only its argv target and accept nothing",
    );
}
