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
//! `LinkstateNetwork` ingest mirrors the FULL-linkstate path, i.e. wz IS a
//! `routing.peer.mode = "linkstate"` peer. The earlier spike put it in a
//! subsystem left at zenoh's `"peer_to_peer"` default, which zenoh's own rule
//! forbids mixing — so `peak 2 node(s)` was the documented consequence of a
//! non-uniform subsystem, not a wall in the demo's mode set. The FIXTURE was
//! what had to change.
//!
//! ## The topology
//!
//! ```text
//!   R  zenohd, router mode  <-- wz's only --connect target
//!   |\
//!   | \
//!   P  W    P = zenohd, mode=peer, LISTENING on its own port
//!           W = wz-ap-demo --peer --autoconnect
//! ```
//!
//! All three run `routing/peer/mode:"linkstate"`. W's argv names R's port and
//! nothing else; P's listen port reaches W only inside R's `LinkStateList`, and
//! the assertion is that W's second face landed on exactly that port.
//!
//! WHO MAY DIAL IS PINNED BY CONFIG, not left to a race. zenoh's own
//! `connect_discovered_peer` sleeps a random 0-100ms before dialing, so a leg
//! asserting `accepted 0` while P's gossip-autoconnect was live would really be
//! asserting that wz reliably wins that backoff — true in practice, flaky by
//! construction. So every leg that asserts wz INITIATED runs P with
//! `scouting/gossip/autoconnect:{router:[],peer:[]}`: P then cannot dial anyone
//! and `accepted 0` is structural. The neuter leg inverts it — P's autoconnect is
//! ON there precisely so the mesh still forms with wz initiating nothing.
//!
//! JOIN ORDER IS NOT A PRECONDITION, and that was measured rather than assumed:
//! in full-linkstate mode `Network::add_link` sends the delta to every existing
//! link (`zenoh/src/net/protocol/network.rs:860-864` — the `whatami == Router`
//! narrowing applies only when `!full_linkstate`), so an already-attached peer is
//! told about a later joiner. Both orders were run and both produce one gossip
//! dial, so this test spawns P and W without an inter-node readiness gate.
//!
//! ## The legs
//!
//!   1. positive — the gossip dial fires exactly once, onto P's LISTEN port,
//!      under the DEFAULT strategy. It also asserts the ROUTER logged no
//!      `unknown link mapping`, the R311y431 propagate regression (below).
//!   2. neuter (`--autoconnect` removed, fixture otherwise untouched) — W still
//!      ingests the same flood and still meshes with P, but W initiates NO dial.
//!      The option-atom pair: the ONLY difference is the flag.
//!   3. control (`--autoconnect` kept, P absent) — nothing to discover, no dial.
//!      Separates "the flag dials" from "a DISCOVERED PEER dials".
//!   4. `--autoconnect-strategy always`, on a fixture where wz's zid is the
//!      LOWER — wz dials the greater-zid peer anyway.
//!   5. `--autoconnect-strategy greater-zid`, same fixture — the very same peer
//!      is declined. The strategy pair: legs 4 and 5 differ in that value alone.
//!   6. `--peer-mode peer-to-peer` in a STOCK subsystem (neither zenohd carries
//!      `routing/peer/mode`) — wz still decodes the gossip flood and dials, and
//!      the router logs no `unknown link mapping`: the `add_link` twin of the
//!      leg-1 regression, since the gossip re-flood relays direct neighbours
//!      only and never taught the router our psid for the new one.
//!   7. `--peer-mode linkstate`, same stock subsystem — the linkstate ingest
//!      rebuilds edges and GCs what the update left unreachable, and a gossip
//!      entry carries no links, so the third party is deleted on arrival and
//!      only the static `--connect` dial happens. The mode pair: without leg 7
//!      `--peer-mode` would be a flag with no demonstrated effect.
//!
//! ## The R311y431 propagate regression, asserted in leg 1
//!
//! wz used to withhold the ENTIRE re-flood from the face an ingest arrived on.
//! zenoh withholds only the `updated` half (`network.rs:661`); `new` nodes ride
//! back out on the source link, because PSID SPACE IS PER-SENDER — the source
//! advertised that node under its own numbering and must still learn ours. With
//! the echo suppressed, wz's next self-entry listing that psid in `links` was
//! unresolvable and the router rejected the edge with `Received LinkState from
//! <zid> with unknown link mapping <psid>`. A pure-zenoh three-node control
//! produced zero such lines, which is what made it wz's bug and not upstream
//! noise. Leg 1 captures the router's log and asserts the line is absent.
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

/// zenohd rejects a leading zero in `--id` (`Invalid id: 01 - Leading 0s are not
/// valid`), so the third party is `1` on the CLI while wz logs the same one-byte
/// id zero-padded as `zid 01`. Same wire value, two spellings; they are named
/// apart because conflating them silently breaks the face-UP needle.
const PEER_ID: &str = "1";
const PEER_ZID_AS_LOGGED: &str = "01";
/// The router's id. Never a gossip dial candidate in any leg: wz already holds a
/// face to it (dialed from argv), so the intent dedups before `Step::Dial`.
const ROUTER_ID: &str = "ee";
/// wz's pinned zid. Only the strategy pair (legs 4/5) depends on its ORDER — it
/// sits below [`HIGH_PEER_ID`] there so `greater-zid` must decline what `always`
/// dials. The other legs run the default `always`, which ignores zids entirely.
const WZ_ZID: &str = "02";
/// A third-party id ABOVE [`WZ_ZID`], for the strategy pair.
const HIGH_PEER_ID: &str = "ff";
/// [`HIGH_PEER_ID`] as wz LOGS it (no leading zero to pad here).
const HIGH_PEER_ZID_AS_LOGGED: &str = "ff";

/// How to spawn one zenohd of the fixture. A param object rather than six
/// positional arguments (the R311lw precedent).
struct ZenohdSpec<'a> {
    label: &'static str,
    port: u16,
    /// Hex id, no leading zero.
    id: &'a str,
    /// `mode:"peer"` when true, zenohd's `mode:"router"` default when false.
    peer_mode: bool,
    /// `-e tcp/127.0.0.1:<port>` seed link, when this node should dial another.
    dial_port: Option<u16>,
    /// Leave zenoh's own gossip-autoconnect ON. `false` pins this node as one
    /// that can never INITIATE, which is what makes a leg's `accepted 0`
    /// structural instead of a bet on zenoh's 0-100ms dial backoff.
    gossip_autoconnect: bool,
    /// Pass `routing/peer/mode:"linkstate"`. `false` leaves the node STOCK, i.e.
    /// on zenoh's own `"peer_to_peer"` default — the subsystem legs 6/7 use to
    /// prove wz can join a mesh nobody configured for it.
    linkstate_subsystem: bool,
}

/// Spawn a zenohd participating in a `routing/peer/mode:"linkstate"` subsystem,
/// block until it is HANDSHAKE-ready, and return its guard plus a readable
/// capture of its log (leg 1 asserts on the router's).
///
/// Every instance carries the uniform peer-mode cfg — a zenohd left at the
/// `"peer_to_peer"` default would be a non-uniform subsystem, which zenoh's own
/// config forbids.
fn spawn_linkstate_zenohd(spec: ZenohdSpec<'_>) -> (ChildGuard, File) {
    let capture = tempfile::tempfile().expect("tempfile for zenohd log");
    let writer = capture.try_clone().expect("dup zenohd log handle");
    let mut command = Command::new(zenohd_binary());
    command
        // Pin the level: leg 1 asserts an ERROR line's ABSENCE, which an
        // inherited `RUST_LOG` could otherwise manufacture by filtering it away.
        .env("RUST_LOG", "z=info")
        .arg("--id")
        .arg(spec.id)
        .arg("-l")
        .arg(format!("tcp/127.0.0.1:{}", spec.port))
        .arg("--no-multicast-scouting")
        .arg("--rest-http-port")
        .arg("none");
    // The `--cfg KEY:VALUE` VALUE is JSON5, so string values are quoted.
    if spec.linkstate_subsystem {
        command.arg("--cfg").arg("routing/peer/mode:\"linkstate\"");
    }
    if spec.peer_mode {
        command.arg("--cfg").arg("mode:\"peer\"");
    }
    if !spec.gossip_autoconnect {
        command
            .arg("--cfg")
            .arg("scouting/gossip/autoconnect:{router:[],peer:[]}");
    }
    if let Some(dial) = spec.dial_port {
        command.arg("-e").arg(format!("tcp/127.0.0.1:{dial}"));
    }
    command.stdout(Stdio::from(writer)).stderr(Stdio::null());
    let label = spec.label;
    let mut guard = ChildGuard::wrap(label, command.spawn().expect("spawn zenohd"));
    if let Err(e) =
        wait_for_tcp_accept_alive(guard.child_mut(), spec.port, ZENOHD_TCP_ACCEPT_BUDGET)
    {
        panic!("{label}: {e}");
    }
    // Close the TCP-accept-vs-handshake-ready gap with a real wz Client session
    // (the shared readiness SSOT); routing mode governs flooding, not Client
    // admission, so the anonymous probe reaches Established either way.
    wait_for_zenohd_handshake_ready(&format!("127.0.0.1:{}", spec.port), || {
        tempfile::tempfile().expect("tempfile for zenohd readiness probe stderr")
    });
    (guard, capture)
}

/// The router of the fixture: `mode:"router"`, no seed link, and no gossip
/// autoconnect of its own (zenoh's router default is the empty matcher anyway —
/// passing it explicitly keeps every node's dial rights stated at the call site).
fn spawn_router(port: u16, linkstate_subsystem: bool) -> (ChildGuard, File) {
    spawn_linkstate_zenohd(ZenohdSpec {
        label: "zenohd (router)",
        port,
        id: ROUTER_ID,
        peer_mode: false,
        dial_port: None,
        gossip_autoconnect: false,
        linkstate_subsystem,
    })
}

/// The THIRD PARTY: a zenohd peer listening on `port` and seeded to the router.
fn spawn_third_party(
    port: u16,
    id: &str,
    router_port: u16,
    may_dial: bool,
    linkstate_subsystem: bool,
) -> (ChildGuard, File) {
    spawn_linkstate_zenohd(ZenohdSpec {
        label: "zenohd (third-party peer)",
        port,
        id,
        peer_mode: true,
        dial_port: Some(router_port),
        gossip_autoconnect: may_dial,
        linkstate_subsystem,
    })
}

/// What `--autoconnect` opt-in a leg gives the wz peer.
enum Autoconnect {
    /// No `--autoconnect` at all.
    Off,
    /// `--autoconnect` with no strategy flag — exercises the DEFAULT, which is
    /// `always` (zenoh's default too).
    DefaultStrategy,
    /// `--autoconnect --autoconnect-strategy <value>`.
    Strategy(&'static str),
}

/// Spawn the wz peer: listen ephemeral, dial ONLY `router_port`, pin the zid.
/// Note what is absent from the argv in every leg — the third party's port.
fn spawn_wz_peer(
    demo: &std::path::Path,
    router_port: u16,
    zid: &str,
    autoconnect: Autoconnect,
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
        .arg(zid);
    let label = match autoconnect {
        Autoconnect::Off => "wz-ap-demo peer (no --autoconnect)",
        Autoconnect::DefaultStrategy => {
            command.arg("--autoconnect");
            "wz-ap-demo peer (--autoconnect, default strategy)"
        }
        Autoconnect::Strategy(s) => {
            command
                .arg("--autoconnect")
                .arg("--autoconnect-strategy")
                .arg(s);
            "wz-ap-demo peer (--autoconnect --autoconnect-strategy)"
        }
    };
    let guard = ChildGuard::wrap(
        label,
        command
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo peer"),
    );
    (guard, stderr)
}

/// The barrier a leg waits on before tearing the fixture down.
///
/// R311y431 — not a style choice. A leg that asserts a link EXISTS must settle on
/// THAT LINK, because the flood which motivates it lands strictly earlier: the
/// foreign peer backs off 0-100ms before dialing, and wz's own dial is a TCP
/// connect plus a handshake after the ingest returns. Settling on the ingest and
/// then asserting `accepted 1` passed in isolation and FAILED as soon as six
/// sibling legs shared the CPU — a real race, fixed rather than retried. A leg
/// asserting a link's ABSENCE has no such event, and the ingest is the right
/// barrier there: the policy decision is synchronous with it.
///
/// `third_party_zid` is the zid as wz LOGS it; matching on `, zid <x>)` accepts
/// the face whichever side dialed, which the neuter leg needs (there the foreign
/// peer dials, so the port is an ephemeral source port, not its listener).
fn settle_needle(assert_a_link: bool, third_party_zid: &str) -> String {
    if assert_a_link {
        format!(", zid {third_party_zid})")
    } else {
        "ingested neighbour link-state".to_string()
    }
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

/// The gossip-dial witness line, with its count.
fn gossip_dial_line(dials: u32) -> String {
    format!("autoconnected to gossip-discovered peer(s) ({dials} dial(s))")
}

// wz-proves: scouting-autoconnect zenohd->wz
// wz-proves: scouting-autoconnect wz->zenohd
//
// BOTH directions, because both are asserted on the one exchange. `zenohd->wz`:
// the only way wz can name P's listen port is by decoding R's LinkStateList,
// which carried P's zid + locators. `wz->zenohd`: wz's own autoconnect policy
// admitted P and wz OPENED the session — P cannot have initiated it, its
// autoconnect is off. Neither claim rests on the other's leg.
#[test]
#[ignore = "binary-dep e2e (2x zenohd + wz-ap-demo --features routing-peer); Layer Z runs via --ignored"]
fn wz_peer_gossip_autoconnects_to_a_zenohd_peer_discovered_through_a_zenohd_router() {
    let demo = wz_ap_demo_binary();
    let (port_res, peer_port) = PortReservation::pick_pair();
    let router_port = port_res.port();

    let (mut router, mut router_log) = spawn_router(router_port, true);
    // may_dial = false: P can never initiate, so `accepted 0` below is structural.
    let (mut peer, _peer_log) = spawn_third_party(peer_port, PEER_ID, router_port, false, true);

    let (mut wz_guard, mut wz_reader) =
        spawn_wz_peer(&demo, router_port, WZ_ZID, Autoconnect::DefaultStrategy);
    drop(port_res);

    // Settle on the face to P — the post-dial barrier. Matching P's LISTEN port
    // here (not merely its zid) also makes the wait itself discriminating.
    let face_needle = format!("UP (peer 127.0.0.1:{peer_port}, zid {PEER_ZID_AS_LOGGED})");
    let face_up = wait_for_substring(&mut wz_reader, &face_needle, Duration::from_secs(20));

    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let captured = read_captured(&mut wz_reader);
    let _ = peer.child_mut().kill();
    let _ = peer.child_mut().wait();
    let _ = router.child_mut().kill();
    let _ = router.child_mut().wait();
    let router_captured = read_captured(&mut router_log);
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
    // forwarder-emitted `DialIntent` reaches. Exactly ONE dial — R is already held
    // (dedup before `Step::Dial`) and P is the only other node in the flood.
    assert!(
        captured.contains(&gossip_dial_line(1)),
        "wz peer must report exactly one gossip-autoconnect dial — the atom's own \
         counter, not the static --connect ledger.\n--- wz peer stderr ---\n{captured}"
    );
    // The DIRECTION: two outbound dials (R from argv, P from gossip) and zero
    // inbound accepts. P's own gossip-autoconnect is disabled, so an accept here
    // could not even come from it — `accepted 0` is a property of the fixture.
    assert_dial_ledger(
        &captured,
        2,
        0,
        "wz must have INITIATED both links; P cannot dial (its autoconnect is off)",
    );

    // R311y431 regression, read off the FOREIGN side: with the source-face echo
    // suppressed, wz's self-entry referenced a psid the router had never been
    // taught, and the router rejected that edge. The absence of this line is what
    // says wz's re-flood now teaches its own psid numbering.
    assert!(
        !router_captured.contains("unknown link mapping"),
        "the router rejected an edge in wz's link-state: wz advertised a psid it had \
         not introduced on that link (the pre-R311y431 propagate bug).\n\
         --- zenohd router log ---\n{router_captured}"
    );
}

// wz-proves: scouting-autoconnect zenohd->wz partial
//
// The option-atom PAIR for the leg above: identical fixture except that
// `--autoconnect` is removed and P is allowed to dial, so the mesh still forms
// with wz initiating nothing. Claimed only `partial` and only in the discovery
// direction, because what this leg establishes is the ABSENCE of the dial.
#[test]
#[ignore = "binary-dep e2e (2x zenohd + wz-ap-demo --features routing-peer); Layer Z runs via --ignored"]
fn wz_peer_without_autoconnect_discovers_the_same_peer_and_dials_nothing() {
    let demo = wz_ap_demo_binary();
    let (port_res, peer_port) = PortReservation::pick_pair();
    let router_port = port_res.port();

    let (mut router, _router_log) = spawn_router(router_port, true);
    // may_dial = true: with wz declining to initiate, P's OWN zenoh autoconnect is
    // the only thing that can form the wz<->P link — which is the point.
    let (mut peer, _peer_log) = spawn_third_party(peer_port, PEER_ID, router_port, true, true);

    let (mut wz_guard, mut wz_reader) = spawn_wz_peer(&demo, router_port, WZ_ZID, Autoconnect::Off);
    drop(port_res);

    // Settle on the FACE, not the ingest: this leg asserts `accepted 1`, i.e.
    // that the foreign peer's own dial LANDED, and that happens after its
    // 0-100ms backoff — well past the flood. See `settle_needle`.
    let ingested = wait_for_substring(
        &mut wz_reader,
        &settle_needle(true, PEER_ZID_AS_LOGGED),
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
            "wz peer never brought up a face to the third-party peer within 20s — the \
             foreign peer's own autoconnect dial never landed, so `accepted 1` below \
             would be a teardown artefact rather than a fact.\n\
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
    // Exactly the one static --connect dial, and one ACCEPT: P's own zenoh
    // autoconnect dialed wz, so the mesh still forms. The flag changed WHO dialed,
    // not whether the mesh exists.
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

    // R alone — the flood carries no node wz is not already attached to.
    let (mut router, _router_log) = spawn_router(router_port, true);

    let (mut wz_guard, mut wz_reader) =
        spawn_wz_peer(&demo, router_port, WZ_ZID, Autoconnect::DefaultStrategy);
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

/// Legs 4/5 share everything but the strategy value, and the third party's zid is
/// ABOVE wz's — the only arrangement in which the two strategies disagree.
/// Returns the wz peer's captured stderr.
fn run_strategy_leg(strategy: &'static str, expects_a_dial: bool) -> String {
    let demo = wz_ap_demo_binary();
    let (port_res, peer_port) = PortReservation::pick_pair();
    let router_port = port_res.port();

    let (mut router, _router_log) = spawn_router(router_port, true);
    // may_dial = false throughout: the question is what WZ decides, so the foreign
    // peer must not be able to form the link on its own and mask the answer.
    let (mut peer, _peer_log) =
        spawn_third_party(peer_port, HIGH_PEER_ID, router_port, false, true);

    let (mut wz_guard, mut wz_reader) =
        spawn_wz_peer(&demo, router_port, WZ_ZID, Autoconnect::Strategy(strategy));
    drop(port_res);

    // The `always` leg asserts a dial and must settle on the FACE; the decline
    // leg has no such event and settles on the flood. See `settle_needle`.
    let ingested = wait_for_substring(
        &mut wz_reader,
        &settle_needle(expects_a_dial, HIGH_PEER_ZID_AS_LOGGED),
        Duration::from_secs(20),
    );

    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let captured = read_captured(&mut wz_reader);
    let _ = peer.child_mut().kill();
    let _ = peer.child_mut().wait();
    let _ = router.child_mut().kill();
    let _ = router.child_mut().wait();
    eprintln!("--- wz peer stderr (strategy {strategy}) ---\n{captured}");

    ingested.unwrap_or_else(|c| {
        panic!(
            "wz peer never ingested a link-state within 20s under strategy \
             `{strategy}` — nothing was discovered, so neither leg's verdict is a \
             policy decision.\n--- wz peer stderr at deadline ---\n{c}"
        )
    });
    captured
}

// wz-proves: scouting-autoconnect wz->zenohd partial
//
// Half of the `--autoconnect-strategy` pair. `always` is zenoh's default
// (`DEFAULT_CONFIG.json5` `autoconnect_strategy`) and, until R311y431, was
// unreachable from this demo — it hardcoded `greater-zid`. Here wz's zid is the
// LOWER, so `always` is the ONLY strategy that produces this dial.
#[test]
#[ignore = "binary-dep e2e (2x zenohd + wz-ap-demo --features routing-peer); Layer Z runs via --ignored"]
fn wz_peer_always_strategy_dials_a_peer_with_a_greater_zid() {
    let captured = run_strategy_leg("always", true);
    assert!(
        captured.contains(&gossip_dial_line(1)),
        "under `always` wz must dial the discovered peer even though ITS zid is the \
         greater — that is exactly what distinguishes the strategy from \
         `greater-zid`.\n--- wz peer stderr ---\n{captured}"
    );
    assert_dial_ledger(
        &captured,
        2,
        0,
        "wz must have initiated both links under `always`",
    );
}

// wz-proves: scouting-autoconnect wz->zenohd partial
//
// The other half: the SAME fixture, the SAME discovered peer, one flag value
// different — and the dial is gone. This is what makes the strategy a real
// option rather than a label.
#[test]
#[ignore = "binary-dep e2e (2x zenohd + wz-ap-demo --features routing-peer); Layer Z runs via --ignored"]
fn wz_peer_greater_zid_strategy_declines_a_peer_with_a_greater_zid() {
    let captured = run_strategy_leg("greater-zid", false);
    assert!(
        !captured.contains("autoconnected to gossip-discovered"),
        "under `greater-zid` wz must DECLINE a discovered peer whose zid is greater \
         than its own; a dial here means the strategy flag is not reaching the \
         policy.\n--- wz peer stderr ---\n{captured}"
    );
    assert_dial_ledger(
        &captured,
        1,
        0,
        "under `greater-zid` only the static --connect dial may happen",
    );
}

/// Legs 6/7: a STOCK zenoh subsystem — no `routing/peer/mode` anywhere, so both
/// zenohd run zenoh's own `peer_to_peer` default — with wz joining under
/// `--peer-mode <mode>`. Returns the wz peer's captured stderr plus the router's.
fn run_subsystem_leg(wz_peer_mode: &'static str, expects_a_dial: bool) -> (String, String) {
    let demo = wz_ap_demo_binary();
    let (port_res, peer_port) = PortReservation::pick_pair();
    let router_port = port_res.port();

    let (mut router, mut router_log) = spawn_router(router_port, false);
    // may_dial = false: the question is whether WZ dials, so the foreign peer
    // must not be able to form the link itself and mask the answer.
    let (mut peer, _peer_log) = spawn_third_party(peer_port, PEER_ID, router_port, false, false);

    let stderr = tempfile::tempfile().expect("tempfile for wz peer stderr");
    let writer = stderr.try_clone().expect("dup wz peer stderr handle");
    let mut wz_guard = ChildGuard::wrap(
        "wz-ap-demo peer (--peer-mode)",
        Command::new(&demo)
            .arg("--peer")
            .arg("127.0.0.1:0")
            .arg("--connect")
            .arg(format!("127.0.0.1:{router_port}"))
            .arg("--zid")
            .arg(WZ_ZID)
            .arg("--autoconnect")
            .arg("--peer-mode")
            .arg(wz_peer_mode)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-ap-demo peer"),
    );
    let mut wz_reader = stderr;
    drop(port_res);

    // The gossip-mode leg asserts a dial and must settle on the FACE; the
    // wrong-mode leg has no such event and settles on the flood.
    let ingested = wait_for_substring(
        &mut wz_reader,
        &settle_needle(expects_a_dial, PEER_ZID_AS_LOGGED),
        Duration::from_secs(20),
    );

    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let captured = read_captured(&mut wz_reader);
    let _ = peer.child_mut().kill();
    let _ = peer.child_mut().wait();
    let _ = router.child_mut().kill();
    let _ = router.child_mut().wait();
    let router_captured = read_captured(&mut router_log);
    eprintln!("--- wz peer stderr (--peer-mode {wz_peer_mode}) ---\n{captured}");

    ingested.unwrap_or_else(|c| {
        panic!(
            "wz peer never ingested a link-state within 20s under --peer-mode \
             `{wz_peer_mode}` — the stock subsystem's flood did not arrive, so this \
             leg's verdict is not a mode decision.\n\
             --- wz peer stderr at deadline ---\n{c}"
        )
    });
    (captured, router_captured)
}

// wz-proves: scouting-autoconnect zenohd->wz
// wz-proves: scouting-autoconnect wz->zenohd
//
// The claim this leg adds over leg 1 is the SUBSYSTEM: nothing here is
// configured for wz. Both zenohd run zenoh's own defaults, and wz still decodes
// the gossip flood, learns the third party's locators and dials it — so the
// autoconnect policy is proven in the mode a stock zenoh deployment actually
// runs, not only in the one wz was written for.
#[test]
#[ignore = "binary-dep e2e (2x stock zenohd + wz-ap-demo --features routing-peer); Layer Z runs via --ignored"]
fn wz_peer_in_gossip_mode_autoconnects_inside_a_stock_zenoh_subsystem() {
    let (captured, router_captured) = run_subsystem_leg("peer-to-peer", true);
    assert!(
        captured.contains(&gossip_dial_line(1)),
        "wz must gossip-autoconnect inside a STOCK (peer_to_peer) subsystem under \
         --peer-mode peer-to-peer.\n--- wz peer stderr ---\n{captured}"
    );
    assert_dial_ledger(
        &captured,
        2,
        0,
        "wz must have INITIATED both links; the foreign peer cannot dial",
    );
    // The R311y431 add_link twin of leg 1's propagate regression: in GOSSIP mode
    // the new neighbour must be introduced by the 2-entry delta unconditionally,
    // since the gossip re-flood relays direct neighbours only and never taught the
    // router our psid for it.
    assert!(
        !router_captured.contains("unknown link mapping"),
        "the router rejected an edge in wz's gossip-mode link-state: the new \
         neighbour's psid was never introduced on that link.\n\
         --- zenohd router log ---\n{router_captured}"
    );
}

// wz-proves: scouting-autoconnect zenohd->wz partial
//
// The mode PAIR: the same stock subsystem, the same flood, wz in the WRONG mode.
// The linkstate ingest rebuilds edges and then GCs whatever the update left
// unreachable — and a gossip entry carries no links, so the third party is
// unreachable by construction and is deleted the moment it arrives. Without this
// half, `--peer-mode` would be a flag with no demonstrated effect.
#[test]
#[ignore = "binary-dep e2e (2x stock zenohd + wz-ap-demo --features routing-peer); Layer Z runs via --ignored"]
fn wz_peer_in_linkstate_mode_discovers_nothing_in_a_stock_zenoh_subsystem() {
    let (captured, _router) = run_subsystem_leg("linkstate", false);
    assert!(
        !captured.contains("autoconnected to gossip-discovered"),
        "under --peer-mode linkstate in a gossip subsystem wz must NOT dial: the \
         reachability GC removes the announcement before it can become a \
         candidate.\n--- wz peer stderr ---\n{captured}"
    );
    assert_dial_ledger(
        &captured,
        1,
        0,
        "in the wrong mode only the static --connect dial may happen",
    );
}
