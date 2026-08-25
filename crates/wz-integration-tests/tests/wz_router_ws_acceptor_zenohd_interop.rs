// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y376 (accept-symmetry Stage 3) — CROSS-IMPL proof that the MULTI-PEER
//! accept loop (the `--router` / `peer_loop` path, not just the one-shot
//! `--listen` acceptor) accepts a FOREIGN non-tcp (WebSocket) face and brings it
//! to Established.
//!
//! `wz_ws_acceptor_zenohd_interop.rs` (R311y374) proved a zenohd ws dialer
//! Establishes with a wz ONE-SHOT `--listen ws/...` acceptor (the single-session
//! `accept_bound` path). But the multi-peer accept loop that backs `--router` /
//! `--peer` was TCP-ONLY: `bind_endpoint` projected its `BoundListener` to a raw
//! `TcpListener` (`into_tcp`), so a `--router --listen ws/...` surfaced
//! `Unsupported` at bind and no foreign peer could dial a wz router over ws.
//! Stage 3 generalized `FaceSources.listener` to a scheme-keyed `BoundListener`
//! (the loop's `select!` arm accepts each raw connection via
//! `BoundListener::accept_raw`, and the ws SERVER handshake is deferred to the
//! spawned per-face open future so a slow handshake never blocks the loop). This
//! test exercises exactly that new capability against a real zenohd.
//!
//! Topology: `zenohd --ws--> wz --router --listen ws/...`. zenohd DIALS the wz
//! router over ws (zenoh-pico's CLI has no ws client, so zenohd is the only
//! foreign ws dialer — the R311y374 vehicle). The wz router's `accept_loop`
//! accepts the ws connection, runs the RFC6455 server upgrade + the zenoh
//! Init/Open handshake over the ws link, and HOLDS the result as face 0.
//!
//! Witness (`wz-ap-demo router: face 0 UP`): the loop accepted the zenohd ws
//! connection AND completed the full bidirectional zenoh handshake over it — a
//! session cannot reach Established unless the InitSyn/InitAck/OpenSyn/OpenAck
//! round-trips all crossed the accepted ws transport, so a held face over an
//! ACCEPTED ws link is itself the data-carries-over-ws proof at the transport
//! layer (this atom is the accept generalization; data-plane forwarding across a
//! ws-listening router is a later composition).
//!
//! Discriminator / RED: without Stage 3, `--router --listen ws/...` fails at bind
//! (`bind_endpoint` -> `into_tcp()` -> `Unsupported`), so `run_router` returns an
//! error before it can log "router: listening on ..." — `spawn_on_ephemeral_port`
//! then never reads a bound port and the test fails at spawn, before zenohd is
//! even started. So the FIRST step (a ws router that logs it is listening) is
//! already load-bearing on the loop's ws-accept generalization; "face 0 UP" then
//! pins that a FOREIGN dialer was actually held over that ws listener.
//!
//! Requires: `wz-ap-demo` built with `--features ws` + a routing-router mode
//! (Layer Z builds `ws,...,router-hat-router,...`) AND a `zenohd` binary. Runs on
//! the `--ignored` lane like the other binary-dep e2es; the `wz_router_` fn
//! prefix keeps the default Layer E sweep's `--skip wz_router` from catching it
//! against an arbitrary-feature binary.

use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_on_ephemeral_port, spawn_zenohd_ws_dialer,
    wait_for_substring, wz_ap_demo_binary,
};

/// zenohd `--ws-->` wz `--router --listen ws/...`: the multi-peer accept loop
/// accepts + holds a foreign ws face — the Stage-3 (`accept_loop` generalized to
/// `BoundListener`) cross-impl proof in the zenohd->wz (router-acceptor) direction.
// wz-proves: transport-link-ws zenohd->wz
// wz-proves: session-unicast-open zenohd->wz
// wz-proves: routing-router zenohd->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features ws + a routing-router mode + zenohd); runs via --ignored"]
fn wz_router_ws_acceptor_holds_a_zenohd_ws_face() {
    let demo = wz_ap_demo_binary();

    // ── wz router: bind an EPHEMERAL ws port and hold N concurrent peer faces.
    //    Reads the bound port back from the "wz-ap-demo router: listening on
    //    127.0.0.1:<port>; holding ..." line (the "; holding" tail follows the
    //    digits, so the port parse is unaffected). Without Stage 3 this line never
    //    appears — a ws `--router` listen was `Unsupported` at bind — so a spawn
    //    that reaches "listening on" is already the ws-accept RED gate.
    let r_stderr = tempfile::tempfile().expect("tempfile for wz router stderr");
    let (mut r_guard, mut r_reader, ws_port) = spawn_on_ephemeral_port(
        &demo,
        &["--router", "ws/127.0.0.1:0"],
        "router: listening on 127.0.0.1:",
        "the wz --router (ws acceptor)",
        r_stderr,
    );

    // ── zenohd: DIAL the wz ws router over ws. Its tcp listener is unused here (no
    //    pico client on this leg) and its port is OS-assigned, read back from
    //    zenohd's own announcement (R311y411/y412) — no port is ever guessed.
    let wz_ws_endpoint = format!("ws/127.0.0.1:{ws_port}");
    let (mut zenohd, _zenohd_tcp_port) = spawn_zenohd_ws_dialer(&wz_ws_endpoint);

    // Cross-impl witness: the wz router's accept_loop accepted the zenohd ws
    // connection AND completed the RFC6455 upgrade + zenoh handshake over it,
    // holding it as face 0. Established-over-an-accepted-ws-link is the
    // transport-layer data-carries proof (the handshake round-trips crossed the
    // accepted ws transport).
    let face_up = wait_for_substring(&mut r_reader, "face 0 UP", Duration::from_secs(15));

    graceful_terminate(zenohd.child_mut(), Duration::from_secs(5));
    graceful_terminate(r_guard.child_mut(), Duration::from_secs(5));

    let r_captured = read_captured(&mut r_reader);
    eprintln!("--- wz ws router stderr ---\n{r_captured}");

    face_up.unwrap_or_else(|c| {
        panic!(
            "wz --router never logged 'face 0 UP' within 15s — the zenohd ws dial did not reach \
             Established as a held face on the wz router's accept loop (the Stage-3 ws-accept \
             generalization)\n--- wz router stderr ---\n{c}"
        )
    });
}
