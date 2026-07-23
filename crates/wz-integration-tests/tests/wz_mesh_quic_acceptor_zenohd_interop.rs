// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y407 — §5.1 transport / §5.21 routing — CROSS-IMPL validation of the wz
//! MESH QUIC acceptor: a real `zenohd` DIALS a wz `--peer quic/...` / `--router-hat
//! quic/...` MESH listen and both FEDERATES over it (control plane) AND routes real
//! DATA across it in BOTH directions (data plane), zenohd->wz accept direction.
//!
//! ## What this proves that no prior test does
//!
//! The quic acceptor surface was proven in pieces, but never in THIS composition:
//!
//!   * `wz_quic_acceptor_zenohd_interop` (R311y401): zenohd dials the ONE-SHOT
//!     `--listen quic/...` acceptor (a single observe-forwarder face) and a pico
//!     Put crosses the quic link. That is the one-shot accept path, NOT the mesh
//!     accept loop, and it emits no federation witness.
//!   * `wz_router_ws_acceptor_zenohd_interop` (R311y376): the MESH accept loop
//!     (`--router` / `peer_loop`) accepts a foreign non-tcp face — but over WS, and
//!     it proves face-HOLD only (no federation tier, no data plane).
//!   * `mesh_accept_loop_holds_two_quic_peers` (R311y404): the mesh accept loop
//!     holds two quic faces — but wz<->wz only, so it cannot catch a wire
//!     divergence from the canonical impl.
//!   * `run_peer_admits_a_quic_listen_with_cert_at_bind` /
//!     `run_router_hat_admits_a_quic_listen_with_cert_at_bind` (R311y406): the
//!     `--peer` / `--router-hat` mesh listen threads a cert into its bind — but
//!     BIND-ONLY (an immediately-ready shutdown; no peer ever connects).
//!   * `wz_peer_zenohd_interop` / `wz_router_hat_zenohd_interop`: wz federates AND
//!     routes data with zenohd at the peer / router tier — but wz is the DIALER (wz
//!     `--connect`) and the transport is plain TCP.
//!
//! The uncovered intersection — (mesh accept loop) x (quic) x (cross-impl) x
//! (wz-as-ACCEPTOR), for BOTH the control plane AND real data in BOTH directions —
//! is this file: the FIRST proof that a foreign implementation can JOIN wz's MESH
//! (not just a one-shot acceptor) over an encrypted QUIC transport where wz presents
//! the server cert, AND that real pub/sub data crosses that accepted quic mesh link
//! each way. It exercises the R311y404 deferred-handshake quic accept split
//! (`accept_quic_incoming` / `complete_quic_accept`) INSIDE the mesh accept loop
//! (`peer_loop` / router-hat), driven by a real zenohd dialer and threaded with the
//! R311y406 `--quic-cert` / `--quic-key` plumbing.
//!
//! ## Topology (the dial direction is REVERSED vs the tcp federation legs)
//!
//!   zenohd  ── dials `-e quic/<wz>` ──▶  wz `--peer|--router-hat quic/127.0.0.1:0`
//!
//! wz binds ONLY a quic listen (no tcp listener exists), so there is no non-quic
//! path a session could fall back to: any federation witness or data delivery
//! necessarily crossed the quic link. zenohd trusts wz's self-signed `localhost`
//! cert via `root_ca_certificate` (chain-of-trust is load-bearing — a wrong CA
//! fails the handshake) and disables SAN matching with `verify_name_on_connect:
//! false` for the by-IP dial. zenoh's QUIC link reads this from the SAME
//! `transport.link.tls` config block as the tls link (no separate quic cert block).
//! For the data-plane legs, a zenoh-pico CLI is a plain-TCP client of zenohd (pico
//! has no quic), so the data crosses pico --tcp--> zenohd --quic--> wz (or reverse):
//! every wz<->zenohd hop is quic, and the pico endpoint is the foreign data
//! origin/sink that makes the crossing cross-impl end to end.
//!
//! ## The five legs
//!
//! Control plane (topology federation floor):
//!   1. [`wz_router_hat_federates_with_a_quic_dialing_zenohd`] — wz `--router-hat
//!      quic/...` (`WhatAmI::Router`); a STOCK (default `mode=router`) zenohd dials
//!      it over quic. `routers_net` converges to 2 AND wz DECODES zenohd's
//!      `LinkStateList` OAM (`learned mesh topology`).
//!   2. [`wz_peer_federates_with_a_quic_dialing_linkstate_zenohd`] — wz `--peer
//!      quic/...` (`WhatAmI::Peer`); a `mode=peer` + `routing/peer/mode=linkstate`
//!      zenohd dials it. wz ingests the `linkstatepeers_net` flood AND forms a
//!      MUTUAL edge (`confirmed reciprocal mesh link`), the full-linkstate
//!      discriminator.
//!   3. [`wz_peer_gossip_quic_dialer_yields_no_linkstate_edge`] (NEUTER) — the SAME
//!      wz `--peer quic/...`, but the quic-dialing zenohd runs DEFAULT gossip
//!      (`mode=peer`, no `routing/peer/mode`). wz still `learned mesh topology`
//!      (the gossip self-announcement decodes) but forms NO edge (`0 graph
//!      edge(s)`, reciprocal witness ABSENT) — proving leg 2's reciprocal witness
//!      is LOAD-BEARING over quic and not a green-but-meaningless ingested-only
//!      pass.
//!
//! Data plane (real pub/sub across the accepted quic mesh link, both directions):
//!   4. [`wz_peer_receives_pico_data_across_a_quic_mesh_link`] — wz `--peer quic/...
//!      --subscribe demo/**`; a pico `z_pub` (TCP client of the quic-dialing
//!      linkstate zenohd) publishes `demo/key`. The Put routes pico --tcp-->
//!      zenohd --quic--> wz's subscriber (`received mesh data`) — data INTO wz over
//!      the accepted quic mesh link.
//!   5. [`wz_peer_publishes_data_across_a_quic_mesh_link_to_pico`] — wz `--peer
//!      quic/... --publish demo/key`; a pico `z_sub` (TCP client of the same
//!      zenohd) subscribes `demo/**`. wz's write-filter deactivates on learning the
//!      remote sub over quic, and its Put routes wz --quic--> zenohd --tcp--> the
//!      pico subscriber (`Received ('demo/key'`) — data OUT of wz over the link.
//!
//! ## The discriminator (RED+TWIN) — binds to the R311y406 cert-threading seam
//!
//! Every leg binds a `quic/...` mesh listen WITH `--quic-cert` / `--quic-key`. The
//! quic bind is cert-GATED: revert the R311y406 threading in `run_peer_until` /
//! `run_router_hat_until` (bind cert-free via `AcceptConfig::default`) and
//! `bind_locator` rejects the quic listen at cert-absence ("quic acceptor requires
//! AcceptConfig.quic") — wz never binds, zenohd cannot dial, no face comes up, and
//! neither a federation witness nor any data delivery fires. A tcp listen would
//! need no cert, so the cert requirement itself pins the transport as quic (there
//! is no `(quic)` tag on the mesh listen line — `local_addr_display` renders a bare
//! `host:port` for the mesh path, unlike the one-shot acceptor). Combined with "wz
//! binds ONLY quic", the reverted-cert RED is what makes every witness here
//! load-bearing for the quic MESH accept path specifically, not the shared tcp
//! federation/data code.
//!
//! Requires: `wz-ap-demo` built with `--features router-hat-router,quic`
//! (`router-hat-router` pulls `routing-peer` for `--peer`; `quic` pulls
//! `transport-link-quic`), a STOCK `zenohd` 1.5.0 (quic is in zenoh's default
//! features — no special oracle, unlike the vsock/unixpipe oracles), and the
//! zenoh-pico `z_pub` / `z_sub` CLIs for the data legs (pico has no quic client, so
//! zenohd is the only foreign quic dialer; pico is the foreign TCP data
//! origin/sink). `#[ignore]` binary-dep e2e; runs on Layer Z via `--ignored
//! --test-threads=1`. Each fn name carries the `wz_router` (leg 1) / `wz_peer`
//! (legs 2-5) prefix plus, for legs 1-2, a `zenohd` substring; libtest `--skip` is a
//! test-NAME (not file-name) substring filter, so the default Layer E sweep's
//! `--skip wz_router` / `--skip wz_peer` / `--skip zenohd` keep every leg here from
//! running against an arbitrary-feature binary (a stray `--peer` server would hang
//! to SIGTERM). Keep the `wz_peer` / `wz_router` fn prefix if renaming.

use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_on_ephemeral_port, spawn_publishing_zpub,
    spawn_subscribed_zsub, spawn_zenohd_quic_dialer, wait_for_substring, wait_for_tcp_accept_alive,
    wz_ap_demo_binary, zenoh_pico_cli_binary, zenohd_binary, ChildGuard, ZENOHD_TCP_ACCEPT_BUDGET,
};
use wz_runtime_tokio_test_support::localhost_cert_key_pem;

const KEYEXPR: &str = "demo/key";
/// The payload wz's `--publish` peer emits each app tick (runner.rs
/// `forwarder.publish(key, b"wz-mesh-data")`) — pinned by the data-OUT leg.
const WZ_PUBLISH_PAYLOAD: &str = "wz-mesh-data";

/// Removes the throwaway cert / key / dialer-config files on drop, so an early
/// panic (before the normal teardown) does not leak them — the same hygiene guard
/// as `wz_quic_acceptor_zenohd_interop` / `wz_tls_acceptor_zenohd_interop`.
struct TempFiles(Vec<String>);
impl Drop for TempFiles {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// The stderr/stdout tempfile factory the common pico spawn helpers require (the
/// lib crate cannot depend on the dev-only `tempfile`, so the caller supplies it).
fn tempfile() -> std::fs::File {
    tempfile::tempfile().expect("tempfile for child capture")
}

/// Write wz's self-signed `localhost` cert + key to pid+leg-unique paths and
/// return `(cert_path, key_path, cleanup)`. The cert wz PRESENTS as the quic mesh
/// acceptor AND the root zenohd trusts (a self-signed leaf is its own root). The
/// cleanup guard also unlinks the dialer config the zenohd-dialer helpers write at
/// `<cert>.dialer.zenohd.json5`.
fn write_wz_cert(leg: &str) -> (String, String, TempFiles) {
    let (cert_pem, key_pem) = localhost_cert_key_pem();
    let base = std::env::temp_dir().join(format!("wz-mesh-quic-{leg}-{}", std::process::id()));
    let cert_path = format!("{}.cert.pem", base.display());
    let key_path = format!("{}.key.pem", base.display());
    std::fs::write(&cert_path, &cert_pem).expect("write wz quic cert pem");
    std::fs::write(&key_path, &key_pem).expect("write wz quic key pem");
    let cleanup = TempFiles(vec![
        cert_path.clone(),
        key_path.clone(),
        format!("{cert_path}.dialer.zenohd.json5"),
    ]);
    (cert_path, key_path, cleanup)
}

/// Spawn a wz `--peer quic/127.0.0.1:0` (+ optional extra args, e.g. `--subscribe`
/// / `--publish`) presenting the cert, and read back its ephemeral quic (UDP) port.
/// wz is a pure quic LISTENER (no `--connect`); zenohd dials IN.
fn spawn_wz_peer_quic(
    demo: &std::path::Path,
    cert_path: &str,
    key_path: &str,
    extra: &[&str],
) -> (ChildGuard, std::fs::File, u16) {
    let mut args = vec![
        "--peer",
        "quic/127.0.0.1:0",
        "--quic-cert",
        cert_path,
        "--quic-key",
        key_path,
    ];
    args.extend_from_slice(extra);
    spawn_on_ephemeral_port(
        demo,
        &args,
        "peer: listening on 127.0.0.1:",
        "wz mesh quic peer",
        tempfile(),
    )
}

/// Spawn a `mode=peer` zenohd that DIALS a wz `quic/<ip:port>` mesh listen
/// (`-e quic/<wz>`) while listening on `tcp/<tcp_port>` for a readiness probe AND
/// (for the data legs) a pico TCP client. `linkstate` selects the routing HAT via
/// the wire cfg, exactly as `wz_peer_zenohd_interop::spawn_peer_zenohd`. When
/// `true`, `routing/peer/mode=linkstate` selects the full-linkstate HAT that floods
/// a self-entry with a reciprocal link back to its dial target (so wz forms a
/// MUTUAL edge and pub/sub routes through the peer mesh). When `false`, zenoh's
/// default `peer_to_peer` gossip is left in place (a node-only self-announcement,
/// no reciprocal link) — the NEUTER. The PEER-mode twin of the shared
/// [`spawn_zenohd_quic_dialer`] (default `mode=router`): the config bundles the tls
/// trust block (byte-identical to the router dialer — zenoh's quic link reuses it)
/// with the peer routing mode in one JSON5 config, following the `spawn_peer_zenohd`
/// cfg-custom-zenohd precedent.
fn spawn_zenohd_peer_quic_dialer(
    wz_quic_endpoint: &str,
    tcp_port: u16,
    ca_cert_path: &str,
    linkstate: bool,
) -> ChildGuard {
    let cfg_path = format!("{ca_cert_path}.dialer.zenohd.json5");
    // The tls trust block (chain-of-trust for the by-IP dial) PLUS the peer routing
    // mode, in one JSON5 config. `routing/peer/mode` is included ONLY for the
    // linkstate variant; the gossip neuter leaves zenoh's default `peer_to_peer`.
    let routing = if linkstate {
        ", routing: { peer: { mode: \"linkstate\" } }"
    } else {
        ""
    };
    let cfg = format!(
        "{{ transport: {{ link: {{ tls: {{ \
         root_ca_certificate: {ca_cert_path:?}, verify_name_on_connect: false }} }} }}, \
         mode: \"peer\"{routing} }}"
    );
    std::fs::write(&cfg_path, cfg).expect("write zenohd peer quic dialer config");
    let label = if linkstate {
        "zenohd (linkstate-peer quic dialer)"
    } else {
        "zenohd (gossip-peer quic dialer)"
    };
    let mut command = Command::new(zenohd_binary());
    command
        .arg("-e")
        .arg(wz_quic_endpoint)
        .arg("-l")
        .arg(format!("tcp/127.0.0.1:{tcp_port}"))
        .arg("--config")
        .arg(&cfg_path)
        .arg("--no-multicast-scouting")
        .arg("--rest-http-port")
        .arg("none")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut guard = ChildGuard::wrap(
        label,
        command.spawn().expect("spawn zenohd peer quic dialer"),
    );
    if let Err(e) = wait_for_tcp_accept_alive(guard.child_mut(), tcp_port, ZENOHD_TCP_ACCEPT_BUDGET)
    {
        panic!("{label}: {e}");
    }
    guard
}

/// Leg 1 — the ROUTER-tier federation floor over a QUIC mesh listen. wz
/// `--router-hat quic/...` binds a quic listen presenting the cert; a STOCK
/// (default `mode=router`) zenohd DIALS it over quic and the two routers converge
/// their `routers_net` link-state tier. The reversed-dial, quic-transport analog
/// of `wz_router_hat_federates_with_zenohd_at_router_tier` leg 1.
// wz-proves: transport-link-quic zenohd->wz
// wz-proves: router-hat-router zenohd->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,quic + zenohd); Layer Z runs via --ignored"]
fn wz_router_hat_federates_with_a_quic_dialing_zenohd() {
    let demo = wz_ap_demo_binary();
    let (cert_path, key_path, _cleanup) = write_wz_cert("rh");

    // wz --router-hat: bind an EPHEMERAL quic port presenting the cert. QUIC binds
    // a real UDP socket -> a real IP address, so the bound port reads back from the
    // "router-hat: listening on 127.0.0.1:<port>" line (the mesh listen line has no
    // (quic) tag, unlike the one-shot acceptor).
    let wz_stderr = tempfile();
    let (mut wz_guard, mut wz_reader, quic_port) = spawn_on_ephemeral_port(
        &demo,
        &[
            "--router-hat",
            "quic/127.0.0.1:0",
            "--quic-cert",
            &cert_path,
            "--quic-key",
            &key_path,
        ],
        "router-hat: listening on 127.0.0.1:",
        "wz mesh quic router-hat",
        wz_stderr,
    );

    // zenohd (STOCK, default router) DIALS the wz quic mesh listen over quic
    // (`-e quic/<wz>`, trusting wz's cert), listening on a distinct tcp port for
    // its readiness probe. quic_port is a UDP port; zenohd's tcp listener uses a
    // different protocol namespace, so quic_port+1 cannot collide.
    let zenohd_tcp_port = quic_port.wrapping_add(1).max(1024);
    let wz_quic_endpoint = format!("quic/127.0.0.1:{quic_port}");
    let mut zenohd = spawn_zenohd_quic_dialer(&wz_quic_endpoint, zenohd_tcp_port, &cert_path);

    // Cross-impl witness #1: the router tier converged to 2 nodes over the quic
    // link (self + the quic-dialing zenohd). Fires on `add_link` from the
    // INIT-derived zid+whatami — handshake-satisfiable, so necessary but not
    // sufficient; witness #2 is the load-bearing wire-decode.
    let converged = wait_for_substring(
        &mut wz_reader,
        "router-hat: routers-net converged (2 node(s))",
        Duration::from_secs(15),
    );

    // Graceful shutdown so wz logs its `learned mesh topology` summary.
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let wz_captured = read_captured(&mut wz_reader);
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    eprintln!("--- wz mesh quic router-hat stderr ---\n{wz_captured}");

    converged.unwrap_or_else(|c| {
        panic!(
            "wz --router-hat never converged its router tier to 2 within 15s against \
             a QUIC-dialing zenohd — the mesh quic accept path did not federate at \
             the router tier (did the cert-threaded quic bind fail?)\n\
             --- wz mesh quic router-hat stderr ---\n{c}"
        )
    });
    // Cross-impl witness #2 (load-bearing): wz DECODED >=1 of zenohd's
    // `LinkStateList` OAM floods over the quic link (`forwarder.ingested() > 0`).
    // Convergence is handshake-satisfiable; THIS is what a `LinkStateList` codec
    // divergence — or a broken mesh quic accept — would break.
    assert!(
        wz_captured.contains("router-hat: learned mesh topology"),
        "wz --router-hat converged its router tier over quic but never ingested a \
         `LinkStateList` OAM from zenohd (no 'learned mesh topology' shutdown \
         witness) — the tiers linked at the transport layer but wz did not DECODE \
         zenohd's routers_net link-state wire\n\
         --- wz mesh quic router-hat stderr ---\n{wz_captured}"
    );
}

/// Leg 2 — the PEER-tier federation floor over a QUIC mesh listen. wz `--peer
/// quic/...` binds a quic listen presenting the cert; a `mode=peer` +
/// `routing/peer/mode=linkstate` zenohd DIALS it over quic and floods its
/// `linkstatepeers_net` self-entry with a reciprocal link, so wz forms a MUTUAL
/// graph edge. The reversed-dial, quic-transport analog of
/// `wz_peer_federates_with_zenohd_at_linkstate_tier`.
// wz-proves: transport-link-quic zenohd->wz
// wz-proves: routing-peer zenohd->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,quic + zenohd peer); Layer Z runs via --ignored"]
fn wz_peer_federates_with_a_quic_dialing_linkstate_zenohd() {
    let demo = wz_ap_demo_binary();
    let (cert_path, key_path, _cleanup) = write_wz_cert("pr");

    let (mut wz_guard, mut wz_reader, quic_port) =
        spawn_wz_peer_quic(&demo, &cert_path, &key_path, &[]);

    // zenohd (mode=peer, routing/peer/mode=linkstate) DIALS the wz quic mesh listen.
    let zenohd_tcp_port = quic_port.wrapping_add(1).max(1024);
    let wz_quic_endpoint = format!("quic/127.0.0.1:{quic_port}");
    let mut zenohd =
        spawn_zenohd_peer_quic_dialer(&wz_quic_endpoint, zenohd_tcp_port, &cert_path, true);

    // Settle on the in-run reciprocal-link witness: wz ingested zenohd's linkstate
    // flood over the quic link AND formed the mutual graph edge (the full-linkstate
    // discriminator). This is the deterministic post-ingest barrier.
    let reciprocal = wait_for_substring(
        &mut wz_reader,
        "peer: reciprocal mesh link confirmed",
        Duration::from_secs(15),
    );

    // Graceful shutdown so wz logs its peer-loop summary witnesses.
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let wz_captured = read_captured(&mut wz_reader);
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    eprintln!("--- wz mesh quic peer stderr ---\n{wz_captured}");

    reciprocal.unwrap_or_else(|c| {
        panic!(
            "wz --peer never confirmed a reciprocal mesh link with a QUIC-dialing \
             linkstate zenohd within 15s — the mesh quic accept path did not \
             converge a mutual edge over the wire (did the cert-threaded quic bind \
             fail?)\n--- wz mesh quic peer stderr ---\n{c}"
        )
    });
    // Weak witness: wz decoded SOME zenohd LinkStateList over quic (necessary but
    // not sufficient for the linkstate claim; shared with a gossip peer — see the
    // NEUTER leg, which proves the reciprocal witness below is load-bearing).
    assert!(
        wz_captured.contains("peer: learned mesh topology"),
        "wz --peer summary must report 'learned mesh topology' — it must ingest \
         zenohd's link-state flood over the quic link\n\
         --- wz mesh quic peer stderr ---\n{wz_captured}"
    );
    // Load-bearing witness: wz formed a MUTUAL edge, which ONLY a full-linkstate
    // self-entry (reciprocal link back to wz) produces — the wz-peer <-> zenohd-peer
    // linkstate-tier federation proof over a QUIC mesh listen wz accepted.
    assert!(
        wz_captured.contains("peer: confirmed reciprocal mesh link"),
        "wz --peer summary must report 'confirmed reciprocal mesh link' — federating \
         with a LINKSTATE zenohd peer that dialed the quic mesh listen must form a \
         mutual graph edge (zenohd's self-entry advertises a link back to wz)\n\
         --- wz mesh quic peer stderr ---\n{wz_captured}"
    );
}

/// Leg 3 (NEUTER) — the SAME wz `--peer quic/...` acceptor as leg 2, but the
/// quic-dialing zenohd runs DEFAULT gossip (`mode=peer`, no `routing/peer/mode`).
/// A gossip self-entry carries no reciprocal link, so wz decodes it (`learned mesh
/// topology` still fires — the weak witness is shared) but forms NO mutual edge.
/// This proves leg 2's `confirmed reciprocal mesh link` witness is LOAD-BEARING
/// over quic: it distinguishes a full-linkstate flood from a gossip one, rather
/// than firing on any decoded LinkStateList. The quic analog of
/// `wz_peer_gossip_zenohd_yields_no_linkstate_edge`.
// wz-proves: routing-peer zenohd->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,quic + zenohd gossip peer); Layer Z runs via --ignored"]
fn wz_peer_gossip_quic_dialer_yields_no_linkstate_edge() {
    let demo = wz_ap_demo_binary();
    let (cert_path, key_path, _cleanup) = write_wz_cert("ng");

    let (mut wz_guard, mut wz_reader, quic_port) =
        spawn_wz_peer_quic(&demo, &cert_path, &key_path, &[]);

    // zenohd in DEFAULT gossip peer mode (linkstate=false) DIALS the wz quic listen.
    let zenohd_tcp_port = quic_port.wrapping_add(1).max(1024);
    let wz_quic_endpoint = format!("quic/127.0.0.1:{quic_port}");
    let mut zenohd =
        spawn_zenohd_peer_quic_dialer(&wz_quic_endpoint, zenohd_tcp_port, &cert_path, false);

    // Settle on the INGEST witness (not the reciprocal one — a gossip flood never
    // trips it): wz decoded the gossip self-announcement over the quic link. This
    // guarantees the flood ARRIVED before shutdown, so the "no reciprocal edge"
    // assertion below is a genuine content distinction, not a premature-teardown
    // false negative.
    let ingested = wait_for_substring(
        &mut wz_reader,
        "peer: ingested neighbour link-state",
        Duration::from_secs(15),
    );

    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let wz_captured = read_captured(&mut wz_reader);
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    eprintln!("--- wz mesh quic peer (gossip neuter) stderr ---\n{wz_captured}");

    ingested.unwrap_or_else(|c| {
        panic!(
            "wz --peer never ingested the gossip zenohd's link-state over quic within \
             15s — the gossip self-announcement did not arrive, so the neuter cannot \
             distinguish it from a linkstate flood\n\
             --- wz mesh quic peer (gossip neuter) stderr ---\n{c}"
        )
    });
    // The weak witness FIRES for a gossip peer too — proof that "learned mesh
    // topology" alone does NOT establish linkstate-tier federation.
    assert!(
        wz_captured.contains("peer: learned mesh topology"),
        "wz --peer summary must still report 'learned mesh topology' against a gossip \
         zenohd dialing over quic — it decoded the gossip self-announcement (the weak \
         witness is shared)\n--- wz mesh quic peer (gossip neuter) stderr ---\n{wz_captured}"
    );
    // The load-bearing witness is ABSENT: a gossip self-entry carries no reciprocal
    // link, so wz forms NO mutual edge. This is what makes leg 2's reciprocal
    // witness load-bearing over the quic mesh accept path.
    assert!(
        !wz_captured.contains("peer: confirmed reciprocal mesh link"),
        "wz --peer must NOT report 'confirmed reciprocal mesh link' against a GOSSIP \
         zenohd dialing over quic — a peer_to_peer self-entry advertises no link \
         back, so no mutual edge can form; leg 2's reciprocal witness would be \
         green-but-meaningless if it fired here\n\
         --- wz mesh quic peer (gossip neuter) stderr ---\n{wz_captured}"
    );
    // Precise corroboration: the shutdown summary reports zero graph edges,
    // comma-bounded on BOTH sides so a multi-digit count cannot spuriously satisfy.
    assert!(
        wz_captured.contains(", 0 graph edge(s),"),
        "wz --peer summary must report '0 graph edge(s)' against a gossip zenohd \
         dialing over quic (node learned, no mutual edge)\n\
         --- wz mesh quic peer (gossip neuter) stderr ---\n{wz_captured}"
    );
}

/// Leg 4 — the DATA plane INTO wz over the accepted quic mesh link. wz `--peer
/// quic/... --subscribe demo/**` hosts a local subscriber; a pico `z_pub` (plain
/// TCP client of the quic-dialing linkstate zenohd) publishes `demo/key`. The Put
/// routes pico --tcp--> zenohd --quic--> wz's subscriber, so wz's `received mesh
/// data` witness proves real data crossed the accepted quic mesh link from a
/// foreign publisher. wz binds ONLY quic, so the zenohd<->wz hop is necessarily
/// quic; pico is the foreign data ORIGIN behind zenohd.
// wz-proves: transport-link-quic zenohd->wz
// wz-proves: routing-peer zenohd->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,quic + zenohd peer + zenoh-pico z_pub); Layer Z runs via --ignored"]
fn wz_peer_receives_pico_data_across_a_quic_mesh_link() {
    let demo = wz_ap_demo_binary();
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let (cert_path, key_path, _cleanup) = write_wz_cert("di");

    // wz --peer quic listen hosting a LOCAL subscriber on demo/**. Its subscription
    // advertises across the peer mesh (over quic) into zenohd's routing table.
    let (mut wz_guard, mut wz_reader, quic_port) =
        spawn_wz_peer_quic(&demo, &cert_path, &key_path, &["--subscribe", "demo/**"]);

    let zenohd_tcp_port = quic_port.wrapping_add(1).max(1024);
    let wz_quic_endpoint = format!("quic/127.0.0.1:{quic_port}");
    let mut zenohd =
        spawn_zenohd_peer_quic_dialer(&wz_quic_endpoint, zenohd_tcp_port, &cert_path, true);

    // Barrier: the mesh converged over quic (wz formed the mutual edge). Only then
    // has wz's subscription had a mesh to advertise across, so zenohd can route a
    // publisher's Put back to it. The 30-Put burst below absorbs the residual
    // route-install slack after this.
    let converged = wait_for_substring(
        &mut wz_reader,
        "peer: reciprocal mesh link confirmed",
        Duration::from_secs(15),
    );
    if converged.is_err() {
        let c = read_captured(&mut wz_reader);
        graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
        let _ = zenohd.child_mut().kill();
        let _ = zenohd.child_mut().wait();
        panic!(
            "wz <-> zenohd peer mesh never converged over quic within 15s — the data \
             leg cannot start\n--- wz stderr ---\n{c}"
        );
    }

    // pico z_pub: a plain-TCP client of ZENOHD, publishing demo/key as a self-
    // healing burst (~30 puts). pico's `-e` needs a scheme'd locator.
    let z_pub_endpoint = format!("tcp/127.0.0.1:{zenohd_tcp_port}");
    let mut z_pub_guard = spawn_publishing_zpub(
        &z_pub,
        KEYEXPR,
        "pico-quic-mesh-into-wz",
        &z_pub_endpoint,
        "zenohd",
        tempfile,
    );

    // The acid test: wz's subscriber received a Put over the accepted quic mesh
    // link. `received mesh data` is a deterministic shutdown counterpart to the
    // in-run app-tick log (runner.rs), emitted unconditionally on `data_seen > 0`.
    let received = wait_for_substring(
        &mut wz_reader,
        "peer: received mesh data",
        Duration::from_secs(15),
    );

    let _ = z_pub_guard.child_mut().kill();
    let _ = z_pub_guard.child_mut().wait();
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let wz_captured = read_captured(&mut wz_reader);
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    eprintln!("--- wz mesh quic peer (data into) stderr ---\n{wz_captured}");

    received.unwrap_or_else(|c| {
        panic!(
            "wz --peer subscriber never received the pico Put within 15s — data did \
             not cross the accepted quic mesh link (pico -> zenohd -> quic -> wz). \
             Did the subscription advertise over quic, or the route install?\n\
             --- wz stderr ---\n{c}"
        )
    });
}

/// Leg 5 — the DATA plane OUT of wz over the accepted quic mesh link. wz `--peer
/// quic/... --publish demo/key` originates a Put each app tick; a pico `z_sub`
/// (plain TCP client of the quic-dialing linkstate zenohd) subscribes `demo/**`.
/// wz's write-filter deactivates when it learns the remote subscription over the
/// quic mesh, and its Put routes wz --quic--> zenohd --tcp--> the pico subscriber,
/// which prints `Received ('demo/key': 'wz-mesh-data')`. This proves real data
/// crossed the accepted quic mesh link OUT of wz to a foreign subscriber — the
/// reverse direction of leg 4.
// wz-proves: transport-link-quic zenohd->wz
// wz-proves: routing-peer zenohd->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,quic + zenohd peer + zenoh-pico z_sub); Layer Z runs via --ignored"]
fn wz_peer_publishes_data_across_a_quic_mesh_link_to_pico() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let (cert_path, key_path, _cleanup) = write_wz_cert("do");

    // wz --peer quic listen ORIGINATING a Put on demo/key each app tick.
    let (mut wz_guard, mut wz_reader, quic_port) =
        spawn_wz_peer_quic(&demo, &cert_path, &key_path, &["--publish", KEYEXPR]);

    let zenohd_tcp_port = quic_port.wrapping_add(1).max(1024);
    let wz_quic_endpoint = format!("quic/127.0.0.1:{quic_port}");
    let mut zenohd =
        spawn_zenohd_peer_quic_dialer(&wz_quic_endpoint, zenohd_tcp_port, &cert_path, true);

    // Barrier: the mesh converged over quic before attaching the pico subscriber,
    // so its subscription propagates into wz (deactivating wz's write-filter) over
    // an established link.
    let converged = wait_for_substring(
        &mut wz_reader,
        "peer: reciprocal mesh link confirmed",
        Duration::from_secs(15),
    );
    if converged.is_err() {
        let c = read_captured(&mut wz_reader);
        graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
        let _ = zenohd.child_mut().kill();
        let _ = zenohd.child_mut().wait();
        panic!(
            "wz <-> zenohd peer mesh never converged over quic within 15s — the data \
             leg cannot start\n--- wz stderr ---\n{c}"
        );
    }

    // pico z_sub: a plain-TCP client of ZENOHD, subscribing demo/**. Its
    // subscription propagates zenohd --quic--> wz, deactivating wz's publisher
    // write-filter so wz's per-tick Put flows back the same path.
    let z_sub_endpoint = format!("tcp/127.0.0.1:{zenohd_tcp_port}");
    let (mut z_sub_guard, mut z_sub_reader) =
        spawn_subscribed_zsub(&z_sub, "demo/**", &z_sub_endpoint, "zenohd", tempfile);

    // The acid test: the pico subscriber received wz's Put, having crossed the
    // accepted quic mesh link OUT of wz. The unique key + payload pin THIS Put.
    let received = wait_for_substring(
        &mut z_sub_reader,
        &format!("Received ('{KEYEXPR}': '{WZ_PUBLISH_PAYLOAD}')"),
        Duration::from_secs(15),
    );

    let _ = z_sub_guard.child_mut().kill();
    let _ = z_sub_guard.child_mut().wait();
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let wz_captured = read_captured(&mut wz_reader);
    let z_sub_captured = read_captured(&mut z_sub_reader);
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    eprintln!("--- wz mesh quic peer (data out) stderr ---\n{wz_captured}");
    eprintln!("--- pico z_sub stdout ---\n{z_sub_captured}");

    received.unwrap_or_else(|c| {
        panic!(
            "pico z_sub behind zenohd never received wz's Put on '{KEYEXPR}' within \
             15s — data did not cross the accepted quic mesh link OUT of wz (wz -> \
             quic -> zenohd -> pico). Did wz's write-filter deactivate on the remote \
             sub learned over quic?\n--- pico z_sub stdout ---\n{c}"
        )
    });
}
