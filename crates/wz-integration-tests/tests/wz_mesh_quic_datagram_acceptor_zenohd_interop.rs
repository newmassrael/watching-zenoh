// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y411 — §5.1 transport / §5.21 routing — CROSS-IMPL validation of the wz
//! MESH QUIC-DATAGRAM acceptor: a real `zenohd` DIALS a wz `--peer
//! quic-datagram/...` / `--router-hat quic-datagram/...` MESH listen and both
//! FEDERATES over it (control plane) AND routes real DATA across it in BOTH
//! directions (data plane) — over RFC9221 UNRELIABLE datagram frames, zenohd->wz
//! accept direction.
//!
//! ## What this proves that no prior test does
//!
//! The quic-datagram acceptor was proven in pieces, but never in THIS composition:
//!
//!   * `wz_quic_datagram_acceptor_zenohd_interop` (R311y408): zenohd dials the
//!     ONE-SHOT `--listen quic-datagram/...` acceptor (a single observe-forwarder
//!     face) and a pico Put crosses. That is the one-shot accept path, NOT the mesh
//!     accept loop, and it emits no federation witness.
//!   * `mesh_accept_loop_holds_two_quic_datagram_peers` (R311y408): the mesh accept
//!     loop holds two datagram faces — but wz<->wz only, so it cannot catch a wire
//!     divergence from the canonical impl.
//!   * `boundlistener_quic_datagram_is_mesh_capable` (R311y408): the BIND-time
//!     mesh predicate — a pure in-process pin, no peer ever connects.
//!   * `wz_mesh_quic_acceptor_zenohd_interop` (R311y407): the full cross-impl MESH
//!     composition — but over RELIABLE quic (a bidi STREAM), whose ordered,
//!     retransmitting link makes every federation flood and every Put arrive by
//!     construction. It says nothing about the datagram link.
//!
//! The uncovered intersection — (mesh accept loop) x (quic-DATAGRAM) x (cross-impl)
//! x (wz-as-ACCEPTOR), for BOTH the control plane AND real data in BOTH directions —
//! is this file: the FIRST proof that a foreign implementation can JOIN wz's MESH
//! over an UNRELIABLE (RFC9221 datagram, no stream, no retransmission) transport
//! where wz presents the server cert. It exercises the R311y408 deferred datagram
//! accept split (`accept_quic_incoming` arrival / `complete_quic_datagram_accept`
//! crypto, which drops the `accept_bi`) INSIDE the mesh accept loop (`peer_loop` /
//! router-hat), driven by a real zenohd dialer and threaded with the R311y406
//! `--quic-cert` / `--quic-key` plumbing.
//!
//! ## Topology (the dial direction is REVERSED vs the tcp federation legs)
//!
//!   zenohd ── dials `-e quic/<wz>?rel=0` ──▶ wz `--peer|--router-hat quic-datagram/127.0.0.1:0`
//!
//! zenoh gives the datagram link NO distinct scheme: its locator prefix is `"quic"`
//! (same as reliable quic) and the DATAGRAM link is selected by the reliability
//! metadata — `quic/<wz>?rel=0` is best-effort, which zenoh's `LinkKind::try_from`
//! routes to `QuicDatagram`. So the wz side names its listen `quic-datagram/<addr>`
//! (a DISTINCT wz scheme) while zenohd dials the SAME UDP endpoint as
//! `quic/<wz>?rel=0`; on the wire it is one QUIC/TLS-1.3 handshake, then DATAGRAM
//! frames. wz binds ONLY that datagram endpoint (no tcp listener, and — leg 6 — not
//! even a reliable-quic session on the same UDP port), so there is no path a session
//! could fall back to: any federation witness or data delivery necessarily crossed
//! RFC9221 datagrams. zenohd trusts wz's self-signed `localhost` cert via
//! `root_ca_certificate` (chain-of-trust is load-bearing) and disables SAN matching
//! with `verify_name_on_connect: false` for the by-IP dial; datagrams reuse the SAME
//! `transport.link.tls` cert block as reliable quic. For the data-plane legs a
//! zenoh-pico CLI is a plain-TCP client of zenohd (pico has no quic at all), so the
//! data crosses pico --tcp--> zenohd --quic-datagram--> wz (or reverse): every
//! wz<->zenohd hop is a datagram, and the pico endpoint is the foreign data
//! origin/sink that makes the crossing cross-impl end to end.
//!
//! ## The six legs
//!
//! Control plane (topology federation floor):
//!   1. [`wz_router_hat_federates_with_a_quic_datagram_dialing_zenohd`] — wz
//!      `--router-hat quic-datagram/...` (`WhatAmI::Router`); a STOCK (default
//!      `mode=router`) zenohd dials it over datagrams. `routers_net` converges to 2
//!      AND wz DECODES zenohd's `LinkStateList` OAM (`learned mesh topology`).
//!   2. [`wz_peer_federates_with_a_quic_datagram_dialing_linkstate_zenohd`] — wz
//!      `--peer quic-datagram/...` (`WhatAmI::Peer`); a `mode=peer` +
//!      `routing/peer/mode=linkstate` zenohd dials it. wz ingests the
//!      `linkstatepeers_net` flood AND forms a MUTUAL edge (`confirmed reciprocal
//!      mesh link`), the full-linkstate discriminator.
//!   3. [`wz_peer_gossip_quic_datagram_dialer_yields_no_linkstate_edge`] (ROUTING
//!      NEUTER) — the SAME wz `--peer quic-datagram/...`, but the dialing zenohd runs
//!      DEFAULT gossip. wz still `learned mesh topology` (the gossip
//!      self-announcement decodes) but forms NO edge (`0 graph edge(s)`, reciprocal
//!      witness ABSENT) — proving leg 2's reciprocal witness is LOAD-BEARING over
//!      datagrams and not a green-but-meaningless ingested-only pass.
//!
//! Data plane (real pub/sub across the accepted datagram mesh link, both directions):
//!   4. [`wz_peer_receives_pico_data_across_a_quic_datagram_mesh_link`] — a pico
//!      `z_pub` behind the dialing zenohd publishes; the Put routes pico --tcp-->
//!      zenohd --datagram--> wz's `--subscribe` (`received mesh data`).
//!   5. [`wz_peer_publishes_data_across_a_quic_datagram_mesh_link_to_pico`] — wz's
//!      `--publish` Put routes wz --datagram--> zenohd --tcp--> a pico `z_sub`
//!      (`Received ('demo/key'`).
//!
//! Transport discrimination:
//!   6. [`wz_peer_reliable_quic_dialer_never_joins_the_datagram_mesh`] (TRANSPORT
//!      NEUTER) — the SAME wz `--peer quic-datagram/...` listen, and a zenohd that
//!      dials the SAME UDP endpoint with the SAME cert but WITHOUT `?rel=0`, i.e. as
//!      RELIABLE quic. wz accepts the QUIC connection (the faces are logged) but every
//!      one FAILS: `served 0 peer(s)`, `ingested 0 link-state(s)`, `0 graph edge(s)`,
//!      no face ever UP. See "the discriminator" below — this is what makes legs 1-5
//!      load-bearing for the DATAGRAM data plane specifically.
//!
//! ## The discriminator (RED+TWIN)
//!
//! Two independent falsifications, one per claim this file makes:
//!
//!   * "it is the quic-DATAGRAM accept seam" — leg 6 IS that discriminator, and it
//!     runs on every green pass rather than only under a hand-applied mutation. Every
//!     variable is held fixed (same wz listen, same UDP endpoint, same cert, same
//!     zenohd, same QUIC/TLS-1.3 handshake); the ONLY difference is the zenoh
//!     reliability metadata that selects the datagram link over the stream one. A
//!     reliable dialer's session dies at the zenoh handshake because wz's datagram
//!     acceptor drops the `accept_bi` and reads DATAGRAM frames, so nothing on the
//!     stream is ever read. If legs 1-5's witnesses could be satisfied by a
//!     reliable-quic session on that port, leg 6 would federate too — it does not.
//!     Externally: a `wz-ap-demo` built WITHOUT the `quic-datagram` feature rejects a
//!     `quic-datagram/...` listen with a typed `Unsupported` at `bind_locator`, so wz
//!     never binds and all six legs redden.
//!   * "it is the MESH accept path, cert-threaded" — every leg binds a
//!     `quic-datagram/...` MESH listen WITH `--quic-cert` / `--quic-key`. The bind is
//!     cert-GATED: revert the R311y406 threading in `run_peer_until` /
//!     `run_router_hat_until` (bind cert-free via `AcceptConfig::default`) and
//!     `bind_locator` rejects at cert-absence — wz never binds, zenohd cannot dial,
//!     and neither a federation witness nor any data delivery fires. Note the mesh
//!     listen line carries NO transport tag (`local_addr_display` renders a bare
//!     `host:port`, unlike the one-shot acceptor's `(quic-datagram)`) and the mesh
//!     path emits no `quic-datagram server handshake` note, so the transport identity
//!     rests on leg 6 + "wz binds ONLY the datagram endpoint", not on a log tag.
//!
//! ## Reliability caveat (honest)
//!
//! These legs rest on loopback UDP being lossless, and more strongly than the y408
//! one-shot leg does: zenoh implements no ARQ, and a QUIC DATAGRAM frame is never
//! retransmitted, so a dropped `LinkStateList` flood would simply never arrive (the
//! control-plane legs are single-flood, fire-and-forget). The data legs are
//! self-healing only for the PAYLOAD — the pico `z_pub` burst is 30 Puts and wz's
//! `--publish` peer emits one per app tick — but NOT for the subscription DECLARE that
//! precedes them: a `--subscribe` peer declares its interest ONCE (runner.rs), and
//! re-advertisement is event-driven off a tree recompute, not periodic. Lose the
//! Declare and all 30 Puts are correctly dropped. So no leg here is fully self-healing;
//! the control-plane legs simply have no redundancy at all.
//! This is the same loopback-lossless precedent as `mesh_accept_loop_holds_two_udp_
//! peers` / `quic_datagram_e2e` / the y408 acceptor leg, stated here rather than
//! assumed. The 15s witness budgets are NOT a loss mitigation (a lost datagram never
//! arrives, so no budget rescues it); they absorb scheduler slack only.
//!
//! Requires: `wz-ap-demo` built with `--features router-hat-router,quic-datagram`
//! (`router-hat-router` pulls `routing-peer` for `--peer`; `quic-datagram` pulls
//! `transport-link-quic-datagram`, which implies `transport-link-quic` for the shared
//! cert plumbing), a STOCK `zenohd` 1.5.0 (`transport_quic_datagram` is in zenoh's
//! DEFAULT feature set and zenohd enables `zenoh/default` — no special oracle, unlike
//! the vsock/unixpipe oracles), and the zenoh-pico `z_pub` / `z_sub` CLIs for the data
//! legs. `#[ignore]` binary-dep e2e; runs on Layer Z via `--ignored
//! --test-threads=1`. Each fn name carries the `wz_router` (leg 1) / `wz_peer` (legs
//! 2-6) prefix plus, for legs 1-2, a `zenohd` substring; libtest `--skip` is a
//! test-NAME (not file-name) substring filter, so the default Layer E sweep's
//! `--skip wz_router` / `--skip wz_peer` / `--skip zenohd` keep every leg here from
//! running against an arbitrary-feature binary (a stray `--peer` server would hang to
//! SIGTERM). Keep the `wz_peer` / `wz_router` fn prefix if renaming.

use std::time::Duration;

use wz_integration_tests::common::{
    graceful_terminate, read_captured, spawn_on_ephemeral_port, spawn_publishing_zpub,
    spawn_subscribed_zsub, spawn_zenohd_dialer_on_ephemeral_tcp, wait_for_substring,
    wz_ap_demo_binary, zenoh_pico_cli_binary, zenohd_binary, ChildGuard,
};
use wz_runtime_tokio_test_support::localhost_cert_key_pem;

const KEYEXPR: &str = "demo/key";
/// The payload wz's `--publish` peer emits each app tick (runner.rs
/// `forwarder.publish(key, b"wz-mesh-data")`) — pinned by the data-OUT leg.
const WZ_PUBLISH_PAYLOAD: &str = "wz-mesh-data";

/// Which zenoh LINK the dialing zenohd selects on the wz UDP endpoint. Both dial the
/// SAME `quic/<addr>` prefix — zenoh gives the datagram link no distinct scheme, so
/// the reliability METADATA is the whole difference, and that is precisely what leg 6
/// exploits as this file's transport discriminator.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DialLink {
    /// `?rel=0` — best-effort, which zenoh routes to its `QuicDatagram` link (RFC9221
    /// datagram frames, no stream). The link every federating leg here uses.
    Datagram,
    /// No reliability metadata — zenoh's default RELIABLE quic (a bidi stream). The
    /// leg-6 neuter: wz's datagram acceptor drops the `accept_bi`, so the stream is
    /// never read and no session can form.
    Reliable,
}

impl DialLink {
    /// The locator suffix zenohd's `-e` carries for this link.
    fn locator_suffix(self) -> &'static str {
        match self {
            DialLink::Datagram => "?rel=0",
            DialLink::Reliable => "",
        }
    }
}

/// Which routing HAT the dialing zenohd runs. All three dial the same wz listen with
/// the same trust anchor; only the routing config differs, which is what makes leg 3 a
/// single-variable neuter against leg 2.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DialerMode {
    /// zenoh's default `mode=router` — no mode key in the config at all. Leg 1's
    /// dialer, federating on the `routers_net` tier against wz's `--router-hat`.
    StockRouter,
    /// `mode=peer` + `routing/peer/mode=linkstate`: the full-linkstate HAT, which
    /// floods a self-entry carrying a reciprocal link back to its dial target, so wz
    /// forms a MUTUAL edge and pub/sub routes through the peer mesh.
    LinkstatePeer,
    /// `mode=peer` with zenoh's default `peer_to_peer` gossip left in place — a
    /// node-only self-announcement with no reciprocal link. Leg 3's routing NEUTER.
    GossipPeer,
}

impl DialerMode {
    /// The JSON5 fragment appended after the shared tls trust block (leading comma
    /// included, empty for the stock router — omitting the key IS the default).
    fn cfg_fragment(self) -> &'static str {
        match self {
            DialerMode::StockRouter => "",
            DialerMode::LinkstatePeer => {
                ", mode: \"peer\", routing: { peer: { mode: \"linkstate\" } }"
            }
            DialerMode::GossipPeer => ", mode: \"peer\"",
        }
    }
}

/// Removes the throwaway cert / key / dialer-config files on drop, so an early panic
/// (before the normal teardown) does not leak them — the same hygiene guard as
/// `wz_mesh_quic_acceptor_zenohd_interop` / `wz_quic_datagram_acceptor_zenohd_interop`.
struct TempFiles(Vec<String>);
impl Drop for TempFiles {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// The stderr/stdout tempfile factory the common pico spawn helpers require (the lib
/// crate cannot depend on the dev-only `tempfile`, so the caller supplies it).
fn tempfile() -> std::fs::File {
    tempfile::tempfile().expect("tempfile for child capture")
}

/// Write wz's self-signed `localhost` cert + key to pid+leg-unique paths and return
/// `(cert_path, key_path, cleanup)`. The cert wz PRESENTS as the quic-datagram mesh
/// acceptor AND the root zenohd trusts (a self-signed leaf is its own root);
/// datagrams reuse the SAME cert as reliable quic, matching zenoh's shared
/// `transport.link.tls` block. The cleanup guard also unlinks the dialer config the
/// zenohd-dialer helpers write at `<cert>.dialer.zenohd.json5`.
fn write_wz_cert(leg: &str) -> (String, String, TempFiles) {
    let (cert_pem, key_pem) = localhost_cert_key_pem();
    let base =
        std::env::temp_dir().join(format!("wz-mesh-quic-dgram-{leg}-{}", std::process::id()));
    let cert_path = format!("{}.cert.pem", base.display());
    let key_path = format!("{}.key.pem", base.display());
    std::fs::write(&cert_path, &cert_pem).expect("write wz quic-datagram cert pem");
    std::fs::write(&key_path, &key_pem).expect("write wz quic-datagram key pem");
    let cleanup = TempFiles(vec![
        cert_path.clone(),
        key_path.clone(),
        format!("{cert_path}.dialer.zenohd.json5"),
    ]);
    (cert_path, key_path, cleanup)
}

/// Spawn a wz `--peer quic-datagram/127.0.0.1:0` (+ optional extra args, e.g.
/// `--subscribe` / `--publish`) presenting the cert, and read back its ephemeral
/// UDP port. wz is a pure datagram LISTENER (no `--connect`); zenohd dials IN.
fn spawn_wz_peer_quic_datagram(
    demo: &std::path::Path,
    cert_path: &str,
    key_path: &str,
    extra: &[&str],
) -> (ChildGuard, std::fs::File, u16) {
    let mut args = vec![
        "--peer",
        "quic-datagram/127.0.0.1:0",
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
        "wz mesh quic-datagram peer",
        tempfile(),
    )
}

/// Spawn a zenohd that DIALS the wz datagram endpoint (`-e quic/<addr>[?rel=0]`),
/// returning the guard and the loopback TCP port zenohd bound for its readiness probe
/// AND (for the data legs) a pico TCP client.
///
/// `mode` selects the routing HAT via the wire cfg; `link` selects the LINK on that
/// one UDP endpoint ([`DialLink::Datagram`] for every federating leg,
/// [`DialLink::Reliable`] for the leg-6 transport neuter). The tls trust block is
/// byte-identical across all four combinations — zenoh's quic and quic-datagram links
/// share it — which is what makes legs 3 and 6 single-variable experiments against
/// leg 2.
///
/// The port is DISCOVERED, not chosen: [`spawn_zenohd_dialer_on_ephemeral_tcp`] has
/// zenohd bind `tcp/127.0.0.1:0` and reads the bound port back out of zenohd's own
/// announcement. The `wz_port + 1` derivation every acceptor test USED to take was a
/// measured flake source (see that helper's doc) — 1 failure in 30 runs of this very
/// lane, `Address already in use` -> zenohd exit 255. R311y412 retired the last of
/// them, so no test in this crate names a zenohd port any more.
fn spawn_zenohd_quic_datagram_mesh_dialer(
    wz_datagram_addr: &str,
    ca_cert_path: &str,
    mode: DialerMode,
    link: DialLink,
) -> (ChildGuard, u16) {
    let cfg_path = format!("{ca_cert_path}.dialer.zenohd.json5");
    let cfg = format!(
        "{{ transport: {{ link: {{ tls: {{ \
         root_ca_certificate: {ca_cert_path:?}, verify_name_on_connect: false }} }} }}{} }}",
        mode.cfg_fragment()
    );
    std::fs::write(&cfg_path, cfg).expect("write zenohd quic-datagram mesh dialer config");
    let label = match (mode, link) {
        (_, DialLink::Reliable) => "zenohd (RELIABLE-quic dialer, leg-6 neuter)",
        (DialerMode::StockRouter, _) => "zenohd (stock-router quic-datagram dialer)",
        (DialerMode::LinkstatePeer, _) => "zenohd (linkstate-peer quic-datagram dialer)",
        (DialerMode::GossipPeer, _) => "zenohd (gossip-peer quic-datagram dialer)",
    };
    spawn_zenohd_dialer_on_ephemeral_tcp(
        &zenohd_binary(),
        label,
        Some(&format!("quic/{wz_datagram_addr}{}", link.locator_suffix())),
        &[],
        Some(&cfg_path),
    )
}

/// Leg 1 — the ROUTER-tier federation floor over a QUIC-DATAGRAM mesh listen. wz
/// `--router-hat quic-datagram/...` binds a datagram listen presenting the cert; a
/// STOCK (default `mode=router`) zenohd DIALS it as `quic/<wz>?rel=0` and the two
/// routers converge their `routers_net` link-state tier over RFC9221 datagrams. The
/// datagram analog of `wz_mesh_quic_acceptor_zenohd_interop` leg 1.
// wz-proves: transport-link-quic-datagram zenohd->wz
// wz-proves: router-hat-router zenohd->wz
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features router-hat-router,quic-datagram + zenohd); Layer Z runs via --ignored"]
fn wz_router_hat_federates_with_a_quic_datagram_dialing_zenohd() {
    let demo = wz_ap_demo_binary();
    let (cert_path, key_path, _cleanup) = write_wz_cert("rh");

    // wz --router-hat: bind an EPHEMERAL quic-datagram port presenting the cert. The
    // datagram backend binds a real UDP socket -> a real IP address, so the bound port
    // reads back from the "router-hat: listening on 127.0.0.1:<port>" line (the mesh
    // listen line has no transport tag, unlike the one-shot acceptor).
    let (mut wz_guard, mut wz_reader, udp_port) = spawn_on_ephemeral_port(
        &demo,
        &[
            "--router-hat",
            "quic-datagram/127.0.0.1:0",
            "--quic-cert",
            &cert_path,
            "--quic-key",
            &key_path,
        ],
        "router-hat: listening on 127.0.0.1:",
        "wz mesh quic-datagram router-hat",
        tempfile(),
    );

    // zenohd (STOCK, default router) DIALS the wz datagram endpoint as
    // `quic/<wz>?rel=0` (trusting wz's cert), listening on a distinct tcp port for its
    // readiness probe.
    let wz_datagram_addr = format!("127.0.0.1:{udp_port}");
    let (mut zenohd, _zenohd_tcp_port) = spawn_zenohd_quic_datagram_mesh_dialer(
        &wz_datagram_addr,
        &cert_path,
        DialerMode::StockRouter,
        DialLink::Datagram,
    );

    // Cross-impl witness #1: the router tier converged to 2 nodes over the datagram
    // link (self + the dialing zenohd). Fires on `add_link` from the INIT-derived
    // zid+whatami — handshake-satisfiable, so necessary but not sufficient; witness #2
    // is the load-bearing wire-decode.
    let converged = wait_for_substring(
        &mut wz_reader,
        "router-hat: routers-net converged (2 node(s))",
        Duration::from_secs(15),
    );
    // BARRIER (R311y411): settle on the INGEST witness before terminating. Witness #2
    // below reads the shutdown summary's `learned mesh topology`, which is gated on
    // `forwarder.ingested() > 0` — a real `LinkStateList` decode. Convergence alone is
    // handshake-satisfiable and can precede the flood by an app tick, so terminating on
    // it races a witness this leg has already earned. Legs 2/3 settle on their own
    // post-ingest barriers for exactly this reason; the router-hat loop grew the
    // matching in-run witness in R311y411 so this leg can too. On an UNRELIABLE link a
    // lost flood is never retransmitted, so the budget is scheduler slack, not a retry.
    let ingested = if converged.is_ok() {
        wait_for_substring(
            &mut wz_reader,
            "router-hat: ingested neighbour link-state",
            Duration::from_secs(15),
        )
    } else {
        // Convergence already failed; its panic below is the report. Do not spend a
        // second budget waiting for a flood that cannot arrive.
        Err(String::new())
    };

    // Graceful shutdown so wz logs its `learned mesh topology` summary.
    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let wz_captured = read_captured(&mut wz_reader);
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    eprintln!("--- wz mesh quic-datagram router-hat stderr ---\n{wz_captured}");

    converged.unwrap_or_else(|c| {
        panic!(
            "wz --router-hat never converged its router tier to 2 within 15s against a \
             QUIC-DATAGRAM-dialing zenohd — the mesh datagram accept path did not \
             federate at the router tier (did the cert-threaded datagram bind fail?)\n\
             --- wz mesh quic-datagram router-hat stderr ---\n{c}"
        )
    });
    assert!(
        ingested.is_ok(),
        "wz --router-hat converged its router tier over quic-datagram but never logged \
         the in-run `ingested neighbour link-state` witness within 15s — no \
         `LinkStateList` flood was decoded, so witness #2 below could only pass by \
         accident of timing\n\
         --- wz mesh quic-datagram router-hat stderr ---\n{wz_captured}"
    );
    // Cross-impl witness #2 (load-bearing): wz DECODED >=1 of zenohd's `LinkStateList`
    // OAM floods carried in RFC9221 datagram frames (`forwarder.ingested() > 0`).
    // Convergence is handshake-satisfiable; THIS is what a `LinkStateList` codec
    // divergence — or a broken mesh datagram accept — would break.
    assert!(
        wz_captured.contains("router-hat: learned mesh topology"),
        "wz --router-hat converged its router tier over quic-datagram but never ingested \
         a `LinkStateList` OAM from zenohd (no 'learned mesh topology' shutdown witness) \
         — the tiers linked at the transport layer but wz did not DECODE zenohd's \
         routers_net link-state wire\n\
         --- wz mesh quic-datagram router-hat stderr ---\n{wz_captured}"
    );
}

/// Leg 2 — the PEER-tier federation floor over a QUIC-DATAGRAM mesh listen. wz
/// `--peer quic-datagram/...` binds a datagram listen presenting the cert; a
/// `mode=peer` + `routing/peer/mode=linkstate` zenohd DIALS it as `quic/<wz>?rel=0`
/// and floods its `linkstatepeers_net` self-entry with a reciprocal link, so wz forms
/// a MUTUAL graph edge over datagrams.
// wz-proves: transport-link-quic-datagram zenohd->wz
// wz-proves: routing-peer zenohd->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,quic-datagram + zenohd peer); Layer Z runs via --ignored"]
fn wz_peer_federates_with_a_quic_datagram_dialing_linkstate_zenohd() {
    let demo = wz_ap_demo_binary();
    let (cert_path, key_path, _cleanup) = write_wz_cert("pr");

    let (mut wz_guard, mut wz_reader, udp_port) =
        spawn_wz_peer_quic_datagram(&demo, &cert_path, &key_path, &[]);

    let wz_datagram_addr = format!("127.0.0.1:{udp_port}");
    let (mut zenohd, _zenohd_tcp_port) = spawn_zenohd_quic_datagram_mesh_dialer(
        &wz_datagram_addr,
        &cert_path,
        DialerMode::LinkstatePeer,
        DialLink::Datagram,
    );

    // Settle on the in-run reciprocal-link witness: wz ingested zenohd's linkstate
    // flood over the datagram link AND formed the mutual graph edge (the
    // full-linkstate discriminator). This is the deterministic post-ingest barrier.
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
    eprintln!("--- wz mesh quic-datagram peer stderr ---\n{wz_captured}");

    reciprocal.unwrap_or_else(|c| {
        panic!(
            "wz --peer never confirmed a reciprocal mesh link with a QUIC-DATAGRAM-dialing \
             linkstate zenohd within 15s — the mesh datagram accept path did not converge \
             a mutual edge over the wire (did the cert-threaded datagram bind fail?)\n\
             --- wz mesh quic-datagram peer stderr ---\n{c}"
        )
    });
    // Weak witness: wz decoded SOME zenohd LinkStateList over datagrams (necessary but
    // not sufficient for the linkstate claim; shared with a gossip peer — see leg 3).
    assert!(
        wz_captured.contains("peer: learned mesh topology"),
        "wz --peer summary must report 'learned mesh topology' — it must ingest zenohd's \
         link-state flood over the datagram link\n\
         --- wz mesh quic-datagram peer stderr ---\n{wz_captured}"
    );
    // Load-bearing witness: wz formed a MUTUAL edge, which ONLY a full-linkstate
    // self-entry (reciprocal link back to wz) produces — the wz-peer <-> zenohd-peer
    // linkstate-tier federation proof over a QUIC-DATAGRAM mesh listen wz accepted.
    assert!(
        wz_captured.contains("peer: confirmed reciprocal mesh link"),
        "wz --peer summary must report 'confirmed reciprocal mesh link' — federating with \
         a LINKSTATE zenohd peer that dialed the quic-datagram mesh listen must form a \
         mutual graph edge (zenohd's self-entry advertises a link back to wz)\n\
         --- wz mesh quic-datagram peer stderr ---\n{wz_captured}"
    );
}

/// Leg 3 (ROUTING NEUTER) — the SAME wz `--peer quic-datagram/...` acceptor as leg 2,
/// but the dialing zenohd runs DEFAULT gossip (`mode=peer`, no `routing/peer/mode`).
/// A gossip self-entry carries no reciprocal link, so wz decodes it (`learned mesh
/// topology` still fires — the weak witness is shared) but forms NO mutual edge. This
/// proves leg 2's `confirmed reciprocal mesh link` witness is LOAD-BEARING over
/// datagrams: it distinguishes a full-linkstate flood from a gossip one, rather than
/// firing on any decoded LinkStateList.
// wz-proves: routing-peer zenohd->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,quic-datagram + zenohd gossip peer); Layer Z runs via --ignored"]
fn wz_peer_gossip_quic_datagram_dialer_yields_no_linkstate_edge() {
    let demo = wz_ap_demo_binary();
    let (cert_path, key_path, _cleanup) = write_wz_cert("ng");

    let (mut wz_guard, mut wz_reader, udp_port) =
        spawn_wz_peer_quic_datagram(&demo, &cert_path, &key_path, &[]);

    let wz_datagram_addr = format!("127.0.0.1:{udp_port}");
    let (mut zenohd, _zenohd_tcp_port) = spawn_zenohd_quic_datagram_mesh_dialer(
        &wz_datagram_addr,
        &cert_path,
        DialerMode::GossipPeer,
        DialLink::Datagram,
    );

    // Settle on the INGEST witness (not the reciprocal one — a gossip flood never trips
    // it): wz decoded the gossip self-announcement over the datagram link. This
    // guarantees the flood ARRIVED before shutdown, so the "no reciprocal edge"
    // assertion below is a genuine content distinction, not a premature-teardown false
    // negative.
    let ingested = wait_for_substring(
        &mut wz_reader,
        "peer: ingested neighbour link-state",
        Duration::from_secs(15),
    );

    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let wz_captured = read_captured(&mut wz_reader);
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    eprintln!("--- wz mesh quic-datagram peer (gossip neuter) stderr ---\n{wz_captured}");

    ingested.unwrap_or_else(|c| {
        panic!(
            "wz --peer never ingested the gossip zenohd's link-state over quic-datagram \
             within 15s — the gossip self-announcement did not arrive, so the neuter \
             cannot distinguish it from a linkstate flood\n\
             --- wz mesh quic-datagram peer (gossip neuter) stderr ---\n{c}"
        )
    });
    // The weak witness FIRES for a gossip peer too — proof that "learned mesh topology"
    // alone does NOT establish linkstate-tier federation.
    assert!(
        wz_captured.contains("peer: learned mesh topology"),
        "wz --peer summary must still report 'learned mesh topology' against a gossip \
         zenohd dialing over quic-datagram — it decoded the gossip self-announcement \
         (the weak witness is shared)\n\
         --- wz mesh quic-datagram peer (gossip neuter) stderr ---\n{wz_captured}"
    );
    // The load-bearing witness is ABSENT: a gossip self-entry carries no reciprocal
    // link, so wz forms NO mutual edge.
    assert!(
        !wz_captured.contains("peer: confirmed reciprocal mesh link"),
        "wz --peer must NOT report 'confirmed reciprocal mesh link' against a GOSSIP \
         zenohd dialing over quic-datagram — a peer_to_peer self-entry advertises no link \
         back, so no mutual edge can form; leg 2's reciprocal witness would be \
         green-but-meaningless if it fired here\n\
         --- wz mesh quic-datagram peer (gossip neuter) stderr ---\n{wz_captured}"
    );
    // Precise corroboration: the shutdown summary reports zero graph edges,
    // comma-bounded on BOTH sides so a multi-digit count cannot spuriously satisfy.
    assert!(
        wz_captured.contains(", 0 graph edge(s),"),
        "wz --peer summary must report '0 graph edge(s)' against a gossip zenohd dialing \
         over quic-datagram (node learned, no mutual edge)\n\
         --- wz mesh quic-datagram peer (gossip neuter) stderr ---\n{wz_captured}"
    );
}

/// Leg 4 — the DATA plane INTO wz over the accepted quic-datagram mesh link. wz
/// `--peer quic-datagram/... --subscribe demo/**` hosts a local subscriber; a pico
/// `z_pub` (plain TCP client of the dialing linkstate zenohd) publishes `demo/key`.
/// The Put routes pico --tcp--> zenohd --quic-datagram--> wz's subscriber, so wz's
/// `received mesh data` witness proves real data crossed the accepted datagram mesh
/// link from a foreign publisher. wz binds ONLY the datagram endpoint, so the
/// zenohd<->wz hop is necessarily RFC9221 datagrams (leg 6 rules out a reliable-quic
/// session on that same port); pico is the foreign data ORIGIN behind zenohd.
// wz-proves: transport-link-quic-datagram zenohd->wz
// wz-proves: routing-peer zenohd->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,quic-datagram + zenohd peer + zenoh-pico z_pub); Layer Z runs via --ignored"]
fn wz_peer_receives_pico_data_across_a_quic_datagram_mesh_link() {
    let demo = wz_ap_demo_binary();
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let (cert_path, key_path, _cleanup) = write_wz_cert("di");

    let (mut wz_guard, mut wz_reader, udp_port) =
        spawn_wz_peer_quic_datagram(&demo, &cert_path, &key_path, &["--subscribe", "demo/**"]);

    let wz_datagram_addr = format!("127.0.0.1:{udp_port}");
    let (mut zenohd, zenohd_tcp_port) = spawn_zenohd_quic_datagram_mesh_dialer(
        &wz_datagram_addr,
        &cert_path,
        DialerMode::LinkstatePeer,
        DialLink::Datagram,
    );

    // Barrier: the mesh converged over datagrams (wz formed the mutual edge). Only then
    // has wz's subscription had a mesh to advertise across, so zenohd can route a
    // publisher's Put back to it. The 30-Put burst below absorbs the residual
    // route-install slack after this, and on this UNRELIABLE link a dropped Put — but
    // NOT a dropped subscription Declare, which is sent once and would strand the whole
    // burst (see the reliability caveat in this file's header).
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
            "wz <-> zenohd peer mesh never converged over quic-datagram within 15s — the \
             data leg cannot start\n--- wz stderr ---\n{c}"
        );
    }

    // pico z_pub: a plain-TCP client of ZENOHD, publishing demo/key as a self-healing
    // burst (~30 puts). pico's `-e` needs a scheme'd locator.
    let z_pub_endpoint = format!("tcp/127.0.0.1:{zenohd_tcp_port}");
    let mut z_pub_guard = spawn_publishing_zpub(
        &z_pub,
        KEYEXPR,
        "pico-quic-datagram-mesh-into-wz",
        &z_pub_endpoint,
        "zenohd",
        tempfile,
    );

    // The acid test: wz's subscriber received a Put over the accepted datagram mesh
    // link. `received mesh data` is a deterministic shutdown counterpart to the in-run
    // app-tick log (runner.rs), emitted unconditionally on `data_seen > 0`.
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
    eprintln!("--- wz mesh quic-datagram peer (data into) stderr ---\n{wz_captured}");

    received.unwrap_or_else(|c| {
        panic!(
            "wz --peer subscriber never received the pico Put within 15s — data did not \
             cross the accepted quic-datagram mesh link (pico -> zenohd -> datagram -> \
             wz). Did the subscription advertise over the datagram link, or the route \
             install?\n--- wz stderr ---\n{c}"
        )
    });
}

/// Leg 5 — the DATA plane OUT of wz over the accepted quic-datagram mesh link. wz
/// `--peer quic-datagram/... --publish demo/key` originates a Put each app tick; a
/// pico `z_sub` (plain TCP client of the dialing linkstate zenohd) subscribes
/// `demo/**`. wz's write-filter deactivates when it learns the remote subscription
/// over the datagram mesh, and its Put routes wz --quic-datagram--> zenohd --tcp-->
/// the pico subscriber, which prints `Received ('demo/key': 'wz-mesh-data')`.
// wz-proves: transport-link-quic-datagram zenohd->wz
// wz-proves: routing-peer zenohd->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,quic-datagram + zenohd peer + zenoh-pico z_sub); Layer Z runs via --ignored"]
fn wz_peer_publishes_data_across_a_quic_datagram_mesh_link_to_pico() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let (cert_path, key_path, _cleanup) = write_wz_cert("do");

    let (mut wz_guard, mut wz_reader, udp_port) =
        spawn_wz_peer_quic_datagram(&demo, &cert_path, &key_path, &["--publish", KEYEXPR]);

    let wz_datagram_addr = format!("127.0.0.1:{udp_port}");
    let (mut zenohd, zenohd_tcp_port) = spawn_zenohd_quic_datagram_mesh_dialer(
        &wz_datagram_addr,
        &cert_path,
        DialerMode::LinkstatePeer,
        DialLink::Datagram,
    );

    // Barrier: the mesh converged over datagrams before attaching the pico subscriber,
    // so its subscription propagates into wz (deactivating wz's write-filter) over an
    // established link.
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
            "wz <-> zenohd peer mesh never converged over quic-datagram within 15s — the \
             data leg cannot start\n--- wz stderr ---\n{c}"
        );
    }

    // pico z_sub: a plain-TCP client of ZENOHD, subscribing demo/**. Its subscription
    // propagates zenohd --quic-datagram--> wz, deactivating wz's publisher write-filter
    // so wz's per-tick Put flows back the same path. The per-tick repetition is what
    // makes this leg self-healing on an unreliable link.
    let z_sub_endpoint = format!("tcp/127.0.0.1:{zenohd_tcp_port}");
    let (mut z_sub_guard, mut z_sub_reader) =
        spawn_subscribed_zsub(&z_sub, "demo/**", &z_sub_endpoint, "zenohd", tempfile);

    // The acid test: the pico subscriber received wz's Put, having crossed the accepted
    // quic-datagram mesh link OUT of wz. The unique key + payload pin THIS Put.
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
    eprintln!("--- wz mesh quic-datagram peer (data out) stderr ---\n{wz_captured}");
    eprintln!("--- pico z_sub stdout ---\n{z_sub_captured}");

    received.unwrap_or_else(|c| {
        panic!(
            "pico z_sub behind zenohd never received wz's Put on '{KEYEXPR}' within 15s — \
             data did not cross the accepted quic-datagram mesh link OUT of wz (wz -> \
             datagram -> zenohd -> pico). Did wz's write-filter deactivate on the remote \
             sub learned over the datagram link?\n--- pico z_sub stdout ---\n{c}"
        )
    });
}

/// Leg 6 (TRANSPORT NEUTER) — the SAME wz `--peer quic-datagram/...` listen as legs
/// 2-5, dialed by a zenohd that differs in EXACTLY ONE variable: it omits `?rel=0`, so
/// zenoh selects its RELIABLE quic link (a bidi stream) on that same UDP endpoint with
/// the same cert. wz's datagram acceptor completes the QUIC/TLS handshake and logs the
/// face, then the session dies at the zenoh handshake: `complete_quic_datagram_accept`
/// drops the `accept_bi` and reads DATAGRAM frames, so the stream zenohd writes its
/// `InitSyn` on is never read. Result: faces FAIL, `served 0 peer(s)`, `ingested 0
/// link-state(s)`, `0 graph edge(s)`.
///
/// This is what makes legs 1-5 load-bearing for the DATAGRAM data plane specifically.
/// The mesh listen line carries no transport tag and the mesh path emits no
/// `quic-datagram server handshake` note, so without this leg a reader could not
/// exclude "a reliable-quic session on the same UDP port satisfied those witnesses".
/// It also runs on every green pass, rather than being a mutation someone must
/// remember to re-apply.
// `partial`, deliberately: this leg carries ZERO datagram frames. It witnesses the
// bind arm and the deferred accept against a foreign dialer, but the arrival it
// reaches (`accept_quic_incoming`) is SHARED with the stream backend, so the datagram
// DATA plane is proven by legs 1/2/4/5, not here.
// wz-proves: transport-link-quic-datagram zenohd->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,quic-datagram + zenohd peer); Layer Z runs via --ignored"]
fn wz_peer_reliable_quic_dialer_never_joins_the_datagram_mesh() {
    let demo = wz_ap_demo_binary();
    let (cert_path, key_path, _cleanup) = write_wz_cert("rn");

    let (mut wz_guard, mut wz_reader, udp_port) =
        spawn_wz_peer_quic_datagram(&demo, &cert_path, &key_path, &[]);

    // The ONE variable: DialLink::Reliable drops `?rel=0`, so zenoh picks its stream
    // link. Same endpoint, same cert, same linkstate routing mode as leg 2.
    let wz_datagram_addr = format!("127.0.0.1:{udp_port}");
    let (mut zenohd, _zenohd_tcp_port) = spawn_zenohd_quic_datagram_mesh_dialer(
        &wz_datagram_addr,
        &cert_path,
        DialerMode::LinkstatePeer,
        DialLink::Reliable,
    );

    // ARRIVAL barrier (not a timeout): wz logged a FAILED face, which it can only do
    // after accepting a real QUIC connection from this dialer and running its deferred
    // crypto. So the absence assertions below are a genuine "the reliable session could
    // not form" distinction, not a "zenohd never showed up" false negative.
    let failed = wait_for_substring(
        &mut wz_reader,
        "peer: face 0 FAILED",
        Duration::from_secs(15),
    );

    graceful_terminate(wz_guard.child_mut(), Duration::from_secs(5));
    let wz_captured = read_captured(&mut wz_reader);
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    eprintln!("--- wz mesh quic-datagram peer (reliable-dial neuter) stderr ---\n{wz_captured}");

    let failed_text = failed.unwrap_or_else(|c| {
        panic!(
            "wz --peer never logged a FAILED face against a RELIABLE-quic dialer within \
             15s — the dialer never reached wz's datagram acceptor at all, so this leg \
             cannot discriminate the datagram link from the stream one\n\
             --- wz mesh quic-datagram peer (reliable-dial neuter) stderr ---\n{c}"
        )
    });
    // The face must die at the ZENOH handshake (`Terminal`), NOT at QUIC/TLS. Without
    // this, any pre-zenoh failure satisfies the leg: a wrong trust anchor also logs a
    // FAILED face (as `AcceptHandshake(... invalid peer certificate ...)`) and every
    // absence assertion below would still hold — so the leg would pass while proving
    // nothing about datagram-vs-stream. Pinning the CAUSE is what makes leg 6 citable
    // on its own as this file's transport discriminator: the QUIC/TLS-1.3 handshake
    // SUCCEEDED, and the session died only because wz's datagram acceptor drops the
    // `accept_bi` and never reads the stream zenohd wrote its `InitSyn` on.
    assert!(
        failed_text.contains("peer: face 0 FAILED") && failed_text.contains(", Terminal)"),
        "wz's face against a RELIABLE-quic dialer must fail as `Terminal` (the zenoh \
         handshake giving up on a stream nobody reads), not at QUIC/TLS — a crypto or \
         trust-anchor failure would satisfy every absence assertion below while saying \
         nothing about the datagram data plane\n\
         --- wz mesh quic-datagram peer (reliable-dial neuter) stderr ---\n{failed_text}"
    );
    // No face ever came UP: the reliable session never completed wz's zenoh handshake.
    assert!(
        !wz_captured.contains("peer: face 0 UP"),
        "a RELIABLE-quic dialer must NOT bring a face UP on wz's quic-datagram listen — \
         if it can, then legs 1-5's witnesses do not pin the RFC9221 datagram data plane \
         and could be satisfied by a stream session on the same UDP port\n\
         --- wz mesh quic-datagram peer (reliable-dial neuter) stderr ---\n{wz_captured}"
    );
    // ...and none of leg 2's federation witnesses fired.
    assert!(
        !wz_captured.contains("peer: confirmed reciprocal mesh link"),
        "a RELIABLE-quic dialer must NOT form a reciprocal mesh edge on wz's quic-datagram \
         listen\n--- wz mesh quic-datagram peer (reliable-dial neuter) stderr ---\n{wz_captured}"
    );
    // Precise corroboration from the shutdown summary, comma-bounded on both sides so a
    // multi-digit count cannot spuriously satisfy: zero peers served, zero link-states
    // ingested, zero graph edges. (`accepted N` is deliberately NOT asserted — zenohd's
    // reconnect backoff makes the accept count timing-dependent.)
    assert!(
        wz_captured.contains(", served 0 peer(s),"),
        "wz --peer summary must report 'served 0 peer(s)' against a RELIABLE-quic dialer\n\
         --- wz mesh quic-datagram peer (reliable-dial neuter) stderr ---\n{wz_captured}"
    );
    assert!(
        wz_captured.contains(", ingested 0 link-state(s),"),
        "wz --peer summary must report 'ingested 0 link-state(s)' against a RELIABLE-quic \
         dialer — nothing on the unread stream can decode\n\
         --- wz mesh quic-datagram peer (reliable-dial neuter) stderr ---\n{wz_captured}"
    );
    assert!(
        wz_captured.contains(", 0 graph edge(s),"),
        "wz --peer summary must report '0 graph edge(s)' against a RELIABLE-quic dialer\n\
         --- wz mesh quic-datagram peer (reliable-dial neuter) stderr ---\n{wz_captured}"
    );
}

/// Leg 7 (REGRESSION, R311y411) — a peer whose zid ends in a ZERO BYTE still
/// recognises itself, and still routes data OUT.
///
/// This is the deterministic form of a flake that cost 6 failures in 250 runs of
/// this very lane. `wz-ap-demo` derives its mesh zid from its listen PORT, so an
/// ephemeral port with a `0x00` low byte (1 in 256) produced a self zid ending in
/// zero. zenoh's identity is the VALUE — `uhlc::ID::size()` counts significant LE
/// bytes — so the flood came back carrying the TRIMMED form, which wz's
/// non-canonical `Zid` did not compare equal to self. The node entered its own
/// topology graph as a phantom third peer with no edges, and the spanning-tree
/// next-hop computation then silently stopped forwarding: the `--publish` peer's
/// data never left the box (5 of the 6 failures), or the router tier counted 3
/// nodes and skipped the `(2 node(s))` witness entirely (the 6th).
///
/// `--zid 70728300` pins that shape with no lottery: the trailing zero is
/// explicit. RED against a `Zid::from_slice` that keeps the caller's length
/// (phantom node present, `peak 3 node(s)`, pico receives NOTHING); GREEN once the
/// constructor canonicalises. The `peak 2` assertion is what binds this leg to the
/// zid fix rather than to the data plane in general — leg 5 already covers the
/// latter with a port-derived zid.
// wz-proves: routing-peer zenohd->wz partial
#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features routing-peer,quic-datagram + zenohd peer + zenoh-pico z_sub); Layer Z runs via --ignored"]
fn wz_peer_with_a_trailing_zero_zid_still_routes_data_out() {
    let demo = wz_ap_demo_binary();
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let (cert_path, key_path, _cleanup) = write_wz_cert("z0");

    // The zid whose LAST byte is zero — the canonicalisation discriminator.
    let (mut wz_guard, mut wz_reader, udp_port) = spawn_wz_peer_quic_datagram(
        &demo,
        &cert_path,
        &key_path,
        &["--zid", "70728300", "--publish", KEYEXPR],
    );

    let wz_datagram_addr = format!("127.0.0.1:{udp_port}");
    let (mut zenohd, zenohd_tcp_port) = spawn_zenohd_quic_datagram_mesh_dialer(
        &wz_datagram_addr,
        &cert_path,
        DialerMode::LinkstatePeer,
        DialLink::Datagram,
    );

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
            "wz <-> zenohd peer mesh never converged over quic-datagram within 15s — the \
             zid regression leg cannot start\n--- wz stderr ---\n{c}"
        );
    }

    let z_sub_endpoint = format!("tcp/127.0.0.1:{zenohd_tcp_port}");
    let (mut z_sub_guard, mut z_sub_reader) =
        spawn_subscribed_zsub(&z_sub, "demo/**", &z_sub_endpoint, "zenohd", tempfile);

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
    eprintln!("--- wz mesh quic-datagram peer (trailing-zero zid) stderr ---\n{wz_captured}");

    received.unwrap_or_else(|c| {
        panic!(
            "pico z_sub behind zenohd never received the Put from a wz peer whose zid ends \
             in a zero byte — the peer did not recognise its own zid in the link-state \
             flood, so it entered its own graph as a phantom node and the spanning tree \
             stopped forwarding\n--- pico z_sub stdout ---\n{c}\n\
             --- wz stderr ---\n{wz_captured}"
        )
    });
    // The load-bearing witness for THIS leg: exactly two nodes — self and zenohd.
    // A phantom self-node shows up as three, which is the state that broke routing.
    assert!(
        wz_captured.contains(", peak 2 node(s) in topology graph,"),
        "a wz peer whose zid ends in a zero byte must see exactly 2 nodes (self + \
         zenohd); a third is its OWN zid arriving back wire-trimmed and failing to \
         compare equal to self\n--- wz stderr ---\n{wz_captured}"
    );
    let _ = z_sub_captured;
}
