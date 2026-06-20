// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311no — FOREIGN-INTEROP multicast pico -> wz dial-in: an external
//! zenoh-pico `z_pub -m peer` multicast publisher announces itself with a
//! JOIN beacon and emits framed Push datagrams over a real UDP multicast
//! group; a watching-zenoh in-library multicast subscriber co-binds the
//! same group port, admits the pico peer from its JOIN, and decodes the
//! Push into a byte-exact subscriber callback.
//!
//! This is the REVERSE direction of `wz_publisher_to_pico_multicast_zsub`
//! (R311nm, wz -> pico) and closes the bidirectional multicast interop
//! proof: each implementation now both admits the other's JOIN and decodes
//! the other's Push over a live multicast socket.
//!
//! ## Direction: pico -> wz (the dial-in R311nm carried forward)
//!
//! Both peers bind the SAME multicast group port (`0.0.0.0:PORT`). R311nm
//! could only run wz -> pico because wz's `UdpDriver::bind_multicast_v4`
//! did not set `SO_REUSEADDR` / `SO_REUSEPORT`, so a wz group receiver
//! could not co-bind the host port already held by pico's group-joined
//! peer (`pico -> wz` dead-locked on `EADDRINUSE`). R311no adds those
//! reuse options to `bind_multicast_v4` (via socket2), matching
//! zenoh-pico's unconditional REUSEADDR+REUSEPORT on its multicast
//! listener (`vendor/zenoh-pico/src/link/transport/udp/
//! udp_multicast_posix.c:180 / :185`), so wz and pico co-bind and this
//! direction runs.
//!
//! ## JOIN admission is asserted DIRECTLY (not transitively)
//!
//! Unlike R311nm — where pico's admission of wz's JOIN could only be
//! proven transitively, by z_sub firing its Received callback — here wz is
//! the in-process admitter, so `dispatcher.active_peers() == 1` is a
//! DIRECT observation that wz parsed and admitted pico's JOIN. wz's
//! `ingest_join` rejects a peer whose JOIN version / seq_num_res /
//! batch_size does not match the wz params (multicast_dispatch.rs §3.2
//! rejection rules), so the wz params below are pinned to pico's CONFIG
//! constants for admission to succeed — the same pinning R311nm used in
//! the other direction.
//!
//! ## Why a periodic publisher (z_pub, not z_put)
//!
//! pico re-emits its JOIN beacon every `Z_JOIN_INTERVAL`, and `z_pub`
//! publishes every second for `-n` iterations. wz binds + joins the group
//! BEFORE pico is spawned, so it witnesses pico's initial JOIN; even were a
//! beacon missed, a later one re-admits and a later Put delivers, so the
//! scenario never races a single admission window (the no-flaky
//! discipline). A one-shot `z_put` has a single delivery that could
//! precede admission — which is why this lane needs `z_pub`, added to
//! `scripts/build-zenoh-pico-cli.sh` in this round.
//!
//! ## Environment dependence (`#[ignore]`, Layer M)
//!
//! Multicast routing is environment-dependent (a container without a
//! multicast route drops the IGMP join), so this is opt-in like the
//! wz<->wz `multicast_pubsub_loopback` lane and the R311nm wz->pico lane.
//! pico's multicast peer needs an explicit `#iface=<dev>`; the test
//! discovers the default-route interface at runtime, which is the
//! interface wz's `INADDR_ANY` multicast join selects, so both peers meet
//! on the same link.

use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_integration_tests::common::{
    default_route_iface, read_captured, zenoh_pico_cli_binary, ChildGuard,
    PICO_BATCH_MULTICAST_SIZE, PICO_PROTO_VERSION, PICO_SN_RESOLUTION, ZENOH_MULTICAST_GROUP,
};
use wz_runtime_tokio::multicast_glue::{drive_multicast_session, MulticastDriveConfig};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::UdpDriver;
use wz_session_core::multicast_dispatch::{MulticastConfig, MulticastDispatcher};
use wz_session_core::multicast_params::MulticastParams;
use wz_session_core::observer::ApplicationLayerObserver;
use wz_session_core::WhatAmI;

// Distinct PORT from every other multicast lane (scouting 7446/7448,
// pubsub-loopback 7449/7450, wz->pico 7457) so the `--ignored` lanes never
// contend on the same bind; GROUP is the shared zenoh group SSOT (common).
const GROUP: Ipv4Addr = ZENOH_MULTICAST_GROUP;
const PORT: u16 = 7458;
// wz subscribes to the exact literal key pico's z_pub publishes (the
// multicast subscriber registry matches by keyexpr).
const KEY: &str = "demo/mc/dialin";
// Distinctive value: pico's z_pub wraps it as `[%4d] <value>` (z_pub.c), so
// the decoded Push payload is byte-exact iff this tail survives intact.
const VALUE: &str = "WZ-MCAST-DIALIN-R311no";

/// wz multicast self-advertisement params pinned to zenoh-pico's CONFIG
/// constants so wz admits the pico peer from its JOIN beacon (symmetric
/// with R311nm's pinning in the wz -> pico direction).
fn wz_mc_params() -> MulticastParams {
    MulticastParams {
        version: PICO_PROTO_VERSION,
        whatami: WhatAmI::Peer,
        zid: vec![0x77; 4],
        lease_ms: 5_000,
        join_interval_ms: 50,
        seq_num_res: PICO_SN_RESOLUTION,
        req_id_res: PICO_SN_RESOLUTION,
        batch_size: PICO_BATCH_MULTICAST_SIZE,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep multicast e2e (zenoh-pico CLI z_pub); Layer M runs via --ignored"]
async fn wz_subscriber_admits_pico_multicast_push() {
    let z_pub = zenoh_pico_cli_binary("z_pub");
    let iface = default_route_iface();
    let locator = format!("udp/{GROUP}:{PORT}#iface={iface}");

    // ── wz multicast subscriber (in-library) ─────────────────────────
    // Bind + join the group FIRST so wz is listening when pico emits its
    // initial JOIN. The REUSEADDR/REUSEPORT bind (R311no) is what lets wz
    // co-bind the host group port that pico's peer also binds.
    let mut driver = UdpDriver::bind_multicast_v4(GROUP, PORT)
        .await
        .expect("bind wz multicast subscriber link (REUSE co-bind)");
    let mut dispatcher = MulticastDispatcher::<8>::new(MulticastConfig::new(5_000));
    let params = wz_mc_params();

    let fired = Arc::new(AtomicUsize::new(0));
    let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let mut observer = ApplicationLayerObserver::new();
    {
        let fired = fired.clone();
        let captured = captured.clone();
        observer.subscribers.register(KEY, move |sample| {
            assert_eq!(sample.keyexpr(), KEY, "delivered keyexpr matches");
            *captured.lock().expect("captured lock") = sample.payload().to_vec();
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }

    let (_hold, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let clock = TokioTime::new();
    let drive = drive_multicast_session(
        &mut dispatcher,
        MulticastDriveConfig {
            params: &params,
            tick_ms: 10,
            // production path: no iteration budget, select! bounds the run
            max_iters: None,
        },
        &mut driver,
        &clock,
        |event| observer.dispatch_event(event),
        &mut rx,
    );

    // ── pico z_pub (multicast peer + publisher) ──────────────────────
    // stdout+stderr → one tempfile; `stdbuf -oL` line-buffers so the
    // captured log is live on the timeout-diagnostic path.
    let z_pub_capture = tempfile::tempfile().expect("tempfile for z_pub capture");
    let z_pub_out = z_pub_capture.try_clone().expect("dup z_pub stdout handle");
    let z_pub_err = z_pub_capture.try_clone().expect("dup z_pub stderr handle");
    let mut z_pub_reader = z_pub_capture;

    let _z_pub_child = ChildGuard::wrap(
        "z_pub multicast peer (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_pub)
            .args([
                "-k", KEY, "-v", VALUE, "-l", &locator, "-m", "peer", "-n", "30",
            ])
            .stdout(Stdio::from(z_pub_out))
            .stderr(Stdio::from(z_pub_err))
            .spawn()
            .expect("spawn z_pub via stdbuf"),
    );

    // Scenario: wait for the subscriber to witness a decoded Push. pico
    // publishes every second for 30 s; the 12 s budget spans several JOIN
    // intervals + Puts, so a missed first beacon never fails the gate.
    let fired_probe = fired.clone();
    let scenario = async move {
        for _ in 0..120 {
            if fired_probe.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let captured_pub = read_captured(&mut z_pub_reader);
        panic!(
            "wz subscriber did not decode a pico multicast Push within 12s on \
             {locator} — co-bind/join or JOIN-admission failed?\n\
             --- captured z_pub ---\n{captured_pub}"
        );
    };

    tokio::select! {
        _ = drive => panic!("subscriber drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    // Borrows released by the completed select!; assert on the dispatcher.
    let count = fired.load(Ordering::SeqCst);
    assert!(count >= 1, "expected at least one delivery, got {count}");

    let got = captured.lock().expect("captured lock").clone();
    let got_str = String::from_utf8(got).expect("pico payload is a C string");
    // pico's z_pub wraps the value as `[%4d] <value>` (z_pub.c). The idx is
    // pico's internal loop counter (which Put arrives first after admission
    // is non-deterministic), so reconstruct the exact template for the
    // observed idx and assert the FULL payload is byte-exact.
    let close = got_str
        .find(']')
        .unwrap_or_else(|| panic!("payload missing pico `[idx]` prefix: {got_str:?}"));
    let idx_field = &got_str[1..close];
    assert_eq!(
        got_str,
        format!("[{idx_field}] {VALUE}"),
        "decoded multicast Push payload not byte-exact for pico's `[%4d] <value>` template"
    );

    assert_eq!(
        dispatcher.active_peers(),
        1,
        "wz admitted pico's JOIN (direct in-process observation, not transitive)"
    );
}
