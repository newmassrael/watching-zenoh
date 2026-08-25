// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311nm — FOREIGN-INTEROP multicast JOIN + Push: a watching-zenoh
//! in-library multicast publisher announces itself with a JOIN beacon and
//! emits a `T_MID_FRAME`/Push over a real UDP multicast group; an external
//! zenoh-pico `z_sub -m peer` admits the wz peer from that JOIN and decodes
//! the Push into a byte-exact subscriber callback.
//!
//! This closes the last open cross-impl proof-gap that the unicast
//! fragmentation interop (`wz_reassembles_pico_fragment_tx.rs`, R311nk/nl)
//! and the static byte-parity (`layer3_join.rs` / `layer3_frame.rs`) left
//! standing: the wz multicast JOIN + Frame wire format had only ever been
//! exercised wz<->wz in-process (`wz-runtime-tokio/tests/
//! multicast_pubsub_loopback.rs`), never against the foreign zenoh-pico
//! multicast transport over a live socket.
//!
//! ## Direction: wz -> pico (NOT pico -> wz)
//!
//! The multicast group port is shared by every peer on the host. wz's
//! `UdpDriver::bind_multicast_v4` does NOT set `SO_REUSEADDR` (lib.rs: the
//! single-receiver scouting deploy never needed multiple binders), so a wz
//! group-joined receiver and a pico group-joined peer cannot co-bind the
//! same host port — `pico -> wz` would dead-lock on `EADDRINUSE`. Driving
//! wz as the PUBLISHER sidesteps this: wz publishes from an ephemeral
//! TX-only socket (`UdpDriver::from_socket`, the same shape the wz<->wz
//! loopback test's node A uses) that never binds the group port, while pico
//! `z_sub` is the sole group-port binder. `pico -> wz` is carried forward
//! as a separate item (it needs `SO_REUSEADDR` on wz's multicast bind, a
//! production change out of scope here).
//!
//! ## JOIN admission is PROVEN transitively, not asserted directly
//!
//! zenoh-pico drops a `T_MID_FRAME` from a transport peer it has not first
//! admitted via a compatible JOIN (`vendor/zenoh-pico/src/transport/
//! multicast/rx.c:373-396`: version / seq_num_res / req_id_res / batch_size
//! must match `Z_PROTO_VERSION` 0x09 / `Z_SN_RESOLUTION` 0x02 /
//! `Z_BATCH_MULTICAST_SIZE` 2048 or the peer is rejected before any Frame is
//! accepted). So z_sub firing its Received callback on wz's Push is itself
//! the proof that pico parsed and accepted wz's JOIN — the wz multicast
//! params below are pinned to exactly those three values so admission can
//! succeed.
//!
//! ## Why republish in a loop
//!
//! wz emits its JOIN beacon every `join_interval_ms` (50 ms). A single Push
//! queued before pico has processed a wz JOIN would be dropped with no
//! retransmit. The scenario republishes the same Put every 100 ms until the
//! subscriber witness appears (or the budget expires), so the test does not
//! race the JOIN-admission window — the no-flaky discipline
//! ([[feedback-no-flaky-ever]]). Each republish is an independent Put; pico
//! prints one Received line per delivery and the gate matches the first.
//!
//! ## Environment dependence (`#[ignore]`, Layer M)
//!
//! Multicast routing is environment-dependent (a container without a
//! multicast route drops the IGMP join), so this is opt-in like the
//! wz<->wz `multicast_pubsub_loopback` lane. pico's multicast peer needs an
//! explicit `#iface=<dev>`; the test discovers the default-route interface
//! at runtime (`ip route show default`), which is exactly the interface
//! wz's `INADDR_ANY` multicast egress selects, so both peers meet on the
//! same link. z_sub's stdout is line-buffered via `stdbuf -oL` (glibc block-
//! buffers a piped fd, which would otherwise hide the Received line until
//! exit).

use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::time::Duration;

use tokio::net::UdpSocket;

use wz_integration_tests::common::{
    default_route_iface, read_captured, wait_for_substring, zenoh_pico_cli_binary, ChildGuard,
    PICO_BATCH_MULTICAST_SIZE, PICO_PROTO_VERSION, PICO_SN_RESOLUTION, ZENOH_MULTICAST_GROUP,
    Z_SUB_INIT_TIMEOUT,
};
use wz_runtime_tokio::multicast_glue::{
    drive_multicast_session, multicast_put_literal, MulticastDriveConfig,
};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::UdpDriver;
use wz_session_core::multicast_dispatch::{MulticastConfig, MulticastDispatcher};
use wz_session_core::multicast_params::MulticastParams;
use wz_session_core::WhatAmI;

// Distinct PORT from every other multicast test (scouting 7446/7448,
// pubsub-loopback 7449) so the `--ignored` lane never contends on the same
// multicast bind; GROUP is the shared zenoh group SSOT (common).
const GROUP: Ipv4Addr = ZENOH_MULTICAST_GROUP;
const PORT: u16 = 7457;
const PUBLISH_KEY: &str = "demo/mc/interop";
// z_sub subscribes to a wildcard so pico's local matcher accepts the
// literal-keyexpr (id=0 + suffix) the wz publisher emits.
const SUB_KEY: &str = "demo/mc/**";
// Distinctive shell-safe payload: appears in z_sub's `Received (... : '...')`
// line only if the reassembled Push delivered byte-exact.
const PAYLOAD: &str = "WZ-MCAST-JOIN-INTEROP-R311nm";

/// wz multicast self-advertisement params pinned to zenoh-pico's CONFIG
/// constants above so pico admits the wz peer from its JOIN beacon.
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
        is_qos: false,
    }
}

// wz-proves: transport-multicast wz->pico
// wz-proves: session-multicast wz->pico partial
// wz-proves: codec-join wz->pico
// wz-proves: codec-frame wz->pico
// wz-proves: codec-push wz->pico
// wz-proves: pubsub-put wz->pico
// wz-proves: keyexpr-literal wz->pico
// wz-proves: transport-link-udp wz->pico
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep multicast e2e (zenoh-pico CLI z_sub); Layer M runs via --ignored"]
async fn wz_publisher_reaches_pico_multicast_zsub() {
    let z_sub = zenoh_pico_cli_binary("z_sub");
    let iface = default_route_iface();
    let locator = format!("udp/{GROUP}:{PORT}#iface={iface}");

    // ── pico z_sub (multicast peer + subscriber) ─────────────────────
    // stdout+stderr → one tempfile (combined capture for diagnosis);
    // `stdbuf -oL` line-buffers so the Received witness surfaces live.
    let z_sub_capture = tempfile::tempfile().expect("tempfile for z_sub capture");
    let z_sub_out = z_sub_capture.try_clone().expect("dup z_sub stdout handle");
    let z_sub_err = z_sub_capture.try_clone().expect("dup z_sub stderr handle");
    let mut z_sub_reader = z_sub_capture;

    let mut z_sub_child = ChildGuard::wrap(
        "z_sub multicast peer (zenoh-pico)",
        Command::new("stdbuf")
            .args(["-oL", "-eL"])
            .arg(&z_sub)
            .args(["-k", SUB_KEY, "-l", &locator, "-m", "peer"])
            .stdout(Stdio::from(z_sub_out))
            .stderr(Stdio::from(z_sub_err))
            .spawn()
            .expect("spawn z_sub via stdbuf"),
    );

    // Gate 1: z_sub joined the group and declared its subscriber. Until
    // this prints, wz's Push has nothing to reach.
    let declared = wait_for_substring(
        &mut z_sub_reader,
        "Declaring Subscriber",
        Z_SUB_INIT_TIMEOUT,
    );
    if let Err(captured) = &declared {
        let _ = z_sub_child.child_mut().kill();
        let _ = z_sub_child.child_mut().wait();
        panic!(
            "z_sub did not log 'Declaring Subscriber' within {Z_SUB_INIT_TIMEOUT:?} on \
             {locator} — multicast bind/join failed?\n--- captured z_sub ---\n{captured}"
        );
    }

    // ── wz multicast publisher (in-library, ephemeral TX-only) ───────
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .expect("bind ephemeral wz publisher socket");
    let mut driver = UdpDriver::from_socket(sock, SocketAddr::from((GROUP, PORT)));
    let mut dispatcher = MulticastDispatcher::<8>::new(MulticastConfig::new(5_000));
    let params = wz_mc_params();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
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
        |_| {},
        &mut rx,
    );

    // Scenario: republish the Put every 100 ms until z_sub prints the
    // payload (covers the JOIN-admission window) or the budget expires.
    let scenario = async move {
        // Brief settle so at least one wz JOIN beacon precedes the first
        // Push; the loop below is the real admission-jitter defense.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut captured = String::new();
        for _ in 0..120 {
            let _ =
                tx.send(multicast_put_literal(PUBLISH_KEY, PAYLOAD.as_bytes()).expect("put item"));
            tokio::time::sleep(Duration::from_millis(100)).await;
            captured = read_captured(&mut z_sub_reader);
            if captured.contains(PAYLOAD) {
                return Ok(captured);
            }
        }
        Err(captured)
    };

    let result = tokio::select! {
        _ = drive => panic!("wz multicast publisher drive loop ended unexpectedly"),
        r = scenario => r,
    };

    let _ = z_sub_child.child_mut().kill();
    let _ = z_sub_child.child_mut().wait();

    let captured = match result {
        Ok(c) => c,
        Err(c) => panic!(
            "z_sub did not receive wz's multicast Push (payload '{PAYLOAD}') within the budget \
             on {locator} — wz JOIN not admitted by pico, or the Frame did not decode.\n\
             --- captured z_sub stdout+stderr at deadline ---\n{c}"
        ),
    };

    // Localize a partial match: the witness line, the keyexpr, and the
    // payload each asserted independently so a regression on any one
    // points at the actual mismatch.
    assert!(
        captured.contains(">> [Subscriber] Received"),
        "z_sub saw the payload but not the Received witness line.\n--- captured ---\n{captured}"
    );
    assert!(
        captured.contains(PUBLISH_KEY),
        "z_sub Received the Push but the publish keyexpr '{PUBLISH_KEY}' is missing.\n\
         --- captured ---\n{captured}"
    );
    assert!(
        captured.contains(PAYLOAD),
        "z_sub Received the Push but the payload '{PAYLOAD}' is missing.\n\
         --- captured ---\n{captured}"
    );
}
