// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A1c — Layer M: two-node pub/sub over a real UDP multicast socket.
//!
//! Node B joins the group (`UdpDriver::bind_multicast_v4`) and runs the
//! full multicast drive loop with an `ApplicationLayerObserver` carrying a
//! registered subscriber. Node A runs the same loop on an ephemeral-bound
//! socket targeting the group (`UdpDriver::from_socket` — the TX-only
//! publisher shape; joining the group too would need SO_REUSEADDR on a
//! shared host port). A's periodic JOIN beacon admits it into B's peer
//! table; a queued `MulticastTxItem::Push` then travels A -> group -> B's
//! SN gate -> `parse_frame_payload` -> subscriber callback. This is the
//! real-socket leg of the in-loop unit e2e
//! (`drive_loop_delivers_frame_push_to_subscriber_once`).
//!
//! Opt-in only (`#[ignore]`, Layer M): multicast routing is
//! environment-dependent (a container without a multicast route drops the
//! IGMP join), so this must not be a default gate (no-flaky rule). The
//! deterministic decode/admission/fan logic is covered without a socket by
//! the C1q `multicast_glue` unit tests.
//!
//! Gated on the data-plane feature union: the whole file is empty under
//! the default set (no `transport-multicast`), so Layer C1's workspace
//! test does not build it; the Layer M lane builds it with
//! `--features transport-multicast` (codec-push / pubsub-put ride the
//! default set).
#![cfg(all(
    feature = "transport-multicast",
    feature = "codec-push",
    feature = "pubsub-put"
))]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use wz_runtime_tokio::multicast_glue::{
    drive_multicast_session, multicast_put_literal, MulticastDriveConfig,
};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::UdpDriver;
use wz_session_core::multicast_dispatch::{MulticastConfig, MulticastDispatcher};
use wz_session_core::multicast_params::MulticastParams;
use wz_session_core::observer::ApplicationLayerObserver;

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 224);
// Distinct group port from the scouting Layer M tests (7446 / 7448) so the
// `--ignored` lane never contends on the same multicast bind.
const PORT: u16 = 7449;
const KEYEXPR: &str = "demo/mc/e2e";
const PAYLOAD: &[u8] = b"pub-over-multicast";

fn mc_params(zid_byte: u8) -> MulticastParams {
    MulticastParams {
        version: 0x09,
        whatami: 0x01, // PEER (wire form)
        zid: vec![zid_byte; 4],
        lease_ms: 5_000,
        join_interval_ms: 50,
        seq_num_res: 0x02,
        req_id_res: 0x02,
        batch_size: 2_048,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "multicast loopback e2e; Layer M runs via --layer M / WZ_RUN_LAYER_M=1 --ignored"]
async fn publisher_push_reaches_group_subscriber() {
    // Subscriber node B: group-joined socket + observer-backed drive loop.
    let mut driver_b = UdpDriver::bind_multicast_v4(GROUP, PORT)
        .await
        .expect("bind multicast subscriber link");
    let mut dispatcher_b = MulticastDispatcher::<8>::new(MulticastConfig::new(5_000));
    let params_b = mc_params(0xBB);

    let fired = Arc::new(AtomicUsize::new(0));
    let mut observer = ApplicationLayerObserver::new();
    {
        let fired = fired.clone();
        observer.subscribers.register(KEYEXPR, move |sample| {
            assert_eq!(sample.keyexpr(), KEYEXPR);
            assert_eq!(sample.payload(), PAYLOAD);
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }

    // Publisher node A: ephemeral-bound socket targeting the group (TX-only
    // publisher; its own RX sees no group traffic, which is fine — the SN
    // gate under test is B's).
    let sock_a = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .expect("bind ephemeral publisher socket");
    let mut driver_a = UdpDriver::from_socket(sock_a, SocketAddr::from((GROUP, PORT)));
    let mut dispatcher_a = MulticastDispatcher::<8>::new(MulticastConfig::new(5_000));
    let params_a = mc_params(0xAA);

    let (tx_a, mut rx_a) = tokio::sync::mpsc::unbounded_channel();
    let (_hold_b, mut rx_b) = tokio::sync::mpsc::unbounded_channel();

    let clock = TokioTime::new();
    let drive_b = drive_multicast_session(
        &mut dispatcher_b,
        MulticastDriveConfig {
            params: &params_b,
            tick_ms: 10,
            // production path: no iteration budget, select! bounds the run
            max_iters: None,
        },
        &mut driver_b,
        &clock,
        |event| observer.dispatch_event(event),
        &mut rx_b,
    );
    let drive_a = drive_multicast_session(
        &mut dispatcher_a,
        MulticastDriveConfig {
            params: &params_a,
            tick_ms: 10,
            max_iters: None,
        },
        &mut driver_a,
        &clock,
        |_| {},
        &mut rx_a,
    );

    // Scenario: give A's JOIN beacons time to admit it into B's peer
    // table, publish once, then wait for the subscriber to fire.
    let fired_probe = fired.clone();
    let scenario = async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        tx_a.send(multicast_put_literal(KEYEXPR, PAYLOAD).expect("put item"))
            .expect("queue publish");
        for _ in 0..100 {
            if fired_probe.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("subscriber did not fire within the 3s budget");
    };

    tokio::select! {
        _ = drive_b => panic!("subscriber drive loop ended unexpectedly"),
        _ = drive_a => panic!("publisher drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    assert_eq!(fired.load(Ordering::SeqCst), 1, "exactly one delivery");
    assert_eq!(
        dispatcher_b.active_peers(),
        1,
        "B admitted A from its JOIN beacon"
    );
}

/// R311ko — the fragmentation leg of the same two-node topology: the
/// group runs a 64-byte batch budget (the owned push codec caps payloads
/// at the bounded profile, so "oversize" is a frame past a SMALL budget —
/// the unicast fixtures shrink the mtu the same way), the publisher's
/// 200-byte put leaves its loop as a `T_MID_FRAGMENT` chain, and the
/// subscriber node's loop reassembles it back into one delivered sample.
/// Distinct group port from `publisher_push_reaches_group_subscriber` so
/// the two tests never contend on the same multicast bind.
#[cfg(feature = "transport-fragmentation")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "multicast loopback e2e; Layer M runs via --layer M / WZ_RUN_LAYER_M=1 --ignored"]
async fn oversize_put_fragments_and_reassembles_across_nodes() {
    const FRAG_PORT: u16 = 7450;
    const FRAG_KEYEXPR: &str = "demo/mc/frag";
    let payload: Vec<u8> = (0..200u32).map(|i| (i * 13) as u8).collect();
    let frag_params = |zid_byte: u8| MulticastParams {
        batch_size: 64,
        ..mc_params(zid_byte)
    };

    let mut driver_b = UdpDriver::bind_multicast_v4(GROUP, FRAG_PORT)
        .await
        .expect("bind multicast subscriber link");
    let mut dispatcher_b = MulticastDispatcher::<8>::new(MulticastConfig::new(5_000));
    let params_b = frag_params(0xBB);

    let fired = Arc::new(AtomicUsize::new(0));
    let mut observer = ApplicationLayerObserver::new();
    {
        let fired = fired.clone();
        let expect = payload.clone();
        observer.subscribers.register(FRAG_KEYEXPR, move |sample| {
            assert_eq!(sample.keyexpr(), FRAG_KEYEXPR);
            assert_eq!(sample.payload(), &expect[..]);
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }

    let sock_a = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .expect("bind ephemeral publisher socket");
    let mut driver_a = UdpDriver::from_socket(sock_a, SocketAddr::from((GROUP, FRAG_PORT)));
    let mut dispatcher_a = MulticastDispatcher::<8>::new(MulticastConfig::new(5_000));
    let params_a = frag_params(0xAA);

    let (tx_a, mut rx_a) = tokio::sync::mpsc::unbounded_channel();
    let (_hold_b, mut rx_b) = tokio::sync::mpsc::unbounded_channel();

    let clock = TokioTime::new();
    let drive_b = drive_multicast_session(
        &mut dispatcher_b,
        MulticastDriveConfig {
            params: &params_b,
            tick_ms: 10,
            max_iters: None,
        },
        &mut driver_b,
        &clock,
        |event| observer.dispatch_event(event),
        &mut rx_b,
    );
    let drive_a = drive_multicast_session(
        &mut dispatcher_a,
        MulticastDriveConfig {
            params: &params_a,
            tick_ms: 10,
            max_iters: None,
        },
        &mut driver_a,
        &clock,
        |_| {},
        &mut rx_a,
    );

    let fired_probe = fired.clone();
    let put_payload = payload.clone();
    let scenario = async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        tx_a.send(multicast_put_literal(FRAG_KEYEXPR, &put_payload).expect("put item"))
            .expect("queue publish");
        for _ in 0..100 {
            if fired_probe.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("subscriber did not fire within the 3s budget");
    };

    tokio::select! {
        _ = drive_b => panic!("subscriber drive loop ended unexpectedly"),
        _ = drive_a => panic!("publisher drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    assert_eq!(fired.load(Ordering::SeqCst), 1, "exactly one delivery");
}
