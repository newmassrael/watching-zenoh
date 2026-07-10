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
    drive_multicast_session, multicast_put_literal, spawn_router_mcast_egress, MulticastDriveConfig,
};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::UdpDriver;
use wz_session_core::multicast_dispatch::{MulticastConfig, MulticastDispatcher};
use wz_session_core::multicast_params::MulticastParams;
use wz_session_core::observer::ApplicationLayerObserver;
use wz_session_core::WhatAmI;
#[cfg(feature = "transport-qos")]
use {
    std::sync::Mutex,
    wz_runtime_tokio::session::{PublishOptions, TokioMulticastSession},
    wz_session_core::qos::Priority,
};

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 224);
// Distinct group port from the scouting Layer M tests (7446 / 7448) so the
// `--ignored` lane never contends on the same multicast bind.
const PORT: u16 = 7449;
const KEYEXPR: &str = "demo/mc/e2e";
const PAYLOAD: &[u8] = b"pub-over-multicast";

fn mc_params(zid_byte: u8) -> MulticastParams {
    MulticastParams {
        version: 0x09,
        whatami: WhatAmI::Peer,
        zid: vec![zid_byte; 4],
        lease_ms: 5_000,
        join_interval_ms: 50,
        seq_num_res: 0x02,
        req_id_res: 0x02,
        batch_size: 2_048,
        is_qos: false,
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

/// R311y232 (transport-qos ACTIVATION e2e) — the composed proof over REAL UDP that
/// closes the direct-multicast QoS-publish path the WHOLE-SESSION finding named.
/// BOTH nodes offer `is_qos` (the `--multicast-qos` knob -> `MulticastParams.is_qos`),
/// node A publishes through a DIRECT [`TokioMulticastSession::publish_qos`] at a
/// NON-DEFAULT priority, and the qos subscriber node B admits A's qos JOIN and
/// delivers the prioritized Put. The admission IS the qos-handshake proof: a
/// NON-qos B would REFUSE a qos peer's JOIN (the group-agreed rule, zenoh
/// multicast/rx.rs:131 / wz multicast_rx self-gate), so delivery on a both-qos
/// group can only happen if the is_qos offer travelled the wire and both sides
/// agreed. This gives `Session::publish_qos` a real end-to-end driver (the
/// per-priority conduit SN-isolation itself is the deterministic dispatch proof
/// `wz_session_core::multicast_tx::qos_emit_tests`, run by run-ci Layer C1bc). The
/// publisher's own JOIN also rides `is_qos=true`, so this exercises the qos JOIN
/// encode + decode + admit path end to end, not only the frame ext_qos.
#[cfg(feature = "transport-qos")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "multicast loopback e2e; Layer A1c qos arm runs it via --ignored"]
async fn qos_group_publish_qos_reaches_subscriber() {
    // Distinct group port from the sibling loopback tests (7449/7450/7451) so the
    // --ignored lane never contends on the same multicast bind.
    const QOS_PORT: u16 = 7453;
    let qos_params = |zid_byte: u8| MulticastParams {
        is_qos: true,
        ..mc_params(zid_byte)
    };

    // Subscriber node B: qos group-joined socket + observer-backed drive loop.
    let mut driver_b = UdpDriver::bind_multicast_v4(GROUP, QOS_PORT)
        .await
        .expect("bind qos multicast subscriber link");
    let mut dispatcher_b = MulticastDispatcher::<8>::new(MulticastConfig::new(5_000));
    let params_b = qos_params(0xBB);

    let fired = Arc::new(AtomicUsize::new(0));
    let mut observer_b = ApplicationLayerObserver::new();
    {
        let fired = fired.clone();
        observer_b.subscribers.register(KEYEXPR, move |sample| {
            assert_eq!(sample.keyexpr(), KEYEXPR);
            assert_eq!(sample.payload(), PAYLOAD);
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }

    // Publisher node A: ephemeral-bound socket targeting the group, DRIVEN through a
    // direct multicast Session so `publish_qos` (not a hand-built tx item) is the
    // originator under test.
    let sock_a = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .expect("bind ephemeral publisher socket");
    let mut driver_a = UdpDriver::from_socket(sock_a, SocketAddr::from((GROUP, QOS_PORT)));
    let mut dispatcher_a = MulticastDispatcher::<8>::new(MulticastConfig::new(5_000));
    let params_a = qos_params(0xAA);

    let (tx_a, mut rx_a) = tokio::sync::mpsc::unbounded_channel();
    let (_hold_b, mut rx_b) = tokio::sync::mpsc::unbounded_channel();

    let clock = Arc::new(TokioTime::new());
    // The direct multicast Session whose `publish_qos` feeds A's drive-loop channel.
    let session_a: TokioMulticastSession = TokioMulticastSession::new_multicast(
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        clock.clone(),
        tx_a,
    );

    let drive_b = drive_multicast_session(
        &mut dispatcher_b,
        MulticastDriveConfig {
            params: &params_b,
            tick_ms: 10,
            max_iters: None,
        },
        &mut driver_b,
        clock.as_ref(),
        |event| observer_b.dispatch_event(event),
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
        clock.as_ref(),
        |_| {},
        &mut rx_a,
    );

    let fired_probe = fired.clone();
    let scenario = async move {
        // Give A's qos JOIN beacons time to admit it into B's peer table.
        tokio::time::sleep(Duration::from_millis(300)).await;
        // The DIRECT multicast-Session prioritized publish (the finding's path):
        // publish_qos stamps InteractiveHigh onto the MulticastTxItem, and A's drive
        // loop `multicast_tx_emit` selects the per-priority conduit + frame ext_qos
        // because params_a.is_qos = true. On a non-qos group the same call would
        // clamp to DEFAULT (byte-identical); here the qos offer travelled the wire.
        session_a
            .publish_qos(
                KEYEXPR,
                PAYLOAD,
                PublishOptions::put(),
                Priority::InteractiveHigh,
            )
            .expect("multicast publish_qos");
        for _ in 0..100 {
            if fired_probe.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("qos subscriber did not fire within the 3s budget");
    };

    tokio::select! {
        _ = drive_b => panic!("subscriber drive loop ended unexpectedly"),
        _ = drive_a => panic!("publisher drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    assert_eq!(fired.load(Ordering::SeqCst), 1, "exactly one qos delivery");
    assert_eq!(
        dispatcher_b.active_peers(),
        1,
        "qos B admitted qos A's JOIN (a non-qos B would refuse a qos peer)"
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

/// R311oq — concurrent multi-peer reassembly pool isolation over a real UDP
/// multicast socket: the pool/quota-under-load (concurrent multi-chain) leg the
/// single-publisher `oversize_put_fragments_and_reassembles_across_nodes` does
/// not exercise.
///
/// Two publishers (A, C) on distinct ephemeral sockets send DISTINCT oversize
/// (fragmented) Puts to the SAME group concurrently. The subscriber node B's
/// reassembly pool keys each chain by source address
/// ([`multicast_chain_key`](wz_session_core::multicast_dispatch)), so the two
/// interleaved fragment streams reassemble into two INDEPENDENT byte-exact
/// samples — neither bleeds into the other even though their datagrams race on
/// the wire.
///
/// ## Determinism (no-flaky)
///
/// OUTCOME-deterministic regardless of how the OS interleaves A's and C's
/// datagrams: per-source keying isolates the chains, so ANY interleaving
/// reassembles both. Loopback multicast does not drop and the volume is small
/// (~8 datagrams total — no UDP burst overflow). Both publishes are queued only
/// AFTER a JOIN-admission settle so B has both peers in its table before their
/// fragments arrive. The sole synchronization is a poll-on-condition for both
/// deliveries. A cross-contaminated merge would match NEITHER expected payload
/// (or fail frame decode), so the two byte-exact assertions are the isolation
/// proof. ([[feedback-no-flaky-ever]])
#[cfg(feature = "transport-fragmentation")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "multicast loopback e2e; Layer M runs via --layer M / WZ_RUN_LAYER_M=1 --ignored"]
async fn concurrent_peers_fragment_reassemble_in_isolation() {
    const CONC_PORT: u16 = 7451;
    const CONC_KEYEXPR: &str = "demo/mc/frag-conc";
    // Two DISTINCT oversize payloads so each delivered sample is attributable to
    // its publisher and a cross-contaminated merge would match NEITHER.
    let payload_a: Vec<u8> = (0..200u32).map(|i| (i * 13) as u8).collect();
    let payload_c: Vec<u8> = (0..200u32).map(|i| (i * 7 + 3) as u8).collect();
    assert_ne!(
        payload_a, payload_c,
        "the two Puts must differ so each delivery is attributable"
    );
    // 64-byte batch budget forces each ~200-byte Put into a T_MID_FRAGMENT chain
    // (same shrink the sibling oversize test uses).
    let conc_params = |zid_byte: u8| MulticastParams {
        batch_size: 64,
        ..mc_params(zid_byte)
    };

    // ── Subscriber B: joins the group, collects every delivered payload.
    let mut driver_b = UdpDriver::bind_multicast_v4(GROUP, CONC_PORT)
        .await
        .expect("bind multicast subscriber link");
    let mut dispatcher_b = MulticastDispatcher::<8>::new(MulticastConfig::new(5_000));
    let params_b = conc_params(0xBB);

    let delivered: Arc<std::sync::Mutex<Vec<Vec<u8>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut observer = ApplicationLayerObserver::new();
    {
        let delivered = delivered.clone();
        observer.subscribers.register(CONC_KEYEXPR, move |sample| {
            assert_eq!(sample.keyexpr(), CONC_KEYEXPR);
            delivered.lock().unwrap().push(sample.payload().to_vec());
        });
    }

    // ── Publishers A and C: distinct ephemeral sockets -> distinct source
    //    addresses -> distinct source-keyed chains in B's pool.
    let sock_a = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .expect("bind ephemeral publisher A socket");
    let mut driver_a = UdpDriver::from_socket(sock_a, SocketAddr::from((GROUP, CONC_PORT)));
    let mut dispatcher_a = MulticastDispatcher::<8>::new(MulticastConfig::new(5_000));
    let params_a = conc_params(0xAA);

    let sock_c = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .expect("bind ephemeral publisher C socket");
    let mut driver_c = UdpDriver::from_socket(sock_c, SocketAddr::from((GROUP, CONC_PORT)));
    let mut dispatcher_c = MulticastDispatcher::<8>::new(MulticastConfig::new(5_000));
    let params_c = conc_params(0xCC);

    let (tx_a, mut rx_a) = tokio::sync::mpsc::unbounded_channel();
    let (tx_c, mut rx_c) = tokio::sync::mpsc::unbounded_channel();
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
    let drive_c = drive_multicast_session(
        &mut dispatcher_c,
        MulticastDriveConfig {
            params: &params_c,
            tick_ms: 10,
            max_iters: None,
        },
        &mut driver_c,
        &clock,
        |_| {},
        &mut rx_c,
    );

    let delivered_probe = delivered.clone();
    let exp_a = payload_a.clone();
    let exp_c = payload_c.clone();
    let scenario = async move {
        // Both publishers' JOIN beacons admit them into B's peer table first
        // (an un-admitted peer's fragments are dropped at B's SN gate).
        tokio::time::sleep(Duration::from_millis(400)).await;
        // Then both publish their oversize Put — the two fragment chains
        // interleave on the group and B's pool must keep them separate.
        tx_a.send(multicast_put_literal(CONC_KEYEXPR, &exp_a).expect("put A"))
            .expect("queue publish A");
        tx_c.send(multicast_put_literal(CONC_KEYEXPR, &exp_c).expect("put C"))
            .expect("queue publish C");
        for _ in 0..150 {
            {
                let got = delivered_probe.lock().unwrap();
                if got.iter().any(|p| p == &exp_a) && got.iter().any(|p| p == &exp_c) {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("both concurrent oversize Puts not delivered within the budget");
    };

    tokio::select! {
        _ = drive_b => panic!("subscriber drive loop ended unexpectedly"),
        _ = drive_a => panic!("publisher A drive loop ended unexpectedly"),
        _ = drive_c => panic!("publisher C drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    let got = delivered.lock().unwrap().clone();
    // Exactly two deliveries, one per concurrent peer, each byte-exact — neither
    // source-keyed chain bled into the other.
    assert_eq!(
        got.len(),
        2,
        "exactly two deliveries (one per concurrent peer), got {}",
        got.len()
    );
    assert!(
        got.contains(&payload_a),
        "publisher A's oversize Put reassembled byte-exact in isolation"
    );
    assert!(
        got.contains(&payload_c),
        "publisher C's oversize Put reassembled byte-exact in isolation"
    );
    // B admitted both concurrent publishers (the two source-keyed chains).
    assert_eq!(
        dispatcher_b.active_peers(),
        2,
        "B admitted both concurrent publishers from their JOIN beacons"
    );
}

/// R311y188 — router-multicast-faces slice 3: the run-mode egress helper
/// `spawn_router_mcast_egress` binds + drives the group loop on a SEPARATE task;
/// a `MulticastTxItem::Push` on its returned sender (the sender a
/// `RouterForwarder::attach_mcast_group` holds) reaches a group subscriber. The
/// forwarder->sender half is the non-socket unit
/// `routed_push_broadcasts_to_attached_mcast_group`; this is the sender->group
/// socket half — the same `MulticastTxItem` seam, closed end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "multicast loopback e2e; Layer M runs via --layer M / WZ_RUN_LAYER_M=1 --ignored"]
async fn router_egress_helper_reaches_group_subscriber() {
    // Distinct group port from the sibling loopback tests (7449 / 7450) so the
    // --ignored lane never contends on the same multicast bind.
    const HELPER_PORT: u16 = 7451;

    // Subscriber node: group-joined socket + observer-backed drive loop.
    let mut driver_b = UdpDriver::bind_multicast_v4(GROUP, HELPER_PORT)
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

    // The router egress: the PRODUCTION helper spawns the group drive loop on its
    // own task and returns the sender `RouterForwarder::attach_mcast_group` holds.
    // `qos = false`: this loopback witness pins the pico-faithful 2-channel group
    // (the per-priority conduit is exercised by the dedicated qos witness, R311y232).
    let tx = spawn_router_mcast_egress(GROUP, HELPER_PORT, vec![0xAA; 4], false);

    let fired_probe = fired.clone();
    let scenario = async move {
        // Give the helper's JOIN beacons time to admit it into B's peer table.
        tokio::time::sleep(Duration::from_millis(300)).await;
        tx.send(multicast_put_literal(KEYEXPR, PAYLOAD).expect("put item"))
            .expect("queue publish on the egress helper's sender");
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
        _ = scenario => {}
    }

    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "exactly one delivery via the egress helper"
    );
    assert_eq!(
        dispatcher_b.active_peers(),
        1,
        "B admitted the egress helper from its JOIN beacon"
    );
}
