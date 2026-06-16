// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "transport-fragmentation", feature = "transport-link-udp"))]

//! R311ol — the first LOSSY-link robustness e2e (P3.10 chaos track): over a
//! real loopback UDP link a DROPPED fragment datagram aborts its reassembly
//! chain, and the SAME live session reassembles a subsequent clean oversize
//! Put byte-exact. The channel RECOVERS from a lossy fragment chain rather
//! than wedging.
//!
//! ## What this proves that `udp_frag_e2e` does not
//!
//! `udp_frag_e2e` fragments + reassembles over a CLEAN loopback link (the
//! kernel never drops a 3-datagram Put on 127.0.0.1). Every existing e2e runs
//! over that clean path, so the reassembly + RX-SN-gate RECOVERY behaviour —
//! exercised only by unit tests in `reassembly_dispatch` — has never been
//! proved end-to-end over a live socket. This test injects a deterministic
//! single-datagram loss into the steady-state fragment stream and asserts the
//! two-stage drop + recover the design documents (zenoh-pico `rx.c` parity):
//!
//! 1. The dropped fragment leaves a GAP. The next fragment's SN still
//!    half-window-FOLLOWS the channel baseline, so it passes the per-channel
//!    RX SN gate (`admit_rx_frame_sn`, `_z_sn_precedes`) — a forward gap is
//!    admitted there. The reassembly dispatcher's strict in-order
//!    continuation check (`sn::consecutive`, §2.5) then ABORTS the chain on
//!    the non-consecutive SN, reclaiming the slot and emitting
//!    `IterationEvent::ReassemblyDropped(OutOfOrder)`. The disrupted message
//!    is lost — correct best-effort behaviour, NOT recovered (wz/pico carry no
//!    ARQ retransmit on the link).
//! 2. A subsequent clean oversize Put on the SAME session opens a FRESH chain
//!    (the aborted slot was reclaimed, the RX baseline advanced past the gap)
//!    and reassembles byte-exact. One bad chain does not wedge the channel.
//!
//! ## Why the loss is injected by a decorator, not the kernel
//!
//! Loopback does not drop, so the loss is applied by [`ChaosReadDriver`], a
//! `LinkDriver` decorator wrapping the acceptor's `InboundLink` AFTER its
//! clean handshake — the drop only perturbs the steady-state fragment stream,
//! never the handshake. It is TEST-LOCAL (no production type carries a chaos
//! variant): the open path runs the real `accept_and_open_session`, then the
//! steady-state drive (generic over `D: LinkDriver`) takes the wrapped driver.
//!
//! ## Non-flakiness
//!
//! The schedule is a fixed counter, NOT RNG: drop the 2nd inbound datagram
//! whose length exceeds 1000 bytes. The ~1450-byte UDP fragment datagrams are
//! the only steady-state traffic over that threshold (keepalives are tiny), so
//! the 2nd large datagram is deterministically the second fragment of the
//! FIRST (lossy) Put — the two Puts are published sequentially, so their
//! fragments never interleave. The acceptor side is driven continuously so the
//! reassembly pool persists across both chains; `select!` drops the drives
//! once the scenario observes the recovery delivery. Bounded sleeps keep a
//! regression failing fast instead of hanging. ([[feedback-no-flaky-ever]])

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::net::UdpSocket;

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio::udp_pipeline::UDP_LINK_MTU;
use wz_runtime_tokio::{LinkDriver, LinkEvent, Reliability, TxFrame};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::driver_loop::{IterationEvent, ReassemblyDropReason};
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/udp-chaos";
/// Size split between a UDP fragment datagram (~1450) and the tiny
/// control/keepalive datagrams (< 100): below the link MTU, far above any
/// control frame, so the chaos counter sees fragments only.
const LARGE_THRESHOLD: usize = 1000;

/// A [`LinkDriver`] decorator that applies a DETERMINISTIC loss schedule to
/// inbound datagrams: it swallows the `drop_large_ordinal`-th (1-based) frame
/// whose length exceeds `large_threshold`, passing everything else through. No
/// RNG — the schedule is a fixed counter, so the lossy-link scenario
/// reproduces byte-for-byte every run ([[feedback-no-flaky-ever]]).
///
/// Wraps any `LinkDriver`; the test wraps the acceptor's `InboundLink` after
/// its clean handshake so only the steady-state fragment stream is perturbed.
/// `dropped` is read after the drive completes to assert the loss was actually
/// injected (not merely inferred from the absence of a delivery).
struct ChaosReadDriver<D: LinkDriver> {
    inner: D,
    large_threshold: usize,
    drop_large_ordinal: usize,
    large_seen: usize,
    dropped: usize,
}

impl<D: LinkDriver> ChaosReadDriver<D> {
    fn new(inner: D, large_threshold: usize, drop_large_ordinal: usize) -> Self {
        Self {
            inner,
            large_threshold,
            drop_large_ordinal,
            large_seen: 0,
            dropped: 0,
        }
    }
}

impl<D: LinkDriver> LinkDriver for ChaosReadDriver<D> {
    async fn open(&mut self) -> io::Result<()> {
        self.inner.open().await
    }

    async fn send(&mut self, frame: &TxFrame<'_>, reliability: Reliability) -> io::Result<()> {
        self.inner.send(frame, reliability).await
    }

    async fn close(&mut self) -> io::Result<()> {
        self.inner.close().await
    }

    async fn poll_event(&mut self) -> LinkEvent {
        loop {
            let event = self.inner.poll_event().await;
            if let LinkEvent::Rx(frame) = &event {
                if frame.bytes.len() > self.large_threshold {
                    self.large_seen += 1;
                    if self.large_seen == self.drop_large_ordinal {
                        // Deterministic single drop: swallow this fragment
                        // datagram and poll for the next. Cancel-safe — a UDP
                        // recv is atomic per datagram, so a `select!` cancel
                        // here loses only the wake, never wire bytes.
                        self.dropped += 1;
                        continue;
                    }
                }
            }
            return event;
        }
    }
}

/// A dropped fragment datagram aborts its reassembly chain (the lossy Put is
/// lost, `ReassemblyDropped` observed) and the SAME live UDP session
/// reassembles a subsequent clean oversize Put byte-exact — the channel
/// recovers from a lossy fragment chain instead of wedging.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_lossy_fragment_chain_aborts_then_channel_recovers() {
    // Two DISTINCT oversize payloads so the delivered one identifies WHICH Put
    // survived: the first is lost to the dropped fragment, the second recovers.
    let payload_lost: Vec<u8> = (0..4096u32).map(|i| i.wrapping_mul(31) as u8).collect();
    let payload_kept: Vec<u8> = (0..4096u32)
        .map(|i| i.wrapping_mul(37).wrapping_add(7) as u8)
        .collect();
    assert!(
        payload_lost.len() > UDP_LINK_MTU,
        "payload must exceed one UDP link frame to force fragmentation"
    );
    assert_ne!(
        payload_lost, payload_kept,
        "the two Puts must differ so the delivered one is attributable"
    );

    let acc_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind acceptor");
    let addr = acc_socket.local_addr().expect("acceptor addr");

    // ── Open BOTH sessions concurrently and CLEANLY (no chaos during the
    //    handshake; mirrors udp_frag_e2e's peer-learning accept).
    let acc_open = async {
        let mut probe = [0u8; 64];
        let (_n, peer) = acc_socket
            .peek_from(&mut probe)
            .await
            .expect("peek initiator InitSyn datagram");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
        accept_and_open_session(
            DialedLink::Udp {
                socket: acc_socket,
                peer,
            },
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established over udp")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("udp/{addr}")).expect("parse loopback locator");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        connect_and_open_session(
            locator,
            params,
            &DialConfig::default(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established over udp")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    // ── Fragmentation precondition (R311nz): the UDP link MTU caps the
    //    negotiated TX budget so a ~4 KB Put splits into datagrams. Without it
    //    the Put would emit as one datagram and the dropped-fragment scenario
    //    would be vacuous.
    assert_eq!(
        opened_init.actions.negotiated_batch_mtu(),
        UDP_LINK_MTU,
        "publisher TX budget must cap to the UDP link MTU so each Put fragments"
    );
    assert_eq!(
        opened_acc.actions.negotiated_batch_mtu(),
        UDP_LINK_MTU,
        "acceptor TX budget caps to the same UDP link MTU (symmetry)"
    );

    // ── Wrap the acceptor's inbound driver to drop the 2nd large (fragment)
    //    datagram — a fragment of the FIRST Put, creating the gap that aborts
    //    its chain. The handshake is already done, so only the fragment stream
    //    is perturbed.
    let mut chaos_inbound = ChaosReadDriver::new(opened_acc.inbound, LARGE_THRESHOLD, 2);

    // ── Subscriber on the acceptor's observer; collects each delivered payload
    //    so the assertion can confirm WHICH Put arrived.
    let delivered: Arc<StdMutex<Vec<Vec<u8>>>> = Arc::new(StdMutex::new(Vec::new()));
    let mut observer = ApplicationLayerObserver::new();
    {
        let delivered = delivered.clone();
        observer.subscribers.register(KEYEXPR, move |sample| {
            assert_eq!(sample.keyexpr(), KEYEXPR);
            delivered.lock().unwrap().push(sample.payload().to_vec());
        });
    }

    // ── Count the lossy-chain abort the acceptor's drive loop reports.
    let drop_events = Arc::new(AtomicUsize::new(0));

    // ── Publisher on the initiator side (fresh observer — no local subscriber,
    //    so the proof is the remote delivery over the lossy link).
    let publisher = TokioSession::new(
        opened_init.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened_init.clock),
    );

    let timeouts = SessionTimeouts::spec_defaults();
    let drive_acc = drive_session_until_terminal(
        &mut chaos_inbound,
        &opened_acc.actions,
        &mut opened_acc.engine,
        None,
        &opened_acc.clock,
        &timeouts,
        {
            let drop_events = drop_events.clone();
            move |event| {
                if let IterationEvent::ReassemblyDropped(ReassemblyDropReason::OutOfOrder) = &event
                {
                    drop_events.fetch_add(1, Ordering::SeqCst);
                }
                observer.dispatch_event(event);
            }
        },
    );
    let drive_init = drive_session_until_terminal(
        &mut opened_init.inbound,
        &opened_init.actions,
        &mut opened_init.engine,
        None,
        &opened_init.clock,
        &timeouts,
        |_| {},
    );

    let delivered_probe = delivered.clone();
    let payload_kept_probe = payload_kept.clone();
    let scenario = async move {
        // Let both drives reach steady state.
        tokio::time::sleep(Duration::from_millis(300)).await;
        // Put #1 — its 2nd fragment datagram is dropped, so the chain aborts
        // and this message is NEVER delivered.
        publisher
            .publish(KEYEXPR, &payload_lost, PublishOptions::put())
            .expect("lossy publish builds and routes through the send seam");
        // Let Put #1's fragments flow through (and abort) before Put #2, so the
        // chaos counter's 2nd large datagram is unambiguously a Put #1 fragment.
        tokio::time::sleep(Duration::from_millis(300)).await;
        // Put #2 — clean: opens a fresh chain on the same session and
        // reassembles byte-exact.
        publisher
            .publish(KEYEXPR, &payload_kept_probe, PublishOptions::put())
            .expect("recovery publish builds and routes through the send seam");
        for _ in 0..100 {
            if delivered_probe
                .lock()
                .unwrap()
                .iter()
                .any(|p| p == &payload_kept_probe)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        // Settle margin so an erroneous extra delivery (e.g. the lossy Put
        // wrongly completing) surfaces before the assertions.
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive loop ended unexpectedly"),
        _ = drive_init => panic!("initiator drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    // ── The chaos driver injected exactly one loss.
    assert_eq!(
        chaos_inbound.dropped, 1,
        "the chaos driver dropped exactly one fragment datagram"
    );
    // ── The acceptor observed the lossy chain abort (the loss was real, not a
    //    slow delivery).
    assert!(
        drop_events.load(Ordering::SeqCst) >= 1,
        "the acceptor observed the lossy chain abort (ReassemblyDropped::OutOfOrder)"
    );
    // ── Exactly one delivery, and it is the SECOND (clean) Put — the first was
    //    lost to the dropped fragment, the channel recovered for the second.
    let got = delivered.lock().unwrap().clone();
    assert_eq!(
        got.len(),
        1,
        "exactly one delivery: the lossy Put aborted, only the clean Put arrived (got {} deliveries)",
        got.len()
    );
    assert_eq!(
        got[0], payload_kept,
        "the delivered payload is the SECOND (clean) Put; the first was lost to the dropped fragment"
    );
}
