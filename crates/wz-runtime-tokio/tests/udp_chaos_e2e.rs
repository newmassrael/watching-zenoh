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
//! Loopback does not drop, so the loss is applied by
//! [`ChaosReadDriver`](wz_runtime_tokio_test_support::ChaosReadDriver), the
//! shared deterministic `LinkDriver` loss decorator. It wraps the acceptor's
//! `InboundLink` AFTER its clean handshake, so only the steady-state fragment
//! stream is perturbed; the open path runs the real `accept_and_open_session`,
//! and the steady-state drive (generic over `D: LinkDriver`) takes the wrapped
//! driver. No PRODUCTION type carries a chaos variant. The decorator is the
//! reusable MECHANISM (count + drop); the POLICY — which datagram is a
//! fragment — is this test's [`is_fragment_datagram`] predicate, which decodes
//! the transport MID (the principled wire identity, not a size heuristic).
//!
//! ## Non-flakiness
//!
//! Deterministic by construction, NOT RNG: drop the 2nd inbound datagram whose
//! transport MID is `T_MID_FRAGMENT`. A 4 KB Put exceeds the UDP link MTU so it
//! always splits into >= 2 fragments, hence the 2nd fragment is always a
//! fragment of the FIRST (lossy) Put. The two Puts are emitted back-to-back
//! with NO inter-publish delay: `emit_frame_or_fragments` writes each Put's
//! whole fragment chain wire-atomically under the TX lock and the writer drains
//! FIFO, so P1's fragments precede P2's on the wire deterministically. The only
//! synchronization is a poll-on-condition wait for the clean delivery; by FIFO
//! the dropped fragment + the abort are already processed by the time P2
//! completes, so the assertions need no settle margin. The acceptor is driven
//! continuously so the reassembly pool persists across both chains; `select!`
//! drops the drives once the scenario observes the recovery delivery.
//! ([[feedback-no-flaky-ever]])

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
use wz_runtime_tokio::RxFrame;
use wz_runtime_tokio_test_support::{fixture_session_init_params, ChaosReadDriver};
use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent, ReassemblyDropReason};
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::wire_const;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/udp-chaos";

/// A UDP datagram carries exactly one transport message, so its first byte is
/// the transport header whose low 5 bits are the MID — the production
/// classifier shape (`multicast_rx` / `inbound`: `header & 0x1f`). A
/// `T_MID_FRAGMENT` datagram is one fragment of an oversize Put. Identifying
/// the drop candidate by wire identity (not a size heuristic) keeps the policy
/// principled: the schedule targets "a fragment", not "a big datagram".
fn is_fragment_datagram(frame: &RxFrame) -> bool {
    frame.bytes.first().map(|h| h & 0x1f) == Some(wire_const::T_MID_FRAGMENT)
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
        "payload must exceed one UDP link frame to force fragmentation (>= 2 fragments)"
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

    // ── Wrap the acceptor's inbound driver to drop the 2nd fragment datagram.
    //    A 4 KB Put is >= 2 fragments, so the 2nd fragment is always a fragment
    //    of the FIRST Put — dropping it leaves a gap that aborts P1's chain.
    //    The handshake is already done, so only the fragment stream is
    //    perturbed.
    let mut chaos_inbound =
        ChaosReadDriver::drop_nth_matching(opened_acc.inbound, 2, is_fragment_datagram);

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
        // Two oversize Puts back-to-back, NO inter-publish delay: each Put's
        // whole fragment chain emits wire-atomically under the TX lock and the
        // writer drains FIFO, so P1's fragments precede P2's deterministically
        // — the 2nd fragment the chaos driver drops is unambiguously P1's.
        publisher
            .publish(KEYEXPR, &payload_lost, PublishOptions::put())
            .expect("lossy publish builds and routes through the send seam");
        publisher
            .publish(KEYEXPR, &payload_kept_probe, PublishOptions::put())
            .expect("recovery publish builds and routes through the send seam");
        // The sole synchronization: poll until the clean Put is delivered. By
        // FIFO the dropped fragment + P1's abort are already processed by the
        // time P2 completes, so the post-drive assertions need no settle.
        for _ in 0..200 {
            if delivered_probe
                .lock()
                .unwrap()
                .iter()
                .any(|p| p == &payload_kept_probe)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("recovery Put not delivered within the ~6s budget");
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

/// A DUPLICATED fragment datagram must not let its message bleed into the next
/// one. R311oo: over a real loopback UDP link a duplicate fragment trips the
/// per-channel RX SN gate (`admit_rx_frame_sn`, a ring distance of 0 is not a
/// forward step), and the drive layer clears the in-progress reassembly chain
/// (`abort_channel`, the zenoh-pico `rx.c` dbuf-clear analogue). The chain's
/// trailing final (M=0) fragment then arrives as a FRESH chain start.
///
/// Before the fix that stranded final fragment parked a stuck reassembly orphan
/// whose SN was ring-consecutive to the NEXT Put's first fragment (SNs run
/// sequentially across messages on a channel), so the next Put was appended onto
/// the orphan and delivered as one merged blob — which then failed frame decode,
/// silently swallowing a perfectly good message. Now the stranded fragment
/// completes + is reclaimed in one step (zenoh-pico `if (!more) decode` parity),
/// so the SAME live session reassembles the subsequent clean Put byte-exact.
///
/// ## What this proves that `udp_lossy_fragment_chain_aborts_then_channel_recovers` does not
///
/// The drop test exercises a GAP (a missing fragment). This exercises a
/// DUPLICATE (a fragment delivered twice) — a different lossy-link hazard that
/// reaches reassembly via a different path (the SN-gate `abort_channel` clear,
/// not the in-chain out-of-order abort) and strands a lone M=0 fragment the
/// drop path never produces. It is the integration counterpart of the
/// `stranded_final_fragment_does_not_merge_into_next_message` Router unit test.
///
/// ## Determinism (no-flaky)
///
/// Not RNG: duplicate the 1st inbound datagram whose transport MID is
/// `T_MID_FRAGMENT`. Each Put is ~2000 B — above one UDP link MTU (1450) so it
/// always splits, and below two fragments' worth of payload so it splits into
/// EXACTLY two fragments. The duplicated 1st fragment is therefore P1's first of
/// two, and the fragment that arrives after the SN gate clears the chain is P1's
/// trailing M=0 final — exactly the lone-final edge the fix addresses (a 3+
/// fragment Put would strand a more!=0 fragment, which never tripped the bug).
/// The two Puts emit back-to-back with no inter-publish delay
/// (`emit_frame_or_fragments` writes each Put's whole chain wire-atomically
/// under the TX lock; the writer drains FIFO), so P1's fragments precede P2's
/// deterministically and SNs run sequentially across the two messages — the
/// exact condition that produced the merge. The sole synchronization is a
/// poll-on-condition wait for the clean delivery. ([[feedback-no-flaky-ever]])
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_duplicate_fragment_strands_then_channel_recovers() {
    // ~2000 B: > UDP_LINK_MTU (always splits) and within two fragments' payload
    // budget (each fragment carries < MTU after its header, so 2000 B is two
    // fragments, never three) — so P1's 2nd fragment is its trailing M=0 final.
    let payload_lost: Vec<u8> = (0..2000u32).map(|i| i.wrapping_mul(31) as u8).collect();
    let payload_kept: Vec<u8> = (0..2000u32)
        .map(|i| i.wrapping_mul(37).wrapping_add(7) as u8)
        .collect();
    assert!(
        payload_lost.len() > UDP_LINK_MTU,
        "payload must exceed one UDP link frame to force fragmentation (>= 2 fragments)"
    );
    assert!(
        payload_lost.len() < 2 * UDP_LINK_MTU,
        "payload must stay within two fragments so P1's 2nd fragment is its lone M=0 final"
    );
    assert_ne!(
        payload_lost, payload_kept,
        "the two Puts must differ so the delivered one is attributable"
    );

    let acc_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind acceptor");
    let addr = acc_socket.local_addr().expect("acceptor addr");

    // ── Open BOTH sessions concurrently and CLEANLY (no chaos during the
    //    handshake; the duplicate perturbs only the steady-state fragment stream).
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

    // ── Fragmentation precondition: the UDP link MTU caps the negotiated TX
    //    budget so each ~2 KB Put splits into datagrams.
    assert_eq!(
        opened_init.actions.negotiated_batch_mtu(),
        UDP_LINK_MTU,
        "publisher TX budget must cap to the UDP link MTU so each Put fragments"
    );

    // ── Wrap the acceptor's inbound driver to DUPLICATE the 1st fragment
    //    datagram (P1's first of two). The handshake is already done, so only
    //    the fragment stream is perturbed.
    let mut chaos_inbound =
        ChaosReadDriver::duplicate_nth_matching(opened_acc.inbound, 1, is_fragment_datagram);

    // ── Subscriber on the acceptor's observer; collects each delivered payload.
    let delivered: Arc<StdMutex<Vec<Vec<u8>>>> = Arc::new(StdMutex::new(Vec::new()));
    let mut observer = ApplicationLayerObserver::new();
    {
        let delivered = delivered.clone();
        observer.subscribers.register(KEYEXPR, move |sample| {
            assert_eq!(sample.keyexpr(), KEYEXPR);
            delivered.lock().unwrap().push(sample.payload().to_vec());
        });
    }

    // ── Count the channel SN-gate rejection the duplicate fragment triggers
    //    (the positive proof the duplicate was processed and cleared the chain).
    let sn_rejected = Arc::new(AtomicUsize::new(0));

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
            let sn_rejected = sn_rejected.clone();
            move |event| {
                if let IterationEvent::Poll(DriverLoopOutcome::RxSnRejected { .. }) = &event {
                    sn_rejected.fetch_add(1, Ordering::SeqCst);
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
        // Two oversize Puts back-to-back, NO inter-publish delay: P1's whole
        // fragment chain precedes P2's on the wire (FIFO), so the duplicated 1st
        // fragment is unambiguously P1's first.
        publisher
            .publish(KEYEXPR, &payload_lost, PublishOptions::put())
            .expect("first publish builds and routes through the send seam");
        publisher
            .publish(KEYEXPR, &payload_kept_probe, PublishOptions::put())
            .expect("recovery publish builds and routes through the send seam");
        for _ in 0..200 {
            if delivered_probe
                .lock()
                .unwrap()
                .iter()
                .any(|p| p == &payload_kept_probe)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("recovery Put not delivered within the ~6s budget");
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive loop ended unexpectedly"),
        _ = drive_init => panic!("initiator drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    // ── The chaos driver injected exactly one duplicate.
    assert_eq!(
        chaos_inbound.duplicated, 1,
        "the chaos driver duplicated exactly one fragment datagram"
    );
    // ── The duplicate tripped the channel SN gate (the chain was cleared) — the
    //    perturbation was real, not absorbed silently.
    assert!(
        sn_rejected.load(Ordering::SeqCst) >= 1,
        "the duplicate fragment tripped the channel RX SN gate (RxSnRejected)"
    );
    // ── Exactly one delivery, and it is the SECOND (clean) Put. The first was
    //    lost (its chain cleared by the duplicate), and — crucially — it did NOT
    //    merge into the second: pre-fix, the stranded final fragment would have
    //    absorbed P2 and the merged blob would have failed decode, yielding ZERO
    //    deliveries.
    let got = delivered.lock().unwrap().clone();
    assert_eq!(
        got.len(),
        1,
        "exactly one clean delivery; the duplicate-stranded P1 fragment did NOT merge into P2 (got {} deliveries)",
        got.len()
    );
    assert_eq!(
        got[0], payload_kept,
        "the delivered payload is the SECOND (clean) Put, reassembled in isolation"
    );
}
