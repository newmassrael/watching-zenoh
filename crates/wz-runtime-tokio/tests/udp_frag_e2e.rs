// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "transport-fragmentation", feature = "transport-link-udp"))]

//! R311nz — unicast >MTU FRAGMENTATION end-to-end over a real loopback UDP
//! link, where the split is LINK-driven (the 1450 UDP link MTU), not
//! batch-negotiated. The UDP sibling of `serial_pty_e2e`'s
//! `wz_to_wz_over_serial_pty_fragments_and_reassembles_oversize_put` and the
//! datagram complement of `layer3_reassembly_tx` (TCP stream).
//!
//! ## What this proves that the TCP / serial e2e do not
//!
//! `layer3_reassembly_tx` fragments over a TCP STREAM (the chunks ride one
//! length-prefixed byte stream); `serial_pty_e2e` fragments over a serial
//! link (COBS-framed). This test fragments over UDP, where each zenoh
//! `T_MID_FRAGMENT` frame is ONE DATAGRAM — no stream reassembly, no link
//! framing, the datagram boundary IS the frame boundary. So it exercises the
//! reassembly pool accumulating a chain across SEPARATE datagrams, a path
//! neither sibling covers. It also pins the UDP link MTU (`UDP_LINK_MTU` =
//! zenoh-pico's `_z_get_link_mtu_udp_unicast` 1450) as the binding term.
//!
//! ## Why the precondition is LINK-driven, asserted by construction
//!
//! Both peers advertise the 65535 default batch (the fixture default — this
//! test does NOT shrink `batch_size` the way `layer3_reassembly_tx` does to
//! force a tiny budget). The negotiated TX budget is therefore
//! `min(own 65535, peer 65535, link 1450) = 1450` purely because
//! `UdpWriteDriver::link_mtu` reports 1450. A ~4 KB Put exceeds it and splits.
//! Without the link cap the budget would be 65535, the 4 KB Put would emit as
//! ONE datagram (< the 65507 `MAX_UDP_PAYLOAD` drop guard) and deliver
//! un-fragmented — a false positive. The test asserts
//! `negotiated_batch_mtu() == UDP_LINK_MTU` up front so a regression that
//! dropped the link bound fails the assert rather than silently passing.
//!
//! ## Non-flakiness
//!
//! Over 127.0.0.1 the kernel does not drop datagrams unless the socket recv
//! buffer overflows; a ~4 KB Put is ~3 sub-1450-byte datagrams plus a handful
//! of tiny handshake datagrams — far under the default recv buffer, so no
//! loss and in-order delivery in practice. The UDP session handshake itself
//! is precedented stable by `static_scout_open::open_session_at_udp_
//! reaches_established`. Both sides are driven continuously (`None`) so the RX
//! reassembly pool persists across the fragment chain's arrivals.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
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
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/udp-frag";

/// An oversize unicast `Session::publish` over UDP fragments on TX — capped by
/// the 1450 UDP link MTU, not a small negotiated batch — and the peer's drive
/// loop reassembles the datagram chain into exactly one byte-exact Sample.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wz_to_wz_over_udp_fragments_and_reassembles_oversize_put() {
    // A payload several datagrams long (4 KB > the 1450 UDP_LINK_MTU),
    // deterministic so the byte-exact reassembly check is reproducible.
    let payload: Vec<u8> = (0..4096u32).map(|i| i.wrapping_mul(31) as u8).collect();
    assert!(
        payload.len() > UDP_LINK_MTU,
        "payload must exceed one UDP link frame to force fragmentation"
    );

    let acc_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind acceptor");
    let addr = acc_socket.local_addr().expect("acceptor addr");

    // ── Open BOTH sessions concurrently (the datagram handshake needs both
    //    sides progressing). Both advertise the fixture default 65535 batch,
    //    so the negotiated steady-state TX budget is the 1450 link MTU.
    let acc_open = async {
        // UDP is connectionless: learn the initiator's ephemeral src from the
        // first datagram (the InitSyn) via MSG_PEEK so it stays queued for the
        // wired read driver's first poll, then accept against that peer. Same
        // peer-learning pattern as `drive_udp_acceptor_to_established`.
        let mut probe = [0u8; 64];
        let (_n, peer) = acc_socket
            .peek_from(&mut probe)
            .await
            .expect("peek initiator InitSyn datagram");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4]; // distinct from the initiator
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

    // ── Fragmentation precondition, asserted BY CONSTRUCTION (R311nz): the
    //    UDP link MTU caps the negotiated TX budget to UDP_LINK_MTU even
    //    though both peers advertised the 65535 default. The publisher side is
    //    load-bearing (it decides the split); the acceptor is asserted for
    //    negotiation symmetry. Without the link cap this would be 65535 and the
    //    ~4 KB Put would emit as one un-fragmented datagram — a false positive
    //    this assert forecloses.
    assert_eq!(
        opened_init.actions.negotiated_batch_mtu(),
        UDP_LINK_MTU,
        "publisher TX budget must cap to the UDP link MTU so the oversize Put fragments"
    );
    assert_eq!(
        opened_acc.actions.negotiated_batch_mtu(),
        UDP_LINK_MTU,
        "acceptor TX budget caps to the same UDP link MTU (symmetry)"
    );

    // ── Subscriber on the acceptor's observer; asserts the reassembled
    //    payload byte-for-byte.
    let fired = Arc::new(AtomicUsize::new(0));
    let mut observer = ApplicationLayerObserver::new();
    {
        let fired = fired.clone();
        let expect = payload.clone();
        observer.subscribers.register(KEYEXPR, move |sample| {
            assert_eq!(sample.keyexpr(), KEYEXPR);
            assert_eq!(
                sample.payload(),
                &expect[..],
                "the reassembled udp payload matches the oversize Put byte-for-byte"
            );
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }

    // ── Publisher on the initiator side (fresh observer — no local
    //    subscriber, so the proof is the remote fragment chain over UDP).
    let publisher = TokioSession::new(
        opened_init.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened_init.clock),
    );

    let timeouts = SessionTimeouts::spec_defaults();
    // Both sides driven continuously (None) so the RX reassembly pool lives
    // across the whole datagram fragment chain. select! drops the drives when
    // the scenario observes the delivery.
    let drive_acc = drive_session_until_terminal(
        &mut opened_acc.inbound,
        &opened_acc.actions,
        &mut opened_acc.engine,
        None,
        &opened_acc.clock,
        &timeouts,
        |event| observer.dispatch_event(event),
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

    let fired_probe = fired.clone();
    let scenario = async move {
        // Let both drives reach steady state, then publish once.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let delivered = publisher
            .publish(KEYEXPR, &payload, PublishOptions::put())
            .expect("oversize udp publish builds and routes through the send seam");
        assert_eq!(delivered, 0, "no local subscriber on the publisher side");
        for _ in 0..100 {
            if fired_probe.load(Ordering::SeqCst) > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("subscriber did not fire within the ~3s budget");
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive loop ended unexpectedly"),
        _ = drive_init => panic!("initiator drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "exactly one reassembled delivery from the oversize fragmented Put over udp"
    );
}
