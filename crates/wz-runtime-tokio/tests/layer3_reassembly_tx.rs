// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(feature = "transport-fragmentation")]

//! R311ni — unicast TX FRAGMENTATION end-to-end over a real loopback TCP
//! link. The complement of `layer3_reassembly_rx.rs` (which feeds
//! hand-crafted `T_MID_FRAGMENT` bytes into the dispatcher): this exercises
//! the PRODUCTION send path — `Session::publish` -> `send_network_message`
//! seam -> `SessionLinkActions::dispatch_network_message` ->
//! `emit_frame_or_fragments` (`session_actions.rs:1325`) — so an oversize
//! Put leaves the publisher node as a fragment chain on the wire, and the
//! subscriber node's steady-state drive loop reassembles it
//! (`report_outcome_reassembling`) back into one delivered Sample.
//!
//! The gap this closes (session review, R311nf): the UNICAST TX split had no
//! end-to-end proof — only codec round-trip (`frame_encode`) plus the
//! RX-ingest half (`layer3_reassembly_rx`). Its multicast counterpart is
//! `multicast_pubsub_loopback::oversize_put_fragments_and_reassembles_across_nodes`
//! (which forces a small MTU by setting `MulticastParams.batch_size` directly
//! — no handshake negotiation). This is the missing oversize real-socket
//! UNICAST send, where the MTU is NEGOTIATED, so the fragmentation
//! precondition is asserted explicitly (see `negotiated_batch_mtu` below)
//! rather than merely trusted.
//!
//! "Oversize" = a frame past a SMALL negotiated batch budget: both peers
//! advertise `batch_size = 64` in their InitSyn/InitAck, the negotiated MTU
//! is `min(own, peer) = 64`, and a 200-byte Put's frame far exceeds it. The
//! test ASSERTS the negotiated MTU is 64 before publishing (R311nj) so the
//! split is guaranteed by construction — a regression that broke negotiation
//! would fail the assert, not silently pass with a single un-fragmented
//! frame. Both sessions are driven with `max_iters = None` (continuous) so
//! the RX reassembly pool persists across the fragment chain's arrivals — a
//! chunked drive would reset it between fragments.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/frag";
// 64-byte negotiated MTU; a 200-byte payload's Put frame exceeds it and
// fragments into a multi-chunk T_MID_FRAGMENT chain.
const BATCH_SIZE: u16 = 64;

/// An oversize unicast `Session::publish` fragments on TX and the peer's
/// drive loop reassembles it into exactly one delivered Sample carrying the
/// full payload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unicast_oversize_put_fragments_on_tx_and_reassembles_on_rx() {
    let payload: Vec<u8> = (0..200u32).map(|i| (i * 13) as u8).collect();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // ── Open BOTH sessions concurrently (the handshake needs both sides
    //    progressing). Each side advertises batch_size = 64 so the
    //    negotiated steady-state MTU is 64.
    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4]; // distinct from the initiator
        params.batch_size = BATCH_SIZE;
        accept_and_open_session(
            DialedLink::Tcp(stream),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
        params.batch_size = BATCH_SIZE;
        connect_and_open_session(
            locator,
            params,
            &DialConfig::default(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    // ── Fragmentation precondition, asserted BY CONSTRUCTION (R311nj). The
    //    TX split in `emit_frame_or_fragments` branches on `frame.len() >
    //    mtu`, where `mtu = negotiated_batch_mtu() = min(own, peer)`. Pin the
    //    negotiated MTU to the tiny budget here: with MTU == 64 and a 200-byte
    //    payload (a Put frame far past 64), the publisher's `Session::publish`
    //    is FORCED through the fragment branch — without this assert the test
    //    would still pass if negotiation silently regressed to the 65535
    //    default (the 200-byte payload fits one frame within the msg_put 256-
    //    byte codec bound and would deliver as a single un-fragmented Sample,
    //    a false positive). The publisher side is the load-bearing one (it
    //    decides the split); the acceptor is asserted too for negotiation
    //    symmetry. Read before the bundles are borrowed by the drive loops.
    assert_eq!(
        opened_init.actions.negotiated_batch_mtu(),
        BATCH_SIZE as usize,
        "publisher negotiated MTU must be the tiny budget so the 200-byte Put fragments"
    );
    assert_eq!(
        opened_acc.actions.negotiated_batch_mtu(),
        BATCH_SIZE as usize,
        "acceptor negotiated the same tiny budget (symmetry)"
    );

    // ── Subscriber on the acceptor's observer.
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
                "the reassembled payload matches the oversize Put byte-for-byte"
            );
            fired.fetch_add(1, Ordering::SeqCst);
        });
    }

    // ── Publisher session over the initiator's bundle (fresh observer — the
    //    publisher has no local subscribers, so the publish loopback leg
    //    delivers nothing and the proof is entirely the remote fragment
    //    chain).
    let publisher = TokioSession::new(
        opened_init.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened_init.clock),
    );

    let timeouts = SessionTimeouts::spec_defaults();

    // Both sides driven continuously (None) so the RX reassembly pool lives
    // across the whole fragment chain. select! drops the drives when the
    // scenario observes the delivery.
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
        // Let both drives reach the steady state, then publish once.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let delivered = publisher
            .publish(KEYEXPR, &payload, PublishOptions::put())
            .expect("oversize publish builds and routes through the send seam");
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
        "exactly one reassembled delivery from the oversize fragmented Put"
    );
}
