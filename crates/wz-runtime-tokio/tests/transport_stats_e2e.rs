// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "transport-stats", feature = "transport-unicast"))]

//! R311y9 — `transport-stats` integration proof: a real driven session
//! increments the per-session byte/message counters.
//!
//! Two wz nodes handshake over a loopback TCP link to Established. The
//! InitSyn/InitAck/OpenSyn/OpenAck exchange routes EVERY emit through the one
//! `send_wire` TX seam (where `transport-stats` counts tx_bytes/tx_msgs) and
//! EVERY inbound frame through the single `dispatch_link_event` RX chokepoint
//! (where it counts rx_bytes/rx_msgs), so by Established BOTH sides have counted
//! at least one tx and one rx wire message with non-zero bytes.
//! `OpenedSession::stats()` exposes the snapshot. Deterministic (a TCP loopback
//! handshake is the same reliable exchange every wz e2e relies on) — no
//! #[ignore], no flake.

use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_any_locator;

use tokio::net::TcpListener;

const ITER_CAP: usize = 64;

/// The handshake alone increments tx + rx byte/message counters on both peers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_increments_tx_and_rx_counters() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local_addr");

    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4]; // distinct from the initiator
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
        let cfg = DialConfig::default();
        connect_and_open_session(
            locator,
            params,
            &cfg,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established")
    };
    let (opened_acc, opened_init) = tokio::join!(acc_open, init_open);

    // By Established, the 2-round handshake has emitted >=2 frames and received
    // >=2 frames on each side (InitSyn/InitAck/OpenSyn/OpenAck), all routed
    // through the counted send_wire (TX) + dispatch_link_event (RX) seams.
    for (who, s) in [
        ("initiator", opened_init.stats()),
        ("acceptor", opened_acc.stats()),
    ] {
        assert!(s.tx_msgs >= 1, "{who} counted >=1 tx message ({s:?})");
        assert!(s.rx_msgs >= 1, "{who} counted >=1 rx message ({s:?})");
        assert!(s.tx_bytes > 0, "{who} counted >0 tx bytes ({s:?})");
        assert!(s.rx_bytes > 0, "{who} counted >0 rx bytes ({s:?})");
    }
}
