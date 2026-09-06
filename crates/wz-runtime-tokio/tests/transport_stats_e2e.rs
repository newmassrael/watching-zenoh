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
        assert!(s.tx.t_msgs >= 1, "{who} counted >=1 tx message ({s:?})");
        assert!(s.rx.t_msgs >= 1, "{who} counted >=1 rx message ({s:?})");
        assert!(s.tx.bytes > 0, "{who} counted >0 tx bytes ({s:?})");
        assert!(s.rx.bytes > 0, "{who} counted >0 rx bytes ({s:?})");

        // R2371 — the handshake is TRANSPORT messages only: InitSyn / InitAck /
        // OpenSyn / OpenAck carry no Frame envelope and no network message, so
        // the network plane must still read zero here. This is the negative half
        // of the `t_msgs` / `n_msgs` distinction, and it is what would catch a
        // seam that charged both counters from one place.
        assert_eq!(
            s.tx.n_msgs_total(),
            0,
            "{who}: a handshake carries no network message ({s:?})"
        );
        assert_eq!(
            s.rx.n_msgs_total(),
            0,
            "{who}: a handshake carries no network message ({s:?})"
        );

        // Nothing was refused and no interceptor ran, so every drop counter is
        // zero. Pinned rather than assumed: `n_dropped` moving during a clean
        // handshake would mean the driver-outcome seam is charging a SENT write.
        assert_eq!(s.tx.n_dropped, 0, "{who} dropped a handshake frame ({s:?})");
        assert_eq!(
            (
                s.tx.downsampler_dropped_msgs,
                s.tx.low_pass_dropped_msgs,
                s.tx.low_pass_dropped_bytes
            ),
            (0, 0, 0),
            "{who}: no interceptor ran, so no interceptor drop is charged ({s:?})"
        );
    }
}

/// R2371 — a real PUBLISH moves the network plane: `n_msgs` on the `net`
/// medium, and the `z_put` payload cell for the `user` space.
///
/// The paired positive to the handshake test's negative. It is the seam the
/// `dispatch_*` wrappers feed, so a sender added without a
/// [`wz_session_core::stats::NetworkStatsClass`] would fail to compile rather
/// than fail this — but what this pins is that the class the Push wrapper
/// derives is the RIGHT one, which no compile can check.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "codec-push")]
async fn a_publish_moves_the_network_and_payload_counters() {
    use wz_session_core::stats::{StatMedium, StatMessage, StatSpace};

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local_addr");

    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4];
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
    let (_opened_acc, opened_init) = tokio::join!(acc_open, init_open);

    let before = opened_init.stats();
    opened_init
        .actions
        .send_push_literal("demo/example/stats", b"twelve bytes", true)
        .expect("the publish reaches the transport");
    let after = opened_init.stats();

    assert_eq!(
        after.tx.n_msgs_on(StatMedium::Net) - before.tx.n_msgs_on(StatMedium::Net),
        1,
        "one Push is one network message on the net medium ({after:?})"
    );
    assert_eq!(
        after.tx.n_msgs_on(StatMedium::Shm),
        0,
        "no SHM descriptor rode this publish ({after:?})"
    );

    let put = after.tx.payload_of(StatMessage::Put, StatSpace::User);
    let put_before = before.tx.payload_of(StatMessage::Put, StatSpace::User);
    assert_eq!(put.msgs - put_before.msgs, 1, "one user-space Put");
    assert_eq!(
        put.pl_bytes - put_before.pl_bytes,
        b"twelve bytes".len(),
        "the payload byte count is the PAYLOAD, not the envelope ({after:?})"
    );

    // The admin cell and the other three kinds stay put: a Put must not bleed
    // into `z_del` / `z_query` / `z_reply`, and a user key must not count admin.
    assert_eq!(
        after.tx.payload_of(StatMessage::Put, StatSpace::Admin),
        put_before_admin(&before),
        "a `demo/...` key is user space, not admin ({after:?})"
    );
    for other in [StatMessage::Del, StatMessage::Query, StatMessage::Reply] {
        assert_eq!(
            after.tx.payload_of(other, StatSpace::User).msgs,
            before.tx.payload_of(other, StatSpace::User).msgs,
            "a Put moved the {other:?} counter ({after:?})"
        );
    }
}

/// The admin-space Put cell as it stood before the publish — hoisted so the
/// assertion above reads as a comparison rather than a nested expression.
#[cfg(feature = "codec-push")]
fn put_before_admin(
    before: &wz_session_core::stats::TransportStatsReport,
) -> wz_session_core::stats::PayloadCounters {
    use wz_session_core::stats::{StatMessage, StatSpace};
    before.tx.payload_of(StatMessage::Put, StatSpace::Admin)
}
