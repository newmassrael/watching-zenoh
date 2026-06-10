// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A4b (session-reconnect) — end-to-end reconnect over a real loopback TCP
//! link: a client session opened via `open_session_with_reconnect` declares
//! a subscriber, the acceptor observes it and then drops the connection
//! abruptly (no Close frame — the link-loss shape, zenoh-pico
//! `_zp_unicast_failed_result` trigger class), the supervisor re-dials and
//! re-handshakes against the re-accepting listener, and the SECOND accepted
//! connection observes the SAME Declare replayed from the declaration cache
//! (pico `_z_client_reopen_task_fn` cache-walk parity).
//!
//! Engines are driven on the current task (the `tokio::join!` pattern of
//! `accept_and_open_session.rs`); iteration caps bound every loop so a
//! regression fails fast instead of hanging.

#![cfg(feature = "session-reconnect")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::net::TcpListener;

use wz_runtime_tokio::reconnect::{
    open_session_with_reconnect, ReconnectDriveOutcome, ReconnectPolicy,
};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::{drive_session_until_terminal, DriverOutcome};
use wz_runtime_tokio::session_open::{
    accept_and_open_session, DialedLink, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
use wz_session_core::locator::parse_locator;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;

/// Accept one connection, complete the accept-side handshake, then drive
/// the steady loop until at least one inbound `Declare` network message is
/// observed. Returns the live acceptor session (dropping it severs the
/// link abruptly) plus the Debug rendering of each observed Declare — the
/// replay assertion compares these across connections, which pins the full
/// decoded declaration (kind, id, keyexpr) without depending on wire SNs.
async fn accept_and_collect_declares(listener: &TcpListener) -> (OpenedSession, Vec<String>) {
    let (stream, _peer) = listener.accept().await.expect("accept");
    let mut params = fixture_session_init_params();
    params.zid = vec![0x02; 4]; // distinct zid from the initiator
    let mut opened = accept_and_open_session(
        DialedLink::Tcp(stream),
        params,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .expect("acceptor reaches Established");

    let mut declares = Vec::new();
    // Drive in single-iteration chunks so the helper returns as soon as the
    // Declare lands (a larger chunk would idle out its remaining iterations
    // on the steady loop's tick cadence before this loop can re-check).
    while declares.is_empty() {
        let outcome = drive_session_until_terminal(
            &mut opened.inbound,
            &opened.actions,
            &mut opened.engine,
            Some(1),
            &opened.clock,
            &SessionTimeouts::spec_defaults(),
            |event| {
                if let IterationEvent::Poll(DriverLoopOutcome::FramePayload { messages, .. }) =
                    event
                {
                    for message in messages {
                        if matches!(message, NetworkMessage::Declare(_)) {
                            declares.push(format!("{message:?}"));
                        }
                    }
                }
            },
        )
        .await;
        assert!(
            !matches!(outcome, DriverOutcome::Terminated),
            "peer terminated before its Declare arrived"
        );
    }
    (opened, declares)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn declares_replay_after_link_loss_and_reconnect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let locator = parse_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
    let mut params = fixture_session_init_params();
    params.zid = vec![0x01; 4];

    // ── Connection #1: client opens (reconnect-supervised wiring), declares
    //    a subscriber; the acceptor handshakes and observes the Declare.
    let policy = ReconnectPolicy {
        retry_delay_ms: 50, // test cadence; production default is pico's 1s
        max_attempts: Some(100),
    };
    let (client, (server_conn1, declares_conn1)) = tokio::join!(
        async {
            let session = open_session_with_reconnect(
                locator,
                params,
                TokioTime::new(),
                policy,
                Some(ITER_CAP),
                DEFAULT_OPEN_TICK_MS,
            )
            .await
            .expect("client reaches Established");
            session
                .actions()
                .send_declare_subscriber(10, 0, Some("home/reconnect"))
                .expect("declare subscriber");
            session
        },
        accept_and_collect_declares(&listener),
    );
    assert_eq!(
        declares_conn1.len(),
        1,
        "connection #1 observes exactly the one declared subscriber"
    );

    // ── Sever the first link abruptly: dropping the acceptor session closes
    //    the socket without a Close frame — the client sees a link loss, not
    //    a peer-initiated close.
    drop(server_conn1);

    // ── Drive the client under the reconnect supervisor while the listener
    //    re-accepts. The supervisor re-dials, re-handshakes, and replays the
    //    declaration cache; connection #2 must observe the SAME Declare.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_server = stop.clone();
    let timeouts = SessionTimeouts::spec_defaults();
    let (drive_outcome, declares_conn2) = tokio::join!(
        client.drive(&timeouts, &stop, Some(ITER_CAP), |_| {}),
        async {
            let (server_conn2, declares) = accept_and_collect_declares(&listener).await;
            // Replay observed — release the client: raise the stop flag
            // FIRST, then sever the link so the supervisor's next loop
            // boundary sees Terminated + stop and returns Stopped instead
            // of reconnecting again.
            stop_for_server.store(true, Ordering::Release);
            drop(server_conn2);
            declares
        },
    );

    assert!(
        matches!(drive_outcome, ReconnectDriveOutcome::Stopped),
        "supervisor must observe the stop flag after the second link drop, \
         got {drive_outcome:?}"
    );
    assert_eq!(
        declares_conn2, declares_conn1,
        "the reconnected link must replay the cached Declare verbatim \
         (kind, id, keyexpr all preserved)"
    );
}
