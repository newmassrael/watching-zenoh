// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311fb — `accept_and_open_session` brings an Accepting session up to
//! Established from an accepted loopback connection, and bounds a silent peer
//! via the accept-side open-deadline (carry #2 of R311fa).
//!
//! The happy path pairs the two lib open helpers symmetrically — the acceptor
//! runs `accept_and_open_session`, the initiator runs `connect_and_open_session`
//! — over one in-process loopback `TcpStream`. Both session engines are
//! Lua-backed and therefore `!Send`, so neither is spawned onto a worker; they
//! run concurrently on the current task via `tokio::join!` (the internal
//! `writer_task`s, which are `Send`, run on the multi-thread workers). Both
//! loops are bounded by an iteration cap so a handshake regression fails fast
//! instead of hanging.
//!
//! The silent-peer path confirms the `accepting.inactivity_timeout` (1s) armed
//! on `AwaitingInitSyn` entry fires through the open loop's tick pump and
//! surfaces as `OpenError::Terminal` instead of hanging the acceptor.

use tokio::net::{TcpListener, TcpStream};

use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialedLink, OpenError, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_locator;

const ITER_CAP: usize = 64;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_and_open_reaches_established_against_wz_initiator() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // ── Acceptor side: accept -> accept_and_open_session (the lib path under
    //    test). Returns the established OpenedSession, whose owned
    //    writer_handle keeps the acceptor's OpenAck flushing while the
    //    initiator still needs it on the wire across `join!`.
    let acceptor_fut = async move {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4]; // distinct zid from the initiator
        accept_and_open_session(
            DialedLink::Tcp(stream),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
    };

    // ── Initiator side: the established dial-side helper.
    let locator = parse_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
    let mut params = fixture_session_init_params();
    params.zid = vec![0x01; 4];
    let initiator_fut = connect_and_open_session(
        locator,
        params,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    );

    let (accepted, opened) = tokio::join!(acceptor_fut, initiator_fut);
    let accepted = accepted.expect("acceptor reaches Established");
    let opened = opened.expect("initiator reaches Established");
    assert!(
        accepted.actions.trace_snapshot().record_established_at >= 1,
        "acceptor OpenedSession is Established"
    );
    assert!(
        opened.actions.trace_snapshot().record_established_at >= 1,
        "initiator OpenedSession is Established"
    );
}

/// R311fb — real wall-clock accept-side open-deadline end-to-end. A peer that
/// completes the TCP connection but never sends InitSyn must surface
/// [`OpenError::Terminal`] within the accept window rather than hang: the open
/// loop's tick pump advances the SCE scheduler past the SCXML
/// `accepting.inactivity_timeout` (1s) armed on `AwaitingInitSyn` entry, the
/// FSM transitions to Closed (silent drop — no Close frame, §2.7
/// anti-amplification), and `drive_open_loop` maps the pre-Established terminal
/// to `Terminal` (indistinguishable from a peer close by design).
///
/// Opt-in (`#[ignore]`): the assertion waits out the real 1s timer, so it is
/// excluded from the default fast lane. The deterministic FSM half is in
/// `session_fsm_handshake_timeout.rs`; this confirms the tick wiring drives it
/// end-to-end against a real socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real-time: waits out the 1s accepting.inactivity_timeout; opt-in lane"]
async fn silent_peer_surfaces_accept_terminal() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // Client connects but never sends InitSyn; hold the socket open past the
    // 1s window so the acceptor sees an inactivity timeout, not a peer close.
    let client = tokio::spawn(async move {
        let stream = TcpStream::connect(addr).await.expect("connect");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        drop(stream);
    });

    let (stream, _peer) = listener.accept().await.expect("accept");
    let result = accept_and_open_session(
        DialedLink::Tcp(stream),
        fixture_session_init_params(),
        TokioTime::new(),
        None, // production wall-clock path: no iteration cap
        DEFAULT_OPEN_TICK_MS,
    )
    .await;

    // OpenedSession is not Debug (it owns the engine), so match instead of
    // matches! + {result:?}.
    match result {
        Err(OpenError::Terminal) => {}
        Err(other) => panic!("expected Terminal, got {other:?}"),
        Ok(_) => panic!("silent peer must not reach Established"),
    }
    client.abort();
}
