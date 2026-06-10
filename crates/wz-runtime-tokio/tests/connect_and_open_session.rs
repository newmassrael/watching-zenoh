// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311eu — `connect_and_open_session` brings an Initiator session up to
//! Established against an in-process wz acceptor, both over the R311et link
//! pipeline.
//!
//! This is the first IN-PROCESS wz<->wz handshake-to-Established test:
//! existing wz<->wz coverage spawns two wz-ap-demo binaries (Layer E). Here
//! both peers run in one process over a loopback TcpStream, so the lib-level
//! Initiator open path (`dial_locator` -> `wire_tcp_stream` ->
//! `SessionLinkActions` -> drive to Established) is exercised directly
//! without the demo binary.
//!
//! Both session engines are Lua-backed and therefore `!Send`, so neither is
//! spawned onto a worker — they run concurrently on the current task via
//! `tokio::join!` (the internal `writer_task`s, which are `Send`, run on the
//! multi-thread workers). The acceptor side is assembled inline from the
//! same production pieces (no public accept helper this round — that pairing
//! lands when the demo de-dups onto the pipeline, R311ev). Both loops are
//! bounded by an iteration cap so a handshake regression fails fast instead
//! of hanging.

use tokio::net::TcpListener;

use wz_runtime_tokio::link_pipeline::wire_tcp_stream;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::SessionFsmUnicastEvent as E;
use wz_runtime_tokio::session_glue::{
    new_session_actions, new_session_engine, poll_and_dispatch_one, DriverLoopOutcome,
};
use wz_runtime_tokio::session_open::{connect_and_open_session, OpenError, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_locator;

const ITER_CAP: usize = 64;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_and_open_reaches_established_against_wz_acceptor() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // ── Acceptor side: accept -> wire -> InboundStart -> drive to
    //    Established, assembled inline from the production pieces. Driven
    //    concurrently with the initiator on the current task (engine !Send).
    let acceptor_fut = async move {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let (mut inbound, outbound, writer_handle) = wire_tcp_stream(stream);

        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4]; // distinct zid from the initiator
        let actions = new_session_actions(outbound, params, TokioTime::new());
        let mut engine = new_session_engine(&actions);
        engine.initialize();
        engine.process_event(E::InboundStart);

        let mut iter = 0usize;
        while actions.trace_snapshot().record_established_at < 1 {
            assert!(
                !engine.is_in_final_state(),
                "acceptor reached terminal before Established"
            );
            assert!(
                iter < ITER_CAP,
                "acceptor did not reach Established in budget"
            );
            iter += 1;
            if let DriverLoopOutcome::LinkLost(cause) =
                poll_and_dispatch_one(&mut inbound, &actions, &mut engine).await
            {
                panic!("acceptor link lost mid-handshake: {cause:?}");
            }
        }
        // Return the established count + the writer handle in a tuple (a
        // tuple is not itself a future, unlike a bare handle) so the handle
        // stays alive across `join!` — the initiator still needs the
        // acceptor's OpenAck on the wire.
        (
            actions.trace_snapshot().record_established_at,
            writer_handle,
        )
    };

    // ── Initiator side: the lib open path under test.
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

    let ((acc_established, _acceptor_writer), opened) = tokio::join!(acceptor_fut, initiator_fut);
    let opened = opened.expect("initiator reaches Established");
    assert!(
        opened.actions.trace_snapshot().record_established_at >= 1,
        "initiator OpenedSession is Established"
    );
    assert!(acc_established >= 1, "acceptor also reached Established");
}

/// R311fa — real wall-clock open-deadline end-to-end. A peer that completes
/// the TCP connection but never answers InitSyn must surface
/// [`OpenError::HandshakeTimeout`] rather than hang: the open loop's tick
/// pump advances the SCE scheduler past the SCXML `init_ack.timeout` (2s)
/// window, the FSM transitions to Closing, and the loop maps that to the
/// typed error.
///
/// Opt-in (`#[ignore]`): the assertion waits out the real 2s timer, so it is
/// excluded from the default fast lane. The deterministic FSM half is in
/// `session_fsm_handshake_timeout.rs`; this confirms the tick wiring drives
/// it end-to-end against a real socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real-time: waits out the 2s init_ack.timeout; opt-in lane"]
async fn silent_peer_surfaces_handshake_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // Accept the connection and stay silent — never answer InitSyn. Hold the
    // stream alive past the 2s window so the initiator sees a handshake
    // timeout, not a peer-closed link.
    let acceptor = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.expect("accept");
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
        drop(stream);
    });

    let locator = parse_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
    let params = fixture_session_init_params();
    let result = connect_and_open_session(
        locator,
        params,
        TokioTime::new(),
        None, // production wall-clock path: no iteration cap
        DEFAULT_OPEN_TICK_MS,
    )
    .await;

    // OpenedSession is not Debug (it owns the engine), so match instead of
    // matches! + {result:?}.
    match result {
        Err(OpenError::HandshakeTimeout) => {}
        Err(other) => panic!("expected HandshakeTimeout, got {other:?}"),
        Ok(_) => panic!("silent peer must not reach Established"),
    }
    acceptor.abort();
}

/// R311kc — a peer whose InitAck ENLARGES a size parameter beyond our
/// InitSyn advertisement must surface the typed
/// [`OpenError::InitAckCapsRejected`] (zenoh-pico
/// `_Z_ERR_TRANSPORT_OPEN_SN_RESOLUTION` parity, unicast/transport.c:
/// 123-140), not fold into `Terminal` or hang to the handshake timeout.
/// The fake acceptor speaks raw length-prefixed wire (`StreamEnvelope`:
/// u16 LE prefix + payload): it drains the initiator's InitSyn envelope
/// and answers with a crafted InitAck advertising seq_num_res=1 — the
/// fixture initiator advertised 0, so adoption is non-conforming.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enlarging_init_ack_surfaces_caps_rejected() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wz_session_wire_fixtures::craft_initack_wire_with_caps;

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let acceptor = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.expect("accept");
        // Drain the InitSyn envelope (u16 LE length prefix + payload).
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.expect("read prefix");
        let mut body = vec![0u8; u16::from_le_bytes(len) as usize];
        stream.read_exact(&mut body).await.expect("read InitSyn");
        // Reply with an InitAck enlarging seq_num_res to 1 (> advertised 0).
        let initack = craft_initack_wire_with_caps(&[0xC0, 0x01], 0x01, 0);
        let mut wire = (initack.len() as u16).to_le_bytes().to_vec();
        wire.extend_from_slice(&initack);
        stream.write_all(&wire).await.expect("write InitAck");
        // Hold the stream so the initiator's verdict is the params
        // rejection, not a racing peer-closed link event.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        drop(stream);
    });

    let locator = parse_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
    let result = connect_and_open_session(
        locator,
        fixture_session_init_params(),
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await;

    match result {
        Err(OpenError::InitAckCapsRejected) => {}
        Err(other) => panic!("expected InitAckCapsRejected, got {other:?}"),
        Ok(_) => panic!("enlarging InitAck must not reach Established"),
    }
    acceptor.abort();
}
