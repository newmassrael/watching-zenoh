// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ew — the scouting -> session-open seam.
//!
//! `open_session_at(&str)` is the mode-agnostic per-locator bridge: it parses
//! a zenoh locator string (as active mode's `ScoutOutcome::Discovered` or
//! static mode's `synth_static_locators` produce) and opens a session.
//! `open_session_static(&[String])` is the static-mode path — try each
//! configured `deploy.connect[]` locator in order, first Established wins.
//!
//! These tests exercise the static path end-to-end IN-PROCESS (no multicast):
//!   - a `tcp/...` locator reaches Established against an inline wz acceptor;
//!   - a `udp/...` locator reaches Established against an inline wz datagram
//!     acceptor (R311ez — datagram session-open, no length-prefix envelope);
//!   - a malformed locator surfaces `BadLocator`;
//!   - `open_session_static` skips an unreachable locator to the first
//!     reachable one, and reports `NoReachableLocator` when none work.
//!
//! The active multicast scout -> open e2e is the Layer M follow-up.
//!
//! Note: the open loop is bounded only by `max_iters` (poll count), not wall
//! clock — a peer that accepts the link but never answers the handshake hangs
//! the loop (transport-agnostic; a silent-but-connected TCP peer hangs the
//! same way). UDP makes this reachable because `dial_udp` only binds locally,
//! so these tests only ever point UDP at a responsive acceptor; the
//! unreachable-exhaustion case uses dead TCP ports, which fail fast at dial.

// R311if — SocketAddr is used only by the static-mode `refused_locator`.
#[cfg(feature = "scouting-static")]
use std::net::SocketAddr;

// R311if — only the static-mode tests (via `refused_locator`) need the
// raw non-listening socket; gate the import with their feature.
#[cfg(feature = "scouting-static")]
use socket2::{Domain, Socket, Type};

use tokio::net::TcpListener;
#[cfg(feature = "transport-link-udp")]
use tokio::net::UdpSocket;

use wz_runtime_tokio::link_pipeline::wire_tcp_stream;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::SessionFsmUnicastEvent as E;
use wz_runtime_tokio::session_glue::{
    new_session_actions, new_session_engine, poll_and_dispatch_one, DriverLoopOutcome,
    SessionInitParams,
};
use wz_runtime_tokio::session_open::{
    open_session_at, DialConfig, OpenError, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::writer_queue::WriterHandle;
// R311if — the static-mode open path is gated on `scouting-static`; the
// mode-agnostic `open_session_at` tests stay in the default run.
#[cfg(feature = "scouting-static")]
use wz_runtime_tokio::session_open::open_session_static;
#[cfg(feature = "transport-link-udp")]
use wz_runtime_tokio::udp_pipeline::wire_udp_socket;
use wz_runtime_tokio_test_support::fixture_session_init_params;

const ITER_CAP: usize = 64;

fn initiator_params() -> SessionInitParams {
    let mut p = fixture_session_init_params();
    p.zid = vec![0x01; 4];
    p
}

/// A loopback TCP address that is *deterministically* connection-refused.
///
/// The returned `Socket` is bound to an ephemeral port but never `listen()`s,
/// so for as long as the caller holds the guard alive: (1) no other process
/// can rebind that port (the bind reservation stands), and (2) a connect to it
/// gets an RST → `ECONNREFUSED` (a bound socket not in `LISTEN` does not accept).
///
/// This replaces the earlier `bind -> local_addr -> drop` pattern, whose freed
/// ephemeral port the OS could recycle to an unrelated live listener under the
/// concurrent-process load of a full CI run (a TOCTOU race). When that happened
/// a "dead" locator turned into either a foreign listener that accepts but
/// never speaks the wz handshake (hanging the open loop) or a false
/// Established — surfacing as the flaky `NoReachableLocator` / `got Ok` results.
/// `std::net::TcpListener::bind` always calls `listen()`, so socket2 is used to
/// bind without listening.
///
/// R311if — used only by the static-mode exhaustion tests; gated with them.
#[cfg(feature = "scouting-static")]
fn refused_locator() -> (Socket, SocketAddr) {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).expect("socket");
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("parse bind addr");
    socket.bind(&bind.into()).expect("bind without listen");
    let addr = socket
        .local_addr()
        .expect("local_addr")
        .as_socket()
        .expect("ipv4 socket addr");
    (socket, addr)
}

/// Inline wz acceptor: accept -> wire -> InboundStart -> drive to Established.
/// Returns (established count, writer handle) — the handle in a tuple (not a
/// bare future) keeps it alive across `join!`.
async fn drive_acceptor_to_established(listener: TcpListener) -> (u32, WriterHandle) {
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
            "acceptor terminal before Established"
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
    (
        actions.trace_snapshot().record_established_at,
        writer_handle,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_session_at_tcp_reaches_established() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let acceptor = drive_acceptor_to_established(listener);
    let loc = format!("tcp/{addr}");
    // Held across `join!` -> bind the cert-free config to outlive the borrow.
    let cfg = DialConfig::default();
    let initiator = open_session_at(
        &loc,
        initiator_params(),
        &cfg,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    );
    let ((acc_est, _w), opened) = tokio::join!(acceptor, initiator);
    assert!(
        opened
            .expect("Established")
            .actions
            .trace_snapshot()
            .record_established_at
            >= 1,
        "initiator established via open_session_at"
    );
    assert!(acc_est >= 1, "acceptor established");
}

/// Inline wz datagram acceptor (R311ez). A UDP server cannot pre-know the
/// Initiator's ephemeral port, so it learns the peer from the first
/// datagram's source via `peek_from` (MSG_PEEK leaves the datagram queued, so
/// the first `poll_event` re-reads it). Then it wires the socket and drives
/// the InboundStart handshake to Established, mirroring the TCP acceptor.
#[cfg(feature = "transport-link-udp")]
async fn drive_udp_acceptor_to_established(socket: UdpSocket) -> (u32, WriterHandle) {
    let mut probe = [0u8; 64];
    let (_n, src) = socket
        .peek_from(&mut probe)
        .await
        .expect("peek first datagram");
    let (mut inbound, outbound, writer_handle) = wire_udp_socket(socket, src);

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
            "udp acceptor terminal before Established"
        );
        assert!(
            iter < ITER_CAP,
            "udp acceptor did not reach Established in budget"
        );
        iter += 1;
        if let DriverLoopOutcome::LinkLost(cause) =
            poll_and_dispatch_one(&mut inbound, &actions, &mut engine).await
        {
            panic!("udp acceptor link lost mid-handshake: {cause:?}");
        }
    }
    (
        actions.trace_snapshot().record_established_at,
        writer_handle,
    )
}

#[cfg(feature = "transport-link-udp")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_session_at_udp_reaches_established() {
    // R311ez — a `udp/...` locator opens a datagram session the same way a
    // `tcp/...` locator opens a stream session: dial_locator binds an
    // ephemeral local socket, wire_dialed_link shares it, and the Initiator
    // handshake reaches Established against the inline datagram acceptor.
    let acc_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind acceptor");
    let addr = acc_socket.local_addr().expect("acceptor addr");
    let acceptor = drive_udp_acceptor_to_established(acc_socket);
    let loc = format!("udp/{addr}");
    // Held across `join!` -> bind the cert-free config to outlive the borrow.
    let cfg = DialConfig::default();
    let initiator = open_session_at(
        &loc,
        initiator_params(),
        &cfg,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    );
    let ((acc_est, _w), opened) = tokio::join!(acceptor, initiator);
    assert!(
        opened
            .expect("Established")
            .actions
            .trace_snapshot()
            .record_established_at
            >= 1,
        "initiator established via open_session_at on a udp locator"
    );
    assert!(acc_est >= 1, "udp acceptor established");
}

#[tokio::test]
async fn open_session_at_malformed_is_bad_locator() {
    let result = open_session_at(
        "not-a-locator",
        initiator_params(),
        &DialConfig::default(),
        TokioTime::new(),
        Some(4),
        DEFAULT_OPEN_TICK_MS,
    )
    .await;
    let Err(err) = result else {
        panic!("expected malformed locator to error, got Ok");
    };
    assert!(
        matches!(err, OpenError::BadLocator(_)),
        "expected BadLocator, got {err:?}"
    );
}

#[cfg(feature = "scouting-static")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_session_static_skips_unreachable_to_first_reachable() {
    // A deterministically connection-refused loopback port (bound, not
    // listening; the guard holds the port so it cannot be recycled mid-test).
    let (_dead_guard, dead) = refused_locator();
    // The reachable peer.
    let good_listener = TcpListener::bind("127.0.0.1:0").await.expect("good bind");
    let good = good_listener.local_addr().expect("good addr");
    let acceptor = drive_acceptor_to_established(good_listener);

    let connect = vec![format!("tcp/{dead}"), format!("tcp/{good}")];
    // Held across `join!` -> bind the cert-free config to outlive the borrow.
    let cfg = DialConfig::default();
    let initiator = open_session_static(
        &connect,
        initiator_params(),
        &cfg,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    );

    let ((acc_est, _w), opened) = tokio::join!(acceptor, initiator);
    assert!(
        opened
            .expect("opened the reachable peer")
            .actions
            .trace_snapshot()
            .record_established_at
            >= 1,
        "static open skipped the dead locator and established on the good one"
    );
    assert!(acc_est >= 1, "acceptor established");
}

#[cfg(feature = "scouting-static")]
#[tokio::test]
async fn open_session_static_empty_is_no_reachable() {
    let result = open_session_static(
        &[],
        initiator_params(),
        &DialConfig::default(),
        TokioTime::new(),
        Some(4),
        DEFAULT_OPEN_TICK_MS,
    )
    .await;
    let Err(err) = result else {
        panic!("expected empty connect list to error, got Ok");
    };
    assert!(
        matches!(err, OpenError::NoReachableLocator),
        "expected NoReachableLocator, got {err:?}"
    );
}

#[cfg(feature = "scouting-static")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_session_static_all_unreachable_is_no_reachable() {
    // A list of dead loopback ports exhausts — each fails fast at dial
    // (connection refused), so open_session_static reports NoReachableLocator
    // without ever blocking on a handshake. (Dead TCP, not a UDP black hole:
    // dial_udp binds locally and would hang the open loop awaiting a datagram
    // that never comes — see the module note on the open-loop time bound.)
    let (_dead_guard_a, dead_a) = refused_locator();
    let (_dead_guard_b, dead_b) = refused_locator();
    let connect = vec![format!("tcp/{dead_a}"), format!("tcp/{dead_b}")];
    let result = open_session_static(
        &connect,
        initiator_params(),
        &DialConfig::default(),
        TokioTime::new(),
        Some(4),
        DEFAULT_OPEN_TICK_MS,
    )
    .await;
    let Err(err) = result else {
        panic!("expected all-unreachable connect list to error, got Ok");
    };
    assert!(
        matches!(err, OpenError::NoReachableLocator),
        "expected NoReachableLocator, got {err:?}"
    );
}
