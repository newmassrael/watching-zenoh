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
//! R311y807 — and the `listen=` half, which static mode had no seam for at
//! all until `open_session_static_config` (the wz analog of pico reading
//! `_z_locators_by_config`'s `peer_op`): a real wz<->wz session whose
//! ACCEPTING half comes up from a `listen=` config alone and announces
//! itself a peer; `listen=` and `connect=` together refused before any
//! socket; and a blank `listen=` falling through to the dial arm.
//!
//! R311y808 — and the dial arm's RETRY (zenoh's `connect.retry` +
//! `connect.timeout_ms`, `connect_peers_single_link`): the two independent
//! zeros that disable it, a peer reached ONLY because the dial was
//! re-attempted, the paired no-retry negative on the same fixture that makes
//! that a measurement, and the connect-timeout bound that ends a retry which
//! upstream otherwise pins to one locator forever.
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
use wz_runtime_tokio::retry_period::RetryPolicy;
#[cfg(feature = "scouting-static")]
use wz_runtime_tokio::session_open::{
    open_session_static, open_session_static_config, AcceptConfig, OpenedSession,
    StaticConnectRetry, StaticDeploy,
};
#[cfg(feature = "transport-link-udp")]
use wz_runtime_tokio::udp_pipeline::wire_udp_socket;
use wz_runtime_tokio_test_support::fixture_session_init_params;
#[cfg(feature = "scouting-static")]
use wz_session_core::scout_static::StaticConfigError;
#[cfg(feature = "scouting-static")]
use wz_session_core::WhatAmI;

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

// ── the `listen=` half of the static deploy config (the wz analog of pico's
//    `_z_locators_by_config` peer_op, vendor/zenoh-pico/src/net/session.c:87-118).
//    Until now static mode could only DIAL: `open_session_static` took a
//    connect list and nothing else, so a `listen=` deploy had no seam at all.

/// Wall-clock bound for the two-half listen tests below.
///
/// Both pair an inline acceptor with an initiator inside one `join!`, and
/// `join!` waits for BOTH: an initiator that errors out WITHOUT connecting
/// leaves the acceptor parked in `accept()` with nothing left to wake it, so
/// the test hangs instead of failing. That is not hypothetical — it is what
/// the R311y807 damage probe measured, when disabling the blank-listen
/// hygiene turned `static_blank_listen_still_dials_the_connect_list` from a
/// failure into a run that never returned. A hang is a worse diagnostic than
/// a failure at every layer that reads it, so these bound their own wait.
#[cfg(feature = "scouting-static")]
const LISTEN_PAIR_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

/// A loopback port that is free at the moment of the call — the repo's
/// standing convention (`wz-capi-pico/tests/listener_multipeer.rs:88`), used
/// because `accept_endpoint` binds INSIDE `open_session_static_config` and
/// therefore cannot hand an ephemeral port back to the dialer. A port stolen
/// between the probe and the bind surfaces as a loud bind error from the
/// acceptor, not as a hang.
#[cfg(feature = "scouting-static")]
use wz_runtime_tokio_test_support::free_port;

/// Dial a static connect list, retrying while the acceptor is still binding.
///
/// The Listen arm binds inside the call being tested, so there is no instant
/// before `join!` at which the port is known to be listening and a single-shot
/// dial races it. Retrying is safe here BECAUSE a retry cannot hide a real
/// failure: the only attempts that fail are the ones refused before the bind
/// lands, which consume none of the acceptor's single accept, and the first
/// attempt that connects at all is between two real wz peers and so runs the
/// handshake to its true verdict. A barrier that probed the port by connecting
/// would instead eat that accept, which is why this waits by retrying the seam
/// rather than by pinging the socket.
#[cfg(feature = "scouting-static")]
async fn dial_static_when_listening(
    connect: &[String],
    cfg: &DialConfig,
) -> Result<OpenedSession, OpenError> {
    let mut last = OpenError::NoReachableLocator;
    for _ in 0..200 {
        match open_session_static(
            connect,
            initiator_params(),
            cfg,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        {
            Ok(opened) => return Ok(opened),
            Err(e) => {
                last = e;
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }
    Err(last)
}

#[cfg(feature = "scouting-static")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn static_listen_accepts_a_dialing_peer_and_announces_peer_mode() {
    let port = free_port();
    let endpoint = format!("tcp/127.0.0.1:{port}");

    let mut acceptor_params = fixture_session_init_params();
    acceptor_params.zid = vec![0x02; 4]; // distinct zid from the initiator

    // Deliberately CLIENT. pico's listen arm inserts `mode=peer` OVER whatever
    // the config said (session.c:96, :110) precisely because its own default is
    // Z_WHATAMI_CLIENT (session.c:122) and a client does not accept. A wiring
    // that bound the socket but skipped that overwrite would still reach
    // Established here — and would put `client` on the wire, which the
    // `peer_whatami` assertion below is what catches.
    acceptor_params.whatami = WhatAmI::Client;

    let dial_cfg = DialConfig::default();
    let accept_cfg = AcceptConfig::default();
    let listen_endpoint = endpoint.clone();
    let acceptor = open_session_static_config(
        StaticDeploy::connect(&[]).with_listen(&listen_endpoint),
        acceptor_params,
        &dial_cfg,
        &accept_cfg,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    );

    let connect = vec![endpoint];
    let dialer_cfg = DialConfig::default();
    let dialer = dial_static_when_listening(&connect, &dialer_cfg);

    let (accepted, dialed) =
        tokio::time::timeout(LISTEN_PAIR_BUDGET, async { tokio::join!(acceptor, dialer) })
            .await
            .expect("the listen/dial pair did not settle within its budget");

    let accepted = accepted.expect("static listen reached Established");
    assert!(
        accepted.actions.trace_snapshot().record_established_at >= 1,
        "the listening half established"
    );

    let dialed = dialed.expect("the dialing peer reached the static listener");
    assert!(
        dialed.actions.trace_snapshot().record_established_at >= 1,
        "the dialing half established"
    );
    assert_eq!(
        dialed.peer_whatami(),
        Some(WhatAmI::Peer),
        "a `listen=` deploy must announce itself a peer (pico's mode=peer \
         insert); the acceptor's params said Client and the listen arm is what \
         overrides them"
    );
}

#[cfg(feature = "scouting-static")]
#[tokio::test]
async fn static_listen_with_connect_is_refused_before_any_socket() {
    // pico returns _Z_ERR_GENERIC for this pair without opening anything
    // (session.c:107-108). Both endpoints below are unreachable on purpose:
    // the call must fail on the CONFIG, so it must never reach them — a wiring
    // that honoured one half and dropped the other would instead block or
    // surface a Dial error.
    let connect = vec!["tcp/127.0.0.1:9".to_string()];
    let result = open_session_static_config(
        StaticDeploy::connect(&connect).with_listen("tcp/127.0.0.1:9"),
        initiator_params(),
        &DialConfig::default(),
        &AcceptConfig::default(),
        TokioTime::new(),
        Some(4),
        DEFAULT_OPEN_TICK_MS,
    )
    .await;
    let Err(err) = result else {
        panic!("expected listen+connect to be refused, got Ok");
    };
    assert!(
        matches!(
            err,
            OpenError::BadStaticConfig(StaticConfigError::ListenWithConnect)
        ),
        "expected BadStaticConfig(ListenWithConnect), got {err:?}"
    );
}

#[cfg(feature = "scouting-static")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_blank_listen_still_dials_the_connect_list() {
    // Config hygiene at the RUNTIME seam, not just in the pure resolution: a
    // whitespace-only `listen=` is an absent one, so the role stays Open and
    // the connect list is dialed. A resolution that treated the blank as
    // present would bind it (or refuse the pair) and never reach this peer.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let acceptor = drive_acceptor_to_established(listener);

    let connect = vec![format!("tcp/{addr}")];
    let dial_cfg = DialConfig::default();
    let accept_cfg = AcceptConfig::default();
    let initiator = open_session_static_config(
        StaticDeploy::connect(&connect).with_listen("   "),
        initiator_params(),
        &dial_cfg,
        &accept_cfg,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    );

    let ((acc_est, _w), opened) = tokio::time::timeout(LISTEN_PAIR_BUDGET, async {
        tokio::join!(acceptor, initiator)
    })
    .await
    .expect("the blank-listen pair did not settle within its budget");
    assert!(
        opened
            .expect("a blank listen dials the connect list")
            .actions
            .trace_snapshot()
            .record_established_at
            >= 1,
        "the blank listen did not flip the role away from the dial arm"
    );
    assert!(acc_est >= 1, "acceptor established");
}

// ── R311y808 — the dial arm's RETRY, zenoh's `connect.retry` +
//    `connect.timeout_ms` (`connect_peers_single_link`,
//    zenoh/src/net/runtime/orchestrator.rs:345-370). The schedule itself is
//    `RetryPolicy`, already pinned by its own unit tests; what these pin is the
//    ARM SELECTION and that a retried dial actually reaches a peer the first
//    attempt could not.

/// A retry that is on: zenoh's shipped `connect.retry` with the infinite
/// `timeout_ms: -1` a router or peer defaults to, but shortened so a test that
/// waits for one retry waits 60ms rather than 1s.
#[cfg(feature = "scouting-static")]
fn brisk_retry(timeout_ms: Option<u64>) -> StaticConnectRetry {
    StaticConnectRetry {
        policy: RetryPolicy {
            period_init_ms: 30,
            period_max_ms: 120,
            period_increase_factor: 2.0,
        },
        timeout_ms,
    }
}

#[cfg(feature = "scouting-static")]
#[test]
fn a_zero_period_init_disables_the_retry() {
    // Upstream's first zero: `retry_config.timeout()` IS `period_init_ms` read
    // as a duration, and `is_zero()` takes the no-retry arm
    // (orchestrator.rs:356). Without this rule the schedule is a hot loop — a
    // `0` wait multiplied by any factor stays `0`.
    let retry = StaticConnectRetry {
        policy: RetryPolicy::constant(0),
        timeout_ms: None,
    };
    assert!(!retry.retries());
}

#[cfg(feature = "scouting-static")]
#[test]
fn a_zero_connect_timeout_disables_the_retry() {
    // Upstream's SECOND zero, independent of the first: `timeout_ms: 0` is how
    // a stock zenoh CLIENT is configured (`{ router: -1, peer: -1, client: 0 }`,
    // DEFAULT_CONFIG.json5:41), and it disables the retry even though the
    // `connect.retry` block is fully populated.
    let retry = StaticConnectRetry {
        policy: RetryPolicy::ZENOH_DEFAULT,
        timeout_ms: Some(0),
    };
    assert!(!retry.retries());
}

#[cfg(feature = "scouting-static")]
#[test]
fn the_zenoh_peer_default_retries() {
    // The populated schedule with upstream's `-1` timeout — the router/peer
    // default, and the arm wz did not have before R311y808.
    let retry = StaticConnectRetry {
        policy: RetryPolicy::ZENOH_DEFAULT,
        timeout_ms: None,
    };
    assert!(retry.retries());
}

#[cfg(feature = "scouting-static")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn static_dial_retry_reaches_a_peer_that_was_not_listening_yet() {
    // THE witness for this arm: the peer does not exist when the dial starts.
    // A single-attempt walk cannot reach it (the paired negative below measures
    // exactly that on the same fixture), so an Established here is the retry.
    let port = free_port();
    let connect = vec![format!("tcp/127.0.0.1:{port}")];

    let late_acceptor = async move {
        // Long enough that the first dial attempt is already refused.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("late bind");
        drive_acceptor_to_established(listener).await
    };

    let dial_cfg = DialConfig::default();
    let accept_cfg = AcceptConfig::default();
    let initiator = open_session_static_config(
        StaticDeploy::connect(&connect).with_retry(brisk_retry(None)),
        initiator_params(),
        &dial_cfg,
        &accept_cfg,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    );

    let ((acc_est, _w), opened) = tokio::time::timeout(LISTEN_PAIR_BUDGET, async {
        tokio::join!(late_acceptor, initiator)
    })
    .await
    .expect("the retrying dial did not settle within its budget");

    assert!(
        opened
            .expect("the retry reached the late peer")
            .actions
            .trace_snapshot()
            .record_established_at
            >= 1,
        "the retried dial established against a peer that appeared later"
    );
    assert!(acc_est >= 1, "the late acceptor established");
}

#[cfg(feature = "scouting-static")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn static_dial_without_retry_gives_up_before_the_peer_appears() {
    // The SAME fixture as above with the retry omitted. Its failure is what
    // makes the test above a measurement of the retry rather than of the
    // acceptor: one attempt, refused, and the walk ends with the list
    // exhausted.
    let port = free_port();
    let connect = vec![format!("tcp/127.0.0.1:{port}")];

    let late_acceptor = async move {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        // Bound the wait: nothing will ever connect, and the point of this
        // half is only that the port is not open when the dial runs.
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("late bind");
        let _ =
            tokio::time::timeout(std::time::Duration::from_millis(300), listener.accept()).await;
    };

    let dial_cfg = DialConfig::default();
    let accept_cfg = AcceptConfig::default();
    let initiator = open_session_static_config(
        StaticDeploy::connect(&connect),
        initiator_params(),
        &dial_cfg,
        &accept_cfg,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    );

    let (_late, opened) = tokio::time::timeout(LISTEN_PAIR_BUDGET, async {
        tokio::join!(late_acceptor, initiator)
    })
    .await
    .expect("the no-retry dial did not settle within its budget");

    let Err(err) = opened else {
        panic!("expected the un-retried dial to give up, got Ok");
    };
    assert!(
        matches!(err, OpenError::NoReachableLocator),
        "expected NoReachableLocator, got {err:?}"
    );
}

#[cfg(feature = "scouting-static")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn static_dial_retry_is_bounded_by_the_connect_timeout() {
    // The retry arm PINS its locator, exactly as `peer_connector_retry` does,
    // so `timeout_ms` is the only thing that ends it. Without the bound this
    // call never returns; with it the call is the one that reports, not a
    // harness timeout. Nothing ever listens on the probed port.
    let (_dead_guard, dead) = refused_locator();
    let connect = vec![format!("tcp/{dead}")];

    let started = std::time::Instant::now();
    // Bounded by the test as well as by the call, and deliberately: this arm's
    // whole hazard is a retry that never ends, so a build that dropped
    // `timeout_ms` must FAIL here rather than hang the suite (the R311y807
    // lesson, applied before a probe had to find it a second time).
    let result = tokio::time::timeout(
        LISTEN_PAIR_BUDGET,
        open_session_static_config(
            StaticDeploy::connect(&connect).with_retry(brisk_retry(Some(200))),
            initiator_params(),
            &DialConfig::default(),
            &AcceptConfig::default(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        ),
    )
    .await
    .expect("the bounded retry never returned — `timeout_ms` did not end it");
    let elapsed = started.elapsed();

    let Err(err) = result else {
        panic!("expected a bounded retry to give up, got Ok");
    };
    assert!(
        matches!(err, OpenError::NoReachableLocator),
        "expected NoReachableLocator, got {err:?}"
    );
    // It must have RETRIED (so longer than one refused attempt) and it must
    // have STOPPED (so nowhere near the harness budget). Both halves matter:
    // the lower bound fails a build that never slept, the upper one fails a
    // build that ignored `timeout_ms`.
    assert!(
        elapsed >= std::time::Duration::from_millis(30),
        "gave up without waiting even the first retry period: {elapsed:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "the connect timeout did not end the retry: {elapsed:?}"
    );
}
