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
//!   - a `udp/...` locator surfaces the typed `Dial(Unsupported)` (datagram
//!     session-open is deferred — UDP locators are skipped, not mis-dialed);
//!   - a malformed locator surfaces `BadLocator`;
//!   - `open_session_static` skips an unreachable locator to the first
//!     reachable one, and reports `NoReachableLocator` when none work.
//!
//! The active multicast scout -> open e2e is the Layer M follow-up.

use std::sync::Arc;

use sce_rust_lua::LuaEngine;
use sce_rust_runtime::scripting::IScriptEngine;
use sce_rust_runtime::Engine;
use tokio::net::TcpListener;

use wz_runtime_tokio::link_pipeline::wire_tcp_stream;
use wz_runtime_tokio::runtime_impl::{TokioJoinHandle, TokioTime};
use wz_runtime_tokio::session_fsm_unicast::{SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy};
use wz_runtime_tokio::session_glue::{
    install_session_actions, poll_and_dispatch_one, DriverLoopOutcome, SessionInitParams,
    SessionLinkActions,
};
use wz_runtime_tokio::session_open::{open_session_at, open_session_static, OpenError};
use wz_runtime_tokio_test_support::fixture_session_init_params;

const ITER_CAP: usize = 64;

fn initiator_params() -> SessionInitParams {
    let mut p = fixture_session_init_params();
    p.zid = vec![0x01; 4];
    p
}

/// Inline wz acceptor: accept -> wire -> InboundStart -> drive to Established.
/// Returns (established count, writer handle) — the handle in a tuple (not a
/// bare future) keeps it alive across `join!`.
async fn drive_acceptor_to_established(listener: TcpListener) -> (u32, TokioJoinHandle<()>) {
    let (stream, _peer) = listener.accept().await.expect("accept");
    let (mut inbound, outbound, writer_handle) = wire_tcp_stream(stream);

    let mut params = fixture_session_init_params();
    params.zid = vec![0x02; 4]; // distinct zid from the initiator
    let actions = SessionLinkActions::new(outbound, params, TokioTime::new());
    let script_engine: Arc<dyn IScriptEngine> = Arc::new(LuaEngine::new());
    install_session_actions(actions.clone(), &script_engine);
    let mut engine: Engine<SessionFsmUnicastPolicy> =
        Engine::new(SessionFsmUnicastPolicy::new(script_engine));
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
    let initiator = open_session_at(&loc, initiator_params(), TokioTime::new(), Some(ITER_CAP));
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

#[tokio::test]
async fn open_session_at_udp_is_unsupported() {
    // UDP datagram session-open is deferred; dial_locator surfaces a typed
    // Unsupported before any socket work. (OpenedSession is not Debug, so
    // match instead of expect_err.)
    let result = open_session_at(
        "udp/127.0.0.1:9",
        initiator_params(),
        TokioTime::new(),
        Some(4),
    )
    .await;
    let Err(err) = result else {
        panic!("expected udp session-open to be unsupported, got Ok");
    };
    assert!(
        matches!(&err, OpenError::Dial(e) if e.kind() == std::io::ErrorKind::Unsupported),
        "expected Dial(Unsupported), got {err:?}"
    );
}

#[tokio::test]
async fn open_session_at_malformed_is_bad_locator() {
    let result = open_session_at(
        "not-a-locator",
        initiator_params(),
        TokioTime::new(),
        Some(4),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_session_static_skips_unreachable_to_first_reachable() {
    // A freed loopback port (nothing listening -> connection refused).
    let probe = TcpListener::bind("127.0.0.1:0").await.expect("probe bind");
    let dead = probe.local_addr().expect("dead addr");
    drop(probe);
    // The reachable peer.
    let good_listener = TcpListener::bind("127.0.0.1:0").await.expect("good bind");
    let good = good_listener.local_addr().expect("good addr");
    let acceptor = drive_acceptor_to_established(good_listener);

    let connect = vec![format!("tcp/{dead}"), format!("tcp/{good}")];
    let initiator = open_session_static(
        &connect,
        initiator_params(),
        TokioTime::new(),
        Some(ITER_CAP),
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

#[tokio::test]
async fn open_session_static_empty_is_no_reachable() {
    let result = open_session_static(&[], initiator_params(), TokioTime::new(), Some(4)).await;
    let Err(err) = result else {
        panic!("expected empty connect list to error, got Ok");
    };
    assert!(
        matches!(err, OpenError::NoReachableLocator),
        "expected NoReachableLocator, got {err:?}"
    );
}

#[tokio::test]
async fn open_session_static_all_unsupported_is_no_reachable() {
    // A udp-only static list exhausts (each Udp arm is Unsupported this round).
    let connect = vec!["udp/127.0.0.1:9".to_string()];
    let result = open_session_static(&connect, initiator_params(), TokioTime::new(), Some(4)).await;
    let Err(err) = result else {
        panic!("expected all-udp connect list to error, got Ok");
    };
    assert!(
        matches!(err, OpenError::NoReachableLocator),
        "expected NoReachableLocator, got {err:?}"
    );
}
