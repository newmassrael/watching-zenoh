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

use std::sync::Arc;

use sce_rust_lua::LuaEngine;
use sce_rust_runtime::scripting::IScriptEngine;
use sce_rust_runtime::Engine;
use tokio::net::TcpListener;

use wz_runtime_tokio::link_pipeline::wire_tcp_stream;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_fsm_unicast::{SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy};
use wz_runtime_tokio::session_glue::{
    install_session_actions, poll_and_dispatch_one, DriverLoopOutcome, SessionLinkActions,
};
use wz_runtime_tokio::session_open::connect_and_open_session;
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
    let initiator_fut = connect_and_open_session(locator, params, TokioTime::new(), Some(ITER_CAP));

    let ((acc_established, _acceptor_writer), opened) = tokio::join!(acceptor_fut, initiator_fut);
    let opened = opened.expect("initiator reaches Established");
    assert!(
        opened.actions.trace_snapshot().record_established_at >= 1,
        "initiator OpenedSession is Established"
    );
    assert!(acc_established >= 1, "acceptor also reached Established");
}
