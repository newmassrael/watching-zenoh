// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ep — Layer M: active-scouting multicast loopback e2e.
//!
//! Exercises the full scout-initiator path end-to-end over a real UDP
//! multicast socket: `UdpDriver::bind_multicast_v4` (join + loop) ->
//! `scout_emit` encode + multicast send -> `poll_event` recv -> Hello
//! decode in `record_hello_and_emit` -> discovered locator. A blind
//! "responder" socket models a peer replying with a Hello on the group.
//!
//! Opt-in only (`#[ignore]`, driven by `scripts/run-ci.sh --layer M` /
//! `WZ_RUN_LAYER_M=1`): multicast routing is environment-dependent (a
//! container without a multicast route on the default interface drops the
//! join), so this must not be a default-gate (no-flaky rule). The
//! deterministic FSM + encode/decode logic is covered without a socket by
//! the `scouting_glue` unit tests in the library crate.
//!
//! Gated on `scouting-active`: the whole file is empty under the default
//! feature set, so Layer C1's `cargo test --workspace` does not build it;
//! the Layer M lane builds it with `--features scouting-active`.
#![cfg(feature = "scouting-active")]

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::net::UdpSocket;
use wz_codecs::hello::HelloOwned;
use wz_codecs::locator::LocatorOwned;
use wz_codecs::wire_const;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::scouting_glue::{
    drive_scouting_until_resolved, new_scouting_engine, ScoutOutcome, ScoutingActions,
};
use wz_runtime_tokio::UdpDriver;
use wz_session_core::scout_params::ScoutParams;

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 224);
const PORT: u16 = 7446;
const PEER_LOCATOR: &str = "udp/127.0.0.1:7447";

/// Build a `[S_MID_HELLO|L][version][cbyte][zid][VLE 1][locator]` Hello
/// datagram carrying one locator (mirror of the layer3_hello wire shape).
fn craft_hello_datagram(locator: &str) -> Vec<u8> {
    let zid = vec![0x01, 0x02, 0x03];
    let cbyte = 0x01 | (((zid.len() as u8) - 1) << 4); // whatami=peer | zid_len_m1
    let body = HelloOwned {
        version: 0x09,
        cbyte,
        zid,
        num_locators: Some(1),
        locators: Some(vec![LocatorOwned {
            locator_len: locator.len() as u64,
            locator: locator.to_string(),
        }]),
    }
    .try_as_borrowed()
    .expect("borrowed projection of owned Hello")
    .encode_to_vec(1 /* L flag projected */);

    let mut dgram = Vec::with_capacity(1 + body.len());
    dgram.push(wire_const::S_MID_HELLO | wire_const::FLAG_S_HELLO_L);
    dgram.extend_from_slice(&body);
    dgram
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "multicast loopback e2e; Layer M runs via --layer M / WZ_RUN_LAYER_M=1 --ignored"]
async fn scout_discovers_peer_locator_over_multicast() {
    // Scout side: bind the group port, join the group, loopback on.
    let mut driver = UdpDriver::bind_multicast_v4(GROUP, PORT)
        .await
        .expect("bind multicast scouting link");
    let actions = ScoutingActions::new(ScoutParams {
        version: 0x09,
        what: 0x03, // ROUTER | PEER
        zid: vec![0xAA, 0xBB, 0xCC, 0xDD],
    });
    let mut engine = new_scouting_engine(&actions);

    // Responder: an ephemeral socket (no group-port bind, so no
    // SO_REUSEADDR contention) that sends a Hello to the group once the
    // scout is in AwaitingHello.
    let responder = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .expect("bind ephemeral responder");
    let hello = craft_hello_datagram(PEER_LOCATOR);
    let responder_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        responder
            .send_to(&hello, (GROUP, PORT))
            .await
            .expect("responder send Hello to group");
    });

    let clock = TokioTime::new();
    let outcome = drive_scouting_until_resolved(
        &mut driver,
        &actions,
        &mut engine,
        &clock,
        Some(10_000), // iteration guard so a missing Hello cannot hang CI
        50,           // scheduler-tick cadence (ms); window itself is SCXML-owned
    )
    .await;

    responder_task.await.expect("responder task");

    assert_eq!(
        outcome,
        ScoutOutcome::Discovered(PEER_LOCATOR.to_string()),
        "scout should resolve the peer locator from the Hello"
    );
    let trace = actions.trace_snapshot();
    assert_eq!(trace.scout_emit, 1, "exactly one Scout emitted");
    assert_eq!(trace.record_hello, 1, "exactly one Hello recorded");
    assert_eq!(trace.tx_failed, 0, "multicast send succeeded");
}

/// R311ex — Layer M round 2: the full active path. A multicast SCOUT/HELLO
/// discovers a peer's *session* locator (a `tcp/...` endpoint), then
/// `open_session_at` dials that locator and drives the Initiator handshake to
/// Established against an inline wz acceptor. This is the active-mode analogue
/// of the in-process static path in `tests/static_scout_open.rs`, wiring
/// `drive_scouting_until_resolved -> ScoutOutcome::Discovered -> open_session_at`
/// end to end (the north-star arbitrary-composition seam, exercised from the
/// active side). Additionally gated on the TCP unicast session features since
/// it opens a real session; the discovery-only test above needs only
/// `scouting-active`. Reuses the parent module's `craft_hello_datagram`; the
/// extra session-side imports live in this gated submodule so the
/// `--no-default-features --features scouting-active` build (no
/// `transport-link-tcp` / `transport-unicast`) stays warning-clean.
#[cfg(all(feature = "transport-link-tcp", feature = "transport-unicast"))]
mod round2 {
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;

    use sce_rust_lua::LuaEngine;
    use sce_rust_runtime::scripting::IScriptEngine;
    use sce_rust_runtime::Engine;
    use tokio::net::{TcpListener, UdpSocket};

    use wz_runtime_tokio::link_pipeline::wire_tcp_stream;
    use wz_runtime_tokio::runtime_impl::{TokioJoinHandle, TokioTime};
    use wz_runtime_tokio::scouting_glue::{
        drive_scouting_until_resolved, new_scouting_engine, ScoutOutcome, ScoutingActions,
    };
    use wz_runtime_tokio::session_fsm_unicast::{
        SessionFsmUnicastEvent as E, SessionFsmUnicastPolicy,
    };
    use wz_runtime_tokio::session_glue::{
        install_session_actions, poll_and_dispatch_one, DriverLoopOutcome, SessionInitParams,
        SessionLinkActions,
    };
    use wz_runtime_tokio::session_open::open_session_at;
    use wz_runtime_tokio::UdpDriver;
    use wz_runtime_tokio_test_support::fixture_session_init_params;
    use wz_session_core::scout_params::ScoutParams;

    // Distinct group port from the discovery-only test so the two `#[ignore]`
    // tests do not contend on the same multicast bind when the Layer M lane
    // runs them together under `--ignored` (cargo's default multi-thread).
    const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 224);
    const PORT: u16 = 7448;
    const ITER_CAP: usize = 64;

    fn initiator_params() -> SessionInitParams {
        let mut p = fixture_session_init_params();
        p.zid = vec![0x01; 4];
        p
    }

    /// Inline wz acceptor: accept -> wire -> InboundStart -> drive to
    /// Established. Returns (established count, writer handle) — the handle in
    /// a tuple (not a bare future) keeps the writer task alive across `join!`.
    /// Mirror of the helper in `tests/static_scout_open.rs`.
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
    #[ignore = "multicast loopback e2e; Layer M runs via --layer M / WZ_RUN_LAYER_M=1 --ignored"]
    async fn active_scout_then_open_reaches_established() {
        // Session endpoint: an inline wz acceptor. Its bound TCP address is
        // what the HELLO advertises as the discovered session locator.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("tcp bind");
        let session_addr = listener.local_addr().expect("tcp addr");
        let session_locator = format!("tcp/{session_addr}");

        // Scout side: bind the multicast group port, join, loopback on.
        let mut driver = UdpDriver::bind_multicast_v4(GROUP, PORT)
            .await
            .expect("bind multicast scouting link");
        let actions = ScoutingActions::new(ScoutParams {
            version: 0x09,
            what: 0x03, // ROUTER | PEER
            zid: vec![0xAA, 0xBB, 0xCC, 0xDD],
        });
        let mut engine = new_scouting_engine(&actions);

        // Responder: an ephemeral socket that replies with a Hello carrying
        // the TCP session locator once the scout is in AwaitingHello.
        let responder = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .expect("bind ephemeral responder");
        let hello = super::craft_hello_datagram(&session_locator);
        let responder_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            responder
                .send_to(&hello, (GROUP, PORT))
                .await
                .expect("responder send Hello to group");
        });

        // Resolve the peer locator over multicast.
        let clock = TokioTime::new();
        let outcome = drive_scouting_until_resolved(
            &mut driver,
            &actions,
            &mut engine,
            &clock,
            Some(10_000), // iteration guard so a missing Hello cannot hang CI
            50,           // scheduler-tick cadence (ms); window itself is SCXML-owned
        )
        .await;
        responder_task.await.expect("responder task");
        let discovered = match outcome {
            ScoutOutcome::Discovered(loc) => loc,
            other => panic!("expected Discovered, got {other:?}"),
        };
        assert_eq!(
            discovered, session_locator,
            "scout resolved the advertised session locator"
        );

        // Open a session to the discovered locator against the inline acceptor.
        let acceptor = drive_acceptor_to_established(listener);
        let initiator = open_session_at(
            &discovered,
            initiator_params(),
            TokioTime::new(),
            Some(ITER_CAP),
        );
        let ((acc_est, _w), opened) = tokio::join!(acceptor, initiator);
        assert!(
            opened
                .expect("Established")
                .actions
                .trace_snapshot()
                .record_established_at
                >= 1,
            "initiator established via open_session_at on the discovered locator"
        );
        assert!(acc_est >= 1, "acceptor established");
    }
}
