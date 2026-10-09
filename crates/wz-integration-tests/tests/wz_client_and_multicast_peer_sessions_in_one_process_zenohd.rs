// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! One process holding TWO local sessions of different transport modes at the
//! same time, on the AP profile: a CLIENT session dialled to a stock zenohd,
//! and a PEER session that joined a UDP multicast group.
//!
//! ## The question this answers
//!
//! Whether a program may hold a client session towards a router and a
//! multicast peer session side by side, each with its own session state, was
//! answerable only by reading. The reading says yes on this profile — the two
//! are different typestates of one `Session` (`TokioSession` and
//! `TokioMulticastSession`), each built from its own observer, dispatcher and
//! link, and the process-wide statics `wz-runtime-tokio` keeps (the runtime
//! pool, the link-RX arena, the SHM registries) are shared by design rather
//! than owned by one session. A reading is not a run, so this leg runs it.
//!
//! ## Topology
//!
//! ```text
//!   this process
//!   ├── session A: Client ──tcp──> zenohd        (query of zenohd's admin space)
//!   ├── session B: Peer, joined to 224.0.0.224:7466 (subscriber)
//!   └── node C:    TX-only group publisher ──udp multicast──> B
//! ```
//!
//! Each session is asked for something only its own transport can deliver,
//! twice, in alternation: A's reply can come only from zenohd over A's TCP
//! link, and B's sample only from the group over B's joined socket. All three
//! drive loops share one tokio runtime, and the leg fails if any of them ends
//! before both rounds are answered.
//!
//! Then the router is killed. That is a fault of session A's alone, and the
//! leg asserts it stays A's: A's loop reaches its own terminal, and B goes on
//! receiving the group's samples with its peer still admitted.
//!
//! ## What it does not claim
//!
//! It is not a witness of the FIXED-MEMORY profile. The MCU session tier
//! cannot express this topology yet: its unicast session runs as a task on a
//! cooperative local set, while its multicast loop owns the thread and pumps
//! only the runtime's shared pool, never the local set — see
//! `wz-session-lwip/src/multicast_drive.rs` and
//! `wz-runtime-coop/src/local.rs`.
//!
//! Node C is in-process because two sockets joined to the same group port in
//! one host would need `SO_REUSEADDR`, the same reason
//! `wz-runtime-tokio/tests/multicast_pubsub_loopback.rs` gives for its TX-only
//! publisher.
//!
//! Opt-in (`#[ignore]`, run-ci Layer M): it needs zenohd and a host that
//! delivers multicast on loopback. The test NAME carries `zenohd` because
//! Layer E's skip filter is a name substring.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::{TcpStream, UdpSocket};

use wz_integration_tests::common::spawn_zenohd_on_ephemeral_tcp;
use wz_runtime_tokio::multicast_glue::{
    drive_multicast_session, multicast_put_literal, MulticastDriveConfig, MulticastTxProducer,
};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{
    QueryAliasError, QueryOptions, SubscribeOptions, TokioMulticastSession, TokioSession,
};
use wz_runtime_tokio::session_glue::{drive_session_until_terminal, DriverOutcome};
use wz_runtime_tokio::session_open::{initiate_and_open_session, DialedLink, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio::{McastSocketConfig, UdpDriver};
use wz_runtime_tokio_test_support::zenohd_interop_session_init_params;
use wz_session_core::multicast_dispatch::{MulticastConfig, MulticastDispatcher};
use wz_session_core::multicast_params::MulticastParams;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::WhatAmI;

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 224);
/// A group port no other multicast leg in this tree binds, so a parallel
/// `--ignored` sweep never contends for it.
const PORT: u16 = 7466;
const GROUP_KEY: &str = "demo/two-sessions/group";
const ADMIN_SELECTOR: &str = "@/*/router";
const ROUNDS: usize = 2;
const ITER_CAP: usize = 4096;

fn group_params(zid_byte: u8) -> MulticastParams {
    MulticastParams {
        version: 0x09,
        whatami: WhatAmI::Peer,
        zid: vec![zid_byte; 4],
        lease_ms: 5_000,
        join_interval_ms: 50,
        seq_num_res: 0x02,
        req_id_res: 0x02,
        batch_size: 2_048,
        is_qos: false,
        tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
    }
}

/// Wait until `counter` reaches `want`, or fail with `what`.
async fn wait_for(counter: &AtomicUsize, want: usize, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while counter.load(Ordering::SeqCst) < want {
        assert!(
            Instant::now() < deadline,
            "{what}: {} of {want} within 10s",
            counter.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// The subject is wz holding two of its own sessions at once, not a behaviour
// graded against zenohd: zenohd is the client session's counterparty, and the
// group's is wz.
// wz-proves: none -- two sessions in one process; zenohd only answers session A
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd) + multicast on loopback; set WZ_ZENOHD_BIN, run via Layer M / --ignored"]
async fn a_client_session_to_zenohd_and_a_multicast_peer_session_run_in_one_process() {
    // Session A — CLIENT, dialled to the router.
    let (mut zenohd, zenohd_port) = spawn_zenohd_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("tempfile for readiness probe stderr")
    });
    let params_a = zenohd_interop_session_init_params();
    assert_eq!(params_a.whatami, WhatAmI::Client, "session A is a client");
    let stream = TcpStream::connect(("127.0.0.1", zenohd_port))
        .await
        .expect("session A dials zenohd");
    let mut opened = initiate_and_open_session(
        DialedLink::Tcp(stream),
        params_a,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .expect("session A reaches Established against zenohd");
    let session_a = TokioSession::new(
        opened.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened.clock),
    );

    // Session B — PEER, joined to the group, with its own observer.
    let mut driver_b = UdpDriver::bind_multicast(GROUP, PORT, McastSocketConfig::default())
        .await
        .expect("session B joins the group");
    let mut dispatcher_b = MulticastDispatcher::<8>::new(MulticastConfig::new(5_000));
    let params_b = group_params(0xBB);
    let producer_b = MulticastTxProducer::new();
    let clock = Arc::new(TokioTime::new());
    let session_b = TokioMulticastSession::new_multicast(
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        clock.clone(),
        producer_b.clone(),
    );
    let group_samples = Arc::new(AtomicUsize::new(0));
    let _group_subscriber = {
        let group_samples = group_samples.clone();
        // Infallible on a multicast session: the declaration is local only.
        session_b.declare_subscriber(GROUP_KEY, SubscribeOptions::default(), move |sample| {
            assert_eq!(sample.keyexpr(), GROUP_KEY);
            group_samples.fetch_add(1, Ordering::SeqCst);
        })
    };

    // Node C — the group's publisher, TX-only.
    let sock_c = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .expect("bind node C's ephemeral socket");
    let mut driver_c = UdpDriver::from_socket(sock_c, SocketAddr::from((GROUP, PORT)));
    let mut dispatcher_c = MulticastDispatcher::<8>::new(MulticastConfig::new(5_000));
    let params_c = group_params(0xCC);
    let producer_c = MulticastTxProducer::new();

    let timeouts = SessionTimeouts::spec_defaults();
    let drive_a = {
        let session = session_a.clone();
        drive_session_until_terminal(
            &mut opened.inbound,
            &opened.actions,
            &mut opened.engine,
            None,
            &opened.clock,
            &timeouts,
            move |event| session.dispatch_iteration_event(event),
        )
    };
    let drive_b = drive_multicast_session(
        &mut dispatcher_b,
        MulticastDriveConfig {
            params: &params_b,
            tick_ms: 10,
            max_iters: None,
        },
        &mut driver_b,
        clock.as_ref(),
        |event| session_b.dispatch_multicast_iteration_event(event),
        &producer_b,
    );
    let drive_c = drive_multicast_session(
        &mut dispatcher_c,
        MulticastDriveConfig {
            params: &params_c,
            tick_ms: 10,
            max_iters: None,
        },
        &mut driver_c,
        clock.as_ref(),
        |_| {},
        &producer_c,
    );

    let admin_replies = Arc::new(AtomicUsize::new(0));
    let admin_finals = Arc::new(AtomicUsize::new(0));
    let scenario = {
        let admin_replies = admin_replies.clone();
        let admin_finals = admin_finals.clone();
        let group_samples = group_samples.clone();
        let session_a = session_a.clone();
        let producer_c = producer_c.clone();
        async move {
            // C's JOIN beacons admit it into B's peer table before it publishes.
            tokio::time::sleep(Duration::from_millis(300)).await;
            for round in 1..=ROUNDS {
                let replies = admin_replies.clone();
                let finals = admin_finals.clone();
                session_a
                    .query(
                        ADMIN_SELECTOR,
                        QueryOptions::default(),
                        move |reply| {
                            let key = reply.keyexpr();
                            assert!(
                                key.starts_with("@/") && key.ends_with("/router"),
                                "a reply from zenohd's admin space, got {key:?}"
                            );
                            replies.fetch_add(1, Ordering::SeqCst);
                        },
                        move |_rid| {
                            finals.fetch_add(1, Ordering::SeqCst);
                        },
                    )
                    .expect("session A sends its query");
                producer_c
                    .push(multicast_put_literal(GROUP_KEY, b"one-of-two").expect("put item"))
                    .expect("node C's loop has attached its pipeline");
                wait_for(&admin_finals, round, "session A's queries completed").await;
                wait_for(&group_samples, round, "session B's group samples").await;
            }
        }
    };

    // Boxed rather than `tokio::pin!`ned so each can be dropped before the
    // dispatchers it borrows are read at the end.
    let mut drive_a = Box::pin(drive_a);
    let mut drive_b = Box::pin(drive_b);
    let mut drive_c = Box::pin(drive_c);

    // Phase 1 — both sessions serve their own transport, in alternation.
    tokio::select! {
        outcome = &mut drive_a => panic!("session A's drive loop ended first: {outcome:?}"),
        outcome = &mut drive_b => panic!("session B's drive loop ended first: {outcome:?}"),
        outcome = &mut drive_c => panic!("node C's drive loop ended first: {outcome:?}"),
        () = scenario => {}
    }
    assert_eq!(admin_finals.load(Ordering::SeqCst), ROUNDS);
    assert!(
        admin_replies.load(Ordering::SeqCst) >= ROUNDS,
        "every query was answered by zenohd, not only finalised"
    );
    assert_eq!(group_samples.load(Ordering::SeqCst), ROUNDS);
    assert!(session_a.is_established(), "session A is still up");

    // Phase 2 — FAULT CONTAINMENT. The router goes away under session A. A's
    // loop must reach its own terminal, and B's and C's must not end with it.
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    let a_outcome = tokio::select! {
        outcome = &mut drive_a => outcome,
        outcome = &mut drive_b => panic!("session B ended when session A lost its router: {outcome:?}"),
        outcome = &mut drive_c => panic!("node C ended when session A lost its router: {outcome:?}"),
        () = tokio::time::sleep(Duration::from_secs(30)) => {
            panic!("session A did not notice its router was gone within 30s")
        }
    };
    // `Terminated` is the engine reaching its final state, which is what "A
    // noticed" means. `is_established()` is not the predicate for it: it reads
    // the bundle's "a session was established here" stamp, which only a
    // reconnect's reset clears.
    assert!(
        matches!(a_outcome, DriverOutcome::Terminated),
        "session A's loop ended without reaching its terminal: {a_outcome:?}"
    );
    // And the loss is visible at A's API: its link was released, so a send is
    // refused typed instead of going to a dead writer.
    let after = session_a.query(
        ADMIN_SELECTOR,
        QueryOptions::default(),
        |_reply| {},
        |_rid| {},
    );
    assert!(
        matches!(after, Err(QueryAliasError::TransportUnavailable)),
        "a query on session A after its router died is refused as TransportUnavailable"
    );

    // Phase 3 — session B is still serving the group after its sibling ended.
    let after_loss = {
        let group_samples = group_samples.clone();
        let producer_c = producer_c.clone();
        async move {
            for round in 1..=ROUNDS {
                producer_c
                    .push(multicast_put_literal(GROUP_KEY, b"after-a").expect("put item"))
                    .expect("node C's loop still has its pipeline");
                wait_for(
                    &group_samples,
                    ROUNDS + round,
                    "session B's group samples after session A ended",
                )
                .await;
            }
        }
    };
    tokio::select! {
        outcome = &mut drive_b => panic!("session B's drive loop ended: {outcome:?}"),
        outcome = &mut drive_c => panic!("node C's drive loop ended: {outcome:?}"),
        () = after_loss => {}
    }
    drop(drive_a);
    drop(drive_b);
    drop(drive_c);
    assert_eq!(group_samples.load(Ordering::SeqCst), 2 * ROUNDS);
    assert_eq!(
        dispatcher_b.active_peers(),
        1,
        "session B still holds node C"
    );
}
