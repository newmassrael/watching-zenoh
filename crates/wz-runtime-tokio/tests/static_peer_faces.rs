// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "scouting-static",
    feature = "routing-peer",
    feature = "transport-link-tcp",
))]

//! R2570 — the LOOP-level witness that a static deploy in peer mode holds
//! EVERY configured locator at once, which is the residual the
//! `scouting-static` atom carried for its whole life.
//!
//! # Why the unit tests cannot supply this
//!
//! `scouting_static`'s own tests prove `static_peer_sources` RESOLVES the whole
//! connect list into dial targets. That is a statement about a `Vec`. The atom's
//! claim is about the wire: pico opens the first locator and then adds every
//! remaining one to the same transport's peer set (`vendor/zenoh-pico/src/net/session.c`
//! @ `z_result_t ret = _z_add_peers(&_Z_RC_IN_VAL(zn)->_tp, zid, &pending_peers, config, connect_exit_on_failure);`),
//! so what has to be measured is how many peers are HELD SIMULTANEOUSLY —
//! [`AcceptLoopSummary::peak_concurrent`], the high-water mark of the live faces
//! table.
//!
//! A build whose resolution is perfect and whose loop dialed only the first
//! target would pass every unit test in the module and fail here, which is what
//! makes this the discriminator rather than a second spelling of them.
//!
//! # The shape of each case
//!
//! Two (or three) `peer_loop`s on one task, joined — the loop's drive future is
//! `!Send`, so this is the same single-task concurrency
//! `router_redial_backoff_e2e` uses rather than spawned tasks. The far ends are
//! accept-only peers (`dial_targets: vec![]`); the SUT is the node whose
//! `FaceSources` come out of `static_peer_sources`. The SUT flips the shared
//! shutdown once the SET of peer zids it holds reaches the expected size, and
//! the whole join is bounded by [`CASE_BUDGET`] — so a build that reaches one
//! peer FAILS on an assertion rather than hanging.
//!
//! The zid SET, never the face COUNT, is the claim. Distinct zids per node are
//! what make that measurable, and the reason is a measured one rather than a
//! precaution: `NoOpForwarder::dedups_faces_by_zid` is `false`, so a build whose
//! resolution mapped every configured locator onto the FIRST one still holds two
//! faces and still reports `peak_concurrent = 2`. It passed this file while these
//! cases counted. Two links to one peer is not a peer set.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::sync::watch;

use wz_runtime_tokio::accept_loop::{peer_loop, AcceptEvent, FaceSources, NoOpForwarder};
use wz_runtime_tokio::link_pipeline::bind_tcp;
use wz_runtime_tokio::retry_period::RetryPolicy;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::scouting_static::static_peer_sources;
use wz_runtime_tokio::session_glue::SessionInitParams;
use wz_runtime_tokio::session_open::{
    AcceptConfig, BoundListener, DialConfig, SessionOffer, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;

/// Wall-clock ceiling for one case. Generous against a loaded runner and still
/// far below a hang: the assertion, not the clock, is what reports a build that
/// held fewer faces than the deploy configured.
const CASE_BUDGET: Duration = Duration::from_secs(20);

/// The fixture params with a DISTINCT zid, so each node in a case is a
/// different peer rather than the same one reached twice.
fn node_params(zid: u8) -> SessionInitParams {
    let mut params = fixture_session_init_params();
    params.zid = vec![zid; 4];
    params
}

/// The node-level `FaceSources` fields a static deploy does NOT decide: the
/// node's own offer, trust material and re-dial cadence. Spelled once so each
/// case names only what it is varying.
fn sources(
    listeners: Vec<BoundListener>,
    dial_targets: Vec<wz_session_core::locator::AnyLocator>,
) -> FaceSources {
    FaceSources {
        listeners,
        dial_targets,
        dial_config: Arc::new(DialConfig::default()),
        dial_intents: None,
        mcast_ingress: None,
        mcast_members: None,
        mcast_group_subs: None,
        reconcile: None,
        #[cfg(feature = "transport-multilink")]
        max_links: 1,
        offer: SessionOffer::universal(),
        retry: RetryPolicy::ZENOH_DEFAULT,
    }
}

async fn bind_loopback() -> (BoundListener, SocketAddr) {
    let listener = bind_tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), None)
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local_addr");
    (BoundListener::Tcp(listener), addr)
}

async fn shutdown_on(mut rx: watch::Receiver<bool>) {
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// EVERY configured locator becomes a held face, at the same time, and the
/// faces reach DIFFERENT peers.
///
/// The zid SET is what is asserted, not the face count, and that is the whole
/// difference between this case and a vacuous one. A count is satisfied by two
/// links to ONE peer: a resolution that mapped every configured locator to the
/// first member keeps `peak_concurrent = 2` and passes a count assertion — it
/// was MEASURED doing exactly that while this case was still counting — because
/// `NoOpForwarder::dedups_faces_by_zid` is `false` and the loop holds both. The
/// set says the deploy reached peer 0xAA and peer 0xBB, which no single-locator
/// build can report.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_deploy_holds_every_configured_locator_at_once() {
    let (a_listener, a_addr) = bind_loopback().await;
    let (b_listener, b_addr) = bind_loopback().await;

    let connect = vec![format!("tcp/{a_addr}"), format!("tcp/{b_addr}")];
    let deploy = static_peer_sources(
        None,
        &connect,
        wz_runtime_tokio::session_glue::WhatAmI::Peer,
        &AcceptConfig::default(),
    )
    .await
    .expect("a two-locator peer deploy resolves");
    assert_eq!(
        deploy.dial_targets.len(),
        2,
        "the deploy's whole connect list reaches the loop"
    );

    let (shut_tx, shut_rx) = watch::channel(false);
    let held = Arc::new(StdMutex::new(BTreeSet::new()));
    let sink = held.clone();
    let done = shut_tx.clone();

    let a = peer_loop(
        sources(vec![a_listener], Vec::new()),
        node_params(0xAA),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(shut_rx.clone()),
        |_: &AcceptEvent| {},
        &NoOpForwarder,
    );
    let b = peer_loop(
        sources(vec![b_listener], Vec::new()),
        node_params(0xBB),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(shut_rx.clone()),
        |_: &AcceptEvent| {},
        &NoOpForwarder,
    );
    let sut = peer_loop(
        sources(Vec::new(), deploy.dial_targets),
        node_params(0x01),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(shut_rx),
        move |event: &AcceptEvent| {
            if let AcceptEvent::FaceUp(face) = event {
                let mut zids = sink.lock().expect("held zids");
                zids.insert(face.peer_zid.clone());
                if zids.len() == 2 {
                    let _ = done.send(true);
                }
            }
        },
        &NoOpForwarder,
    );

    let joined = tokio::time::timeout(CASE_BUDGET, async { tokio::join!(a, b, sut) }).await;
    let (_, _, summary) = joined.unwrap_or_else(|_| {
        panic!(
            "the deploy never reached both peers within {CASE_BUDGET:?}; the zids \
             held were {:?}",
            held.lock().expect("held zids")
        )
    });

    assert_eq!(
        summary.dialed, 2,
        "both configured locators were dialed, not just the first"
    );
    assert_eq!(
        summary.peak_concurrent, 2,
        "the deploy's faces are held AT ONCE — a single-session static open \
         reports 1 here"
    );
    assert_eq!(
        *held.lock().expect("held zids"),
        BTreeSet::from([Some(vec![0xAAu8; 4]), Some(vec![0xBBu8; 4])]),
        "the two faces reach two DIFFERENT peers, which is what makes this a \
         peer SET rather than two links to one peer"
    );
}

/// `listen=` AND `connect=` at once — the pair the single-session opener
/// refuses as `ListenWithConnect`, live on both halves.
///
/// The SUT dials its one configured peer AND accepts an inbound one, so it ends
/// up holding two faces that arrived from opposite directions. A build that
/// honoured one half and dropped the other reports 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deploy_with_both_halves_holds_a_dialed_and_an_accepted_face() {
    // The peer the SUT DIALS.
    let (dialed_listener, dialed_addr) = bind_loopback().await;
    // The SUT's own listen endpoint — bound by `static_peer_sources`, not here,
    // which is the half under test. A concrete free port is taken and released
    // so the deploy string can name it.
    let sut_listen = {
        let (probe, addr) = bind_loopback().await;
        drop(probe);
        addr
    };

    let connect = vec![format!("tcp/{dialed_addr}")];
    let deploy = static_peer_sources(
        Some(&format!("tcp/{sut_listen}")),
        &connect,
        wz_runtime_tokio::session_glue::WhatAmI::Peer,
        &AcceptConfig::default(),
    )
    .await
    .expect("a listen+connect peer deploy resolves");
    assert_eq!(deploy.listeners.len(), 1, "the listen half is bound");
    assert_eq!(deploy.dial_targets.len(), 1, "the connect half is resolved");

    let (shut_tx, shut_rx) = watch::channel(false);
    let held = Arc::new(StdMutex::new(BTreeSet::new()));
    let sink = held.clone();
    let done = shut_tx.clone();

    let dialed_peer = peer_loop(
        sources(vec![dialed_listener], Vec::new()),
        node_params(0xAA),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(shut_rx.clone()),
        |_: &AcceptEvent| {},
        &NoOpForwarder,
    );
    // The peer that DIALS the SUT's listen endpoint.
    let inbound_peer = peer_loop(
        sources(
            Vec::new(),
            vec![
                wz_session_core::locator::parse_any_locator(&format!("tcp/{sut_listen}"))
                    .expect("tcp/<addr> locator"),
            ],
        ),
        node_params(0xBB),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(shut_rx.clone()),
        |_: &AcceptEvent| {},
        &NoOpForwarder,
    );
    let sut = peer_loop(
        sources(deploy.listeners, deploy.dial_targets),
        node_params(0x01),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(shut_rx),
        move |event: &AcceptEvent| {
            if let AcceptEvent::FaceUp(face) = event {
                let mut zids = sink.lock().expect("held zids");
                zids.insert(face.peer_zid.clone());
                if zids.len() == 2 {
                    let _ = done.send(true);
                }
            }
        },
        &NoOpForwarder,
    );

    let joined = tokio::time::timeout(CASE_BUDGET, async {
        tokio::join!(dialed_peer, inbound_peer, sut)
    })
    .await;
    let (_, _, summary) = joined.unwrap_or_else(|_| {
        panic!(
            "both halves never came up within {CASE_BUDGET:?}; the zids held were {:?}",
            held.lock().expect("held zids")
        )
    });

    assert_eq!(summary.dialed, 1, "the connect half dialed its one peer");
    assert_eq!(summary.accepted, 1, "the listen half accepted its one peer");
    assert_eq!(
        summary.peak_concurrent, 2,
        "a dialed face and an accepted face are held at the same time — the \
         config the single-session opener refuses outright"
    );
    assert_eq!(
        *held.lock().expect("held zids"),
        BTreeSet::from([Some(vec![0xAAu8; 4]), Some(vec![0xBBu8; 4])]),
        "the dialed peer and the accepting one are two different nodes"
    );
}
