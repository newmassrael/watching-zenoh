// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "routing-router-hat", feature = "transport-link-tcp"))]

//! Open-debt item 751 — the LOOP-level witness that a router whose south is
//! partitioned announces, on every session the production `peer_loop` opens,
//! the bound its partition gives the far end.
//!
//! The session half is unit-tested in `open_remote_bound.rs`: a session told a
//! partition puts the bound on its Open. What those tests cannot see is whether
//! the node tells its sessions anything. The pin decides the bound from the one
//! config its routing also reads (`zenoh/src/net/runtime/region.rs`
//! @ `pub(crate) fn compute_transient_bound_of(`), so a router that placed a far
//! router in a south subregion and announced nothing would be a gateway its
//! neighbour does not know it has. Here the router's forwarder is partitioned
//! and nothing else is: the loop must carry the partition from the forwarder to
//! the session it accepts and to the one it dials.
//!
//! The far end is a bare session opened by the test, so the bound it read off
//! the router's Open is the observable. The control is the same router on the
//! `auto` preset, which announces nothing.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use wz_runtime_tokio::accept_loop::{peer_loop, AcceptEvent, FaceSources};
use wz_runtime_tokio::link_pipeline::bind_tcp;
use wz_runtime_tokio::link_socket::LinkSocket;
use wz_runtime_tokio::linkstate_forward::Zid;
use wz_runtime_tokio::retry_period::RetryPolicy;
use wz_runtime_tokio::router_forward::RouterForwarder;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::{SessionInitParams, WhatAmI};
use wz_runtime_tokio::session_open::{
    accept_and_open_session_with_offer, initiate_and_open_session_with_offer, BoundListener,
    DialConfig, DialedLink, SessionOffer, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::extbound::Bound;
use wz_session_core::locator::{parse_any_locator, AnyLocator};
use wz_session_core::region_partition::{SouthPartition, SouthSubregion};

/// Wall-clock ceiling for one case: the assertion, not the clock, reports a
/// loop that announced the wrong bound.
const CASE_BUDGET: Duration = Duration::from_secs(20);

/// The step the far end's open may take before it gives up.
const OPEN_ITER_CAP: usize = 4096;

/// The zid of the router under test.
const ROUTER_ZID: [u8; 4] = [0x05; 4];

/// A ROUTER's session parameters with zid `zid`: the far end is a router too,
/// so the partition puts it in a subregion's router region.
fn router_params(zid: [u8; 4]) -> SessionInitParams {
    let mut params = fixture_session_init_params();
    params.whatami = WhatAmI::Router;
    params.zid = zid.to_vec();
    params
}

/// One subregion with no filters, so every remote is placed in it.
fn one_open_subregion() -> SouthPartition {
    SouthPartition::Custom(vec![SouthSubregion { filters: None }])
}

fn sources(listeners: Vec<BoundListener>, dial_targets: Vec<AnyLocator>) -> FaceSources {
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
        max_sessions: usize::MAX,
        offer: SessionOffer::universal(),
        retry: RetryPolicy::ZENOH_DEFAULT,
        stats: None,
    }
}

async fn shutdown_on(mut rx: watch::Receiver<bool>) {
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Which way the router's face is opened.
#[derive(Clone, Copy)]
enum Direction {
    /// The far end dials the router; the router announces on its OpenAck.
    RouterAccepts,
    /// The router dials the far end; it announces on its OpenSyn.
    RouterDials,
}

/// Run a router partitioned as `partition` against one far-end router and
/// return the bound the far end read off the router's Open.
async fn bound_the_router_announced(
    partition: SouthPartition,
    direction: Direction,
) -> Option<Bound> {
    let forwarder =
        RouterForwarder::new(Zid::from_slice(&ROUTER_ZID)).with_south_partition(partition);
    let (shut_tx, shut_rx) = watch::channel(false);

    let (router_sources, far_end) = match direction {
        Direction::RouterAccepts => {
            let listener = bind_tcp(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                &LinkSocket::NONE,
            )
            .await
            .expect("bind loopback");
            let addr = listener.local_addr().expect("local_addr");
            (
                sources(vec![BoundListener::Tcp(listener)], Vec::new()),
                FarEnd::Dials(addr),
            )
        }
        Direction::RouterDials => {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind the far end");
            let addr = listener.local_addr().expect("local_addr");
            let target = parse_any_locator(&format!("tcp/{addr}")).expect("tcp locator");
            (sources(Vec::new(), vec![target]), FarEnd::Accepts(listener))
        }
    };

    let router = peer_loop(
        router_sources,
        router_params(ROUTER_ZID),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(shut_rx),
        |_: &AcceptEvent| {},
        &forwarder,
    );
    let far = async move {
        let opened = match far_end {
            FarEnd::Dials(addr) => {
                let stream = TcpStream::connect(addr).await.expect("dial the router");
                initiate_and_open_session_with_offer(
                    DialedLink::Tcp(stream),
                    router_params([0xAA; 4]),
                    SessionOffer::universal(),
                    TokioTime::new(),
                    Some(OPEN_ITER_CAP),
                    DEFAULT_OPEN_TICK_MS,
                )
                .await
            }
            FarEnd::Accepts(listener) => {
                let (stream, _) = listener.accept().await.expect("the router dials");
                accept_and_open_session_with_offer(
                    DialedLink::Tcp(stream),
                    router_params([0xAA; 4]),
                    SessionOffer::universal(),
                    TokioTime::new(),
                    Some(OPEN_ITER_CAP),
                    DEFAULT_OPEN_TICK_MS,
                )
                .await
            }
        }
        .unwrap_or_else(|e| panic!("the far end did not open a session with the router: {e:?}"));
        let bound = opened.actions.peer_remote_bound();
        let _ = shut_tx.send(true);
        bound
    };
    let joined = tokio::time::timeout(CASE_BUDGET, async { tokio::join!(router, far) })
        .await
        .unwrap_or_else(|_| panic!("the session did not open within {CASE_BUDGET:?}"));
    joined.1
}

enum FarEnd {
    Dials(SocketAddr),
    Accepts(TcpListener),
}

/// THE CLAIM, accept side: the router's rule puts the far end in a subregion, so
/// its OpenAck tells the far end it is SOUTH of the router.
#[tokio::test(flavor = "current_thread")]
async fn a_partitioned_router_announces_south_on_the_sessions_it_accepts() {
    let bound = bound_the_router_announced(one_open_subregion(), Direction::RouterAccepts).await;
    assert_eq!(bound, Some(Bound::South));
}

/// THE CLAIM, dial side: the same on the OpenSyn of a session the router dials.
#[tokio::test(flavor = "current_thread")]
async fn a_partitioned_router_announces_south_on_the_sessions_it_dials() {
    let bound = bound_the_router_announced(one_open_subregion(), Direction::RouterDials).await;
    assert_eq!(bound, Some(Bound::South));
}

/// THE CONTROL: on the `auto` preset the router announces nothing, either way,
/// which is what every session the loop opened before this round carried.
#[tokio::test(flavor = "current_thread")]
async fn a_router_on_the_auto_preset_announces_nothing() {
    for direction in [Direction::RouterAccepts, Direction::RouterDials] {
        assert_eq!(
            bound_the_router_announced(SouthPartition::Auto, direction).await,
            None
        );
    }
}
