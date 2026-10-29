// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "routing-router-hat", feature = "transport-link-tcp"))]

//! Two nodes that each listen and each dial the other end with ONE link, the same one at both
//! ends: the link the node with the lower zid dialled.
//!
//! This is the LOOP-level witness of `crate::link_collision` and of the rule it reads
//! (`wz_session_core::link_admission`). The machine and the rule are tested without sockets, over
//! every order the two ends can complete their links in; what only a loop can show is that the
//! loop does what the machine says: asks the held face to close, parks the link that replaces
//! it, admits it after the face has gone, and leaves the node holding one face and the routing
//! state of one.
//!
//! The nodes are two `peer_loop`s on one task, joined, each with a router's forwarder (which keys
//! its graph on the zid and so keeps one face per zid), each bound before either dials. Both
//! start their dial in the same poll, so the two links cross: each end sees the link it dialled
//! and the link the other dialled complete in whichever order the handshakes interleave in. With
//! "the first up" the two ends decide that differently and each closes the link the other kept;
//! the rounds alternate which node has the lower zid, so the rule's two arms (the held face is
//! kept, the held face is replaced) are both run.
//!
//! What is read is what each loop reports: the faces it holds, by their `FaceUp` and `FaceDown`
//! events, and whether it dialled each.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use wz_runtime_tokio::accept_loop::{peer_loop, AcceptEvent, FaceSources};
use wz_runtime_tokio::link_pipeline::bind_tcp;
use wz_runtime_tokio::link_socket::LinkSocket;
use wz_runtime_tokio::linkstate_forward::Zid;
use wz_runtime_tokio::retry_period::RetryPolicy;
use wz_runtime_tokio::router_forward::RouterForwarder;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::SessionInitParams;
use wz_runtime_tokio::session_open::{
    BoundListener, DialConfig, SessionOffer, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;

/// Rounds, alternating which node has the lower zid.
const ROUNDS: u8 = 8;

/// How long both nodes must hold one face, unchanged, before it is called settled. Longer than a
/// handshake and than the loop's first re-dial, so a link that is about to be closed, or a dial
/// that is about to be retried, has had its turn.
const SETTLE: Duration = Duration::from_millis(2500);

/// Wall-clock ceiling for one round.
const ROUND_BUDGET: Duration = Duration::from_secs(40);

/// What one loop reports of the faces it holds: each by id, with the zid its peer named and
/// whether this node dialled it, and how many came and went.
#[derive(Default)]
struct Held {
    faces: BTreeMap<u64, (Vec<u8>, bool)>,
    events: usize,
    log: Vec<String>,
}

fn recorder(held: &Arc<StdMutex<Held>>) -> impl Fn(&AcceptEvent) + 'static {
    let held = Arc::clone(held);
    move |event: &AcceptEvent| {
        let mut held = held.lock().expect("held faces");
        match event {
            AcceptEvent::FaceUp(face) => {
                held.faces.insert(
                    face.id.0,
                    (face.peer_zid.clone().unwrap_or_default(), face.dialed),
                );
                held.events += 1;
                let line = format!("up {} dialled={}", face.id.0, face.dialed);
                held.log.push(line);
            }
            AcceptEvent::FaceDown(face, _) => {
                held.faces.remove(&face.id.0);
                held.events += 1;
                let line = format!("down {}", face.id.0);
                held.log.push(line);
            }
            _ => {}
        }
    }
}

fn node_params(zid: u8) -> SessionInitParams {
    let mut params = fixture_session_init_params();
    params.zid = vec![zid; 4];
    params
}

fn sources(listener: BoundListener, dial: SocketAddr) -> FaceSources {
    FaceSources {
        listeners: vec![listener],
        dial_targets: vec![
            wz_session_core::locator::parse_any_locator(&format!("tcp/{dial}"))
                .expect("tcp/<addr> locator"),
        ],
        dial_config: Arc::new(DialConfig::default()),
        dial_intents: None,
        mcast_ingress: None,
        mcast_members: None,
        mcast_group_subs: None,
        reconcile: None,
        #[cfg(feature = "transport-multilink")]
        max_links: 1,
        max_sessions: usize::MAX,
        accept: wz_runtime_tokio::accept_loop::AcceptBounds::default(),
        ceiling: None,
        peer_board: None,
        offer: SessionOffer::universal(),
        retry: RetryPolicy::ZENOH_DEFAULT,
        stats: None,
    }
}

async fn bind_loopback() -> (BoundListener, SocketAddr) {
    let listener = bind_tcp(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &LinkSocket::NONE,
    )
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

/// Run one round: nodes of zid bytes `a_zid` and `b_zid` dial each other, and return what each
/// holds once both have held one face, unchanged, for [`SETTLE`].
async fn round(a_zid: u8, b_zid: u8) -> (Held, Held) {
    let (a_listener, a_addr) = bind_loopback().await;
    let (b_listener, b_addr) = bind_loopback().await;
    let a_held = Arc::new(StdMutex::new(Held::default()));
    let b_held = Arc::new(StdMutex::new(Held::default()));
    let (shut_tx, shut_rx) = watch::channel(false);

    let a_router = RouterForwarder::new(Zid::from_slice(&[a_zid; 4]));
    let b_router = RouterForwarder::new(Zid::from_slice(&[b_zid; 4]));
    let a = peer_loop(
        sources(a_listener, b_addr),
        node_params(a_zid),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(shut_rx.clone()),
        recorder(&a_held),
        &a_router,
    );
    let b = peer_loop(
        sources(b_listener, a_addr),
        node_params(b_zid),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(shut_rx),
        recorder(&b_held),
        &b_router,
    );
    let controller = {
        let (a_held, b_held) = (Arc::clone(&a_held), Arc::clone(&b_held));
        async move {
            // Settled: both hold one face and no event has come for SETTLE.
            let mut seen = (usize::MAX, usize::MAX);
            let mut since = Instant::now();
            loop {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let (a_events, a_faces) = {
                    let a = a_held.lock().expect("a faces");
                    (a.events, a.faces.len())
                };
                let (b_events, b_faces) = {
                    let b = b_held.lock().expect("b faces");
                    (b.events, b.faces.len())
                };
                if (a_events, b_events) != seen {
                    seen = (a_events, b_events);
                    since = Instant::now();
                }
                if a_faces == 1 && b_faces == 1 && since.elapsed() >= SETTLE {
                    let _ = shut_tx.send(true);
                    return;
                }
            }
        }
    };
    let joined = tokio::time::timeout(ROUND_BUDGET, async { tokio::join!(a, b, controller) }).await;
    if joined.is_err() {
        let a = a_held.lock().expect("a faces");
        let b = b_held.lock().expect("b faces");
        panic!(
            "the nodes never settled on one face each within {ROUND_BUDGET:?}: a holds {:?} \
             (events {:?}), b holds {:?} (events {:?})",
            a.faces, a.log, b.faces, b.log
        );
    }
    let take = |held: &Arc<StdMutex<Held>>| {
        let mut held = held.lock().expect("held faces");
        Held {
            faces: std::mem::take(&mut held.faces),
            events: held.events,
            log: std::mem::take(&mut held.log),
        }
    };
    (take(&a_held), take(&b_held))
}

/// Two nodes that dial each other keep one link, the one the lower zid dialled, at both ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_routers_that_dial_each_other_keep_the_link_the_lower_zid_dialled() {
    for n in 0..ROUNDS {
        // The lower zid is the first node's in the even rounds and the second's in the odd ones.
        let (low, high) = (0x10 + n, 0xa0 + n);
        let (a_zid, b_zid) = if n % 2 == 0 { (low, high) } else { (high, low) };
        let (a, b) = round(a_zid, b_zid).await;

        let (a_face, b_face) = (
            a.faces.values().next().expect("a holds a face"),
            b.faces.values().next().expect("b holds a face"),
        );
        assert_eq!(
            (a.faces.len(), b.faces.len()),
            (1, 1),
            "round {n}: one face each (a {:?}, b {:?})",
            a.log,
            b.log
        );
        assert_eq!(a_face.0, vec![b_zid; 4], "round {n}: a's face is to b");
        assert_eq!(b_face.0, vec![a_zid; 4], "round {n}: b's face is to a");
        assert_ne!(
            a_face.1, b_face.1,
            "round {n}: both ends keep one link, so one of them dialled it and the other did not \
             (a {:?}, b {:?})",
            a.log, b.log
        );
        let a_is_lower = a_zid < b_zid;
        assert_eq!(
            a_face.1, a_is_lower,
            "round {n}: the link kept is the one the lower zid dialled (a lower: {a_is_lower}; \
             a {:?}, b {:?})",
            a.log, b.log
        );
    }
}
