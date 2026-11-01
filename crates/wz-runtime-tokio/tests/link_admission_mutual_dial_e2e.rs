// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(feature = "routing-accept", feature = "transport-link-tcp"))]

//! Two nodes that each listen and each dial the other end with ONE link, and no face of either was
//! ever brought up on a link that was then closed.
//!
//! This is the LOOP-level witness of [`wz_session_core::link_admission::LinkAdmission`]: the node's
//! say on a second link to a node it holds, asked while the link is still being established. The
//! registry and its rule are tested without sockets over every order the two ends can reach their
//! handshakes in (`link_registry`); what only a real handshake shows is where the question is
//! asked: the acceptor before its OpenAck, the initiator before its OpenSyn and again before it
//! takes the OpenAck, so that the link a node refuses has said nothing the application could see.
//!
//! `router_mutual_dial_e2e` is its sibling for the loop's own collision resolution, which decides
//! AFTER a link is up and so lets the loser's face come up, receive, and be closed: each end ends
//! with one face, but not before the other was told of it. Here the forwarder answers the question
//! in the handshake, and what is read is stronger: the faces each loop ever reported are ONE `FaceUp`
//! and no `FaceDown`.
//!
//! The nodes are two `peer_loop`s on one task, joined, each bound before either dials. Both start
//! their dial in the same poll, so the two links cross, and the rounds alternate which node has the
//! lower zid, so that the rule's two arms (the dial that went first against the dial it prefers)
//! are both run.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use wz_runtime_tokio::accept_loop::{peer_loop, AcceptEvent, FaceForwarder, FaceId, FaceSources};
use wz_runtime_tokio::link_pipeline::bind_tcp;
use wz_runtime_tokio::link_registry::LinkRegistry;
use wz_runtime_tokio::link_socket::LinkSocket;
use wz_runtime_tokio::retry_period::RetryPolicy;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::{SessionInitParams, SessionLinkActions};
use wz_runtime_tokio::session_open::{
    BoundListener, DialConfig, SessionOffer, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::link_admission::LinkAdmission;

/// Rounds, alternating which node has the lower zid.
const ROUNDS: u8 = 8;

/// How long both nodes must hold one face, unchanged, before it is called settled. Longer than a
/// handshake and than the loop's first re-dial, so a link that is about to be closed, or a dial
/// that is about to be retried, has had its turn.
const SETTLE: Duration = Duration::from_millis(2500);

/// Wall-clock ceiling for one round.
const ROUND_BUDGET: Duration = Duration::from_secs(40);

/// A node that holds one face for each remote zid and answers the question of a second link in the
/// handshake, through its [`LinkRegistry`]. It routes nothing.
struct AdmittingNode {
    links: Arc<LinkRegistry>,
}

impl AdmittingNode {
    fn new(zid: &[u8]) -> Self {
        Self {
            links: Arc::new(LinkRegistry::new(zid)),
        }
    }
}

impl FaceForwarder for AdmittingNode {
    fn register(&self, _id: FaceId, _actions: &Arc<SessionLinkActions>) {}

    fn deregister(&self, _id: FaceId) {}

    fn forward(&self, _id: FaceId, _event: IterationEvent<'_>) {}

    fn dedups_faces_by_zid(&self) -> bool {
        true
    }

    fn link_admission(&self) -> Option<Arc<dyn LinkAdmission>> {
        Some(Arc::clone(&self.links) as Arc<dyn LinkAdmission>)
    }
}

/// What one loop reports of its faces: how many it brought up and how many went down, and each
/// face's story in order.
#[derive(Default)]
struct Held {
    up: usize,
    down: usize,
    dialled: Vec<bool>,
    failed: usize,
    log: Vec<String>,
}

fn recorder(held: &Arc<StdMutex<Held>>) -> impl Fn(&AcceptEvent) + 'static {
    let held = Arc::clone(held);
    move |event: &AcceptEvent| {
        let mut held = held.lock().expect("held faces");
        match event {
            AcceptEvent::FaceUp(face) => {
                held.up += 1;
                held.dialled.push(face.dialed);
                let line = format!("up {} dialled={}", face.id.0, face.dialed);
                held.log.push(line);
            }
            AcceptEvent::FaceDown(face, _) => {
                held.down += 1;
                let line = format!("down {}", face.id.0);
                held.log.push(line);
            }
            AcceptEvent::FaceFailed { id, .. } => {
                held.failed += 1;
                let line = format!("failed {}", id.0);
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
/// reported once both have held one face, unchanged, for [`SETTLE`].
async fn round(a_zid: u8, b_zid: u8) -> (Held, Held) {
    let (a_listener, a_addr) = bind_loopback().await;
    let (b_listener, b_addr) = bind_loopback().await;
    let a_held = Arc::new(StdMutex::new(Held::default()));
    let b_held = Arc::new(StdMutex::new(Held::default()));
    let (shut_tx, shut_rx) = watch::channel(false);

    let a_node = AdmittingNode::new(&[a_zid; 4]);
    let b_node = AdmittingNode::new(&[b_zid; 4]);
    let a = peer_loop(
        sources(a_listener, b_addr),
        node_params(a_zid),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(shut_rx.clone()),
        recorder(&a_held),
        &a_node,
    );
    let b = peer_loop(
        sources(b_listener, a_addr),
        node_params(b_zid),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(shut_rx),
        recorder(&b_held),
        &b_node,
    );
    let controller = {
        let (a_held, b_held) = (Arc::clone(&a_held), Arc::clone(&b_held));
        async move {
            // Settled: both brought one face up, and nothing came for SETTLE.
            let mut seen = (usize::MAX, usize::MAX);
            let mut since = Instant::now();
            loop {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let a = {
                    let a = a_held.lock().expect("a faces");
                    (a.up, a.down)
                };
                let b = {
                    let b = b_held.lock().expect("b faces");
                    (b.up, b.down)
                };
                let now = (a.0 + a.1, b.0 + b.1);
                if now != seen {
                    seen = now;
                    since = Instant::now();
                }
                if a.0 >= 1 && b.0 >= 1 && since.elapsed() >= SETTLE {
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
            "the nodes never settled with a face each within {ROUND_BUDGET:?}: a {:?}, b {:?}",
            a.log, b.log
        );
    }
    let take = |held: &Arc<StdMutex<Held>>| {
        let mut held = held.lock().expect("held faces");
        Held {
            up: held.up,
            down: held.down,
            dialled: std::mem::take(&mut held.dialled),
            failed: held.failed,
            log: std::mem::take(&mut held.log),
        }
    };
    (take(&a_held), take(&b_held))
}

/// Two nodes that dial each other bring up ONE face each, the same link at both ends, and no face
/// of either is closed afterwards: the link a node refuses is closed before it is a face.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_that_dial_each_other_never_bring_up_a_face_they_close() {
    for n in 0..ROUNDS {
        // The lower zid is the first node's in the even rounds and the second's in the odd ones.
        let (low, high) = (0x10 + n, 0xa0 + n);
        let (a_zid, b_zid) = if n % 2 == 0 { (low, high) } else { (high, low) };
        let (a, b) = round(a_zid, b_zid).await;

        assert_eq!(
            (a.up, a.down, b.up, b.down),
            (1, 0, 1, 0),
            "round {n}: one face each and none closed (a {:?}, b {:?})",
            a.log,
            b.log
        );
        assert_ne!(
            a.dialled[0], b.dialled[0],
            "round {n}: both ends keep ONE link, so one of them dialled it and the other did not \
             (a {:?}, b {:?})",
            a.log, b.log
        );
    }
}
