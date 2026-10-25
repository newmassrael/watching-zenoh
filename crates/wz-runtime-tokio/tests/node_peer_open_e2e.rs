// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Decision D5 of `docs/session-lifecycle-intent.md` on AP: a node a lifecycle
//! `open` names (`ConnectReconcile::AddNode`) is held by its connection machine
//! in the face loop, not by the desired connect-set.
//!
//! Two real face loops on loopback: the node under test, and a far node with a
//! known zid listening on TCP. The node under test is told to hold a zid at the
//! far node's locator, and the loop's events say what its machine did:
//!
//! - the far node's own zid: the dial opens and the face is held;
//! - another zid: the far node answers, the InitAck carries its zid, and the
//!   dial fails as a mismatch (decision D4); the machine is refused
//!   (`IdentityMismatch`), so it does not dial again;
//! - a zid at a port nobody listens on: every attempt fails, and the machine
//!   backs off and dials again on the retry schedule;
//! - the far node's zid, withdrawn once its face is up (a lifecycle `close`,
//!   decision D6): the machine closes the session, and the node is not dialled
//!   again although the retry wait is far shorter than the run.
//!
//! Each run also reads the board the loop publishes its machines to (decision
//! D6's status), and the board says the same thing the events do: held, out of
//! the intent, refused for the mismatch, waiting to dial again.

#![cfg(all(
    feature = "router-connect-reconcile",
    feature = "routing-peer",
    feature = "transport-link-tcp",
    feature = "session-close-ingress",
))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::sync::watch;

use wz_runtime_tokio::accept_loop::{
    peer_loop, AcceptEvent, ConnectReconcile, FaceSources, NoOpForwarder,
};
use wz_runtime_tokio::link_pipeline::bind_tcp;
use wz_runtime_tokio::link_socket::LinkSocket;
use wz_runtime_tokio::peer_board::{BoardRow, PeerBoard};
use wz_runtime_tokio::retry_period::RetryPolicy;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_open::{
    BoundListener, DialConfig, OpenError, SessionOffer, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;

/// The far node's zid on the wire, and the node under test's.
const FAR: [u8; 4] = [0xfa, 0xfa, 0xfa, 0xfa];
const NEAR: [u8; 4] = [0x0e, 0x0e, 0x0e, 0x0e];

fn sixteen(zid: [u8; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&zid);
    out
}

fn sources(
    listeners: Vec<BoundListener>,
    reconcile: Option<tokio::sync::mpsc::UnboundedReceiver<ConnectReconcile>>,
    retry: RetryPolicy,
    peer_board: Option<PeerBoard>,
) -> FaceSources {
    FaceSources {
        listeners,
        dial_targets: Vec::new(),
        dial_config: Arc::new(DialConfig::default()),
        dial_intents: None,
        mcast_ingress: None,
        mcast_members: None,
        mcast_group_subs: None,
        reconcile,
        #[cfg(feature = "transport-multilink")]
        max_links: 1,
        max_sessions: usize::MAX,
        ceiling: None,
        peer_board,
        offer: SessionOffer::universal(),
        retry,
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

/// What the node under test's loop reported: a face up and its peer's zid, or a
/// dial that failed and whether another node answered (decision D4).
#[derive(Debug, Clone)]
enum Seen {
    Up(Option<Vec<u8>>),
    Down,
    Failed { mismatch: bool },
}

/// Run the node under test, told to hold `zid` at `target`, beside a far node
/// listening as `FAR`, for `window`; return what its loop reported, and the rows
/// its board holds for `zid` at the end. With `withdraw_on_up`, the node is
/// withdrawn from the intent the moment a face comes up, as a lifecycle `close`
/// withdraws it.
async fn hold(
    zid: [u8; 4],
    target: Option<SocketAddr>,
    window: Duration,
    withdraw_on_up: bool,
) -> (Vec<Seen>, Vec<BoardRow>) {
    let far_listener = BoundListener::Tcp(
        bind_tcp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &LinkSocket::NONE,
        )
        .await
        .expect("bind the far node"),
    );
    let far_addr = far_listener.local_addr().expect("far addr");
    let target = target.unwrap_or(far_addr);
    let (shut_tx, shut_rx) = watch::channel(false);

    let mut far_params = fixture_session_init_params();
    far_params.zid = FAR.to_vec();
    let far = peer_loop(
        sources(vec![far_listener], None, RetryPolicy::constant(1000), None),
        far_params,
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(shut_rx.clone()),
        |_: &AcceptEvent| {},
        &NoOpForwarder,
    );

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tx.send(ConnectReconcile::AddNode {
        zid: sixteen(zid),
        locators: vec![format!("tcp/{target}")],
    })
    .expect("the loop's channel");
    let seen: Arc<StdMutex<Vec<Seen>>> = Arc::new(StdMutex::new(Vec::new()));
    let sink = seen.clone();
    let withdraw = tx.clone();
    let mut near_params = fixture_session_init_params();
    near_params.zid = NEAR.to_vec();
    let board = PeerBoard::new();
    let near = peer_loop(
        sources(
            Vec::new(),
            Some(rx),
            RetryPolicy::constant(150),
            Some(board.clone()),
        ),
        near_params,
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(shut_rx),
        move |event: &AcceptEvent| {
            let mut seen = sink.lock().expect("seen");
            match event {
                AcceptEvent::FaceUp(face) => {
                    seen.push(Seen::Up(face.peer_zid.clone()));
                    if withdraw_on_up {
                        withdraw
                            .send(ConnectReconcile::Withdraw { zid: sixteen(zid) })
                            .expect("the loop's channel");
                    }
                }
                AcceptEvent::FaceDown(..) => seen.push(Seen::Down),
                AcceptEvent::FaceFailed { cause, .. } => seen.push(Seen::Failed {
                    mismatch: matches!(cause, OpenError::InitAckPeerMismatch),
                }),
                _ => {}
            }
        },
        &NoOpForwarder,
    );

    let stop = async {
        tokio::time::sleep(window).await;
        let _ = shut_tx.send(true);
    };
    tokio::time::timeout(window + Duration::from_secs(10), async {
        tokio::join!(far, near, stop)
    })
    .await
    .expect("both loops stop when told");
    drop(tx);
    let seen = seen.lock().expect("seen").clone();
    (seen, board.rows(&sixteen(zid)))
}

/// The node's own machine, as the board shows it.
fn machine(state: &'static str, cause: Option<&'static str>, in_intent: bool) -> BoardRow {
    BoardRow {
        endpoint: None,
        state,
        cause,
        in_intent,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_node_opened_by_its_own_zid_is_held() {
    let (seen, board) = hold(FAR, None, Duration::from_millis(1500), false).await;
    assert!(
        matches!(seen.as_slice(), [Seen::Up(Some(zid))] if zid.as_slice() == FAR),
        "one face, to the far node: {seen:?}"
    );
    assert_eq!(board, vec![machine("established", None, true)]);
}

/// Decision D6 — a withdrawn node's session is closed by its machine, and the
/// loss is nobody's to retry: with a 150 ms retry wait in a 1.5 s run, a
/// machine that still held the node would have brought a second face up.
#[tokio::test(flavor = "current_thread")]
async fn a_withdrawn_node_is_closed_and_not_dialled_again() {
    let (seen, board) = hold(FAR, None, Duration::from_millis(1500), true).await;
    assert!(
        matches!(seen.as_slice(), [Seen::Up(Some(zid)), Seen::Down] if zid.as_slice() == FAR),
        "one face, closed by the withdrawal, and no second: {seen:?}"
    );
    assert_eq!(
        board,
        vec![machine("idle", None, false)],
        "out of the intent"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_node_another_answers_for_is_refused_and_not_dialled_again() {
    let (seen, board) = hold(
        [0xb0, 0xb1, 0xb2, 0xb3],
        None,
        Duration::from_millis(1500),
        false,
    )
    .await;
    assert!(
        matches!(seen.as_slice(), [Seen::Failed { mismatch: true }]),
        "one dial, closed at the InitAck, and no retry of a refused node: {seen:?}"
    );
    assert_eq!(
        board,
        vec![machine("refused", Some("identity_mismatch"), true)],
        "the refusal holds until the next open, and says why"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn an_unreachable_node_is_dialled_again_on_the_retry_schedule() {
    let refusing = wz_runtime_tokio_test_support::refusing_port();
    let (seen, board) = hold(
        FAR,
        Some(refusing.addr()),
        Duration::from_millis(1500),
        false,
    )
    .await;
    assert!(
        seen.len() >= 3
            && seen
                .iter()
                .all(|s| matches!(s, Seen::Failed { mismatch: false })),
        "a node that is not reached is dialled again and again: {seen:?}"
    );
    // Stopped between two attempts or inside one: either way still held.
    assert!(
        matches!(board.as_slice(), [row] if row.in_intent
            && (row.state == "backoff" || row.state == "connecting")),
        "{board:?}"
    );
}
