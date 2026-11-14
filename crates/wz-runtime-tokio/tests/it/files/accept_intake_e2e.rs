// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "routing-accept",
    feature = "routing-peer",
    feature = "transport-link-tcp"
))]

//! A routing node keeps accepting and keeps answering handshakes while its face loop is held.
//!
//! The face loop admits each face, drops each face that leaves and runs the forwarder's tick on
//! its own task, and a routing forwarder does each of those as a write of its tables, waiting for
//! every face that is routing by them. The forwarder here stands for that wait without the
//! tables: its first admission holds the loop's task until the test lets it go, so what the loop
//! cannot do while it waits is fixed by construction and not by timing.
//!
//! Under the `routing-face-drive` value `task-per-face` the listeners and the handshake of each
//! link they yield run as tasks of their own, as upstream accepts on a task per listener and
//! spawns each link's accept, and a second peer reaches Established while the loop is held. Under
//! `one-task` the node serves everything from one task by contract, and the same second peer is
//! not answered until the loop is let go: the control that shows the first test reads where the
//! handshake runs and nothing else. The third test is a peer that connects and never sends its
//! InitSyn, mid-handshake for the whole run, beside peers that open one after the other.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex as StdMutex};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::watch;

use wz_runtime_tokio::accept_loop::{
    peer_loop_shared, AcceptBounds, AcceptEvent, AcceptLoopSummary, FaceForwarder, FaceId,
    FaceSources, RoutingFaceDrive,
};
use wz_runtime_tokio::link_pipeline::bind_tcp;
use wz_runtime_tokio::link_socket::LinkSocket;
use wz_runtime_tokio::retry_period::RetryPolicy;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal, SessionInitParams, SessionLinkActions, SessionTimeouts,
};
use wz_runtime_tokio::session_open::{
    initiate_and_open_session, BoundListener, DialConfig, DialedLink, OpenedSession, SessionOffer,
    DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::driver_loop::IterationEvent;

/// How long the second peer is given to open while the loop is held. Its own InitAck window (2 s)
/// ends an unanswered open before this does; this only keeps a broken run from waiting for ever.
const SECOND_BUDGET: Duration = Duration::from_secs(10);

/// The longest the held admission waits to be let go, so that a run whose test failed before
/// letting it go still ends.
const HOLD_CEILING: Duration = Duration::from_secs(20);

/// Wall-clock ceiling of one run.
const RUN_BUDGET: Duration = Duration::from_secs(40);

/// A forwarder whose first admission holds the loop's task until [`Self::let_go`], and says when
/// it has begun to. It routes nothing.
struct HoldsTheFirstAdmission {
    admissions: AtomicUsize,
    entered: watch::Sender<bool>,
    released: StdMutex<bool>,
    wake: Condvar,
}

impl HoldsTheFirstAdmission {
    fn new(entered: watch::Sender<bool>) -> Self {
        Self {
            admissions: AtomicUsize::new(0),
            entered,
            released: StdMutex::new(false),
            wake: Condvar::new(),
        }
    }

    fn let_go(&self) {
        *self.released.lock().expect("release flag") = true;
        self.wake.notify_all();
    }
}

impl FaceForwarder for HoldsTheFirstAdmission {
    fn register(&self, _id: FaceId, _actions: &Arc<SessionLinkActions>) {}

    fn admit(&self, _id: FaceId, _actions: &Arc<SessionLinkActions>) -> bool {
        if self.admissions.fetch_add(1, Ordering::SeqCst) == 0 {
            let _ = self.entered.send(true);
            let released = self.released.lock().expect("release flag");
            let _held = self
                .wake
                .wait_timeout_while(released, HOLD_CEILING, |released| !*released)
                .expect("release flag");
        }
        true
    }

    fn deregister(&self, _id: FaceId) {}

    fn forward(&self, _id: FaceId, _event: IterationEvent<'_, '_>) {}
}

fn node_params(zid: u8) -> SessionInitParams {
    let mut params = fixture_session_init_params();
    params.zid = vec![zid; 4];
    params
}

fn sources(listener: BoundListener) -> FaceSources {
    FaceSources {
        listeners: vec![listener],
        dial_targets: Vec::new(),
        dial_config: Arc::new(DialConfig::default()),
        dial_intents: None,
        mcast_ingress: None,
        mcast_members: None,
        mcast_group_subs: None,
        reconcile: None,
        #[cfg(feature = "transport-multilink")]
        max_links: 1,
        max_sessions: usize::MAX,
        accept: AcceptBounds::default(),
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

/// A peer that dials `addr` and opens a session as `zid`, or `None` when it does not reach
/// Established.
async fn open_peer(addr: SocketAddr, zid: u8) -> Option<OpenedSession> {
    let stream = TcpStream::connect(addr).await.ok()?;
    initiate_and_open_session(
        DialedLink::Tcp(stream),
        node_params(zid),
        TokioTime::new(),
        None,
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .ok()
}

/// Keep `opened` alive, driven, until `go` flips, then close it.
fn hold(mut opened: OpenedSession, mut go: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let timeouts = SessionTimeouts::spec_defaults();
        tokio::select! {
            _ = go.wait_for(|&flipped| flipped) => {}
            _ = drive_session_until_terminal(
                &mut opened.inbound,
                &opened.actions,
                &mut opened.engine,
                None,
                &opened.clock,
                &timeouts,
                |_event| {},
            ) => {}
        }
        opened.drain_to_close().await;
    })
}

/// An observer that counts the faces brought up and ends the run at the `up_to`th.
fn ends_at(
    up_to: usize,
    up: &Arc<AtomicUsize>,
    go: &watch::Sender<bool>,
) -> impl FnMut(&AcceptEvent) + 'static {
    let (up, go) = (Arc::clone(up), go.clone());
    move |event: &AcceptEvent| {
        if let AcceptEvent::FaceUp(_) = event {
            if up.fetch_add(1, Ordering::SeqCst) + 1 == up_to {
                let _ = go.send(true);
            }
        }
    }
}

/// A node served as `drive` says, whose first admission holds its loop: one peer opens and is held
/// in that admission, a second dials while it is, and the loop is let go once the second's open
/// has ended. Returns whether the second reached Established while the loop was held, and the
/// loop's summary.
async fn second_peer_against_a_held_loop(drive: RoutingFaceDrive) -> (bool, AcceptLoopSummary) {
    let (listener, addr) = bind_loopback().await;
    let (go_tx, go_rx) = watch::channel(false);
    let (entered_tx, mut entered_rx) = watch::channel(false);
    let forwarder = Arc::new(HoldsTheFirstAdmission::new(entered_tx));
    let up = Arc::new(AtomicUsize::new(0));
    let node = peer_loop_shared(
        sources(listener),
        node_params(0xAA),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(go_rx.clone()),
        ends_at(2, &up, &go_tx),
        Arc::clone(&forwarder) as Arc<dyn FaceForwarder + Send + Sync>,
        drive,
    );
    // The node runs on this test's own task and the held admission holds it, so everything that
    // has to happen meanwhile runs on the workers.
    let peers = tokio::spawn(async move {
        let first = open_peer(addr, 0x01)
            .await
            .expect("the first peer reaches Established");
        let first = hold(first, go_rx.clone());
        let _ = entered_rx.wait_for(|&entered| entered).await;
        let second = tokio::time::timeout(SECOND_BUDGET, open_peer(addr, 0x02))
            .await
            .ok()
            .flatten();
        let opened_meanwhile = second.is_some();
        let second = second.map(|opened| hold(opened, go_rx.clone()));
        forwarder.let_go();
        // A second peer that did not open is never brought up, so the observer cannot end the run.
        if !opened_meanwhile {
            let _ = go_tx.send(true);
        }
        let _ = first.await;
        if let Some(second) = second {
            let _ = second.await;
        }
        opened_meanwhile
    });
    let (summary, opened_meanwhile) =
        tokio::time::timeout(RUN_BUDGET, async { tokio::join!(node, peers) })
            .await
            .expect("the run ends within its budget");
    (
        opened_meanwhile.expect("the peers' task ends with a result"),
        summary,
    )
}

/// `task-per-face`: the second peer's handshake is answered by a task of its own while the loop is
/// held inside the first face's admission, and both faces are held once it is let go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_opens_while_the_loop_is_held_inside_the_admission_of_another() {
    let (opened_meanwhile, summary) =
        second_peer_against_a_held_loop(RoutingFaceDrive::TaskPerFace).await;
    assert!(
        opened_meanwhile,
        "the second peer reaches Established while the loop waits in the first face's admission"
    );
    assert_eq!(summary.accepted, 2, "both links were accepted");
    assert_eq!(
        summary.established, 2,
        "both faces are held once the loop is let go"
    );
}

/// `one-task`: the node serves every link from its loop's task, so the same second peer is not
/// answered while that task is held. The pair of the test above.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn under_one_task_a_peer_is_not_answered_while_the_loop_is_held() {
    let (opened_meanwhile, summary) =
        second_peer_against_a_held_loop(RoutingFaceDrive::OneTask).await;
    assert!(
        !opened_meanwhile,
        "the one task that would answer the second peer is the one held"
    );
    assert_eq!(summary.established, 1, "only the first face was held");
}

/// A peer that connects and never sends its InitSyn is mid-handshake for the whole run, and the
/// peers that dial after it open one after the other, each while it still is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_never_sends_its_init_syn_keeps_no_other_peer_from_opening() {
    const OPENING: usize = 3;
    let (listener, addr) = bind_loopback().await;
    let (go_tx, go_rx) = watch::channel(false);
    let (entered_tx, _entered_rx) = watch::channel(false);
    let forwarder = Arc::new(HoldsTheFirstAdmission::new(entered_tx));
    // Nothing here is held: the forwarder is let go before any face reaches it.
    forwarder.let_go();
    let up = Arc::new(AtomicUsize::new(0));
    let node = peer_loop_shared(
        sources(listener),
        node_params(0xAA),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(go_rx.clone()),
        ends_at(OPENING, &up, &go_tx),
        Arc::clone(&forwarder) as Arc<dyn FaceForwarder + Send + Sync>,
        RoutingFaceDrive::TaskPerFace,
    );
    let peers = async move {
        let silent = TcpStream::connect(addr)
            .await
            .expect("the silent peer connects");
        let mut opened = 0;
        let mut held = Vec::new();
        for zid in 1..=OPENING as u8 {
            if let Some(session) = open_peer(addr, zid).await {
                opened += 1;
                held.push(hold(session, go_rx.clone()));
            }
        }
        // A peer that did not open is never brought up, so the observer cannot end the run.
        if opened < OPENING {
            let _ = go_tx.send(true);
        }
        for peer in held {
            let _ = peer.await;
        }
        drop(silent);
        opened
    };
    let (summary, opened) = tokio::time::timeout(RUN_BUDGET, async { tokio::join!(node, peers) })
        .await
        .expect("the run ends within its budget");
    assert_eq!(
        opened, OPENING,
        "every peer that sent its InitSyn reached Established"
    );
    assert_eq!(summary.established, OPENING);
    assert_eq!(
        summary.accepted,
        OPENING + 1,
        "the silent link was accepted too, and its handshake was still in flight at the end"
    );
}
