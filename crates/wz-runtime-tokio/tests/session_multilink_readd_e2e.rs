// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-multilink",
    feature = "routing-peer",
    feature = "transport-link-tcp",
    feature = "codec-push",
    feature = "codec-close",
))]

//! R311y212 (transport-multilink per-link AUTO-RE-ADD) — proves the production
//! `peer_loop` automatically RE-DIALS + RE-JOINS a dropped aggregated link it
//! DIALED, so a flapped link COMES BACK onto the surviving session with no manual
//! intervention. This is slice-2 of S2 (reconnect × multilink); slice-1 (y211)
//! only made the two features safely coexist.
//!
//! Role inversion vs `session_multilink_deploy_e2e`: there node B was the SUT loop
//! and node A a manual death-injector. Here the DIALER (node A) is the SUT loop —
//! it is the side that owns re-dial — and node B is a manual acceptor whose links
//! the harness can kill deterministically (the only deterministic way to make a
//! loop observe a single-link death is a socket close from the peer).
//!
//! `readd_dialed_link_auto_reconnects_onto_surviving_session`:
//!   1. A (`peer_loop`, max_links = 2, dials B twice) aggregates its two OUTBOUND
//!      links into ONE session (`live_link_count() == 2`, one registered face).
//!   2. The harness kills ONE of B's accepted links (aborts its drive → the socket
//!      closes) — A's loop observes the partial loss (`live_link_count() == 1`).
//!   3. WITHOUT any manual re-dial, A's loop AUTO-re-dials + re-JOINs the dropped
//!      link onto the SAME session (`live_link_count()` back to 2, still ONE
//!      registered face — a re-JOIN, not a new session).
//!   4. The re-added link CARRIES traffic: a Put sent by B over the re-added link
//!      is delivered at A.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::watch;

use wz_runtime_tokio::accept_loop::{peer_loop, AcceptEvent, FaceForwarder, FaceId, FaceSources};
use wz_runtime_tokio::config::LinkReliabilityPref;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::{drive_session_until_terminal, SessionLinkActions};
use wz_runtime_tokio::session_open::{
    accept_and_open_session_with_multilink, BoundListener, DialedLink, OpenedSession,
    DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_params_with_zid;
use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 8192;

/// The state a [`CapturingForwarder`] threads out of A's production loop so the
/// test observes the aggregated session without reaching into loop internals: the
/// primary session's actions (its shared `SessionCore` reports `live_link_count()`),
/// the per-face Push deliveries, and the register count (a second registration
/// would mean a second SESSION — a failed re-JOIN).
#[derive(Default)]
struct CapState {
    primary: Option<Arc<SessionLinkActions>>,
    deliveries: Vec<(u64, bool, u64)>,
    registered: usize,
    deregistered: usize,
}

struct CapturingForwarder {
    state: Arc<StdMutex<CapState>>,
}

impl FaceForwarder for CapturingForwarder {
    fn register(&self, _id: FaceId, actions: &Arc<SessionLinkActions>) {
        let mut s = self.state.lock().unwrap();
        if s.primary.is_none() {
            s.primary = Some(actions.clone());
        }
        s.registered += 1;
    }

    fn deregister(&self, _id: FaceId) {
        self.state.lock().unwrap().deregistered += 1;
    }

    fn forward(&self, id: FaceId, event: IterationEvent<'_>) {
        if let IterationEvent::Poll(DriverLoopOutcome::FramePayload {
            reliable,
            sn,
            messages,
            ..
        }) = event
        {
            if messages
                .iter()
                .any(|m| matches!(m, NetworkMessage::Push(_)))
            {
                self.state
                    .lock()
                    .unwrap()
                    .deliveries
                    .push((id.0, *reliable, *sn));
            }
        }
    }
}

/// Resolve `shutdown` when `go` flips true (level-triggered `watch`).
async fn shutdown_on(mut go: watch::Receiver<bool>) {
    let _ = go.wait_for(|&v| v).await;
}

/// Drive one manual link's steady state on a spawned task. Node B discards inbound
/// events — it only accepts, drives, and (for one link) is killed.
fn spawn_drive(
    mut opened: OpenedSession,
    actions: Arc<SessionLinkActions>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let timeouts = SessionTimeouts::spec_defaults();
        let _ = drive_session_until_terminal(
            &mut opened.inbound,
            &actions,
            &mut opened.engine,
            None,
            &opened.clock,
            &timeouts,
            |_e| {},
        )
        .await;
    })
}

/// Poll `pred` against A's captured state until it holds or `budget` elapses.
async fn poll_state(
    state: &Arc<StdMutex<CapState>>,
    budget: Duration,
    pred: impl Fn(&CapState) -> bool,
) -> bool {
    let step = Duration::from_millis(25);
    let mut waited = Duration::ZERO;
    loop {
        if pred(&state.lock().unwrap()) {
            return true;
        }
        if waited >= budget {
            return false;
        }
        tokio::time::sleep(step).await;
        waited += step;
    }
}

/// `live_link_count()` of A's captured primary session, or 0 before it registers.
fn live_links(state: &Arc<StdMutex<CapState>>) -> usize {
    state
        .lock()
        .unwrap()
        .primary
        .as_ref()
        .map_or(0, |a| a.live_link_count())
}

/// B's manual acceptor: a spawned loop that accepts each inbound multilink link,
/// drives it, and retains `(drive task, its actions)` in `b_links` so the harness
/// can kill one. B does NOT aggregate — every accepted link is its own session
/// sharing zid 0x0B + B's process-wide multilink pubkey, which is all A's
/// dial-side aggregation needs. B keeps accepting, so a re-dialed link is accepted
/// and driven identically.
type BLinks = Arc<StdMutex<Vec<(tokio::task::JoinHandle<()>, Arc<SessionLinkActions>)>>>;

/// The core slice-2 gate: A's production loop auto-re-adds a dropped dialed link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn readd_dialed_link_auto_reconnects_onto_surviving_session() {
    let b_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind B");
    let b_addr = b_listener.local_addr().expect("B addr");
    let b_links: BLinks = Arc::new(StdMutex::new(Vec::new()));

    // Node B — manual acceptor loop (accepts, drives, retains kill levers).
    let b_links_acc = b_links.clone();
    let b_accept = tokio::spawn(async move {
        loop {
            let (stream, _peer) = match b_listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let opened = match accept_and_open_session_with_multilink(
                DialedLink::Tcp(stream),
                fixture_params_with_zid(0x0B),
                LinkReliabilityPref::Any,
                false,
                // R311y219 — qos=false, so the band is inert (no priority routing).
                (
                    wz_session_core::qos::Priority::Control,
                    wz_session_core::qos::Priority::Background,
                ),
                TokioTime::new(),
                Some(ITER_CAP),
                DEFAULT_OPEN_TICK_MS,
            )
            .await
            {
                Ok(o) => o,
                Err(_) => continue,
            };
            let actions = opened.actions.clone();
            let task = spawn_drive(opened, actions.clone());
            b_links_acc.lock().unwrap().push((task, actions));
        }
    });

    // Node A — the SYSTEM UNDER TEST: a real peer_loop, max_links = 2, dialing B
    // TWICE (two outbound links to the same peer), aggregating them through the
    // loop's dial path. It is the side that owns per-link re-dial.
    let a_state: Arc<StdMutex<CapState>> = Arc::new(StdMutex::new(CapState::default()));
    let a_fwd = CapturingForwarder {
        state: a_state.clone(),
    };
    let a_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind A");
    let (a_shut_tx, a_shut_rx) = watch::channel(false);
    let a_loop = peer_loop(
        FaceSources {
            listener: BoundListener::Tcp(a_listener),
            dial_targets: vec![b_addr, b_addr],
            dial_intents: None,
            mcast_ingress: None,
            mcast_members: None,
            mcast_group_subs: None,
            reconcile: None,
            max_links: 2,
            qos: false,
        },
        fixture_params_with_zid(0x0A),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(a_shut_rx.clone()),
        |_e: &AcceptEvent| {},
        &a_fwd,
    );

    let a_state_h = a_state.clone();
    let b_links_h = b_links.clone();
    let harness = async move {
        // 1. A aggregated its two dialed links into ONE session.
        assert!(
            poll_state(&a_state_h, Duration::from_secs(12), |s| s
                .primary
                .as_ref()
                .is_some_and(|a| a.live_link_count() == 2))
            .await,
            "A aggregated its two dialed links through the loop (live_link_count == 2)"
        );
        assert_eq!(
            a_state_h.lock().unwrap().registered,
            1,
            "A registered exactly ONE session (the second link joined, not a new session)"
        );
        // B must have accepted both before we kill one.
        for _ in 0..200 {
            if b_links_h.lock().unwrap().len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            b_links_h.lock().unwrap().len() >= 2,
            "B accepted both of A's dialed links"
        );

        // 2. Kill ONE of B's accepted links: aborting its drive drops the owned
        //    stream, closing the socket, so A's loop's outbound link for it returns
        //    Terminated -> Step::Driven -> the partial-loss re-dial trigger.
        {
            let mut v = b_links_h.lock().unwrap();
            let (task, actions) = v.remove(1);
            task.abort();
            drop(actions);
        }
        assert!(
            poll_state(&a_state_h, Duration::from_secs(10), |s| s
                .primary
                .as_ref()
                .is_some_and(|a| a.live_link_count() == 1))
            .await,
            "A's loop observed the partial link loss (live_link_count drops to 1)"
        );

        // 3. THE SLICE-2 PROOF: without any manual re-dial, A's loop auto-re-dials
        //    (1s backoff) + re-JOINs the dropped link onto the SAME session.
        assert!(
            poll_state(&a_state_h, Duration::from_secs(12), |s| s
                .primary
                .as_ref()
                .is_some_and(|a| a.live_link_count() == 2))
            .await,
            "A's loop AUTO-re-dialed + re-JOINed the dropped link (live_link_count back to 2)"
        );
        assert_eq!(
            a_state_h.lock().unwrap().registered,
            1,
            "the auto-re-add joined the SAME session — no new registration (re-JOIN, not a new session)"
        );
        assert_eq!(
            live_links(&a_state_h),
            2,
            "the aggregate is back to full strength on the surviving + re-added link"
        );

        // 4. The re-added link CARRIES traffic: B sends a Put over its newest
        //    accepted link (the one A re-dialed); A delivers it. Wait for B's accept
        //    task to have PUSHED the re-dialed link (len back to 2 after the kill's
        //    `remove(1)`) so `last()` is deterministically the re-add, not a race with
        //    the surviving link (A's live==2 can fire fractionally before B's push).
        for _ in 0..200 {
            if b_links_h.lock().unwrap().len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let pre = a_state_h.lock().unwrap().deliveries.len();
        {
            let v = b_links_h.lock().unwrap();
            assert!(
                v.len() >= 2,
                "B accepted the re-dialed link (last() is the re-add)"
            );
            let (_task, actions) = v.last().expect("B holds the re-added link");
            actions
                .send_push_literal("test/readd", b"back", true)
                .expect("B sends a Put over the re-added link");
        }
        assert!(
            poll_state(&a_state_h, Duration::from_secs(8), |s| s.deliveries.len()
                > pre)
            .await,
            "the re-added link carries traffic: B's Put is delivered at A"
        );

        let _ = a_shut_tx.send(true);
        b_accept.abort();
    };

    tokio::time::timeout(Duration::from_secs(40), async {
        let (_summary, _) = tokio::join!(a_loop, harness);
    })
    .await
    .expect("the multilink per-link auto-re-add gate completes within 40s");
}
