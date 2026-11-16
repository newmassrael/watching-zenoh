// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
//!   1. A (`peer_loop`, max_links = 2, dials B at its two endpoints) aggregates its two OUTBOUND
//!      links into ONE session (`live_link_count() == 2`, one registered face).
//!   2. The harness kills ONE of B's accepted links (aborts its drive → the socket
//!      closes) — A's loop observes the partial loss (`live_link_count() == 1`).
//!   3. WITHOUT any manual re-dial, A's loop AUTO-re-dials + re-JOINs the dropped
//!      link onto the SAME session (`live_link_count()` back to 2, still ONE
//!      registered face — a re-JOIN, not a new session).
//!   4. The re-added link CARRIES traffic: a Put sent by B over the re-added link
//!      is delivered at A.
//!
//! `a_readded_link_lost_again_waits_the_initial_period`: a re-add that opened
//! ends its address's outage, so the same link lost again is re-added after the
//! initial wait and not after the wait the first outage grew to.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::sync::watch;

use wz_runtime_tokio::accept_loop::{peer_loop, AcceptEvent, FaceForwarder, FaceId, FaceSources};
use wz_runtime_tokio::retry_period::RetryPolicy;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_glue::{drive_session_until_terminal, SessionLinkActions};
use wz_runtime_tokio::session_open::SessionOffer;
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

    fn forward(&self, id: FaceId, event: IterationEvent<'_, '_>) {
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

/// Run B's manual acceptor on `listener`, retaining each accepted link in `b_links`.
fn spawn_b_acceptor(listener: TcpListener, b_links: BLinks) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let opened = match accept_and_open_session_with_multilink(
                DialedLink::Tcp(stream),
                fixture_params_with_zid(0x0B),
                // R2096 (open-debt item 516) — the whole offer, where this took
                // a bare `qos: bool`. The zero offer is what `false` meant, and
                // it is what this suite wants: it measures the re-ADD, not a
                // capability, so the handshake stays byte-identical to the era
                // before the offer reached this entrypoint.
                SessionOffer::universal(),
                // R311y219 — no QoS offer, so the band is inert (no priority routing).
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
            b_links.lock().unwrap().push((task, actions));
        }
    })
}

/// Node A's sources: listening on `a_listener`, `max_links = 2`, dialing B once
/// at each of its two endpoints, with its re-dials paced by `retry`.
fn a_dials_b_twice(
    a_listener: TcpListener,
    b_addr: SocketAddr,
    b_addr_2: SocketAddr,
    retry: RetryPolicy,
) -> FaceSources {
    FaceSources {
        listeners: vec![BoundListener::Tcp(a_listener)],
        // R2233 (open-debt item 585) — LOCATORS, built through the locator
        // SSOT so the fixture reads the grammar a configured `--connect` does.
        dial_targets: vec![
            wz_session_core::locator::parse_any_locator(&format!("tcp/{b_addr}"))
                .expect("tcp/<addr> locator"),
            wz_session_core::locator::parse_any_locator(&format!("tcp/{b_addr_2}"))
                .expect("tcp/<addr> locator"),
        ],
        // Plain tcp dials — no client trust material.
        dial_config: Arc::new(wz_runtime_tokio::session_open::DialConfig::default()),
        dial_intents: None,
        mcast_ingress: None,
        mcast_members: None,
        mcast_group_subs: None,
        reconcile: None,
        offer: SessionOffer::universal(),
        retry,
        stats: None,
        max_links: 2,
        // R2758 — unbounded: this suite's subject is per-link re-add.
        max_sessions: usize::MAX,
        accept: wz_runtime_tokio::accept_loop::AcceptBounds::default(),
        ceiling: None,
        peer_board: None,
    }
}

/// The core slice-2 gate: A's production loop auto-re-adds a dropped dialed link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn readd_dialed_link_auto_reconnects_onto_surviving_session() {
    // Two listeners, so A has two endpoints that reach one node: a configured
    // endpoint is named by its address, and one address listed twice is one
    // endpoint (decision D5), as upstream's links to a peer are made over its
    // several endpoints.
    let b_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind B");
    let b_addr = b_listener.local_addr().expect("B addr");
    let b_listener_2 = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind B again");
    let b_addr_2 = b_listener_2.local_addr().expect("B's second addr");
    let b_links: BLinks = Arc::new(StdMutex::new(Vec::new()));

    // Node B — a manual acceptor loop on each listener (accepts, drives, retains
    // kill levers).
    let b_accept = spawn_b_acceptor(b_listener, b_links.clone());
    let b_accept_2 = spawn_b_acceptor(b_listener_2, b_links.clone());

    // Node A — the SYSTEM UNDER TEST: a real peer_loop, max_links = 2, dialing B
    // TWICE, once at each of its endpoints (two outbound links to the same peer),
    // aggregating them through the loop's dial path. It is the side that owns
    // per-link re-dial.
    let a_state: Arc<StdMutex<CapState>> = Arc::new(StdMutex::new(CapState::default()));
    let a_fwd = CapturingForwarder {
        state: a_state.clone(),
    };
    let a_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind A");
    let (a_shut_tx, a_shut_rx) = watch::channel(false);
    let a_loop = peer_loop(
        // R311y786 — pin the PRE-y786 cadence (fixed 1 s, no growth): this test
        // asserts the re-add lands, and its comment relies on "the 1s backoff
        // means the del_link always lands first". The growth has its own witnesses.
        a_dials_b_twice(a_listener, b_addr, b_addr_2, RetryPolicy::constant(1000)),
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
        b_accept_2.abort();
    };

    tokio::time::timeout(Duration::from_secs(40), async {
        let (_summary, _) = tokio::join!(a_loop, harness);
    })
    .await
    .expect("the multilink per-link auto-re-add gate completes within 40s");
}

/// Poll `pred` until it holds or `budget` elapses.
async fn wait_until(budget: Duration, pred: impl Fn() -> bool) -> bool {
    let step = Duration::from_millis(10);
    let mut waited = Duration::ZERO;
    loop {
        if pred() {
            return true;
        }
        if waited >= budget {
            return false;
        }
        tokio::time::sleep(step).await;
        waited += step;
    }
}

/// Kill B's newest link, the one A dialed last, and time A's re-add of it:
/// from the kill to the join (the `joined_before`-th entry of `joins`, counted
/// from 0) that brings the session back to two links.
async fn kill_newest_and_time_readd(
    b_links: &BLinks,
    joins: &StdMutex<Vec<Instant>>,
    joined_before: usize,
) -> Duration {
    let killed_at = {
        let mut v = b_links.lock().unwrap();
        let (task, actions) = v.pop().expect("B holds a link to kill");
        task.abort();
        drop(actions);
        Instant::now()
    };
    assert!(
        wait_until(Duration::from_secs(12), || joins.lock().unwrap().len()
            > joined_before)
        .await,
        "A re-added the killed link onto its session"
    );
    let joined_at = joins.lock().unwrap()[joined_before];
    joined_at.duration_since(killed_at)
}

/// The re-add's wait before its re-dial, and its growth after each one: wide
/// enough apart that the second re-add of an address that kept its grown wait
/// (`INIT_MS * FACTOR`) is told from one that started again (`INIT_MS`) by
/// seconds, not by scheduler noise.
const INIT_MS: u64 = 600;
const FACTOR: u64 = 8;

/// A re-added link that SUCCEEDED ends its address's outage: when the same
/// link is lost again, its re-add waits the initial period, not the period the
/// previous outage grew to. zenoh's `period` is a local of the connector that
/// dies with the successful connect; the loop forgets the address's schedule
/// when a dial to it opens.
///
/// Both losses kill the link to the SAME address (the re-added one is B's
/// newest), so the second re-add reads the schedule the first one grew. The
/// two re-adds are timed from the kill to the join, and the second may not
/// exceed the first by half the growth: with the schedule forgotten the two
/// are equal, kept they differ by `INIT_MS * (FACTOR - 1)`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_readded_link_lost_again_waits_the_initial_period() {
    let b_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind B");
    let b_addr = b_listener.local_addr().expect("B addr");
    let b_listener_2 = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind B again");
    let b_addr_2 = b_listener_2.local_addr().expect("B's second addr");
    let b_links: BLinks = Arc::new(StdMutex::new(Vec::new()));
    let b_accept = spawn_b_acceptor(b_listener, b_links.clone());
    let b_accept_2 = spawn_b_acceptor(b_listener_2, b_links.clone());

    let a_state: Arc<StdMutex<CapState>> = Arc::new(StdMutex::new(CapState::default()));
    let a_fwd = CapturingForwarder {
        state: a_state.clone(),
    };
    // The instant of each join A reports: the first is the initial aggregation,
    // each later one a re-add.
    let joins: Arc<StdMutex<Vec<Instant>>> = Arc::new(StdMutex::new(Vec::new()));
    let joins_sink = joins.clone();
    let a_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind A");
    let (a_shut_tx, a_shut_rx) = watch::channel(false);
    let a_loop = peer_loop(
        a_dials_b_twice(
            a_listener,
            b_addr,
            b_addr_2,
            RetryPolicy {
                period_init_ms: INIT_MS,
                period_max_ms: 0,
                period_increase_factor: FACTOR as f64,
            },
        ),
        fixture_params_with_zid(0x0A),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(a_shut_rx.clone()),
        move |e: &AcceptEvent| {
            if let AcceptEvent::LinkAggregated { live_links: 2, .. } = e {
                joins_sink.lock().unwrap().push(Instant::now());
            }
        },
        &a_fwd,
    );

    let harness = async move {
        assert!(
            wait_until(Duration::from_secs(12), || !joins
                .lock()
                .unwrap()
                .is_empty())
            .await,
            "A aggregated its two dialed links into one session"
        );
        assert!(
            wait_until(Duration::from_secs(6), || b_links.lock().unwrap().len()
                >= 2)
            .await,
            "B accepted both of A's dialed links"
        );

        let first = kill_newest_and_time_readd(&b_links, &joins, 1).await;
        assert!(
            first >= Duration::from_millis(INIT_MS),
            "the first re-add waits the initial period; it took {first:?}"
        );
        assert!(
            wait_until(Duration::from_secs(6), || b_links.lock().unwrap().len()
                >= 2)
            .await,
            "B accepted A's re-added link"
        );
        assert_eq!(
            a_state.lock().unwrap().registered,
            1,
            "the re-add joined the same session"
        );

        let second = kill_newest_and_time_readd(&b_links, &joins, 2).await;
        let half_growth = Duration::from_millis(INIT_MS * (FACTOR - 1) / 2);
        assert!(
            second < first + half_growth,
            "the second loss of the same link must wait the initial period again \
             (first re-add {first:?}, second {second:?}); a second re-add that \
             waited the grown period ({} ms) kept the outage the successful \
             re-add ended",
            INIT_MS * FACTOR
        );

        let _ = a_shut_tx.send(true);
        b_accept.abort();
        b_accept_2.abort();
    };

    tokio::time::timeout(Duration::from_secs(40), async {
        let (_summary, _) = tokio::join!(a_loop, harness);
    })
    .await
    .expect("the re-add schedule test completes within 40s");
}
