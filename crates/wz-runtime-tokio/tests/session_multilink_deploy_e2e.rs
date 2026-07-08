// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-multilink",
    feature = "routing-peer",
    feature = "transport-link-tcp",
    feature = "codec-push",
    feature = "codec-close",
))]

//! R311y205 (transport-multilink DEPLOY-ACTIVE gate) — proves the aggregation
//! mechanism is wired into the PRODUCTION accept/dial path, not just callable in
//! isolation. Distinct from `session_multilink_e2e` (which drives
//! `multilink::join_link` directly): here node B is a real
//! [`peer_loop`](wz_runtime_tokio::accept_loop::peer_loop) configured with
//! `max_links = 2`, and it aggregates two inbound links into ONE logical session
//! entirely THROUGH its own `Step::Opened` / `Step::Driven` handlers — the test
//! never calls `join_link` on B's sessions.
//!
//! `deploy_active_two_links_aggregate_segregate_reject_survive` is the four-part
//! gate on B (the production loop is the system under test; node A is a manual
//! traffic generator + link-death injector):
//!   1. B aggregates A's two links into ONE session (`live_link_count() == 2`).
//!   2. A reliable Put and a best-effort Put both arrive at B on DIFFERENT
//!      physical faces (reliability segregation across the 2 links).
//!   3. A third inbound link over `max_links` is rejected MAX_LINKS — B stays at
//!      2 links and never registers a second session.
//!   4. Killing one link leaves B's session alive on the other (failover): B's
//!      `live_link_count()` drops to 1 and a subsequent reliable Put still
//!      arrives, on the surviving face, with a CONTINUOUS RX SN (shared core).
//!
//! `deploy_active_dial_side_aggregates_through_the_loop` covers the DIAL half of
//! the wiring: a `max_links = 2` peer that DIALS another twice aggregates its two
//! OUTBOUND links through the loop's `dial_face_multilink` path, and the accept
//! side aggregates them too — both reach `live_link_count() == 2`.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use wz_runtime_core::Runtime;
use wz_runtime_tokio::accept_loop::{peer_loop, AcceptEvent, FaceForwarder, FaceId, FaceSources};
use wz_runtime_tokio::config::LinkReliabilityPref;
use wz_runtime_tokio::multilink::{join_link, JoinOutcome};
use wz_runtime_tokio::runtime_impl::{TokioRuntime, TokioTime};
use wz_runtime_tokio::session_glue::{drive_session_until_terminal, SessionLinkActions};
use wz_runtime_tokio::session_open::{
    initiate_and_open_session_with_multilink, DialedLink, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_params_with_zid;
use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 8192;

/// The state a [`CapturingForwarder`] threads out of a production loop so the
/// test can observe the aggregated session WITHOUT reaching into the loop's
/// internals: the primary session's actions handle (captured at `register`, its
/// shared `SessionCore` reports `live_link_count()`), the per-face Push
/// deliveries (which link carried each Put), and the register/deregister counts
/// (a second registration would mean a second SESSION, i.e. a failed aggregation).
#[derive(Default)]
struct CapState {
    primary: Option<Arc<SessionLinkActions>>,
    deliveries: Vec<(u64, bool, u64)>,
    registered: usize,
    deregistered: usize,
}

/// A production [`FaceForwarder`] whose only job is observation — it keys no
/// routing state on zid (`dedups_faces_by_zid` stays the default `false`, so the
/// loop's multilink JOIN, not the single-link dedup drop, handles a second link).
struct CapturingForwarder {
    state: Arc<StdMutex<CapState>>,
}

impl FaceForwarder for CapturingForwarder {
    fn register(&self, _id: FaceId, actions: &Arc<SessionLinkActions>) {
        let mut s = self.state.lock().unwrap();
        // The FIRST link to a peer is the session's primary and the only face
        // registered; capture its shared-core handle once.
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

/// Dial one OUTBOUND multilink link to `addr` (initiator side, 0x4-negotiating)
/// and bring it to Established with the given traffic-class preference.
async fn dial_multilink(
    addr: std::net::SocketAddr,
    init_zid: u8,
    pref: LinkReliabilityPref,
) -> OpenedSession {
    let stream = TcpStream::connect(addr).await.expect("dial peer");
    initiate_and_open_session_with_multilink(
        DialedLink::Tcp(stream),
        fixture_params_with_zid(init_zid),
        pref,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .expect("dialed link reaches Established (multilink)")
}

/// Drive one manual link's steady state on a spawned task, admitting RX against
/// `actions` (the joined handle for a transplanted secondary, its own for the
/// primary). Node A discards inbound events — it only sends.
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

/// Poll `pred` against the captured state until it holds or `budget` elapses.
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

/// `live_link_count()` of the captured primary session, or 0 before it registers.
fn live_links(state: &Arc<StdMutex<CapState>>) -> usize {
    state
        .lock()
        .unwrap()
        .primary
        .as_ref()
        .map_or(0, |a| a.live_link_count())
}

/// The four-part deploy-active gate on B (production `peer_loop`, `max_links=2`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deploy_active_two_links_aggregate_segregate_reject_survive() {
    let b_state: Arc<StdMutex<CapState>> = Arc::new(StdMutex::new(CapState::default()));
    let b_fwd = CapturingForwarder {
        state: b_state.clone(),
    };
    let b_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind B");
    let b_addr = b_listener.local_addr().expect("B addr");
    let (b_shut_tx, b_shut_rx) = watch::channel(false);

    // Node B: the system under test — a real peer_loop with max_links = 2 and no
    // dials (accept-only). It aggregates inbound links through its own handlers.
    let b_loop = peer_loop(
        FaceSources {
            listener: b_listener,
            dial_targets: vec![],
            dial_intents: None,
            mcast_ingress: None,
            mcast_members: None,
            mcast_group_subs: None,
            reconcile: None,
            max_links: 2,
        },
        fixture_params_with_zid(0x0B),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(b_shut_rx.clone()),
        |_e: &AcceptEvent| {},
        &b_fwd,
    );

    let b_state_h = b_state.clone();
    let harness = async move {
        // Node A (manual traffic generator): dial B twice with distinct traffic-
        // class prefs, aggregate the two OUTBOUND links, and retain a send handle.
        let a1 = dial_multilink(b_addr, 0x0A, LinkReliabilityPref::Reliable).await;
        let a2 = dial_multilink(b_addr, 0x0A, LinkReliabilityPref::BestEffort).await;
        let a1_actions = a1.actions.clone();
        let a_joined = match join_link(&a1.actions, &a2.actions, 2) {
            JoinOutcome::Joined(h) => h,
            _ => panic!("A must aggregate its two outbound links"),
        };
        let a_send = a_joined.clone();
        let a1_task = spawn_drive(a1, a1_actions.clone());
        let a2_task = spawn_drive(a2, a_joined.clone());

        // Assertion 1 — B aggregated the two inbound links into ONE session.
        assert!(
            poll_state(&b_state_h, Duration::from_secs(8), |s| s
                .primary
                .as_ref()
                .is_some_and(|a| a.live_link_count() == 2))
            .await,
            "B aggregated 2 inbound links into ONE logical session (live_link_count == 2)"
        );
        assert_eq!(
            b_state_h.lock().unwrap().registered,
            1,
            "B registered exactly ONE forwarder face (the second link joined, not a new session)"
        );

        // Assertion 2 — a reliable Put and a best-effort Put ride DIFFERENT links.
        // A's send routes reliable -> the Reliable-pref link, best-effort -> the
        // BestEffort-pref link (segregation); B observes them on distinct faces.
        a_send
            .send_push_literal("test/reliable", b"R1", true)
            .expect("reliable Put routes onto the reliable-pref link");
        a_send
            .send_push_literal("test/besteffort", b"B1", false)
            .expect("best-effort Put routes onto the best-effort-pref link");
        assert!(
            poll_state(&b_state_h, Duration::from_secs(8), |s| {
                s.deliveries.iter().any(|d| d.1) && s.deliveries.iter().any(|d| !d.1)
            })
            .await,
            "both a reliable AND a best-effort Put reached B: {:?}",
            b_state_h.lock().unwrap().deliveries
        );
        let (reliable_face, reliable_sn_1, best_effort_face) = {
            let s = b_state_h.lock().unwrap();
            let r = s.deliveries.iter().find(|d| d.1).unwrap();
            let b = s.deliveries.iter().find(|d| !d.1).unwrap();
            (r.0, r.2, b.0)
        };
        assert_ne!(
            reliable_face, best_effort_face,
            "reliability SEGREGATION: the reliable and best-effort Puts arrived on DIFFERENT faces"
        );

        // Assertion 3 — a THIRD inbound link over max_links is rejected MAX_LINKS.
        // B must never aggregate it (stays at 2 live links) nor register a second
        // session. Drive it so B can accept + reject it; B closes it MAX_LINKS.
        let a3 = dial_multilink(b_addr, 0x0A, LinkReliabilityPref::Any).await;
        let a3_actions = a3.actions.clone();
        let a3_task = spawn_drive(a3, a3_actions);
        // Give B time to accept + reject the third link, then confirm it never
        // became a third live link nor a second session.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(
            live_links(&b_state_h),
            2,
            "the third link over max_links was rejected MAX_LINKS (B stays at 2 live links)"
        );
        assert_eq!(
            b_state_h.lock().unwrap().registered,
            1,
            "the rejected third link registered no new session"
        );
        a3_task.abort();

        // Assertion 4 — kill link 1 (the reliable-pref link). Aborting its drive +
        // dropping A's references to its LinkState closes the socket, so B's loop
        // sees the link die and del_links it (failover): B survives on link 2.
        a1_task.abort();
        TokioRuntime::with_mutex_mut(&a1_actions.link.transport_available, |g| *g = false);
        a1_actions.del_link(&a1_actions.link);
        drop(a1_actions);
        assert!(
            poll_state(&b_state_h, Duration::from_secs(8), |s| s
                .primary
                .as_ref()
                .is_some_and(|a| a.live_link_count() == 1))
            .await,
            "B's session SURVIVES the link death on its other link (live_link_count == 1)"
        );

        // A subsequent reliable Put fails over onto the surviving (best-effort-pref)
        // link and still reaches B, on the OTHER face, with a CONTINUOUS RX SN
        // (shared SN generator + shared per-channel rx-SN gate, not a per-link reset).
        a_send
            .send_push_literal("test/reliable", b"R2", true)
            .expect("post-death reliable Put fails over to the surviving link");
        assert!(
            poll_state(&b_state_h, Duration::from_secs(8), |s| s
                .deliveries
                .iter()
                .filter(|d| d.1)
                .count()
                >= 2)
            .await,
            "the post-death reliable Put still delivered at B: {:?}",
            b_state_h.lock().unwrap().deliveries
        );
        let (reliable_sn_2, reliable_face_2) = {
            let s = b_state_h.lock().unwrap();
            let d = s.deliveries.iter().filter(|d| d.1).nth(1).unwrap();
            (d.2, d.0)
        };
        assert!(
            reliable_sn_2 > reliable_sn_1,
            "RX reliable SN is CONTINUOUS across the failover (sn2={reliable_sn_2} > sn1={reliable_sn_1})"
        );
        assert_ne!(
            reliable_face_2, reliable_face,
            "the failed-over reliable Put arrived on the surviving (other) face"
        );

        // Assertion 5 — a FRESH link re-joins the session AFTER a link died (a
        // flapped link rejoining): the aggregation registry survived the death, so
        // the new link aggregates onto the same shared core (live_link_count back
        // to 2). This exercises the join-after-link-death path — whichever face was
        // the primary, the session is resolved from its STABLE core handle, never a
        // per-link entry that teardown removed.
        let a4 = dial_multilink(b_addr, 0x0A, LinkReliabilityPref::Reliable).await;
        let a4_actions = a4.actions.clone();
        let a4_task = spawn_drive(a4, a4_actions);
        assert!(
            poll_state(&b_state_h, Duration::from_secs(8), |s| s
                .primary
                .as_ref()
                .is_some_and(|a| a.live_link_count() == 2))
            .await,
            "a fresh link re-joins the session after the earlier link death (live_link_count == 2)"
        );

        a4_task.abort();
        a2_task.abort();
        let _ = b_shut_tx.send(true);
    };

    tokio::time::timeout(Duration::from_secs(40), async {
        let (_summary, _) = tokio::join!(b_loop, harness);
    })
    .await
    .expect("the deploy-active multilink gate completes within 40s");
}

/// The DIAL-side wiring: a `max_links = 2` peer that dials another twice
/// aggregates its two OUTBOUND links through the loop (the `dial_face_multilink`
/// path), and the accept side aggregates them too — both reach 2 live links,
/// entirely through the production `peer_loop`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deploy_active_dial_side_aggregates_through_the_loop() {
    // Accept side (B): a max_links = 2 acceptor.
    let b_state: Arc<StdMutex<CapState>> = Arc::new(StdMutex::new(CapState::default()));
    let b_fwd = CapturingForwarder {
        state: b_state.clone(),
    };
    let b_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind B");
    let b_addr = b_listener.local_addr().expect("B addr");
    let (b_shut_tx, b_shut_rx) = watch::channel(false);
    let b_loop = peer_loop(
        FaceSources {
            listener: b_listener,
            dial_targets: vec![],
            dial_intents: None,
            mcast_ingress: None,
            mcast_members: None,
            mcast_group_subs: None,
            reconcile: None,
            max_links: 2,
        },
        fixture_params_with_zid(0x0B),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(b_shut_rx.clone()),
        |_e: &AcceptEvent| {},
        &b_fwd,
    );

    // Dial side (A): a max_links = 2 peer that dials B TWICE (two outbound links
    // to the same peer), aggregating them through the loop's dial path.
    let a_state: Arc<StdMutex<CapState>> = Arc::new(StdMutex::new(CapState::default()));
    let a_fwd = CapturingForwarder {
        state: a_state.clone(),
    };
    let a_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind A");
    let (a_shut_tx, a_shut_rx) = watch::channel(false);
    let a_loop = peer_loop(
        FaceSources {
            listener: a_listener,
            dial_targets: vec![b_addr, b_addr],
            dial_intents: None,
            mcast_ingress: None,
            mcast_members: None,
            mcast_group_subs: None,
            reconcile: None,
            max_links: 2,
        },
        fixture_params_with_zid(0x0A),
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_on(a_shut_rx.clone()),
        |_e: &AcceptEvent| {},
        &a_fwd,
    );

    let a_state_h = a_state.clone();
    let b_state_h = b_state.clone();
    let harness = async move {
        let a_ok = poll_state(&a_state_h, Duration::from_secs(10), |s| {
            s.primary.as_ref().is_some_and(|a| a.live_link_count() == 2)
        })
        .await;
        let b_ok = poll_state(&b_state_h, Duration::from_secs(10), |s| {
            s.primary.as_ref().is_some_and(|a| a.live_link_count() == 2)
        })
        .await;
        assert!(
            a_ok,
            "the DIAL side aggregated its two outbound links through the loop (live_link_count == 2)"
        );
        assert!(
            b_ok,
            "the ACCEPT side aggregated the two inbound links through the loop (live_link_count == 2)"
        );
        let _ = a_shut_tx.send(true);
        let _ = b_shut_tx.send(true);
    };

    tokio::time::timeout(Duration::from_secs(40), async {
        let (_a, _b, _) = tokio::join!(a_loop, b_loop, harness);
    })
    .await
    .expect("the dial-side aggregation gate completes within 40s");
}
