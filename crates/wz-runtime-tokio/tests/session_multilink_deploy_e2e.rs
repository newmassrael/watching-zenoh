// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
use wz_runtime_tokio::retry_period::RetryPolicy;
use wz_runtime_tokio::runtime_impl::{TokioRuntime, TokioTime};
use wz_runtime_tokio::session_glue::{drive_session_until_terminal, SessionLinkActions};
use wz_runtime_tokio::session_open::{
    initiate_and_open_session_with_multilink, BoundListener, DialedLink, OpenedSession,
    DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::session_open::{SessionOffer, TransportMode};
use wz_runtime_tokio_test_support::fixture_params_with_zid;
use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::qos::Priority;
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
    /// The face ids passed to `register` (the primary of each session).
    registered_ids: Vec<u64>,
    /// R311y219b — the (joined_id, primary_id) pairs the loop passes to
    /// `register_joined` at each aggregation JOIN. An observation-only forwarder
    /// records them (and keeps `forward` observing the PHYSICAL id, so the per-face
    /// segregation witness is unaffected — the joined->primary resolution is the
    /// REAL LinkstateForwarder's concern, tested directly in its lib units).
    joined_calls: Vec<(u64, u64)>,
    /// R311y221 — the delivered band per received Push, read off the new
    /// `FramePayload.priority` field. The app-observability witness: a prioritized
    /// Put must surface at B with its REAL decoded band (not DEFAULT), proving the
    /// unicast Frame producer (`drive.rs`) threads the decoded ext_qos onto the
    /// delivered outcome rather than re-clamping to DEFAULT.
    band_deliveries: Vec<Priority>,
}

/// A production [`FaceForwarder`] whose only job is observation — it keys no
/// routing state on zid (`dedups_faces_by_zid` stays the default `false`, so the
/// loop's multilink JOIN, not the single-link dedup drop, handles a second link).
struct CapturingForwarder {
    state: Arc<StdMutex<CapState>>,
}

impl FaceForwarder for CapturingForwarder {
    fn register(&self, id: FaceId, actions: &Arc<SessionLinkActions>) {
        let mut s = self.state.lock().unwrap();
        // The FIRST link to a peer is the session's primary and the only face
        // registered; capture its shared-core handle once.
        if s.primary.is_none() {
            s.primary = Some(actions.clone());
        }
        s.registered += 1;
        s.registered_ids.push(id.0);
    }

    fn deregister(&self, _id: FaceId) {
        self.state.lock().unwrap().deregistered += 1;
    }

    fn register_joined(&self, joined_id: FaceId, primary_id: FaceId) {
        self.state
            .lock()
            .unwrap()
            .joined_calls
            .push((joined_id.0, primary_id.0));
    }

    fn forward(&self, id: FaceId, event: IterationEvent<'_>) {
        if let IterationEvent::Poll(DriverLoopOutcome::FramePayload {
            reliable,
            sn,
            messages,
            priority,
            ..
        }) = event
        {
            if messages
                .iter()
                .any(|m| matches!(m, NetworkMessage::Push(_)))
            {
                let mut s = self.state.lock().unwrap();
                s.deliveries.push((id.0, *reliable, *sn));
                // R311y221 — record the delivered band alongside the per-face
                // segregation witness (a separate vec, so the committed
                // `deliveries` tuple and its assertions are untouched).
                s.band_deliveries.push(*priority);
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
    qos: bool,
    band: (Priority, Priority),
) -> OpenedSession {
    let stream = TcpStream::connect(addr).await.expect("dial peer");
    initiate_and_open_session_with_multilink(
        DialedLink::Tcp(stream),
        fixture_params_with_zid(init_zid),
        pref,
        // R2096 (open-debt item 516) — the entrypoint takes the whole
        // `SessionOffer` now. This file's axis is still the one boolean, so the
        // adapter lives here rather than as a second representation in the
        // library; `false` is the zero offer, byte-identical on the wire.
        if qos {
            SessionOffer::universal().with_mode(TransportMode::Qos)
        } else {
            SessionOffer::universal()
        },
        band,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .expect("dialed link reaches Established (multilink)")
}

/// The full-priority band (`Control..=Background`) — the inert band the qos=false
/// deploy tests pass (no prioritized send exercises `select_link`'s band tier).
const FULL_BAND: (Priority, Priority) = (Priority::Control, Priority::Background);

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
            listener: BoundListener::Tcp(b_listener),
            dial_targets: vec![],
            dial_intents: None,
            mcast_ingress: None,
            mcast_members: None,
            mcast_group_subs: None,
            reconcile: None,
            offer: SessionOffer::universal(),
            // R311y786 — pin the PRE-y786 cadence (fixed 1 s, no growth) so this
            // suite keeps measuring the aggregation path it was written for rather
            // than the new schedule; the growth has its own witnesses.
            retry: RetryPolicy::constant(1000),
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
        let a1 = dial_multilink(
            b_addr,
            0x0A,
            LinkReliabilityPref::Reliable,
            false,
            FULL_BAND,
        )
        .await;
        let a2 = dial_multilink(
            b_addr,
            0x0A,
            LinkReliabilityPref::BestEffort,
            false,
            FULL_BAND,
        )
        .await;
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
        let a3 = dial_multilink(b_addr, 0x0A, LinkReliabilityPref::Any, false, FULL_BAND).await;
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
        let a4 = dial_multilink(
            b_addr,
            0x0A,
            LinkReliabilityPref::Reliable,
            false,
            FULL_BAND,
        )
        .await;
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
            listener: BoundListener::Tcp(b_listener),
            dial_targets: vec![],
            dial_intents: None,
            mcast_ingress: None,
            mcast_members: None,
            mcast_group_subs: None,
            reconcile: None,
            offer: SessionOffer::universal(),
            // R311y786 — pin the PRE-y786 cadence (fixed 1 s, no growth) so this
            // suite keeps measuring the aggregation path it was written for rather
            // than the new schedule; the growth has its own witnesses.
            retry: RetryPolicy::constant(1000),
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
            listener: BoundListener::Tcp(a_listener),
            dial_targets: vec![b_addr, b_addr],
            dial_intents: None,
            mcast_ingress: None,
            mcast_members: None,
            mcast_group_subs: None,
            reconcile: None,
            offer: SessionOffer::universal(),
            // R311y786 — pin the PRE-y786 cadence (fixed 1 s, no growth) so this
            // suite keeps measuring the aggregation path it was written for rather
            // than the new schedule; the growth has its own witnesses.
            retry: RetryPolicy::constant(1000),
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

/// R311y219 (transport-multilink + transport-qos) — the DEPLOY-active priority-band
/// segregation gate: the PRIORITY twin of the assertion-2 reliability segregation in
/// [`deploy_active_two_links_aggregate_segregate_reject_survive`]. With QoS
/// negotiated on a 2-link aggregate, an EXPRESS (Control-priority) Put and a LOW
/// (Background-priority) Put ride DIFFERENT physical links — proving
/// [`SessionCore::select_link`]'s priority (full) tier is reachable through the
/// production `_with_multilink` open path, not just the y217 recording-driver unit.
///
/// B is a real [`peer_loop`] (`qos = true`, `max_links = 2`); A is a manual generator
/// whose two outbound links are opened UNIFORM-Reliable (a 2-link aggregate can
/// segregate on ONE axis, and QoS makes it priority — reliability is deliberately NOT
/// the discriminant here) with DISTINCT priority bands (link 1 HIGH
/// `[Control..=InteractiveLow]`, link 2 LOW `[DataHigh..=Background]`) applied by the
/// real `initiate_and_open_session_with_multilink` band plumbing. A then sends a
/// Control Put and a Background Put; B's [`CapturingForwarder`] observes them on
/// DISTINCT faces (`assert_eq!(faces.len(), 2)`).
///
/// `is_qos()` is asserted FIRST: a non-negotiated session forces every Frame to
/// `Priority::DEFAULT` (the `dispatch_network_message` clamp), which would route both
/// Puts to one conduit/link and pass the face check for the WRONG reason. Both Puts
/// are RELIABLE, so with uniform-Reliable links the priority band is the SOLE
/// discriminant.
///
/// NAMED BOUND (coverage): this composes the SHARED band-plumbing entrypoint
/// (`initiate_and_open_session_with_multilink` — the same one the loop's dial path
/// uses) + `select_link` over real TCP, proving distinct-priority Puts SEGREGATE
/// onto two distinct physical links. It does NOT prove (a) the specific band->link
/// mapping (the y217 recording-driver unit, `multilink.rs`), nor (b) the production
/// loop's PER-ID auto-assignment (`multilink_priority_range` / `multilink_pref_for`
/// at the dial/accept sites) driving a ROUTING decision — A is a manual generator
/// passing EXPLICIT bands, so those helpers are proven here only by the accept_loop
/// unit tests; the loop-auto-assigned routing observed over the wire needs a
/// prioritized publish path and is deferred to y219b.
#[cfg(feature = "transport-qos")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deploy_active_qos_priority_segregates_across_links() {
    let b_state: Arc<StdMutex<CapState>> = Arc::new(StdMutex::new(CapState::default()));
    let b_fwd = CapturingForwarder {
        state: b_state.clone(),
    };
    let b_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind B");
    let b_addr = b_listener.local_addr().expect("B addr");
    let (b_shut_tx, b_shut_rx) = watch::channel(false);

    // B: a real peer_loop with QoS ON and max_links = 2 (accept-only observer). Its
    // own links get the deploy-assigned uniform-Reliable pref + parity bands too, but
    // B only RECEIVES here, so what B observes is decided entirely by A's select_link.
    let b_loop = peer_loop(
        FaceSources {
            listener: BoundListener::Tcp(b_listener),
            dial_targets: vec![],
            dial_intents: None,
            mcast_ingress: None,
            mcast_members: None,
            mcast_group_subs: None,
            reconcile: None,
            // R2096 (open-debt item 516) — B's QoS offer, which used to be the
            // separate `qos: true` field below. One value now: `FaceSources.qos`
            // is gone because it and `offer.mode` answered the same question,
            // and a pair that can disagree is what let `--max-links` decide
            // whether a capability reached the wire.
            offer: SessionOffer::universal().with_mode(TransportMode::Qos),
            // R311y786 — pin the PRE-y786 cadence (fixed 1 s, no growth) so this
            // suite keeps measuring the aggregation path it was written for rather
            // than the new schedule; the growth has its own witnesses.
            retry: RetryPolicy::constant(1000),
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
        // A dials B TWICE, both UNIFORM-Reliable + qos, with DISTINCT bands (HIGH /
        // LOW). The band comes from the real `_with_multilink` entrypoint — the SAME
        // code path the deploy accept/dial sites drive.
        const HIGH: (Priority, Priority) = (Priority::Control, Priority::InteractiveLow);
        const LOW: (Priority, Priority) = (Priority::DataHigh, Priority::Background);
        let a1 = dial_multilink(b_addr, 0x0A, LinkReliabilityPref::Reliable, true, HIGH).await;
        let a2 = dial_multilink(b_addr, 0x0A, LinkReliabilityPref::Reliable, true, LOW).await;
        let a1_actions = a1.actions.clone();
        let a_joined = match join_link(&a1.actions, &a2.actions, 2) {
            JoinOutcome::Joined(h) => h,
            _ => panic!("A must aggregate its two outbound links"),
        };
        let a_send = a_joined.clone();
        let _a1_task = spawn_drive(a1, a1_actions.clone());
        let _a2_task = spawn_drive(a2, a_joined.clone());

        // B aggregated the two inbound links into ONE session.
        assert!(
            poll_state(&b_state_h, Duration::from_secs(8), |s| s
                .primary
                .as_ref()
                .is_some_and(|a| a.live_link_count() == 2))
            .await,
            "B aggregated 2 inbound links into ONE logical session (live_link_count == 2)"
        );

        // R311y219b WIRING — the aggregation JOIN told the forwarder to map the
        // joined (secondary) link onto the PRIMARY registered face
        // (`register_joined`), so a routing forwarder delivers its inbound instead
        // of dropping it at the faces.get gate. The joined id is NEVER `register`ed
        // (it shares the primary's face); the primary IS. (The forwarder RESOLUTION
        // itself — the delivery — is proven directly in the LinkstateForwarder lib
        // unit `joined_link_inbound_delivers_...`; here we only prove the loop wires
        // the mapping.) Barrier on `joined_calls` ITSELF (not the `live_link_count`
        // barrier above): `register_joined` is written AFTER `join_link` bumps the
        // link count, under a DIFFERENT lock, so gating on the count could observe
        // the pre-`register_joined` window and panic the `.first()` — poll the
        // asserted predicate so the read below is unreachable-empty by construction.
        assert!(
            poll_state(&b_state_h, Duration::from_secs(8), |s| !s
                .joined_calls
                .is_empty())
            .await,
            "the aggregation JOIN wired register_joined(secondary -> primary)"
        );
        {
            let s = b_state_h.lock().unwrap();
            let (joined_id, primary_id) = *s
                .joined_calls
                .first()
                .expect("joined_calls is non-empty (just polled)");
            assert!(
                s.registered_ids.contains(&primary_id),
                "register_joined's primary is the session's REGISTERED face: {:?}",
                s.registered_ids
            );
            assert!(
                !s.registered_ids.contains(&joined_id),
                "the joined (secondary) link is NOT registered as its own face: {:?}",
                s.registered_ids
            );
        }

        // QoS negotiated on the aggregate — asserted BEFORE the sends so the
        // DEFAULT-clamp (which would collapse the priority split) cannot false-green.
        assert!(
            a_send.is_qos(),
            "A negotiated QoS on the aggregate (a non-qos session clamps every Frame to \
             DEFAULT, which would route both Puts to one link)"
        );

        // An EXPRESS (Control) Put and a LOW (Background) Put — BOTH reliable, so with
        // uniform-Reliable links the priority band is the SOLE discriminant.
        // select_link routes Control -> the HIGH-band link, Background -> the LOW-band.
        a_send
            .send_push_literal_qos("test/express", b"E", true, Priority::Control)
            .expect("express (Control) Put routes onto the high-band link");
        a_send
            .send_push_literal_qos("test/low", b"L", true, Priority::Background)
            .expect("low (Background) Put routes onto the low-band link");

        // Both arrive at B, on DISTINCT faces — priority SEGREGATION across the 2
        // physical links (the priority twin of assertion 2's reliability segregation).
        assert!(
            poll_state(&b_state_h, Duration::from_secs(8), |s| s.deliveries.len()
                >= 2)
            .await,
            "both the express and low Puts reached B: {:?}",
            b_state_h.lock().unwrap().deliveries
        );
        let faces: std::collections::BTreeSet<u64> = b_state_h
            .lock()
            .unwrap()
            .deliveries
            .iter()
            .map(|d| d.0)
            .collect();
        assert_eq!(
            faces.len(),
            2,
            "priority SEGREGATION: the express (Control) and low (Background) Puts arrived on \
             DIFFERENT physical faces (both reliable, so priority is the sole discriminant): {:?}",
            b_state_h.lock().unwrap().deliveries
        );

        // R311y221 app-observability — B's delivered `FramePayload.priority` carries
        // each Put's REAL decoded band, NOT DEFAULT. `select_link` (asserted above via
        // the face split) proves the band reached the RIGHT link; this proves the band
        // is also SURFACED to the application on receipt. A DEFAULT-clamp regression in
        // the unicast Frame producer would collapse both bands to `Priority::DEFAULT`
        // here even while the face split (driven by the TX-side pin) still passed —
        // so this is the direct witness that `drive.rs` threads the decoded ext_qos.
        let bands: std::collections::BTreeSet<Priority> = b_state_h
            .lock()
            .unwrap()
            .band_deliveries
            .iter()
            .copied()
            .collect();
        assert!(
            bands.contains(&Priority::Control) && bands.contains(&Priority::Background),
            "app-observability: both delivered bands surface on FramePayload.priority \
             (Control for the express Put, Background for the low Put), not DEFAULT: {bands:?}"
        );

        let _ = b_shut_tx.send(true);
    };

    tokio::time::timeout(Duration::from_secs(40), async {
        let (_summary, _) = tokio::join!(b_loop, harness);
    })
    .await
    .expect("the deploy-active priority-segregation gate completes within 40s");
}
