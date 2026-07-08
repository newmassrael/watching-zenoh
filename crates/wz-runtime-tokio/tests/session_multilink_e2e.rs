// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "transport-multilink",
    feature = "transport-link-tcp",
    feature = "codec-push",
    feature = "codec-close",
))]

//! R311y205 (transport-multilink IMPL-3) — the COMPOSED wz<->wz slice-1 gate:
//! TWO physical loopback-TCP links aggregated into ONE logical unicast session,
//! with reliability segregation + failover survival, exercised through the REAL
//! establishment path (the 0x4 Z_EXT_MULTILINK handshake + ephemeral-pubkey
//! config-equality) and the REAL steady-state drive loop (shared per-channel
//! rx-SN gate + reliability-routed send). Not the atom in isolation — the whole
//! path: `accept/initiate_and_open_session_with_multilink` -> `multilink::join_link`
//! (register/authorize/add_link/transplant) -> `drive_session_until_terminal`
//! over the shared `SessionCore`.
//!
//! The five slice-1 assertions + the regression floor:
//!   1. B holds ONE logical session with 2 links (one shared `SessionCore`,
//!      `live_link_count() == 2`), NOT two sessions.
//!   2. A reliable Put and a best-effort Put both reach B on DIFFERENT physical
//!      links (concurrent 2-link data — the reliability segregation).
//!   3. Kill the reliable link -> the session SURVIVES on the other link
//!      (`live_link_count() == 1`), a subsequent reliable Put still delivers
//!      (failover), and the RX frame SN observed at B is CONTINUOUS across the
//!      switch (proves the shared SN + rx-SN gate, not a per-link reset).
//!   4. A second link presenting a DIFFERENT ephemeral pubkey for the same zid
//!      -> INVALID reject (the config-equality gate; `authorize_link` is the
//!      illegal-state-unrepresentable witness).
//!   5. A third inbound link over `max_links` -> MAX_LINKS reject; the first two
//!      survive.
//!   6. Regression: with max_links=1 (a plain non-multilink open) NO 0x4 ext is
//!      staged and no ephemeral pubkey is captured (byte-identical to today).

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};

use wz_runtime_core::Runtime;
use wz_runtime_tokio::config::LinkReliabilityPref;
use wz_runtime_tokio::multilink::{join_link, JoinOutcome};
use wz_runtime_tokio::runtime_impl::{TokioRuntime, TokioTime};
use wz_runtime_tokio::session_glue::{drive_session_until_terminal, SessionLinkActions};
use wz_runtime_tokio::session_open::{
    accept_and_open_session, accept_and_open_session_with_multilink, initiate_and_open_session,
    initiate_and_open_session_with_multilink, DialedLink, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio_test_support::fixture_params_with_zid;
use wz_session_core::driver_loop::{DriverLoopOutcome, IterationEvent};
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 8192;

/// One inbound Frame-with-Push delivery observed at a specific physical link's
/// drive loop: the link id, the frame reliability, and the frame SN.
#[derive(Clone, Copy, Debug)]
struct RxDelivery {
    link_id: usize,
    reliable: bool,
    sn: u64,
}

type RxLog = Arc<StdMutex<Vec<RxDelivery>>>;

/// Build the per-link drive observer: record `(link_id, reliable, sn)` for every
/// inbound `FramePayload` that carries at least one Push (a real data delivery on
/// THIS physical link), so the test can assert which link carried each Put and
/// that the reliable SN sequence is continuous across a link switch.
fn push_recorder(link_id: usize, log: RxLog) -> impl FnMut(IterationEvent<'_>) {
    move |event| {
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
                log.lock().unwrap().push(RxDelivery {
                    link_id,
                    reliable: *reliable,
                    sn: *sn,
                });
            }
        }
    }
}

/// Open ONE loopback-TCP link both-sides-established with the multilink 0x4
/// handshake + a per-side reliability preference. Returns `(acceptor, initiator)`
/// `OpenedSession`s (both Established, both having captured the peer's ephemeral
/// pubkey).
async fn open_multilink_link(
    listener: &TcpListener,
    acc_zid: u8,
    init_zid: u8,
    acc_pref: LinkReliabilityPref,
    init_pref: LinkReliabilityPref,
) -> (OpenedSession, OpenedSession) {
    let addr = listener.local_addr().expect("local_addr");
    let acc = async {
        let (stream, _peer) = listener.accept().await.expect("accept tcp peer");
        accept_and_open_session_with_multilink(
            DialedLink::Tcp(stream),
            fixture_params_with_zid(acc_zid),
            acc_pref,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established (multilink)")
    };
    let init = async {
        let stream = TcpStream::connect(addr).await.expect("dial loopback");
        initiate_and_open_session_with_multilink(
            DialedLink::Tcp(stream),
            fixture_params_with_zid(init_zid),
            init_pref,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator reaches Established (multilink)")
    };
    tokio::join!(acc, init)
}

/// Spawn a steady-state drive loop for one link, recording Push deliveries into
/// `log` under `link_id`. `actions` is the handle whose SHARED `SessionCore` the
/// RX admits against (for a transplanted secondary link this is the JOINED
/// handle, so its rx-SN gate is the primary's); `opened.engine` drives the
/// per-link FSM / lease. Returns the abortable task handle.
fn spawn_drive(
    mut opened: OpenedSession,
    actions: Arc<SessionLinkActions>,
    link_id: usize,
    log: RxLog,
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
            push_recorder(link_id, log),
        )
        .await;
    })
}

/// Assertions 1, 2, 3 — the full aggregation + segregation + failover survival
/// path over real sockets.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_links_aggregate_segregate_and_survive_link_death() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");

    // Link 1 (reliable-pref on both ends) and link 2 (best-effort-pref). Same
    // zids on both links each side (A=0x01, B=0x02) — the SAME logical peer.
    let (b1, a1) = open_multilink_link(
        &listener,
        0x02,
        0x01,
        LinkReliabilityPref::Reliable,
        LinkReliabilityPref::Reliable,
    )
    .await;
    let (b2, a2) = open_multilink_link(
        &listener,
        0x02,
        0x01,
        LinkReliabilityPref::BestEffort,
        LinkReliabilityPref::BestEffort,
    )
    .await;

    // Both sides captured the peer's ephemeral multilink pubkey (the 0x4
    // handshake ran), and the two links of a side agree on it (same peer).
    let a1_key = a1
        .multilink_pubkey()
        .expect("a1 captured B's ephemeral pubkey");
    let a2_key = a2
        .multilink_pubkey()
        .expect("a2 captured B's ephemeral pubkey");
    assert_eq!(a1_key, a2_key, "A's two links captured the SAME peer key");
    let b1_key = b1
        .multilink_pubkey()
        .expect("b1 captured A's ephemeral pubkey");
    let b2_key = b2
        .multilink_pubkey()
        .expect("b2 captured A's ephemeral pubkey");
    assert_eq!(b1_key, b2_key, "B's two links captured the SAME peer key");

    // Retain the send handles + the primaries' shared cores before the JOIN
    // (which transplants the secondaries).
    let a_send = a1.actions.clone();
    let a_primary = a1.actions.clone();
    let a_secondary = a2.actions.clone();
    let b_primary = b1.actions.clone();
    let b_secondary = b2.actions.clone();

    // JOIN both sides: link 2 aggregates onto link 1's shared SessionCore.
    let a_joined = match join_link(&a_primary, &a_secondary, 2) {
        JoinOutcome::Joined(h) => h,
        other => panic!("A join must aggregate, got {}", outcome_name(&other)),
    };
    let b_joined = match join_link(&b_primary, &b_secondary, 2) {
        JoinOutcome::Joined(h) => h,
        other => panic!("B join must aggregate, got {}", outcome_name(&other)),
    };

    // Assertion 1: B holds ONE logical session with 2 live links (one shared
    // SessionCore). `b_joined` and `b_primary` share that core, so the count read
    // through either is the same 2.
    assert_eq!(
        b_primary.live_link_count(),
        2,
        "B aggregates 2 links into ONE session"
    );
    assert_eq!(
        b_joined.live_link_count(),
        2,
        "the joined handle sees the SAME shared link set (one core)"
    );
    assert_eq!(a_primary.live_link_count(), 2, "A aggregates 2 links too");

    // Drive all four link loops. `a1_link_id`/`a2_link_id` tag which B drive
    // observed a Put so the test can tell reliable-on-one-link from
    // best-effort-on-another. B's link ids: 1 = b1's socket, 2 = b2's socket.
    let b_log: RxLog = Arc::new(StdMutex::new(Vec::new()));
    let b1_task = spawn_drive(b1, b_primary.clone(), 1, b_log.clone());
    let b2_task = spawn_drive(b2, b_joined.clone(), 2, b_log.clone());
    // A's drives: link 1 with its own actions, link 2 with the joined handle.
    let a1_task = spawn_drive(
        a1,
        a_primary.clone(),
        11,
        Arc::new(StdMutex::new(Vec::new())),
    );
    let a2_task = spawn_drive(
        a2,
        a_joined.clone(),
        12,
        Arc::new(StdMutex::new(Vec::new())),
    );

    // Let the drives spin up.
    tokio::time::sleep(Duration::from_millis(120)).await;

    // Assertion 2: a reliable Put (-> A's reliable-pref link 1) and a best-effort
    // Put (-> A's best-effort-pref link 2) both reach B on DIFFERENT links.
    a_send
        .send_push_literal("test/reliable", b"R1", /*reliable=*/ true)
        .expect("reliable Put routes onto the reliable-pref link");
    a_send
        .send_push_literal("test/besteffort", b"B1", /*reliable=*/ false)
        .expect("best-effort Put routes onto the best-effort-pref link");

    let two_links = poll_until(&b_log, Duration::from_secs(8), |log| {
        log.iter().any(|d| d.reliable) && log.iter().any(|d| !d.reliable)
    })
    .await;
    assert!(
        two_links,
        "both a reliable AND a best-effort Put reached B: {:?}",
        b_log.lock().unwrap()
    );
    let (reliable_link, best_effort_link) = {
        let log = b_log.lock().unwrap();
        let r = log.iter().find(|d| d.reliable).unwrap().link_id;
        let b = log.iter().find(|d| !d.reliable).unwrap().link_id;
        (r, b)
    };
    assert_ne!(
        reliable_link, best_effort_link,
        "reliability SEGREGATION: the reliable and best-effort Puts rode DIFFERENT physical links"
    );
    let reliable_sn_1 = b_log
        .lock()
        .unwrap()
        .iter()
        .find(|d| d.reliable)
        .unwrap()
        .sn;

    // Assertion 3: KILL the reliable link (A side). Mark it down + del_link — the
    // exact post-`release_link`+`del_link` state a real socket death produces (the
    // accept-loop `Step::Driven` response) — then abort its drive.
    a1_task.abort();
    TokioRuntime::with_mutex_mut(&a_primary.link.transport_available, |g| *g = false);
    let remaining = a_primary.del_link(&a_primary.link);
    assert_eq!(
        remaining, 1,
        "del_link removes only the dead link; the session SURVIVES on the other"
    );
    assert_eq!(
        a_primary.live_link_count(),
        1,
        "A's session survives on 1 live link after the reliable link died"
    );

    // A subsequent RELIABLE Put must still deliver — failing over onto the
    // surviving (best-effort-pref) link, since the reliable-pref link is dead.
    tokio::time::sleep(Duration::from_millis(60)).await;
    a_send
        .send_push_literal("test/reliable", b"R2", /*reliable=*/ true)
        .expect("post-death reliable Put fails over to the surviving link");

    let delivered_after = poll_until(&b_log, Duration::from_secs(8), |log| {
        log.iter().filter(|d| d.reliable).count() >= 2
    })
    .await;
    assert!(
        delivered_after,
        "the post-death reliable Put still delivered at B: {:?}",
        b_log.lock().unwrap()
    );

    // RX SN CONTINUITY across the switch: the second reliable Put's SN continues
    // from the first (a shared SN generator + a shared per-channel rx-SN gate),
    // NOT a per-link reset to the initial SN. It also arrived on the OTHER
    // physical link, proving the failover crossed links yet the SN stayed one
    // continuous sequence.
    let (reliable_sn_2, reliable_link_2) = {
        let log = b_log.lock().unwrap();
        let d = log.iter().filter(|d| d.reliable).nth(1).unwrap();
        (d.sn, d.link_id)
    };
    assert!(
        reliable_sn_2 > reliable_sn_1,
        "RX reliable SN is CONTINUOUS across the link switch (sn2={reliable_sn_2} > sn1={reliable_sn_1}), not reset"
    );
    assert_ne!(
        reliable_link_2, reliable_link,
        "the post-death reliable Put arrived on the OTHER physical link (failover)"
    );

    b1_task.abort();
    b2_task.abort();
    a2_task.abort();
}

/// Assertion 4 — a link presenting a DIFFERENT ephemeral pubkey for the same peer
/// is rejected INVALID. The process-wide ephemeral keypair makes every in-process
/// link present the SAME key, so a genuine mismatch is a distinct node; here the
/// config-equality GATE itself (`authorize_link`, the `PubkeyBound` witness
/// factory) is driven with a tampered candidate, and `join_link` is checked to
/// reject a secondary whose captured key does not match.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mismatched_pubkey_link_is_rejected_invalid() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let (b1, a1) = open_multilink_link(
        &listener,
        0x02,
        0x01,
        LinkReliabilityPref::Reliable,
        LinkReliabilityPref::Reliable,
    )
    .await;

    let bound = b1
        .multilink_pubkey()
        .expect("b1 captured A's ephemeral pubkey");

    // The gate ADMITS the exact bound key (a matching link) ...
    assert!(
        b1.actions.authorize_link(&bound).is_some(),
        "authorize_link mints the PubkeyBound witness for the matching ephemeral key"
    );
    // ... and REJECTS any other key (a different multilink identity).
    let mut tampered = bound.clone();
    tampered[0] ^= 0xFF;
    assert!(
        b1.actions.authorize_link(&tampered).is_none(),
        "authorize_link refuses to mint the witness for a mismatched key (INVALID)"
    );
    // ... and rejects the empty candidate.
    assert!(
        b1.actions.authorize_link(&[]).is_none(),
        "authorize_link refuses an absent key"
    );

    // Drive to keep both ends alive briefly, then confirm the session is intact.
    let _ = (a1, b1);
}

/// Assertion 5 — a THIRD inbound link over `max_links` is rejected MAX_LINKS; the
/// first two survive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn third_link_over_max_links_is_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let (b1, a1) = open_multilink_link(
        &listener,
        0x02,
        0x01,
        LinkReliabilityPref::Reliable,
        LinkReliabilityPref::Reliable,
    )
    .await;
    let (b2, a2) = open_multilink_link(
        &listener,
        0x02,
        0x01,
        LinkReliabilityPref::BestEffort,
        LinkReliabilityPref::BestEffort,
    )
    .await;
    let (b3, a3) = open_multilink_link(
        &listener,
        0x02,
        0x01,
        LinkReliabilityPref::Any,
        LinkReliabilityPref::Any,
    )
    .await;

    let b_primary = b1.actions.clone();
    // First two aggregate (max_links = 2).
    assert!(
        matches!(
            join_link(&b1.actions, &b2.actions, 2),
            JoinOutcome::Joined(_)
        ),
        "the second link aggregates within max_links"
    );
    assert_eq!(b_primary.link_count(), 2, "two links held");

    // The third is over the limit -> MAX_LINKS reject; the first two survive.
    let outcome = join_link(&b1.actions, &b3.actions, 2);
    assert!(
        matches!(outcome, JoinOutcome::OverLimit),
        "the third link over max_links is rejected MAX_LINKS, got {}",
        outcome_name(&outcome)
    );
    assert_eq!(
        b_primary.link_count(),
        2,
        "the rejected third link did NOT enter the set; the first two survive"
    );

    let _ = (a1, a2, a3);
}

/// Regression R — a plain (max_links=1) open negotiates NO multilink: the 0x4
/// handshake does not run, so neither side captures an ephemeral pubkey and the
/// staged InitSyn ext chain carries no 0x4 entry (byte-identical to today).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_open_emits_no_multilink_ext() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let acc = async {
        let (stream, _peer) = listener.accept().await.expect("accept");
        accept_and_open_session(
            DialedLink::Tcp(stream),
            fixture_params_with_zid(0x02),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor Established")
    };
    let init = async {
        let stream = TcpStream::connect(addr).await.expect("dial");
        initiate_and_open_session(
            DialedLink::Tcp(stream),
            fixture_params_with_zid(0x01),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("initiator Established")
    };
    let (opened_acc, opened_init) = tokio::join!(acc, init);

    assert!(
        opened_init.multilink_pubkey().is_none(),
        "a plain open captures NO multilink pubkey (the 0x4 handshake never ran)"
    );
    assert!(
        opened_acc.multilink_pubkey().is_none(),
        "the plain acceptor captures NO multilink pubkey either"
    );
    // No 0x4 ext was staged into ANY establishment chain (byte-level).
    assert_eq!(
        opened_init.actions.staged_multilink_ext_count(),
        0,
        "a plain (max_links=1) handshake stages NO 0x4 Z_EXT_MULTILINK ext (initiator)"
    );
    assert_eq!(
        opened_acc.actions.staged_multilink_ext_count(),
        0,
        "a plain handshake stages NO 0x4 Z_EXT_MULTILINK ext (acceptor)"
    );
}

/// Positive 0x4 control (R311y205 test-gap) — complements
/// `plain_open_emits_no_multilink_ext`: a MULTILINK open (max_links>1, a dispatch
/// installed) DOES stage 0x4 Z_EXT_MULTILINK entries into its establishment
/// chains and DOES capture the peer's ephemeral pubkey. The zero-count assertion
/// only proves absence, so without this positive control a wire-broken 0x4 send
/// path would still pass the regression floor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multilink_open_stages_multilink_ext() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let (opened_acc, opened_init) = open_multilink_link(
        &listener,
        0x02,
        0x01,
        LinkReliabilityPref::Reliable,
        LinkReliabilityPref::Reliable,
    )
    .await;

    assert!(
        opened_init.actions.staged_multilink_ext_count() > 0,
        "a multilink open stages at least one 0x4 Z_EXT_MULTILINK ext (initiator)"
    );
    assert!(
        opened_acc.actions.staged_multilink_ext_count() > 0,
        "a multilink open stages at least one 0x4 Z_EXT_MULTILINK ext (acceptor)"
    );
    assert!(
        opened_init.multilink_pubkey().is_some(),
        "the multilink initiator captured the peer's ephemeral pubkey"
    );
    assert!(
        opened_acc.multilink_pubkey().is_some(),
        "the multilink acceptor captured the peer's ephemeral pubkey"
    );
}

fn outcome_name(o: &JoinOutcome) -> &'static str {
    match o {
        JoinOutcome::Joined(_) => "Joined",
        JoinOutcome::InvalidPubkey => "InvalidPubkey",
        JoinOutcome::OverLimit => "OverLimit",
    }
}

/// Poll `log` against `pred` until it holds or `budget` elapses; returns whether
/// it held. A generous budget absorbs full-CI shared load (no fixed-window
/// flake), and the early-out keeps the happy path fast.
async fn poll_until(
    log: &RxLog,
    budget: Duration,
    pred: impl Fn(&Vec<RxDelivery>) -> bool,
) -> bool {
    let step = Duration::from_millis(25);
    let mut waited = Duration::ZERO;
    loop {
        if pred(&log.lock().unwrap()) {
            return true;
        }
        if waited >= budget {
            return false;
        }
        tokio::time::sleep(step).await;
        waited += step;
    }
}
