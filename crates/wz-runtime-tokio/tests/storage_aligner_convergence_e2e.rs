// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "storage-aligner",
    feature = "transport-link-tcp",
    feature = "transport-unicast"
))]

//! R311 §5.11 A11 — the LIVE two-replica storage convergence e2e: the ONE place
//! the full storage-replication + storage-aligner path runs end-to-end over a
//! real link. A source replica A holds an entry B lacks; A periodically
//! publishes its replication Digest and answers alignment queries, B subscribes
//! to peer digests and — on detecting it diverges from A — automatically pulls
//! the diverging entry off A's aligner queryable until B converges.
//!
//! ## Why this can only be a two-instance test
//!
//! Both the digest subscriber and the aligner answer queryable are declared
//! [`Locality::Remote`](wz_session_core::locality::Locality::Remote): a replica
//! must NOT process its own digest or answer its own alignment query. A
//! single-session loopback is `SessionLocal`-origin, so it cannot drive either
//! by construction. This is the first and only place the async transport glue —
//! `spawn_digest_aligner`'s `on_diff` → pull spawn, `query_replica_aligner` /
//! `run_alignment` / `issue_and_collect` (the `Session::query` I/O + the
//! `on_final` await + its self-bounding timeout backstop) — actually EXECUTES;
//! the deterministic decode / answer / followup helpers are unit-tested in the
//! driver, and the off-wire All-pull convergence is proven there, but the wire
//! round-trip rides here.
//!
//! ## The end-to-end path this proves
//!
//! A.DigestPublisher publishes `@-digest/<zidA>/<fp>` -> B's
//! `spawn_digest_aligner` subscriber (`@-digest/*/<fp>`, Remote) receives it ->
//! `handle_peer_digest` diffs B's (empty) local digest against A's ->
//! `on_diff(zidA_hex, DigestDiff)` -> rebuilds A's aligner keyexpr
//! (`@zid/<zidA>/<fp>/aligner`) -> spawns `query_replica_aligner` with
//! `AlignmentQuery::Diff` -> the GET routes to A's `AlignerService` queryable
//! over the wire -> A answers each diverging event via `reply_keyed_attached`
//! (the AlignmentReply on the reply attachment, the Put value on the payload) ->
//! B's `on_reply` decodes each + `process_alignment_reply` lands it in B's live
//! store -> B converges (holds A's entry; the two replication digests are equal
//! -- structural `Digest` equality, which the byte-exact wire codec makes
//! equivalent to byte-identical on the wire).
//!
//! ## Non-flakiness ([[feedback-no-flaky-ever]])
//!
//! The convergence signal is poll-on-condition (B's store gains the entry), not
//! a fixed settle sleep. A short digest interval (the publisher re-publishes
//! every `interval_ms`) means the `on_diff` -> pull re-triggers each tick until
//! B converges, so the test does not depend on any single declaration /
//! publish / query winning a propagation race — it only requires convergence
//! within the generous budget. Once B has pulled the entry the condition is
//! monotonic (an aligned entry is not lost), so there is no settle window after.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::net::TcpListener;

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::TokioSession;
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::storage_aligner_service::{spawn_digest_aligner, AlignerService};
use wz_runtime_tokio::storage_replication_service::DigestPublisher;
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio::timestamp_source::wall_clock_ntp64;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::sample::TimestampHint;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::storage_backend::MemoryStorage;
use wz_session_core::storage_replication::ReplicationConfig;
use wz_session_core::storage_state::StorageState;

const ITER_CAP: usize = 64;
/// The storage key space the replication configuration is scoped to (its
/// fingerprint seed); both replicas MUST share it so their digest / aligner
/// keyexprs (and thus their fingerprints) match.
const STORAGE_KEYEXPR: &str = "demo/**";
/// The single entry source replica A holds that B must converge to.
const DATA_KEY: &str = "demo/x";
const DATA_VALUE: &[u8] = b"value-x-on-source-replica-A";

type SharedState = Arc<StdMutex<StorageState<MemoryStorage>>>;

/// Two wz replicas over a real loopback TCP link converge: source A holds an
/// entry B lacks, and B's digest-driven aligner automatically pulls it off A's
/// aligner queryable until B's store (and replication digest) matches A's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_replicas_converge_via_digest_driven_alignment() {
    // Distinct replica zids. A is the acceptor/source, B the initiator/dest;
    // the storage zid each passes to its drivers is its own session zid, so the
    // keyexprs A declares on are exactly the ones B derives from A's digest.
    let zid_a = vec![0x0A; 4];
    let zid_b = vec![0x0B; 4];

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // ── Open both sessions to Established (engines are `!Send`, driven on the
    //    current task; the `tokio::join!` open pattern).
    let a_open = {
        let zid_a = zid_a.clone();
        async move {
            let (stream, _peer) = listener.accept().await.expect("accept");
            let mut params = fixture_session_init_params();
            params.zid = zid_a;
            accept_and_open_session(
                DialedLink::Tcp(stream),
                params,
                TokioTime::new(),
                Some(ITER_CAP),
                DEFAULT_OPEN_TICK_MS,
            )
            .await
            .expect("replica A (acceptor) reaches Established")
        }
    };
    let b_open = {
        let zid_b = zid_b.clone();
        async move {
            let locator =
                parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
            let mut params = fixture_session_init_params();
            params.zid = zid_b;
            let cfg = DialConfig::default();
            connect_and_open_session(
                locator,
                params,
                &cfg,
                TokioTime::new(),
                Some(ITER_CAP),
                DEFAULT_OPEN_TICK_MS,
            )
            .await
            .expect("replica B (initiator) reaches Established")
        }
    };
    let (mut opened_a, mut opened_b) = tokio::join!(a_open, b_open);

    // Short interval so the first digest publishes fast and re-triggers the pull
    // each tick until convergence; the other parameters mirror zenoh defaults.
    let config = ReplicationConfig::new(STORAGE_KEYEXPR, None, 100, 5, 6, 30, 250);
    let timeouts = SessionTimeouts::spec_defaults();

    // ── Replica A (source): seed the diverging entry with a wall-clock NTP64
    //    timestamp (so it lands in a live era), then declare the aligner answer
    //    queryable + spawn the periodic digest publisher. The service handles
    //    are held for the whole test (RAII: dropping undeclares / aborts).
    let state_a: SharedState = Arc::new(StdMutex::new(StorageState::new(MemoryStorage::new())));
    state_a
        .lock()
        .unwrap()
        .process_put(
            Some(DATA_KEY),
            DATA_VALUE.to_vec(),
            None,
            TimestampHint {
                time: wall_clock_ntp64(),
                zid: zid_a.clone(),
            },
        )
        .expect("the in-memory backend commits");
    let observer_a = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session_a = TokioSession::new(
        opened_a.actions.clone(),
        observer_a,
        Arc::new(opened_a.clock),
    );
    let _aligner_a =
        AlignerService::declare(&session_a, state_a.clone(), config.clone(), zid_a.clone())
            .expect("A declares its aligner answer queryable");
    let _digest_pub_a =
        DigestPublisher::spawn(&session_a, state_a.clone(), config.clone(), zid_a.clone());
    let session_a_drive = session_a.clone();
    let drive_a = drive_session_until_terminal(
        &mut opened_a.inbound,
        &opened_a.actions,
        &mut opened_a.engine,
        None,
        &opened_a.clock,
        &timeouts,
        move |event| session_a_drive.dispatch_iteration_event(event),
    );

    // ── Replica B (dest): starts EMPTY; wire the digest->aligner handoff
    //    (declares the Remote peer-digest subscriber whose on_diff auto-spawns
    //    the Diff pull against the diverging peer).
    let state_b: SharedState = Arc::new(StdMutex::new(StorageState::new(MemoryStorage::new())));
    let observer_b = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session_b = TokioSession::new(
        opened_b.actions.clone(),
        observer_b,
        Arc::new(opened_b.clock),
    );
    let _digest_aligner_b = spawn_digest_aligner(&session_b, state_b.clone(), config.clone())
        .expect("B wires its digest -> aligner pull");
    let session_b_drive = session_b.clone();
    let drive_b = drive_session_until_terminal(
        &mut opened_b.inbound,
        &opened_b.actions,
        &mut opened_b.engine,
        None,
        &opened_b.clock,
        &timeouts,
        move |event| session_b_drive.dispatch_iteration_event(event),
    );

    // ── Drive both replicas continuously; the scenario polls until B converges
    //    (holds A's entry). Generous budget; convergence is monotonic.
    let scenario = {
        let state_b = state_b.clone();
        async move {
            for _ in 0..400 {
                {
                    let guard = state_b.lock().unwrap();
                    if guard.get(Some(DATA_KEY)).map(|s| s.payload.as_slice()) == Some(DATA_VALUE) {
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            panic!("replica B did not converge (never pulled {DATA_KEY}) within the ~10s budget");
        }
    };

    tokio::select! {
        _ = drive_a => panic!("replica A drive loop ended unexpectedly"),
        _ = drive_b => panic!("replica B drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    // ── B converged: it holds A's entry verbatim (value + A's timestamp), and
    //    the two replicas' replication digests are EQUAL at a single shared `now`
    //    (the strong, era-stable convergence proof).
    {
        let gb = state_b.lock().unwrap();
        let stored = gb
            .get(Some(DATA_KEY))
            .expect("B converged: the aligned entry is present in B's store");
        assert_eq!(
            stored.payload, DATA_VALUE,
            "B holds source A's value for the aligned entry"
        );
    }
    let now = wall_clock_ntp64();
    let hot_upper = config.classify(now).0;
    let digest_a = state_a
        .lock()
        .unwrap()
        .replication_digest(&config, hot_upper);
    let digest_b = state_b
        .lock()
        .unwrap()
        .replication_digest(&config, hot_upper);
    assert_eq!(
        digest_a, digest_b,
        "after alignment the two replicas' replication digests are EQUAL (structural \
         `Digest` equality; the wire codec is separately proven byte-exact, so equal \
         structs imply equal wire bytes)"
    );
}
