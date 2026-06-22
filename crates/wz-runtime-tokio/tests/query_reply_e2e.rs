// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "query-get",
    feature = "query-queryable",
    feature = "query-reply",
    feature = "transport-link-tcp",
    feature = "transport-unicast"
))]

//! R311 §5.11 A11 foundation — the FIRST in-process end-to-end exercise of the
//! high-level query/reply transport over a real link: an initiator session
//! [`Session::query`](wz_runtime_tokio::session::Session::query)s a keyexpr a
//! SEPARATE acceptor session answers via
//! [`Session::declare_queryable`](wz_runtime_tokio::session::Session::declare_queryable),
//! and the queryable's reply + the terminal `ResponseFinal` travel back over
//! the wire to the asker's callbacks.
//!
//! ## Why this exists (the coverage gap it closes)
//!
//! Every prior query/queryable test exercises either a single-session loopback
//! (the `QueryableRegistry::local_query` unit tests in `wz-session-core`) or
//! only the DECLARATION half over the wire (`session_reconnect_e2e`'s
//! `queryable_declares_replay_after_link_loss_and_reconnect` observes the
//! inbound `Declare(DeclQueryable)`, never a reply). No test had ever driven a
//! `Session::query` to a reply + final delivered from a remote peer's queryable
//! over a real link. This is that test — the generic transport foundation the
//! storage-aligner A11 two-replica convergence e2e builds on (the aligner's ASK
//! pull is exactly this query/reply round-trip carrying alignment attachments).
//! Isolating the generic path here means an A11 failure is a storage/digest
//! concern, not an unproven query transport.
//!
//! ## The wiring this pins (the deferred-fire path)
//!
//! A high-level `declare_queryable` callback and a `query`'s `on_reply` /
//! `on_final` are NOT invoked synchronously inside the observer dispatch — they
//! are STAGED on the session's [`DeferredFireQueue`](wz_session_core::deferred_fire::DeferredFireQueue)
//! (shared by every clone of the session) and run by
//! [`Session::dispatch_iteration_event`](wz_runtime_tokio::session::Session::dispatch_iteration_event),
//! which drains the queue after the dispatch lock drops. So the drive loop's
//! event closure MUST be `session.dispatch_iteration_event(event)` (not a bare
//! `observer.dispatch_event`, which only stages and never drains), and the
//! session used for `declare_queryable` / `query` MUST share the same observer
//! and fire-queue as the one the drive loop dispatches through. A session clone
//! shares both (`Arc`-backed), so the drive loop takes a clone of the same
//! session.
//!
//! ## Non-flakiness ([[feedback-no-flaky-ever]])
//!
//! A query routes to a peer's queryable only once that peer's
//! `Declare(DeclQueryable)` has propagated to the asker's session. Rather than
//! sleep a fixed settle margin (which would race), the scenario RE-ISSUES the
//! query on a poll cadence until a reply is observed, holding each
//! [`ReplyHandle`] so the pending query is not torn down. Over loopback the
//! declaration propagates in milliseconds, so the first or second attempt
//! routes; the retry only absorbs propagation latency, it does not mask a
//! missing reply (the assertion still requires a real reply within the budget).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::net::TcpListener;

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{QueryOptions, QueryableOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::reply_sink::ReplyView;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 64;
const KEYEXPR: &str = "demo/query-reply";
const REPLY_PAYLOAD: &[u8] = b"reply-aligner-foundation";

/// An initiator's `Session::query` reaches a remote acceptor's queryable over a
/// real loopback TCP link, the queryable's reply and the terminal
/// `ResponseFinal` travel back, and the asker's `on_reply` / `on_final` fire —
/// the generic query/reply transport the storage-aligner A11 e2e rides on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_reaches_remote_queryable_and_reply_returns() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    // ── Open BOTH sessions concurrently to Established (the `tokio::join!`
    //    pattern; the engines are `!Send`, so they are driven on the current
    //    task, never spawned). The acceptor is the ANSWERER, the initiator the
    //    ASKER.
    let acc_open = async {
        let (stream, _peer) = listener.accept().await.expect("accept");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x02; 4]; // distinct zid from the initiator
        accept_and_open_session(
            DialedLink::Tcp(stream),
            params,
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("acceptor reaches Established")
    };
    let init_open = async {
        let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
        let mut params = fixture_session_init_params();
        params.zid = vec![0x01; 4];
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
        .expect("initiator reaches Established")
    };
    let (mut opened_acc, mut opened_init) = tokio::join!(acc_open, init_open);

    let timeouts = SessionTimeouts::spec_defaults();

    // ── ANSWERER: a session sharing ONE observer with its drive loop declares a
    //    queryable on KEYEXPR that replies with REPLY_PAYLOAD. The reply is keyed
    //    on the query's own keyexpr (the base `reply`). The `Queryable` handle is
    //    held for the whole test (dropping it would undeclare).
    let observer_acc = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session_acc = TokioSession::new(
        opened_acc.actions.clone(),
        observer_acc,
        Arc::new(opened_acc.clock),
    );
    let _queryable = session_acc
        .declare_queryable(
            KEYEXPR,
            QueryableOptions::default(), // Locality::Any — fires on the remote query
            |_view: &dyn QueryView, out: &mut dyn ReplyOut| {
                out.reply(REPLY_PAYLOAD);
            },
        )
        .expect("acceptor declares the answering queryable");
    let session_acc_drive = session_acc.clone();
    let drive_acc = drive_session_until_terminal(
        &mut opened_acc.inbound,
        &opened_acc.actions,
        &mut opened_acc.engine,
        None,
        &opened_acc.clock,
        &timeouts,
        move |event| session_acc_drive.dispatch_iteration_event(event),
    );

    // ── ASKER: a session sharing ONE observer with its drive loop. The query is
    //    issued from the scenario; replies + finals land in shared buffers.
    let observer_init = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    let session_init = TokioSession::new(
        opened_init.actions.clone(),
        observer_init,
        Arc::new(opened_init.clock),
    );
    let session_init_drive = session_init.clone();
    let drive_init = drive_session_until_terminal(
        &mut opened_init.inbound,
        &opened_init.actions,
        &mut opened_init.engine,
        None,
        &opened_init.clock,
        &timeouts,
        move |event| session_init_drive.dispatch_iteration_event(event),
    );

    let replies: Arc<StdMutex<Vec<Vec<u8>>>> = Arc::new(StdMutex::new(Vec::new()));
    let finals = Arc::new(AtomicUsize::new(0));

    let scenario = {
        let session = session_init.clone();
        let replies = replies.clone();
        let finals = finals.clone();
        async move {
            // Re-issue on a poll cadence until a reply is observed (absorbs the
            // Declare(DeclQueryable) propagation latency without a racy fixed
            // sleep); hold every handle so the pending query is not torn down.
            let mut handles = Vec::new();
            for _ in 0..120 {
                let replies_cb = replies.clone();
                let finals_cb = finals.clone();
                if let Ok(handle) = session.query(
                    KEYEXPR,
                    QueryOptions::get(),
                    move |view: &dyn ReplyView| {
                        replies_cb.lock().unwrap().push(view.payload().to_vec());
                    },
                    move |_rid: u64| {
                        finals_cb.fetch_add(1, Ordering::SeqCst);
                    },
                ) {
                    handles.push(handle);
                }
                for _ in 0..4 {
                    if !replies.lock().unwrap().is_empty() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }
            panic!("the query received no reply within the ~12s budget");
        }
    };

    tokio::select! {
        _ = drive_acc => panic!("acceptor drive loop ended unexpectedly"),
        _ = drive_init => panic!("initiator drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    // ── The asker received the queryable's reply over the wire, and every reply
    //    carries the queryable's payload (no spurious reply from elsewhere).
    let got = replies.lock().unwrap().clone();
    assert!(
        !got.is_empty(),
        "the asker received at least one reply from the remote queryable over the wire"
    );
    assert!(
        got.iter().all(|p| p.as_slice() == REPLY_PAYLOAD),
        "every reply carries the queryable's payload"
    );
    // ── The terminal ResponseFinal fired (the query completed, not hung).
    assert!(
        finals.load(Ordering::SeqCst) >= 1,
        "the terminal ResponseFinal fired on the asker"
    );
}
