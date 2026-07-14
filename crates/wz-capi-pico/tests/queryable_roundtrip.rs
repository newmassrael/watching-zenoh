// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! R3 acceptance gate for the §5.27 api-compat-pico QUERYABLE (responder) half.
//!
//! Drives the exported `z_declare_queryable` / `z_query_reply` C ABI against a
//! **wz-native querier** over loopback TCP: the C session listens and declares
//! the queryable, a plain `wz_runtime_tokio::Session` dials it and issues a real
//! wire `Request(Query)`, and the test asserts the reply the C callback produced
//! comes back to that querier.
//!
//! Why a native querier rather than a second C session: this round builds the
//! responder half, so a C-to-C test would have no `z_get` to ask with. Reaching
//! for the native side is not a workaround — it is the stronger proof. It
//! exercises the actual wire (`Request(Query)` → C handler → `Response(Reply)`)
//! and pins the C queryable against wz's own querier rather than against another
//! copy of this crate's marshalling, so a bug symmetric across the C ABI cannot
//! hide. The C-to-C `z_get` path is the sibling round's gate.

use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_query, z_closure_query_move,
    z_config_default, z_config_loan_mut, z_config_move, z_declare_queryable, z_loaned_query_t,
    z_open, z_owned_closure_query_t, z_owned_config_t, z_owned_queryable_t, z_owned_session_t,
    z_query_keyexpr, z_query_reply, z_queryable_move, z_queryable_options_t, z_session_drop,
    z_session_loan, z_session_loan_mut, z_session_move, z_undeclare_queryable,
    z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert,
    Z_CONFIG_LISTEN_KEY, Z_OK,
};

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::reply_sink::ReplyView;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{QueryOptions, TokioSession};
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal, IterationEvent, SessionInitParams, SessionTimeouts, SigningKey,
    WhatAmI,
};
use wz_runtime_tokio::session_open::{
    dial_endpoint, initiate_and_open_session, DialConfig, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex as WzMutex;

const KEYEXPR: &str = "demo/q";
const ANSWER: &str = "answer-from-c-queryable";

/// Context the C query callback writes into / replies from.
struct QCtx {
    seen: Arc<Mutex<Vec<String>>>,
}

/// The C queryable callback: read the query's keyexpr the pico way and reply.
/// Runs on the C session's drive thread.
unsafe extern "C" fn on_query(query: *const z_loaned_query_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const QCtx);

    let ke = z_query_keyexpr(query);
    assert!(!ke.is_null(), "z_query_keyexpr must borrow the query's key");
    ctx.seen.lock().unwrap().push(ANSWER.to_owned());

    // Reply under the query's own keyexpr, exactly as a pico queryable does.
    let payload_str = std::ffi::CString::new(ANSWER).unwrap();
    let mut payload = std::mem::zeroed();
    assert_eq!(
        z_bytes_copy_from_str(&mut payload, payload_str.as_ptr()),
        Z_OK
    );
    assert_eq!(
        z_query_reply(query, ke, z_bytes_move(&mut payload), std::ptr::null()),
        Z_OK
    );
}

/// The C drop callback: free the boxed context.
unsafe extern "C" fn on_query_drop(ctx: *mut c_void) {
    drop(Box::from_raw(ctx as *const QCtx as *mut QCtx));
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn init_params(whatami: WhatAmI) -> SessionInitParams {
    let mut zid = vec![0u8; 16];
    getrandom::getrandom(&mut zid).expect("OS entropy");
    SessionInitParams {
        version: 0x09,
        whatami,
        zid,
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 65535,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: Vec::new(),
        cookie_signing_key: SigningKey::new(vec![0xAB; 32]).expect("32-byte key"),
    }
}

/// A wz-native dialing session that issues one query and reports the replies it
/// received. Mirrors `session.rs`'s `drive_dial` — the same open → drive →
/// dispatch bridge, but staying on the Rust side so the C queryable is pinned
/// against wz's own querier.
fn native_querier(endpoint: String, replies_tx: mpsc::Sender<Vec<String>>) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async move {
        let clock = TokioTime::new();
        let dialed = dial_endpoint(&endpoint, &DialConfig::default())
            .await
            .expect("dial the C listener");
        let opened = initiate_and_open_session(
            dialed,
            init_params(WhatAmI::Client),
            clock,
            None,
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("handshake with the C listener");
        let OpenedSession {
            mut engine,
            actions,
            inbound,
            writer_handle,
            ..
        } = opened;

        let observer = Arc::new(WzMutex::new(ApplicationLayerObserver::new()));
        let session = TokioSession::new(actions.clone(), observer, Arc::new(clock));

        let got: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let got_cb = got.clone();

        let mut driver = inbound;
        let timeouts = SessionTimeouts::spec_defaults();
        let dispatch_session = session.clone();
        let mut dispatch =
            |event: IterationEvent<'_>| dispatch_session.dispatch_iteration_event(event);

        // Query UNTIL a reply arrives, bounded — the convergence pattern the
        // sibling `pubsub_roundtrip.rs` uses and documents ("the acceptor
        // republishes until the subscriber's declaration has propagated").
        //
        // This is NOT a retry-pass papering over flakiness: the wait is for the
        // C side's queryable DECLARATION to reach this peer, and a get is
        // idempotent, so re-asking is how a querier converges on a declaration
        // it cannot observe directly. A single query after a fixed sleep would
        // instead be a bet on scheduler latency — it would answer Final with
        // zero replies if the declare had not landed, and this repo's rule is
        // that no test may be flaky by construction. The bound makes a genuine
        // failure fail fast rather than hang.
        let query_session = session.clone();
        let got_poll = got.clone();
        let issued = tokio::spawn(async move {
            for _ in 0..50 {
                if !got_poll.lock().unwrap().is_empty() {
                    return;
                }
                let got_cb = got_cb.clone();
                let _ = query_session.query(
                    KEYEXPR,
                    QueryOptions::default().with_timeout_ms(3_000),
                    move |reply: &dyn ReplyView| {
                        got_cb
                            .lock()
                            .unwrap()
                            .push(String::from_utf8_lossy(reply.payload()).into_owned());
                    },
                    |_rid| {},
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        // Pump the link until the reply has arrived (bounded, so a genuine
        // failure fails fast rather than hanging).
        let pump = async {
            drive_session_until_terminal(
                &mut driver,
                &actions,
                &mut engine,
                None,
                &clock,
                &timeouts,
                &mut dispatch,
            )
            .await
        };
        // The convergence task returns as soon as a reply has landed (the pump
        // is what lands it), so racing it makes the test finish on success
        // rather than always burning the timeout. The sleep is the fail-fast
        // bound for the case where no reply ever arrives.
        tokio::select! {
            _ = pump => {}
            _ = issued => {}
            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
        }
        let _ = replies_tx.send(got.lock().unwrap().clone());
        drop(writer_handle);
    });
}

#[test]
fn c_queryable_answers_a_native_wz_querier_over_loopback_tcp() {
    let port = free_port();
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let endpoint = format!("tcp/127.0.0.1:{port}");

    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_c = seen.clone();

    unsafe {
        // --- the C session: listen + declare the queryable -------------------
        let mut cfg: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut cfg), Z_OK);
        assert_eq!(
            zp_config_insert(
                z_config_loan_mut(&mut cfg),
                Z_CONFIG_LISTEN_KEY,
                listen.as_ptr()
            ),
            Z_OK
        );
        let mut zs: z_owned_session_t = std::mem::zeroed();
        // `z_open(listen)` binds and returns with zero peers (R2), so the
        // endpoint is live before the querier dials — no bind race.
        assert_eq!(
            z_open(&mut zs, z_config_move(&mut cfg), std::ptr::null()),
            Z_OK
        );

        let ctx = Box::into_raw(Box::new(QCtx { seen: seen_c })) as *mut c_void;
        let mut closure: z_owned_closure_query_t = std::mem::zeroed();
        assert_eq!(
            z_closure_query(&mut closure, Some(on_query), Some(on_query_drop), ctx),
            Z_OK
        );

        let ke_str = std::ffi::CString::new(KEYEXPR).unwrap();
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, ke_str.as_ptr()), Z_OK);

        let mut qbl: z_owned_queryable_t = std::mem::zeroed();
        let opts = z_queryable_options_t { complete: true };
        // Declared BEFORE any peer connects — the SSOT replays it onto the
        // face as it comes up (pico's declare-before-peer).
        assert_eq!(
            z_declare_queryable(
                z_session_loan(&zs),
                &mut qbl,
                z_view_keyexpr_loan(&ke),
                z_closure_query_move(&mut closure),
                &opts
            ),
            Z_OK
        );

        // --- the wz-native querier ------------------------------------------
        let (tx, rx) = mpsc::channel();
        let querier = std::thread::spawn(move || native_querier(endpoint, tx));

        let replies = rx
            .recv_timeout(Duration::from_secs(15))
            .expect("the native querier must report back");
        let _ = querier.join();

        // Convergence may land more than one query before the first reply is
        // observed, so the gate is "every reply is the C queryable's answer",
        // not an exact count — counting would re-introduce the timing bet the
        // convergence loop exists to remove.
        assert!(
            !replies.is_empty(),
            "the wz querier must receive the C queryable's reply"
        );
        assert!(
            replies.iter().all(|reply| reply == ANSWER),
            "every reply must be the one the C queryable emitted, got {replies:?}"
        );
        assert!(
            !seen.lock().unwrap().is_empty(),
            "the C query callback must have fired"
        );

        // --- teardown --------------------------------------------------------
        assert_eq!(z_undeclare_queryable(z_queryable_move(&mut qbl)), Z_OK);
        assert_eq!(z_close(z_session_loan_mut(&mut zs), std::ptr::null()), Z_OK);
        z_session_drop(z_session_move(&mut zs));
    }
}

/// Context whose drop bumps a shared counter.
struct DropCtx {
    drops: Arc<AtomicUsize>,
}

unsafe extern "C" fn counting_on_query(_query: *const z_loaned_query_t, _ctx: *mut c_void) {}

unsafe extern "C" fn counting_on_drop(ctx: *mut c_void) {
    let ctx = Box::from_raw(ctx as *mut DropCtx);
    ctx.drops.fetch_add(1, Ordering::SeqCst);
}

/// The C `drop(context)` fires EXACTLY ONCE per declared queryable — the
/// property the `Arc<CQueryClosure>` fan-out exists to guarantee.
///
/// A listener with no peer is the sharp case: the registry's SSOT entry then
/// holds the LAST reference, so the drop runs from `undeclare_queryable`'s
/// entry removal rather than from a face's queryable teardown. Getting that
/// wrong leaks the context (drop never runs) or double-frees it (drop runs per
/// face AND per entry). No networking needed beyond the bind.
#[test]
fn c_query_closure_drop_runs_exactly_once() {
    let port = free_port();
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let drops = Arc::new(AtomicUsize::new(0));

    unsafe {
        let mut cfg: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut cfg), Z_OK);
        assert_eq!(
            zp_config_insert(
                z_config_loan_mut(&mut cfg),
                Z_CONFIG_LISTEN_KEY,
                listen.as_ptr()
            ),
            Z_OK
        );
        let mut zs: z_owned_session_t = std::mem::zeroed();
        assert_eq!(
            z_open(&mut zs, z_config_move(&mut cfg), std::ptr::null()),
            Z_OK
        );

        let ctx = Box::into_raw(Box::new(DropCtx {
            drops: drops.clone(),
        })) as *mut c_void;
        let mut closure: z_owned_closure_query_t = std::mem::zeroed();
        assert_eq!(
            z_closure_query(
                &mut closure,
                Some(counting_on_query),
                Some(counting_on_drop),
                ctx
            ),
            Z_OK
        );

        let ke_str = std::ffi::CString::new(KEYEXPR).unwrap();
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, ke_str.as_ptr()), Z_OK);

        let mut qbl: z_owned_queryable_t = std::mem::zeroed();
        let opts = z_queryable_options_t { complete: false };
        assert_eq!(
            z_declare_queryable(
                z_session_loan(&zs),
                &mut qbl,
                z_view_keyexpr_loan(&ke),
                z_closure_query_move(&mut closure),
                &opts
            ),
            Z_OK
        );
        assert_eq!(
            drops.load(Ordering::SeqCst),
            0,
            "a live queryable must not have dropped its context"
        );

        assert_eq!(z_undeclare_queryable(z_queryable_move(&mut qbl)), Z_OK);
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "undeclare must run the C drop exactly once"
        );

        // A defensive second undeclare on the now-nulled handle is a safe
        // no-op (pico's consume-and-null contract), and must not re-drop.
        assert_eq!(z_undeclare_queryable(z_queryable_move(&mut qbl)), Z_OK);
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "a second undeclare must not re-run the C drop"
        );

        assert_eq!(z_close(z_session_loan_mut(&mut zs), std::ptr::null()), Z_OK);
        z_session_drop(z_session_move(&mut zs));
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "closing the session must not re-run an already-dropped context"
        );
    }
}
