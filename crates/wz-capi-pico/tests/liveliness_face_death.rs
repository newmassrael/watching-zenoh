// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! R311y522 acceptance gate — a dying face must UNDECLARE its remote liveliness
//! tokens to the C application.
//!
//! ## The defect this pins
//!
//! A C program declares `z_liveliness_declare_subscriber`, a peer connects and
//! declares a liveliness token, and the program's callback fires with a PUT.
//! Then the peer dies. Before R311y522 the program was never told: `face_down`
//! removed the `FaceEntry` and dropped it, taking that face's whole
//! `ApplicationLayerObserver` — and every remote token it held — with it, in
//! silence. The application went on believing the token was alive.
//!
//! No `UndeclToken` can rescue that: the link that would carry one is exactly
//! what died. Only the local teardown path can tell the application, which is
//! what pico does — it fires `_z_liveliness_subscription_undeclare_all` from
//! unicast transport FAILURE (`src/transport/unicast/lease.c:74-78` into
//! `src/session/liveliness.c:99-120`), drawing no dial/accept distinction.
//!
//! ## Why the token is LEAKED, and why binding it is not enough
//!
//! `std::mem::forget` is load-bearing here, not sloppiness. A merely BOUND
//! token emits an `UndeclToken` from its RAII drop, and since R311y519's
//! teardown drain that tail frame is actually DELIVERED — so the C side learns
//! through the ORDINARY undeclare path and this test passes while proving
//! nothing about face death. That was measured, not feared: with the token
//! bound, this test passed even with the face-death flush removed.
//!
//! Leaking models what the gate is about — a peer that VANISHES (killed,
//! crashed, cable pulled) and never gets to say goodbye.
//!
//! ## Why the far end is wz-native
//!
//! The peer declares its token through wz's own session API and then returns,
//! dropping its link, so the death is a real socket close observed by the C
//! listener's accept loop rather than a second copy of this crate's own
//! bookkeeping.
//!
//! ## What keeps the assertion non-vacuous
//!
//! The PUT is asserted first, from the same sink. A test that only demanded a
//! Delete could pass on a session where the token never arrived at all.

use std::ffi::c_void;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_capi_pico::liveliness::{
    z_liveliness_declare_subscriber, z_liveliness_subscriber_options_default,
    z_liveliness_subscriber_options_t,
};
use wz_capi_pico::{
    z_close, z_closure_sample, z_closure_sample_move, z_config_default, z_config_loan_mut,
    z_config_move, z_keyexpr_as_view_string, z_loaned_sample_t, z_open, z_owned_closure_sample_t,
    z_owned_config_t, z_owned_session_t, z_owned_subscriber_t, z_sample_keyexpr, z_sample_kind,
    z_session_drop, z_session_loan, z_session_loan_mut, z_session_move, z_string_data,
    z_string_len, z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t,
    z_view_string_loan, z_view_string_t, zp_config_insert, Z_CONFIG_LISTEN_KEY, Z_OK,
    Z_SAMPLE_KIND_DELETE, Z_SAMPLE_KIND_PUT,
};

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{LivelinessOptions, TokioSession};
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal, IterationEvent, SessionInitParams, SessionTimeouts, SigningKey,
    WhatAmI,
};
use wz_runtime_tokio::session_open::{
    dial_endpoint, initiate_and_open_session, DialConfig, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex as WzMutex;

const KEYEXPR: &str = "wz/live/peer1";
const PATTERN: &str = "wz/live/**";

type Captured = Arc<Mutex<Vec<(i32, String)>>>;

struct Ctx {
    captured: Captured,
}

/// The C liveliness callback: record `(kind, keyexpr)` for every sample.
///
/// # Safety
/// `sample` is a live borrowed sample for the call's duration and `ctx` is the
/// `Ctx` this test leaked into the closure.
unsafe extern "C" fn on_liveliness(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const Ctx);
    let kind = z_sample_kind(sample);
    let ke = z_sample_keyexpr(sample);
    // The view string aliases the sample's bytes, so copy it out before
    // returning. Same idiom as `pubsub_roundtrip.rs`'s sample callback.
    let mut text = String::new();
    let mut vs: z_view_string_t = std::mem::zeroed();
    if z_keyexpr_as_view_string(ke, &mut vs) == Z_OK {
        let ls = z_view_string_loan(&vs);
        let data = z_string_data(ls);
        let len = z_string_len(ls);
        if !data.is_null() {
            text = String::from_utf8_lossy(std::slice::from_raw_parts(data as *const u8, len))
                .into_owned();
        }
    }
    ctx.captured.lock().unwrap().push((kind, text));
}

use wz_runtime_tokio_test_support::free_port;

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

/// A wz-native peer that dials the C listener, declares ONE liveliness token,
/// drives until told to die, and then returns — dropping its link.
fn native_peer(endpoint: String, ready_tx: mpsc::Sender<()>, die: Arc<tokio::sync::Notify>) {
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
        // LEAKED ON PURPOSE — see the module doc. A bound token's RAII drop
        // emits an UndeclToken that R311y519's drain now DELIVERS, which would
        // make this gate pass through the ordinary undeclare path.
        let token = session
            .declare_token(KEYEXPR.to_owned(), LivelinessOptions::new())
            .expect("declare the native liveliness token");
        std::mem::forget(token);

        let mut driver = inbound;
        let timeouts = SessionTimeouts::spec_defaults();
        let dispatch_session = session.clone();
        let mut dispatch =
            |event: IterationEvent<'_>| dispatch_session.dispatch_iteration_event(event);

        let _ = ready_tx.send(());

        let pump = drive_session_until_terminal(
            &mut driver,
            &actions,
            &mut engine,
            None,
            &clock,
            &timeouts,
            &mut dispatch,
        );
        tokio::select! {
            _ = pump => {}
            _ = die.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(20)) => {}
        }
        // Returning drops the session and the link together — the peer
        // vanishes exactly as a killed process would.
        drop(writer_handle);
    });
}

/// # Safety
/// The returned session must be closed + dropped by the caller.
unsafe fn open_c_listener(port: u16) -> z_owned_session_t {
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
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
    zs
}

fn wait_for<F: Fn() -> bool>(cond: F, budget: Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn a_dying_face_undeclares_its_remote_liveliness_tokens_to_the_c_app() {
    let port = free_port();
    let captured: Captured = Arc::new(Mutex::new(Vec::new()));
    let ctx = Box::into_raw(Box::new(Ctx {
        captured: captured.clone(),
    }));

    let mut session = unsafe { open_c_listener(port) };

    let mut sub: z_owned_subscriber_t = unsafe { std::mem::zeroed() };
    unsafe {
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        let pattern = std::ffi::CString::new(PATTERN).unwrap();
        assert_eq!(
            z_view_keyexpr_from_str(&mut ke, pattern.as_ptr()),
            Z_OK,
            "the liveliness pattern did not parse"
        );
        let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
        z_closure_sample(&mut closure, Some(on_liveliness), None, ctx as *mut c_void);
        let mut opts: z_liveliness_subscriber_options_t = std::mem::zeroed();
        z_liveliness_subscriber_options_default(&mut opts);
        assert_eq!(
            z_liveliness_declare_subscriber(
                z_session_loan(&session),
                &mut sub,
                z_view_keyexpr_loan(&ke),
                z_closure_sample_move(&mut closure),
                &mut opts,
            ),
            Z_OK,
            "the C liveliness subscriber was not declared"
        );
    }

    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let die = Arc::new(tokio::sync::Notify::new());
    let die_peer = die.clone();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let peer = std::thread::spawn(move || native_peer(endpoint, ready_tx, die_peer));
    ready_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the native peer never reached Established");

    // PRECONDITION, asserted rather than assumed: the token arrived as a PUT.
    // Without this leg the Delete assertion could pass on a session where the
    // token never propagated at all.
    let saw_put = wait_for(
        || {
            captured
                .lock()
                .unwrap()
                .iter()
                .any(|(k, ke)| *k == Z_SAMPLE_KIND_PUT && ke == KEYEXPR)
        },
        Duration::from_secs(10),
    );
    assert!(
        saw_put,
        "the C liveliness subscriber never saw the peer's token as a PUT, so the \
         Delete leg below would be testing nothing. captured: {:?}",
        captured.lock().unwrap()
    );

    // Kill the peer. `notify_one`, NEVER `notify_waiters`: the latter DROPS the
    // signal when no waiter is parked, which would make this test depend on the
    // peer already being inside its `select!` — the sibling `get_roundtrip.rs`
    // documents the same choice for the same reason.
    die.notify_one();
    peer.join().expect("native peer thread panicked");

    // THE GATE.
    let saw_delete = wait_for(
        || {
            captured
                .lock()
                .unwrap()
                .iter()
                .any(|(k, ke)| *k == Z_SAMPLE_KIND_DELETE && ke == KEYEXPR)
        },
        Duration::from_secs(15),
    );
    let final_capture = captured.lock().unwrap().clone();
    unsafe {
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
        drop(Box::from_raw(ctx));
    }
    assert!(
        saw_delete,
        "the peer that declared {KEYEXPR} vanished and the C application was \
         never told: no DELETE reached its liveliness subscriber. No UndeclToken \
         can arrive either — the link that would carry one is what died — so the \
         application is left believing a dead peer's token is alive. \
         captured: {final_capture:?}"
    );
}
