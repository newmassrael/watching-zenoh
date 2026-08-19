// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! R3b acceptance gate for the §5.27 api-compat-pico GET (querier) half.
//!
//! Drives the exported `z_get` / `z_closure_reply` C ABI against a **wz-native
//! queryable** over loopback TCP — the mirror of `queryable_roundtrip.rs`, which
//! pins R3a's C queryable against a wz-native querier. Reaching for the native
//! side on the far end is the stronger proof: it exercises the real wire
//! (`Request(Query)` → native responder → `Response(Reply)` → C callback) and
//! pins the C getter against wz's own responder rather than against another copy
//! of this crate's marshalling, so a bug symmetric across the C ABI cannot hide.
//!
//! ## What these tests are really guarding
//!
//! The get plane's hard part is not the happy path — it is COMPLETION. pico
//! signals a get's end by running the reply closure's `drop(context)` exactly
//! once, and there are five independent ways a get can end: a real
//! `ResponseFinal`, a timeout, the peer's face dying, `z_close`, and having no
//! peer at all.
//! [`wz_capi_pico::get`] handles all four with ONE mechanism (the shared
//! `Arc`'s refcount), so each test below fixes one of those paths against the
//! designs that would break it:
//!
//! - [`c_get_completes_at_its_timeout_when_the_peer_never_finals`] — the sweep
//!   gate, and the reason the drive loop grew an extra-deadline hook at all.
//! - [`c_dialed_get_completes_at_its_timeout_when_the_peer_never_finals`] — the
//!   same gate for the `connect` role, which reaches the extra-deadline by
//!   SEPARATE wiring and so can regress on its own.
//! - [`c_get_completes_promptly_when_the_face_dies_mid_flight`] — the case an
//!   N-finals COUNTER hangs on forever (a dead face's pending entry is dropped,
//!   never swept, so it fires no final).
//! - [`c_close_completes_an_in_flight_get`] — the fifth way a get ends, and the
//!   one the refcount does NOT reach by itself (the accept loop's shutdown never
//!   deregisters its faces).
//! - [`c_get_with_no_peer_completes_immediately_without_a_reply`] — the
//!   zero-faces path, which must not wait for a deadline.
//! - [`c_get_fans_every_face_and_completes_once`] — the fan, and the reason the
//!   C thread holds its own `Arc` guard across the loop.
//!
//! `timeout_ms == 0` → `Z_GET_TIMEOUT_DEFAULT` is pinned by a unit test
//! (`get::tests::timeout_zero_means_picos_default_not_wzs_never_expires`) rather
//! than here: it is a pure mapping, and an e2e version would have to burn the
//! full 10 s default to observe it.
//!
//! A per-face `query()` erroring AT ISSUE is deliberately NOT given a test of
//! its own. Forcing one needs a face caught mid-teardown, which is a race — and
//! a test that only sometimes reproduces its own precondition is the flaky kind
//! this repo forbids. It is the SAME mechanism as face death (the rolled-back
//! sink drops the closure, releasing the `Arc` clone), which
//! `c_get_completes_promptly_when_the_face_dies_mid_flight` pins deterministically.

use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_pico::{
    z_bytes_to_slice, z_close, z_closure_reply, z_closure_reply_move, z_config_default,
    z_config_loan_mut, z_config_move, z_get, z_get_options_default, z_get_options_t,
    z_loaned_bytes_t, z_loaned_reply_t, z_open, z_owned_closure_reply_t, z_owned_config_t,
    z_owned_session_t, z_owned_slice_t, z_reply_is_ok, z_reply_ok, z_sample_kind, z_sample_payload,
    z_session_drop, z_session_loan, z_session_move, z_slice_data, z_slice_drop, z_slice_len,
    z_slice_loan, z_slice_move, zp_config_insert, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_OK,
    Z_SAMPLE_KIND_PUT,
};

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::query_sink::{QueryView, ReplyOut};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{QueryableOptions, TokioSession};
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal, IterationEvent, SessionInitParams, SessionTimeouts, SigningKey,
    WhatAmI,
};
use wz_runtime_tokio::session_open::{
    accept_and_open_session, accept_endpoint, dial_endpoint, initiate_and_open_session,
    AcceptConfig, DialConfig, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex as WzMutex;

const KEYEXPR: &str = "demo/g";

// --- the C side ------------------------------------------------------------

/// Context the C reply callback writes into. `completed_at` is stamped by the
/// closure's DROP — which is pico's get-completion signal, and the thing most of
/// this file is about.
struct RCtx {
    replies: Arc<Mutex<Vec<String>>>,
    completions: Arc<AtomicUsize>,
    completed_at: Arc<Mutex<Option<Instant>>>,
    /// Failures seen INSIDE the callback. Recorded, not asserted — see
    /// [`on_reply`].
    errors: Arc<Mutex<Vec<String>>>,
}

/// The C reply callback: read the reply exactly the pico way —
/// `z_reply_is_ok` → `z_reply_ok` → `z_sample_payload` → `z_bytes_to_slice` →
/// `z_slice_data`/`z_slice_len`, the same chain `pubsub_roundtrip.rs` reads a
/// sample with.
///
/// Failures are RECORDED rather than asserted. A panic here would unwind into
/// `fire_reply`'s `catch_unwind` (which exists because unwinding across the
/// `extern "C"` boundary is UB and would tear down the drive thread), so an
/// assert would be SWALLOWED and the test would report the indistinguishable
/// "no reply arrived" instead of the real cause. The test body asserts on
/// `errors` after the fact, where a failure is actually visible.
unsafe extern "C" fn on_reply(reply: *mut z_loaned_reply_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const RCtx);
    let fail = |msg: &str| ctx.errors.lock().unwrap().push(msg.to_owned());

    if !z_reply_is_ok(reply) {
        fail("z_reply_is_ok was false: the native queryable answers with a data reply");
        return;
    }
    let sample = z_reply_ok(reply);
    if sample.is_null() {
        fail("z_reply_ok returned null for an ok reply");
        return;
    }
    if z_sample_kind(sample) != Z_SAMPLE_KIND_PUT {
        fail("z_sample_kind must report PUT for a reply_keyed answer");
        return;
    }
    let payload: *const z_loaned_bytes_t = z_sample_payload(sample);
    if payload.is_null() {
        fail("z_sample_payload returned null for a Put reply");
        return;
    }
    // Copy the bytes out DURING the call — the borrow is callback-scoped.
    let mut slice: z_owned_slice_t = std::mem::zeroed();
    if z_bytes_to_slice(payload, &mut slice) != Z_OK {
        fail("z_bytes_to_slice failed on the reply payload");
        return;
    }
    let loaned = z_slice_loan(&slice);
    let data = z_slice_data(loaned);
    if data.is_null() {
        fail("z_slice_data returned null");
        z_slice_drop(z_slice_move(&mut slice));
        return;
    }
    let bytes = std::slice::from_raw_parts(data, z_slice_len(loaned)).to_vec();
    z_slice_drop(z_slice_move(&mut slice));
    ctx.replies
        .lock()
        .unwrap()
        .push(String::from_utf8_lossy(&bytes).into_owned());
}

/// The C drop callback — pico's GET COMPLETION signal. Stamps when the get
/// ended and frees the context.
unsafe extern "C" fn on_reply_drop(ctx: *mut c_void) {
    {
        let ctx = &*(ctx as *const RCtx);
        *ctx.completed_at.lock().unwrap() = Some(Instant::now());
        ctx.completions.fetch_add(1, Ordering::SeqCst);
    }
    drop(Box::from_raw(ctx as *const RCtx as *mut RCtx));
}

/// One observation of a C get: what it received and when it completed.
#[derive(Clone)]
struct GetProbe {
    replies: Arc<Mutex<Vec<String>>>,
    completions: Arc<AtomicUsize>,
    completed_at: Arc<Mutex<Option<Instant>>>,
    errors: Arc<Mutex<Vec<String>>>,
}

impl GetProbe {
    fn new() -> Self {
        Self {
            replies: Arc::new(Mutex::new(Vec::new())),
            completions: Arc::new(AtomicUsize::new(0)),
            completed_at: Arc::new(Mutex::new(None)),
            errors: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn is_complete(&self) -> bool {
        self.completions.load(Ordering::SeqCst) > 0
    }

    fn replies(&self) -> Vec<String> {
        self.replies.lock().unwrap().clone()
    }

    /// Panic if the reply callback recorded a failure. Called by every test
    /// before its own assertions, so a marshalling bug reports ITSELF instead
    /// of masquerading as "no reply arrived".
    fn assert_no_callback_errors(&self) {
        let errors = self.errors.lock().unwrap();
        assert!(errors.is_empty(), "the C reply callback failed: {errors:?}");
    }

    /// Wait (bounded) for the get's completion, returning how long it took from
    /// `issued_at`. `None` if it never completed — which every caller treats as
    /// a failure, so a regression FAILS rather than hangs.
    fn await_completion(&self, issued_at: Instant, bound: Duration) -> Option<Duration> {
        let deadline = Instant::now() + bound;
        while Instant::now() < deadline {
            if let Some(at) = *self.completed_at.lock().unwrap() {
                return Some(at.duration_since(issued_at));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        None
    }
}

/// Issue one C `z_get`, wired to a fresh [`GetProbe`].
///
/// # Safety
/// `zs` must be a live loaned session.
unsafe fn issue_get(zs: *const wz_capi_pico::z_loaned_session_t, timeout_ms: u64) -> GetProbe {
    let probe = GetProbe::new();
    let ctx = Box::into_raw(Box::new(RCtx {
        replies: probe.replies.clone(),
        completions: probe.completions.clone(),
        completed_at: probe.completed_at.clone(),
        errors: probe.errors.clone(),
    })) as *mut c_void;

    let mut closure: z_owned_closure_reply_t = std::mem::zeroed();
    assert_eq!(
        z_closure_reply(&mut closure, Some(on_reply), Some(on_reply_drop), ctx),
        Z_OK
    );

    let ke_str = std::ffi::CString::new(KEYEXPR).unwrap();
    let mut ke: wz_capi_pico::z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(
        wz_capi_pico::z_view_keyexpr_from_str(&mut ke, ke_str.as_ptr()),
        Z_OK
    );

    let mut opts: z_get_options_t = std::mem::zeroed();
    z_get_options_default(&mut opts);
    opts.timeout_ms = timeout_ms;

    assert_eq!(
        z_get(
            zs,
            wz_capi_pico::z_view_keyexpr_loan(&ke),
            std::ptr::null(),
            z_closure_reply_move(&mut closure),
            &mut opts
        ),
        Z_OK
    );
    probe
}

// --- the wz-native far end -------------------------------------------------

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

/// The signals a silent peer waits on.
///
/// `notify_one`, never `notify_waiters` — the production code makes the same
/// choice for the same reason (`get::fan_get`): `notify_waiters` DROPS the
/// signal when no waiter is parked, so it would need an unstated ordering
/// argument ("the peer is definitely inside its `select!` by now") that a later
/// refactor could quietly break, turning a lost signal into a confusing
/// assertion failure. `notify_one` stores a permit, so no argument is required.
///
/// What a [`native_peer`] should do once its handshake has settled.
enum PeerBehaviour {
    /// Declare a queryable answering `answer`, and keep driving.
    Answer { answer: String },
    /// Declare a queryable answering `answer`, drive until told to go SILENT,
    /// then hold the socket open while reading nothing — until told to DIE, at
    /// which point the socket closes.
    ///
    /// The two phases are separate because they prove different things, and
    /// conflating them would make each prove neither:
    /// - **silent, socket held**: the C side's face stays UP and the query is
    ///   simply never answered. That is the only way to test the TIMEOUT — a
    ///   closed socket would tear the face down and complete the get via the
    ///   face-death path instead, passing for the wrong reason.
    /// - **die**: the face goes down with a query in flight, which is the
    ///   face-death path itself.
    AnswerThenGoSilent {
        answer: String,
        go_silent: Arc<tokio::sync::Notify>,
        die: Arc<tokio::sync::Notify>,
    },
}

/// A wz-native peer that dials the C listener, declares a queryable, and drives.
/// Mirrors `session.rs`'s `drive_dial` — the same open → drive → dispatch
/// bridge, staying on the Rust side so the C getter is pinned against wz's own
/// responder.
///
/// `ready_tx` fires once the queryable is declared and the peer is driving.
fn native_peer(endpoint: String, behaviour: PeerBehaviour, ready_tx: mpsc::Sender<()>) {
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

        let (answer, silence) = match behaviour {
            PeerBehaviour::Answer { answer } => (answer, None),
            PeerBehaviour::AnswerThenGoSilent {
                answer,
                go_silent,
                die,
            } => (answer, Some((go_silent, die))),
        };

        let reply_bytes = answer.into_bytes();
        // BIND the handle: `declare_queryable` returns an RAII `Queryable` whose
        // drop emits the wire undeclare, so `.expect(..)` without a binding
        // would declare and immediately retract it — the query would then arrive
        // and match nothing.
        let _queryable = session
            .declare_queryable(
                KEYEXPR.to_owned(),
                QueryableOptions::new().with_complete(true),
                move |view: &dyn QueryView, out: &mut dyn ReplyOut| {
                    out.reply_keyed(view.keyexpr(), &reply_bytes);
                },
            )
            .expect("declare the native queryable");

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
        match silence {
            Some((go_silent, die)) => {
                tokio::select! {
                    _ = pump => {}
                    _ = go_silent.notified() => {}
                }
                // Stop reading, but HOLD the link: `writer_handle` and the
                // driver stay alive, so the socket stays open and the C side's
                // face stays up (its 10 s lease outlives every bound here)
                // while nothing ever answers the query. Returning from here
                // drops both and closes the socket — which is how `die` kills
                // the face.
                tokio::select! {
                    _ = die.notified() => {}
                    _ = tokio::time::sleep(Duration::from_secs(20)) => {}
                }
            }
            None => {
                tokio::select! {
                    _ = pump => {}
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {}
                }
            }
        }
        drop(writer_handle);
    });
}

/// Open a C session listening on `port`.
///
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
    // `z_open(listen)` binds and returns with zero peers (R2), so the endpoint
    // is live before any peer dials — no bind race.
    assert_eq!(
        z_open(&mut zs, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK
    );
    zs
}

/// Converge on "the face is up and its queryable is declared" by retrying gets
/// until one gets a reply, then return.
///
/// This is NOT a retry-pass papering over flakiness. A get is idempotent, and
/// what is being waited for — the peer's face reaching the C session's registry
/// and its queryable declaration landing — is not observable from the C API. So
/// re-asking is how a getter converges on it, exactly as the sibling
/// `queryable_roundtrip.rs` converges from the other side. A single get after a
/// fixed sleep would instead bet on scheduler latency. The bound makes a genuine
/// failure fail fast rather than hang.
///
/// # Safety
/// `zs` must be a live loaned session.
unsafe fn converge_face_up(zs: *const wz_capi_pico::z_loaned_session_t, expect: &str) {
    for _ in 0..250 {
        let probe = issue_get(zs, 300);
        std::thread::sleep(Duration::from_millis(20));
        if probe.replies().iter().any(|r| r == expect) {
            return;
        }
    }
    panic!("the C get never reached the native queryable — face never converged");
}

// --- tests -----------------------------------------------------------------

/// The happy path: a C `z_get` reaches a wz-native queryable over real TCP and
/// its reply lands in the C reply callback, followed by exactly one completion.
#[test]
fn c_get_receives_a_native_queryables_reply_over_loopback_tcp() {
    let port = free_port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    const ANSWER: &str = "answer-to-the-c-getter";

    unsafe {
        let mut zs = open_c_listener(port);
        let (ready_tx, ready_rx) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            native_peer(
                endpoint,
                PeerBehaviour::Answer {
                    answer: ANSWER.to_owned(),
                },
                ready_tx,
            )
        });
        ready_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the native peer must declare its queryable");

        converge_face_up(z_session_loan(&zs), ANSWER);

        // The converged state is the precondition; THIS get is the assertion.
        let issued_at = Instant::now();
        let probe = issue_get(z_session_loan(&zs), 3_000);
        let elapsed = probe
            .await_completion(issued_at, Duration::from_secs(10))
            .expect("the get must complete");

        probe.assert_no_callback_errors();
        assert_eq!(
            probe.replies(),
            vec![ANSWER.to_owned()],
            "the C reply callback must receive the native queryable's answer"
        );
        assert_eq!(
            probe.completions.load(Ordering::SeqCst),
            1,
            "the reply closure's drop — pico's completion signal — fires exactly once"
        );
        // A real ResponseFinal ended it, so it must NOT have waited for the
        // 3 s timeout. This is what separates "the final works" from "the
        // sweep happens to clean up after it".
        assert!(
            elapsed < Duration::from_millis(2_000),
            "a get answered by a real Final completes on the Final, not on its \
             timeout (took {elapsed:?})"
        );

        assert_eq!(
            z_close(z_session_loan_mut_of(&mut zs), std::ptr::null()),
            Z_OK
        );
        z_session_drop(z_session_move(&mut zs));
        let _ = peer.join();
    }
}

/// THE SWEEP GATE. A peer whose face is up but which never answers must not
/// hold the get open forever: the C completion has to fire at `timeout_ms`.
///
/// Without `SharedSession::dispatch`'s `sweep_expired_queries` the pending entry
/// is never swept, the `Arc` never releases, and the C `drop(context)` NEVER
/// runs — the get hangs for the life of the session.
///
/// The bounds are chosen so the test also binds on the drive loop's extra
/// deadline (`FaceForwarder::next_extra_deadline_ms`), not just on the sweep
/// existing:
/// - **lower** (>= 400 ms): proves the TIMEOUT ended the get. Face death or a
///   zero-face get would complete near-instantly, so this is what stops the test
///   passing for the wrong reason.
/// - **upper** (< 2500 ms): without the extra-deadline wake the sweep could only
///   run on the loop's own Established cadence — the keepalive wake at
///   `adopted_lease_ms / 3` = ~3333 ms for this crate's 10 s lease — because a
///   silent peer generates no other event. So a regression that drops the
///   deadline hook lands at ~3333 ms and fails here.
#[test]
fn c_get_completes_at_its_timeout_when_the_peer_never_finals() {
    let port = free_port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    const ANSWER: &str = "answer-before-going-silent";

    unsafe {
        let mut zs = open_c_listener(port);
        let go_silent = Arc::new(tokio::sync::Notify::new());
        let go_silent_peer = go_silent.clone();
        // Never notified here: the peer must stay SILENT-BUT-ALIVE for the whole
        // test, so the face stays up and only the timeout can end the get.
        let die = Arc::new(tokio::sync::Notify::new());
        let die_peer = die.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            native_peer(
                endpoint,
                PeerBehaviour::AnswerThenGoSilent {
                    answer: ANSWER.to_owned(),
                    go_silent: go_silent_peer,
                    die: die_peer,
                },
                ready_tx,
            )
        });
        ready_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the native peer must declare its queryable");

        // Converge FIRST, while the peer still answers: this proves the face is
        // genuinely up, so the timeout below cannot be a zero-faces get in
        // disguise.
        converge_face_up(z_session_loan(&zs), ANSWER);

        // Now the peer stops reading — but holds its socket open, so the face
        // stays up and the query below is simply never answered.
        go_silent.notify_one();
        // Let the silence take effect before issuing the get under test.
        std::thread::sleep(Duration::from_millis(200));

        let issued_at = Instant::now();
        let probe = issue_get(z_session_loan(&zs), 500);
        let elapsed = probe
            .await_completion(issued_at, Duration::from_secs(8))
            .expect(
                "a get whose peer never Finals MUST still complete at its timeout — \
                 without the drive-thread sweep it hangs forever",
            );

        probe.assert_no_callback_errors();
        assert!(
            probe.replies().is_empty(),
            "a silent peer sends no reply, so the reply callback must never fire"
        );
        assert_eq!(
            probe.completions.load(Ordering::SeqCst),
            1,
            "the timeout completes the get exactly once"
        );
        assert!(
            elapsed >= Duration::from_millis(400),
            "the get must end on its 500 ms TIMEOUT, not instantly — completing \
             early would mean the face died or was never up, which would make \
             this test prove nothing about the sweep (took {elapsed:?})"
        );
        assert!(
            elapsed < Duration::from_millis(2_500),
            "the sweep must run on the get's OWN deadline. ~3333 ms would mean it \
             only ran on the keepalive wake — i.e. the drive loop's extra-deadline \
             hook is not wired (took {elapsed:?})"
        );

        assert_eq!(
            z_close(z_session_loan_mut_of(&mut zs), std::ptr::null()),
            Z_OK
        );
        z_session_drop(z_session_move(&mut zs));
        die.notify_one();
        let _ = peer.join();
    }
}

/// A get with NO peer completes immediately and never calls the reply callback.
///
/// pico does the same — `_z_query` runs the drop handler on the CALLING thread
/// when `remaining_finals == 0` (`src/net/primitives.c:560-562`) — and it is the
/// zero-faces arm of the one `Arc` mechanism: the C thread's own fan-loop guard
/// is the last clone, so releasing it completes the get.
///
/// The `timeout_ms` here is 30 s precisely so a completion can only come from
/// the zero-faces path; if this ever waited for the deadline the bound would
/// catch it.
#[test]
fn c_get_with_no_peer_completes_immediately_without_a_reply() {
    let port = free_port();

    unsafe {
        let mut zs = open_c_listener(port);

        let issued_at = Instant::now();
        let probe = issue_get(z_session_loan(&zs), 30_000);
        // The completion is synchronous on this thread, so it has already
        // happened by the time `z_get` returned.
        assert!(
            probe.is_complete(),
            "a get with no connected peer completes on the calling thread, before \
             z_get returns"
        );
        let elapsed = probe
            .await_completion(issued_at, Duration::from_secs(1))
            .expect("already complete");
        assert!(
            elapsed < Duration::from_millis(500),
            "a zero-peer get must not wait for its 30 s timeout (took {elapsed:?})"
        );
        probe.assert_no_callback_errors();
        assert!(
            probe.replies().is_empty(),
            "no peer means no reply callback"
        );
        assert_eq!(probe.completions.load(Ordering::SeqCst), 1);

        assert_eq!(
            z_close(z_session_loan_mut_of(&mut zs), std::ptr::null()),
            Z_OK
        );
        z_session_drop(z_session_move(&mut zs));
    }
}

/// A face dying mid-flight must still complete the get, PROMPTLY — the case
/// that kills an N-finals counter design.
///
/// The dead face's pending entry is DROPPED with its registry, not swept, so it
/// fires no final: a counter waiting for one would hang until the session ended.
/// The `Arc` handles it because dropping the entry drops the `on_reply` closure
/// and releases its clone.
///
/// The face is killed by the PEER going away (its socket closes, the accept
/// loop's `Step::Driven` deregisters it, `face_down` drops the entry) — the real
/// link-loss path. Closing the LOCAL session would be a different mechanism and
/// would not exercise `face_down` at all.
///
/// The 30 s `timeout_ms` is the whole point of the bound below: a completion
/// inside a few seconds cannot have come from the timeout sweep, so it must have
/// come from the face-death drop.
#[test]
fn c_get_completes_promptly_when_the_face_dies_mid_flight() {
    let port = free_port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    const ANSWER: &str = "answer-before-dying";

    unsafe {
        let mut zs = open_c_listener(port);
        let go_silent = Arc::new(tokio::sync::Notify::new());
        let go_silent_peer = go_silent.clone();
        let die = Arc::new(tokio::sync::Notify::new());
        let die_peer = die.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            native_peer(
                endpoint,
                PeerBehaviour::AnswerThenGoSilent {
                    answer: ANSWER.to_owned(),
                    go_silent: go_silent_peer,
                    die: die_peer,
                },
                ready_tx,
            )
        });
        ready_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the native peer must declare its queryable");
        converge_face_up(z_session_loan(&zs), ANSWER);

        // Go silent so the get below is genuinely IN FLIGHT (unanswered) when
        // the face dies — otherwise the peer would just answer it and the test
        // would prove nothing about face death.
        go_silent.notify_one();
        std::thread::sleep(Duration::from_millis(200));

        let issued_at = Instant::now();
        // A 30 s timeout: far beyond the bound below, so the sweep cannot be
        // what completes this get.
        let probe = issue_get(z_session_loan(&zs), 30_000);
        assert!(
            !probe.is_complete(),
            "the get must still be in flight — the face is up and unanswered"
        );

        // Kill the PEER: its socket closes, so the C side's face goes down and
        // takes its pending table (and the `on_reply` closure holding the Arc
        // clone) with it.
        die.notify_one();

        let elapsed = probe
            .await_completion(issued_at, Duration::from_secs(15))
            .expect(
                "a get whose face dies MUST still complete — under an N-finals \
                 counter it would hang, because a dropped pending entry fires no \
                 final",
            );
        // 2 s, not 10 s. The bound has to discriminate the mechanism, not just
        // "faster than the timeout": if the socket close ever regressed, the
        // face would STILL go down — via lease expiry — and a 10 s bound would
        // pass deterministically. `last_inbound_at` freezes when the peer goes
        // silent, the lease is 10 s (`session.rs` init_params), and the get is
        // issued ~200 ms after that, so the lease path lands at ~9800 ms. The
        // intended socket-close path lands in milliseconds; 2 s sits ~5x clear
        // of the fallback while leaving ample headroom for a loaded machine.
        assert!(
            elapsed < Duration::from_secs(2),
            "face death must complete the get from the PEER's socket closing \
             (milliseconds), not from the 10 s lease expiring and not from the \
             30 s timeout (took {elapsed:?})"
        );
        assert_eq!(
            probe.completions.load(Ordering::SeqCst),
            1,
            "exactly one completion, whatever ended the get"
        );
        assert!(
            probe.replies().is_empty(),
            "the peer went silent before the get, so no reply can have arrived"
        );

        assert_eq!(
            z_close(z_session_loan_mut_of(&mut zs), std::ptr::null()),
            Z_OK
        );
        z_session_drop(z_session_move(&mut zs));
        let _ = peer.join();
    }
}

/// A wz-native peer that LISTENS, completes one handshake, and then never reads
/// again — the far end for the `connect`-role tests.
///
/// It deliberately never drives: `accept_and_open_session` settles the
/// handshake (so the C dialer's `z_open` returns and its face is up), and then
/// the link is simply held open with nothing answering. That makes the C side's
/// face UP and permanently SILENT with no convergence step needed.
///
/// `bound_tx` fires once the listener is bound, so the dialer cannot race the
/// bind.
fn native_silent_listener(endpoint: String, bound_tx: mpsc::Sender<()>) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async move {
        let clock = TokioTime::new();
        // `accept_endpoint` binds then accepts; signalling before it means the
        // dialer may still beat the bind, so the C side retries its open below.
        let _ = bound_tx.send(());
        let accepted = match accept_endpoint(&endpoint, &AcceptConfig::default()).await {
            Ok(link) => link,
            Err(_) => return,
        };
        let opened = accept_and_open_session(
            accepted,
            init_params(WhatAmI::Peer),
            clock,
            None,
            DEFAULT_OPEN_TICK_MS,
        )
        .await;
        let Ok(opened) = opened else { return };
        // Hold the link open, read nothing, answer nothing. Dropping `opened`
        // would close the socket and take the C side's face down, which is the
        // one thing that must NOT happen here.
        tokio::time::sleep(Duration::from_secs(20)).await;
        drop(opened);
    });
}

/// THE DIAL-ROLE SWEEP GATE — the `connect` twin of
/// [`c_get_completes_at_its_timeout_when_the_peer_never_finals`].
///
/// This is not redundant with it. The two roles reach the drive loop's
/// extra-deadline by SEPARATE wiring: `listen` goes through `accept_loop` ->
/// `drive_face` -> the `FaceForwarder::next_extra_deadline_ms` /
/// `deadline_revised` hooks, while `connect` hand-rolls its own closure and its
/// own `deadline_revised` lookup in `session::drive_dial`. Either can regress
/// alone, and `revised.as_deref().unwrap_or(&never)` degrades SILENTLY to a
/// ~3333 ms-late get rather than failing — so an untested path is an
/// unprotected one. And `connect` is the ORDINARY pico get client (a `z_get` to
/// a router), i.e. the path that matters most.
///
/// Fully deterministic with no convergence step: `z_open(connect)` blocks until
/// Established and registers the face before it returns, so the face is
/// provably up the moment the open succeeds.
#[test]
fn c_dialed_get_completes_at_its_timeout_when_the_peer_never_finals() {
    let port = free_port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    let connect = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();

    let (bound_tx, bound_rx) = mpsc::channel();
    let peer = std::thread::spawn(move || native_silent_listener(endpoint, bound_tx));
    bound_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the native listener must bind");

    unsafe {
        // Retry the open to cover the residual bind race — a transport
        // establishment retry, the same one `pubsub_roundtrip.rs` documents,
        // not a flake.
        let mut zs: z_owned_session_t = std::mem::zeroed();
        let mut opened = false;
        for _ in 0..250 {
            let mut cfg: z_owned_config_t = std::mem::zeroed();
            assert_eq!(z_config_default(&mut cfg), Z_OK);
            assert_eq!(
                zp_config_insert(
                    z_config_loan_mut(&mut cfg),
                    Z_CONFIG_CONNECT_KEY,
                    connect.as_ptr()
                ),
                Z_OK
            );
            if z_open(&mut zs, z_config_move(&mut cfg), std::ptr::null()) == Z_OK {
                opened = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(opened, "the C dialer's z_open never succeeded");
        // z_open(connect) returned Z_OK, so the handshake settled and the face
        // is registered — no convergence needed.

        let issued_at = Instant::now();
        let probe = issue_get(z_session_loan(&zs), 500);
        let elapsed = probe
            .await_completion(issued_at, Duration::from_secs(8))
            .expect(
                "a DIALED get whose peer never Finals MUST still complete at its \
                 timeout — the connect role wires its own extra-deadline and can \
                 regress independently of the listen role",
            );

        probe.assert_no_callback_errors();
        assert!(
            probe.replies().is_empty(),
            "a silent peer sends no reply, so the reply callback must never fire"
        );
        assert_eq!(probe.completions.load(Ordering::SeqCst), 1);
        assert!(
            elapsed >= Duration::from_millis(400),
            "the get must end on its 500 ms TIMEOUT, not instantly (took {elapsed:?})"
        );
        assert!(
            elapsed < Duration::from_millis(2_500),
            "the dial role's sweep must run on the get's OWN deadline; ~3333 ms \
             means drive_dial's ExtraDeadline is not wired (took {elapsed:?})"
        );

        assert_eq!(
            z_close(z_session_loan_mut_of(&mut zs), std::ptr::null()),
            Z_OK
        );
        z_session_drop(z_session_move(&mut zs));
    }
    let _ = peer.join();
}

/// `z_close` must END every in-flight get — pico's `_z_session_close` ->
/// `_z_flush_pending_queries` (`~/zenoh-pico/src/session/utils.c:194`).
///
/// Before R311y296's `clear_faces`, the `listen` role's shutdown broke out of
/// the accept loop WITHOUT deregistering its faces, so the registry kept every
/// face's session — and every pending entry's `Arc` — alive with no drive thread
/// left to sweep it. The completion then fired only at `z_session_drop`, and
/// never at all for a program that keeps the handle (`z_close` does not free
/// it). The dial role already did the right thing, so identical C code completed
/// on `connect` and hung on `listen`.
///
/// The 30 s `timeout_ms` is what makes this test mean something: nothing but the
/// close can complete the get inside the bound.
#[test]
fn c_close_completes_an_in_flight_get() {
    let port = free_port();
    let endpoint = format!("tcp/127.0.0.1:{port}");
    const ANSWER: &str = "answer-before-close";

    unsafe {
        let mut zs = open_c_listener(port);
        let go_silent = Arc::new(tokio::sync::Notify::new());
        let go_silent_peer = go_silent.clone();
        let die = Arc::new(tokio::sync::Notify::new());
        let die_peer = die.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            native_peer(
                endpoint,
                PeerBehaviour::AnswerThenGoSilent {
                    answer: ANSWER.to_owned(),
                    go_silent: go_silent_peer,
                    die: die_peer,
                },
                ready_tx,
            )
        });
        ready_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the native peer must declare its queryable");
        converge_face_up(z_session_loan(&zs), ANSWER);

        // Silence the peer so the get is genuinely in flight at close time.
        go_silent.notify_one();
        std::thread::sleep(Duration::from_millis(200));

        let issued_at = Instant::now();
        let probe = issue_get(z_session_loan(&zs), 30_000);
        assert!(!probe.is_complete(), "the get must still be in flight");

        assert_eq!(
            z_close(z_session_loan_mut_of(&mut zs), std::ptr::null()),
            Z_OK
        );

        // `z_close` is synchronous (it joins the drive thread, then clears the
        // registry), so the completion has already fired by the time it returns.
        assert!(
            probe.is_complete(),
            "z_close MUST end every in-flight get, as pico's \
             _z_flush_pending_queries does — without clear_faces the registry \
             outlives the drive thread and the get hangs until z_session_drop"
        );
        let elapsed = probe
            .await_completion(issued_at, Duration::from_secs(1))
            .expect("already complete");
        assert!(
            elapsed < Duration::from_secs(5),
            "the close completes the get, not the 30 s timeout (took {elapsed:?})"
        );
        assert_eq!(probe.completions.load(Ordering::SeqCst), 1);

        // A get issued AFTER close sees an empty peer set and completes at once
        // — pico's behaviour for a closed session. Before clear_faces this
        // found the orphaned faces and hung forever.
        let after = issue_get(z_session_loan(&zs), 30_000);
        assert!(
            after.is_complete(),
            "a get after z_close must complete immediately (empty peer set), not hang"
        );
        assert!(after.replies().is_empty());

        z_session_drop(z_session_move(&mut zs));
        die.notify_one();
        let _ = peer.join();
    }
}

/// A get fans across EVERY connected face: two peers, two replies, and still
/// exactly ONE completion.
///
/// The single completion is the assertion that matters. It pins the C thread's
/// own `Arc` guard across the fan loop: without it, face 1 answering and
/// dropping its pending entry before face 2's `query` was issued would take the
/// refcount to zero and complete the get early — which would show up here as a
/// completion with only one reply.
#[test]
fn c_get_fans_every_face_and_completes_once() {
    let port = free_port();
    const ANSWER_A: &str = "answer-from-peer-a";
    const ANSWER_B: &str = "answer-from-peer-b";

    unsafe {
        let mut zs = open_c_listener(port);

        let mut peers = Vec::new();
        for answer in [ANSWER_A, ANSWER_B] {
            let endpoint = format!("tcp/127.0.0.1:{port}");
            let (ready_tx, ready_rx) = mpsc::channel();
            peers.push(std::thread::spawn(move || {
                native_peer(
                    endpoint,
                    PeerBehaviour::Answer {
                        answer: answer.to_owned(),
                    },
                    ready_tx,
                )
            }));
            ready_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("each native peer must declare its queryable");
        }

        // Converge until BOTH faces answer one get — the precondition for the
        // assertion below (one peer converging says nothing about the other).
        let mut converged = false;
        for _ in 0..250 {
            let probe = issue_get(z_session_loan(&zs), 500);
            std::thread::sleep(Duration::from_millis(40));
            let replies = probe.replies();
            if replies.iter().any(|r| r == ANSWER_A) && replies.iter().any(|r| r == ANSWER_B) {
                converged = true;
                break;
            }
        }
        assert!(converged, "both faces must come up and answer");

        let issued_at = Instant::now();
        let probe = issue_get(z_session_loan(&zs), 3_000);
        probe
            .await_completion(issued_at, Duration::from_secs(10))
            .expect("the two-face get must complete");

        probe.assert_no_callback_errors();
        let mut replies = probe.replies();
        replies.sort();
        assert_eq!(
            replies,
            vec![ANSWER_A.to_owned(), ANSWER_B.to_owned()],
            "one C get must fan to EVERY face and thread both replies back"
        );
        assert_eq!(
            probe.completions.load(Ordering::SeqCst),
            1,
            "N faces still complete the get exactly ONCE — the C thread's own Arc \
             guard is what stops face A's early final completing it mid-fan"
        );

        assert_eq!(
            z_close(z_session_loan_mut_of(&mut zs), std::ptr::null()),
            Z_OK
        );
        z_session_drop(z_session_move(&mut zs));
        for peer in peers {
            let _ = peer.join();
        }
    }
}

/// `z_session_loan_mut` takes `*mut z_owned_session_t`; this keeps the call
/// sites readable.
///
/// # Safety
/// `zs` must be a live owned session.
unsafe fn z_session_loan_mut_of(
    zs: *mut z_owned_session_t,
) -> *mut wz_capi_pico::z_loaned_session_t {
    wz_capi_pico::z_session_loan_mut(zs)
}
