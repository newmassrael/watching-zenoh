// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! R311y528 — the MATCHING plane across MORE THAN ONE FACE, which is the entire
//! reason `MatchAggregate` exists and was the one thing R311y527 shipped no test
//! for.
//!
//! ## What was untested, and why a green suite meant nothing
//!
//! wz holds N peers as N sessions; pico holds them as one session with a peer
//! list and ONE write-filter context. So wz has to aggregate: the verdict a C
//! program is told must be the OR across faces, or `z_pub.c -a` prints
//! "Publisher has NO MORE matching subscribers." while another peer is still
//! subscribed and every subsequent put still reaches it.
//!
//! R311y527's coverage was a registry unit test (one watch set), two
//! session-tier tests in `wz-runtime-tokio` (one session, one face), and foreign
//! LEG 8 (one pico subscriber, so one face). **A build that forwarded each
//! face's verdict straight through would have passed every one of them.** The
//! cross-face OR had no witness at all, and neither did `face_down`'s aggregate
//! purge.
//!
//! ## The discriminator is the EXACT sequence, not the final state
//!
//! Two peers subscribe and then both leave. Four behaviours are distinguishable
//! only by the sequence delivered to C:
//!
//! | build | log |
//! |---|---|
//! | correct (OR across faces) | `[true, false]` |
//! | per-face pass-through | `[true, true, false, false]` |
//! | `face_down` purge missing | `[true]` — the last `false` never arrives |
//! | registration silent (pre-R311y527) | `[]` |
//!
//! So every assertion below is on the whole sequence. The ordering barrier is
//! `z_publisher_get_matching_status`, which recomputes the verdict from the
//! LIVE faces rather than reading the aggregate's cache — so it cannot agree
//! with a broken aggregate by construction, and "it now reports false" is a
//! positive fact that can only hold once both faces are gone.

use std::ffi::{c_void, CStr, CString};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_pico::matching::{
    z_closure_matching_status, z_closure_matching_status_move, z_matching_status_t,
    z_owned_closure_matching_status_t, z_owned_matching_listener_t,
    z_publisher_declare_matching_listener, z_publisher_get_matching_status,
};
use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_sample, z_closure_sample_move,
    z_config_default, z_config_loan_mut, z_config_move, z_declare_publisher, z_declare_subscriber,
    z_loaned_sample_t, z_open, z_owned_config_t, z_owned_publisher_t, z_owned_session_t,
    z_owned_subscriber_t, z_publisher_loan, z_publisher_move, z_put, z_session_drop,
    z_session_loan, z_session_loan_mut, z_session_move, z_subscriber_move, z_undeclare_publisher,
    z_undeclare_subscriber, z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t,
    zp_config_insert, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_OK,
};

/// How long any barrier below waits before declaring the property unmet. Every
/// wait is a bounded poll ending in an assertion, never an unbounded one: a
/// regression that stalls the drive thread — a lock-order inversion holding the
/// registry across a C callback, say — has to read as a RED with a message,
/// never as a hung suite.
const BARRIER: Duration = Duration::from_secs(10);

// --- verdict log -----------------------------------------------------------

/// The C context behind the matching closure: every verdict, in arrival order.
struct VerdictLog {
    seen: Arc<Mutex<Vec<bool>>>,
    dropped: Arc<AtomicUsize>,
}

unsafe extern "C" fn on_matching(status: *const z_matching_status_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const VerdictLog);
    ctx.seen.lock().unwrap().push((*status).matching);
}

unsafe extern "C" fn on_matching_drop(ctx: *mut c_void) {
    let ctx = Box::from_raw(ctx as *mut VerdictLog);
    ctx.dropped.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn on_sample_flag(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    (*(ctx as *const AtomicBool)).store(true, Ordering::SeqCst);
}

unsafe extern "C" fn on_flag_drop(ctx: *mut c_void) {
    drop(Box::from_raw(ctx as *mut AtomicBool));
}

// --- helpers ---------------------------------------------------------------

use wz_runtime_tokio_test_support::free_port;

unsafe fn open_role(port: u16, key: u8, role: &str) -> z_owned_session_t {
    let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK,
        "{role} z_open failed"
    );
    session
}

unsafe fn open_listen(port: u16) -> z_owned_session_t {
    open_role(port, Z_CONFIG_LISTEN_KEY, "listener")
}

unsafe fn open_connect(port: u16) -> z_owned_session_t {
    open_role(port, Z_CONFIG_CONNECT_KEY, "dialer")
}

unsafe fn declare_publisher(session: &z_owned_session_t, keyexpr: &CStr) -> z_owned_publisher_t {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, keyexpr.as_ptr()), Z_OK);
    let mut pubr: z_owned_publisher_t = std::mem::zeroed();
    assert_eq!(
        z_declare_publisher(
            z_session_loan(session),
            &mut pubr,
            z_view_keyexpr_loan(&ke),
            std::ptr::null(),
        ),
        Z_OK
    );
    pubr
}

/// Attach a matching listener logging into `seen`, counting its C drop in
/// `dropped`. Returns the owned handle.
unsafe fn declare_matching(
    pubr: &z_owned_publisher_t,
    seen: Arc<Mutex<Vec<bool>>>,
    dropped: Arc<AtomicUsize>,
) -> z_owned_matching_listener_t {
    let ctx = Box::into_raw(Box::new(VerdictLog { seen, dropped })) as *mut c_void;
    let mut closure: z_owned_closure_matching_status_t = std::mem::zeroed();
    assert_eq!(
        z_closure_matching_status(&mut closure, Some(on_matching), Some(on_matching_drop), ctx),
        Z_OK
    );
    let mut listener: z_owned_matching_listener_t = std::mem::zeroed();
    assert_eq!(
        z_publisher_declare_matching_listener(
            z_publisher_loan(pubr),
            &mut listener,
            z_closure_matching_status_move(&mut closure),
        ),
        Z_OK
    );
    listener
}

/// Declare a subscriber whose only job is to EXIST, so the peer's declaration
/// reaches the publisher's session and moves the matching verdict.
unsafe fn declare_flag_sub(
    session: &z_owned_session_t,
    keyexpr: &CStr,
    flag: &Arc<AtomicBool>,
) -> z_owned_subscriber_t {
    // The flag is boxed for C and ALSO held by the caller; the box is what the C
    // drop releases, so the caller's `Arc` clone must not be the box itself.
    let ctx = Box::into_raw(Box::new(AtomicBool::new(false))) as *mut c_void;
    let _ = flag;
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_sample(&mut closure, Some(on_sample_flag), Some(on_flag_drop), ctx),
        Z_OK
    );
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, keyexpr.as_ptr()), Z_OK);
    let mut sub: z_owned_subscriber_t = std::mem::zeroed();
    assert_eq!(
        z_declare_subscriber(
            z_session_loan(session),
            &mut sub,
            z_view_keyexpr_loan(&ke),
            z_closure_sample_move(&mut closure),
            std::ptr::null(),
        ),
        Z_OK
    );
    sub
}

unsafe fn matching_now(pubr: &z_owned_publisher_t) -> bool {
    let mut status = z_matching_status_t { matching: false };
    assert_eq!(
        z_publisher_get_matching_status(z_publisher_loan(pubr), &mut status),
        Z_OK
    );
    status.matching
}

/// Poll the LIVE verdict (not the aggregate's cache) until it reads `want`.
///
/// This is the ordering barrier every assertion below hangs off. It recomputes
/// from the connected faces each call (`SharedSession::has_matching`), so it
/// cannot be satisfied by a stale aggregate — which is exactly what makes
/// "it reads false now" mean "both faces are gone", and therefore makes a
/// missing `false` in the log a defect rather than a race.
unsafe fn await_live_verdict(pubr: &z_owned_publisher_t, want: bool, what: &str) {
    let deadline = Instant::now() + BARRIER;
    while Instant::now() < deadline {
        if matching_now(pubr) == want {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("live matching verdict never reached {want} ({what})");
}

/// Wait for the delivered sequence to equal `want`, then assert it. On timeout
/// the panic names what actually arrived, so an over- or under-delivering build
/// is diagnosed from the message rather than from a bare timeout.
fn await_log(seen: &Arc<Mutex<Vec<bool>>>, want: &[bool], what: &str) {
    let deadline = Instant::now() + BARRIER;
    while Instant::now() < deadline {
        if *seen.lock().unwrap() == want {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "matching verdicts were {:?}, expected {want:?} ({what})",
        seen.lock().unwrap()
    );
}

/// Assert the sequence is `want` and STAYS `want` for a settling window — the
/// only honest way to assert an absence. Used where the property is "nothing
/// further was delivered".
fn assert_log_settles(seen: &Arc<Mutex<Vec<bool>>>, want: &[bool], what: &str) {
    let until = Instant::now() + Duration::from_millis(500);
    while Instant::now() < until {
        assert_eq!(
            *seen.lock().unwrap(),
            want,
            "matching verdicts diverged from {want:?} ({what})"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

unsafe fn close_session(session: &mut z_owned_session_t) {
    z_close(z_session_loan_mut(session), std::ptr::null());
    z_session_drop(z_session_move(session));
}

unsafe fn put(session: &z_owned_session_t, keyexpr: &CStr, payload: &CStr) {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, keyexpr.as_ptr()), Z_OK);
    let mut buf = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut buf, payload.as_ptr()), Z_OK);
    assert_eq!(
        z_put(
            z_session_loan(session),
            z_view_keyexpr_loan(&ke),
            z_bytes_move(&mut buf),
            std::ptr::null(),
        ),
        Z_OK
    );
}

// --- tests -----------------------------------------------------------------

#[test]
fn the_c_verdict_is_the_or_across_two_peer_faces() {
    // TWO peers subscribe to the publisher's keyexpr and then both leave. The C
    // side must be told exactly twice: `true` when the FIRST arrives and `false`
    // when the LAST leaves. See this file's header for the four builds this
    // sequence separates.
    let port = free_port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let dropped = Arc::new(AtomicUsize::new(0));
    let flag_one = Arc::new(AtomicBool::new(false));
    let flag_two = Arc::new(AtomicBool::new(false));

    unsafe {
        let mut listener = open_listen(port);
        let pubr = declare_publisher(&listener, c"match/data");
        let mut mlistener = declare_matching(&pubr, seen.clone(), dropped.clone());

        // No peer yet: pico fires the `true` arm only, so registration on an
        // unmatched publisher is silent.
        assert_log_settles(&seen, &[], "registration with no peer must be silent");
        assert!(!matching_now(&pubr), "no peer, no match");

        // FACE 1 arrives -> the session verdict flips.
        let mut dialer_one = open_connect(port);
        let mut sub_one = declare_flag_sub(&dialer_one, c"match/**", &flag_one);
        await_live_verdict(&pubr, true, "peer 1 subscribed");
        await_log(&seen, &[true], "the first matching peer delivers true");

        // FACE 2 arrives -> the OR does not move, so C hears NOTHING. The
        // barrier that makes this an ordered assertion rather than a guess: the
        // publisher's put reaches peer 2, which can only happen once peer 2's
        // subscription has been processed by the listener session.
        let mut dialer_two = open_connect(port);
        let mut sub_two = declare_flag_sub(&dialer_two, c"match/**", &flag_two);
        let mut reached_two = false;
        let deadline = Instant::now() + BARRIER;
        while Instant::now() < deadline {
            put(&listener, c"match/data", c"probe");
            // Peer 2's own subscriber flag lives in the C box; the observable
            // here is the LISTENER's view, so re-poll the live verdict, which
            // consults every face's observer including peer 2's.
            if matching_now(&pubr) {
                reached_two = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(reached_two, "peer 2 never registered on the listener");
        assert_log_settles(&seen, &[true], "a SECOND matching peer must be silent");

        // FACE 1 leaves while face 2 still matches -> still silent.
        //
        // The subscriber is NOT undeclared first, and that is the whole point:
        // an undeclare would empty the aggregate down the ORDINARY per-face path
        // (`UndeclSubscriber` on the wire -> the face's own matching listener
        // fires `false`), which is not the path under test. Killing the link
        // with the declaration still standing leaves `face_down`'s purge as the
        // only thing that can remove the face -- measured: with the purge
        // disabled and the undeclare in place this test still passed, and it is
        // the undeclare's removal that makes it a witness. The handle is
        // released AFTER the close so the C context is still freed, without a
        // wire undeclare ever going out.
        close_session(&mut dialer_one);
        z_undeclare_subscriber(z_subscriber_move(&mut sub_one));
        assert_log_settles(&seen, &[true], "one of two peers leaving must be silent");
        assert!(
            matching_now(&pubr),
            "peer 2 is still subscribed, so the live verdict must stay true"
        );

        // FACE 2 leaves -> the OR empties and C hears `false` exactly once.
        //
        // This is also `face_down`'s ONLY witness: peer 1's face was purged from
        // the aggregate when it dropped, and if it had not been, the set would
        // still hold it here and this `false` would never arrive.
        close_session(&mut dialer_two);
        z_undeclare_subscriber(z_subscriber_move(&mut sub_two));
        await_live_verdict(&pubr, false, "both peers gone");
        await_log(
            &seen,
            &[true, false],
            "the LAST peer leaving delivers false",
        );

        // The listener's C context is released exactly once, at undeclare.
        assert_eq!(dropped.load(Ordering::SeqCst), 0, "not dropped while live");
        z_undeclare_matching(&mut mlistener);
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            1,
            "undeclaring the listener must run the C drop(context) exactly once"
        );

        z_undeclare_publisher(z_publisher_move(&mut { pubr }));
        close_session(&mut listener);
    }
}

/// Thin wrapper so the test body reads in pico's own vocabulary.
unsafe fn z_undeclare_matching(listener: &mut z_owned_matching_listener_t) {
    use wz_capi_pico::matching::{z_matching_listener_move, z_undeclare_matching_listener};
    assert_eq!(
        z_undeclare_matching_listener(z_matching_listener_move(listener)),
        Z_OK
    );
}

#[test]
fn undeclaring_a_publisher_retracts_its_matching_listeners() {
    // R311y528 DEFECT 2. pico ties the write-filter context to the publisher, so
    // `z_undeclare_publisher` takes its matching callbacks with it. wz keys the
    // matching SSOT on the SESSION (it has to — the verdict is aggregated across
    // faces), and R311y527 shipped no back-reference: the entry stayed
    // registered, every per-face listener stayed installed, and the C closure
    // kept being invoked for a publisher the program had already dropped.
    //
    // The discriminator is the `false` that a retracted listener must NOT
    // receive. It is asserted against a positive barrier — a SECOND publisher on
    // the same keyexpr reporting the live verdict — so "nothing arrived" is
    // pinned to a moment when something would have.
    let port = free_port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let dropped = Arc::new(AtomicUsize::new(0));
    let flag = Arc::new(AtomicBool::new(false));

    unsafe {
        let mut listener = open_listen(port);
        // `witness` never declares a matching listener; it exists purely to poll
        // the live verdict after the subject publisher is gone.
        let witness = declare_publisher(&listener, c"drop/data");
        let mut subject = declare_publisher(&listener, c"drop/data");
        let listener_handle = declare_matching(&subject, seen.clone(), dropped.clone());
        // ABANDONED, not undeclared: this test releases the PUBLISHER and never
        // calls `z_undeclare_matching_listener`, which is the path under test.
        // `z_owned_matching_listener_t` is a plain `repr(C)` handle with no
        // `Drop` — pico's ownership is explicit, not RAII — so letting the
        // binding fall out of scope retracts nothing, which is exactly the
        // situation being set up.
        let _abandoned = listener_handle;

        let mut dialer = open_connect(port);
        let mut sub = declare_flag_sub(&dialer, c"drop/**", &flag);
        await_live_verdict(&witness, true, "the peer subscribed");
        await_log(&seen, &[true], "the matching peer delivers true");

        // The publisher goes away. Its listener must go with it — including the
        // C context, whose drop is the receipt.
        assert_eq!(dropped.load(Ordering::SeqCst), 0, "still live");
        z_undeclare_publisher(z_publisher_move(&mut { subject }));
        assert_eq!(
            dropped.load(Ordering::SeqCst),
            1,
            "undeclaring the publisher must release its matching closure -- \
             the C drop(context) is the receipt that the registry entry is gone"
        );

        // Now move the verdict. A retained entry would deliver `false` here.
        z_undeclare_subscriber(z_subscriber_move(&mut sub));
        close_session(&mut dialer);
        await_live_verdict(&witness, false, "the peer left");
        assert_log_settles(
            &seen,
            &[true],
            "a retracted matching listener must not be invoked for a publisher \
             the program already undeclared",
        );

        z_undeclare_publisher(z_publisher_move(&mut { witness }));
        close_session(&mut listener);
    }
}

/// Re-entrancy context: the session and publisher the matching callback calls
/// back into, carried as addresses because a raw pointer is not `Send` and the
/// callback runs on the drive thread.
struct ReentrantCtx {
    publisher: usize,
    polled: Arc<Mutex<Vec<bool>>>,
}

unsafe extern "C" fn on_matching_reenter(status: *const z_matching_status_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const ReentrantCtx);
    // Re-enter the session from INSIDE the matching callback, holding the
    // aggregate mutex. This deadlocks the drive thread if any path ever takes
    // the registry lock before an aggregate mutex.
    let pubr = ctx.publisher as *const z_owned_publisher_t;
    let mut poll = z_matching_status_t { matching: false };
    let _ = z_publisher_get_matching_status(z_publisher_loan(&*pubr), &mut poll);
    ctx.polled.lock().unwrap().push((*status).matching);
}

unsafe extern "C" fn on_reentrant_drop(ctx: *mut c_void) {
    drop(Box::from_raw(ctx as *mut ReentrantCtx));
}

#[test]
fn a_matching_callback_may_reenter_the_session_while_the_aggregate_is_held() {
    // The lock order the R311y528 fix rests on, exercised rather than argued.
    //
    // `deliver_matching_flip` holds the entry's aggregate mutex across the C
    // call; that is only safe because no path takes the registry lock FIRST.
    // A C callback re-entering the session takes them in the surviving order
    // (aggregate -> registry) and must complete. A regression that restored
    // `registry -> aggregate` in `face_down` or the declare path stalls the
    // drive thread here, and the bounded barrier turns that stall into a RED
    // with a message instead of a hung suite.
    let port = free_port();
    let polled = Arc::new(Mutex::new(Vec::new()));
    let flag = Arc::new(AtomicBool::new(false));

    unsafe {
        let mut listener = open_listen(port);
        let pubr = Box::new(declare_publisher(&listener, c"reenter/data"));
        let pub_addr = (&*pubr) as *const z_owned_publisher_t as usize;

        let ctx = Box::into_raw(Box::new(ReentrantCtx {
            publisher: pub_addr,
            polled: polled.clone(),
        })) as *mut c_void;
        let mut closure: z_owned_closure_matching_status_t = std::mem::zeroed();
        assert_eq!(
            z_closure_matching_status(
                &mut closure,
                Some(on_matching_reenter),
                Some(on_reentrant_drop),
                ctx
            ),
            Z_OK
        );
        let mut mlistener: z_owned_matching_listener_t = std::mem::zeroed();
        assert_eq!(
            z_publisher_declare_matching_listener(
                z_publisher_loan(&*pubr),
                &mut mlistener,
                z_closure_matching_status_move(&mut closure),
            ),
            Z_OK
        );

        let mut dialer = open_connect(port);
        let mut sub = declare_flag_sub(&dialer, c"reenter/**", &flag);
        await_log(
            &polled,
            &[true],
            "the re-entrant callback did not complete -- the drive thread is \
             likely deadlocked on a registry/aggregate lock inversion",
        );

        z_undeclare_subscriber(z_subscriber_move(&mut sub));
        close_session(&mut dialer);
        await_log(
            &polled,
            &[true, false],
            "the departure edge's re-entrant callback did not complete",
        );

        z_undeclare_matching(&mut mlistener);
        let mut owned = *pubr;
        z_undeclare_publisher(z_publisher_move(&mut owned));
        close_session(&mut listener);
    }
}

// --- the vanishing peer ----------------------------------------------------

/// A wz-native peer that dials the C listener, declares ONE subscriber, drives
/// until told to die, and then returns — dropping its link with the declaration
/// still standing.
///
/// The subscriber is `mem::forget`-ed for the same reason
/// `liveliness_face_death.rs` leaks its token: a BOUND handle emits an
/// `UndeclSubscriber` from its RAII drop, the C side then learns through the
/// ORDINARY per-face path, and the test passes while proving nothing about face
/// death. That is not a hypothetical here — it was measured on this very file:
/// with the peer departing gracefully, disabling `face_down`'s purge left the
/// suite green.
fn vanishing_subscriber_peer(
    endpoint: String,
    ready_tx: std::sync::mpsc::Sender<()>,
    die: Arc<tokio::sync::Notify>,
) {
    use wz_runtime_tokio::observer::ApplicationLayerObserver;
    use wz_runtime_tokio::runtime_impl::TokioTime;
    use wz_runtime_tokio::session::{SubscribeOptions, TokioSession};
    use wz_runtime_tokio::session_glue::{
        drive_session_until_terminal, IterationEvent, SessionInitParams, SessionTimeouts,
        SigningKey, WhatAmI,
    };
    use wz_runtime_tokio::session_open::{
        dial_endpoint, initiate_and_open_session, DialConfig, OpenedSession, DEFAULT_OPEN_TICK_MS,
    };
    use wz_runtime_tokio::sync::Mutex as WzMutex;

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
        let mut zid = vec![0u8; 16];
        getrandom::getrandom(&mut zid).expect("OS entropy");
        let opened = initiate_and_open_session(
            dialed,
            SessionInitParams {
                version: 0x09,
                whatami: WhatAmI::Client,
                zid,
                seq_num_res: 2,
                req_id_res: 2,
                batch_size: 65535,
                lease_ms: 10_000,
                initial_sn: 0,
                cookie: Vec::new(),
                cookie_signing_key: SigningKey::new(vec![0xAB; 32]).expect("32-byte key"),
            },
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
        // LEAKED ON PURPOSE — see this function's doc comment.
        let sub = session
            .declare_subscriber("vanish/**".to_owned(), SubscribeOptions::new(), |_: &_| {})
            .expect("declare the native subscriber");
        std::mem::forget(sub);

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
        // Returning drops the session and the link together — the peer vanishes
        // exactly as a killed process would, with its subscriber declaration
        // still standing on the C listener's side.
        drop(writer_handle);
    });
}

#[test]
fn a_vanishing_peer_is_purged_from_the_matching_aggregate() {
    // `face_down`'s aggregate purge, which R311y527 shipped and nothing tested.
    //
    // A peer that VANISHES cannot retract its subscriber — the link that would
    // carry the `UndeclSubscriber` is what died. Its per-face wz matching
    // listener therefore never fires `false`, so without the purge the face
    // stays in the aggregate FOREVER: the C program is told it still has
    // matching subscribers after its only subscribing peer is gone, and — worse
    // — the aggregate never flips again, so a genuine later `true` is suppressed
    // as "no change".
    //
    // Both halves are asserted: the `false` on death, and that a NEW peer
    // arriving afterwards still produces a `true`. The second is what separates
    // a purge from a build that merely forced one `false` out.
    let port = free_port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let dropped = Arc::new(AtomicUsize::new(0));

    unsafe {
        let mut listener = open_listen(port);
        let pubr = declare_publisher(&listener, c"vanish/data");
        let mut mlistener = declare_matching(&pubr, seen.clone(), dropped.clone());

        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let die = Arc::new(tokio::sync::Notify::new());
        let peer_die = die.clone();
        let endpoint = format!("tcp/127.0.0.1:{port}");
        let peer =
            std::thread::spawn(move || vanishing_subscriber_peer(endpoint, ready_tx, peer_die));
        ready_rx
            .recv_timeout(BARRIER)
            .expect("the native peer never finished its handshake");

        await_live_verdict(&pubr, true, "the native peer subscribed");
        await_log(&seen, &[true], "the matching peer delivers true");

        // The peer VANISHES. No undeclare goes out.
        die.notify_waiters();
        peer.join().expect("the native peer thread panicked");

        await_log(
            &seen,
            &[true, false],
            "a VANISHED peer was never purged from the aggregate -- the C \
             program still believes it has matching subscribers",
        );

        // And the aggregate is genuinely empty, not merely forced to report
        // false once: a fresh peer must move it back to true.
        let mut revived = open_connect(port);
        let flag = Arc::new(AtomicBool::new(false));
        let mut sub = declare_flag_sub(&revived, c"vanish/**", &flag);
        await_log(
            &seen,
            &[true, false, true],
            "the aggregate never flipped back -- the vanished face is still in \
             the set, suppressing a genuine later match as 'no change'",
        );

        z_undeclare_subscriber(z_subscriber_move(&mut sub));
        close_session(&mut revived);
        z_undeclare_matching(&mut mlistener);
        z_undeclare_publisher(z_publisher_move(&mut { pubr }));
        close_session(&mut listener);
    }
}

// --- the QUERIER half of the matching family --------------------------------

/// R311y528 — the querier matching plane R311y527 left unexported.
///
/// The gap was a BINDING gap, not a capability one:
/// `Querier::declare_matching_listener` had existed all along, and the ranking
/// that opened R311y527 — programs blocked — could not see the omission because
/// no upstream example calls the querier form. So the only thing that can
/// witness it is a test written against the C ABI directly, which is what this
/// is.
///
/// The property is the QUERYABLE scope, and that is what separates this from the
/// publisher plane: a querier watching remote SUBSCRIBERS would stay silent
/// here, because the peer below declares a queryable and never a subscriber.
/// The publisher-scope negative is asserted alongside it in the same session, so
/// a build that collapsed the two scopes into one fails on whichever half it
/// chose.
#[test]
fn a_querier_matches_on_remote_queryables_not_remote_subscribers() {
    use wz_capi_pico::querier::{
        z_declare_querier, z_owned_querier_t, z_querier_declare_matching_listener,
        z_querier_get_matching_status, z_querier_loan, z_querier_move, z_undeclare_querier,
    };
    use wz_capi_pico::query::{
        z_closure_query, z_closure_query_move, z_declare_queryable, z_loaned_query_t,
        z_owned_queryable_t, z_queryable_move, z_undeclare_queryable,
    };

    unsafe extern "C" fn on_query(_query: *const z_loaned_query_t, _ctx: *mut c_void) {}
    unsafe extern "C" fn on_query_drop(_ctx: *mut c_void) {}

    let port = free_port();
    let querier_seen = Arc::new(Mutex::new(Vec::new()));
    let publisher_seen = Arc::new(Mutex::new(Vec::new()));
    let dropped = Arc::new(AtomicUsize::new(0));

    unsafe {
        let mut listener = open_listen(port);

        // A QUERIER and a PUBLISHER on the SAME keyexpr, each with its own
        // matching listener. Same key, different scope — so the two logs
        // separate the scopes without any other variable moving.
        let mut querier: z_owned_querier_t = std::mem::zeroed();
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut ke, c"scope/data".as_ptr()),
            Z_OK
        );
        assert_eq!(
            z_declare_querier(
                z_session_loan(&listener),
                &mut querier,
                z_view_keyexpr_loan(&ke),
                std::ptr::null_mut(),
            ),
            Z_OK
        );
        let pubr = declare_publisher(&listener, c"scope/data");
        let mut pub_listener = declare_matching(&pubr, publisher_seen.clone(), dropped.clone());

        let qctx = Box::into_raw(Box::new(VerdictLog {
            seen: querier_seen.clone(),
            dropped: dropped.clone(),
        })) as *mut c_void;
        let mut qclosure: z_owned_closure_matching_status_t = std::mem::zeroed();
        assert_eq!(
            z_closure_matching_status(
                &mut qclosure,
                Some(on_matching),
                Some(on_matching_drop),
                qctx
            ),
            Z_OK
        );
        let mut qmatching: z_owned_matching_listener_t = std::mem::zeroed();
        assert_eq!(
            z_querier_declare_matching_listener(
                z_querier_loan(&querier),
                &mut qmatching,
                z_closure_matching_status_move(&mut qclosure),
            ),
            Z_OK,
            "z_querier_declare_matching_listener must exist and succeed -- \
             R311y527 shipped the publisher family whole and this one not at all"
        );

        // A peer declaring a QUERYABLE moves the QUERIER's verdict and must
        // leave the PUBLISHER's alone.
        let mut peer = open_connect(port);
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_query(
                &mut closure,
                Some(on_query),
                Some(on_query_drop),
                std::ptr::null_mut()
            ),
            Z_OK
        );
        let mut qke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut qke, c"scope/**".as_ptr()),
            Z_OK
        );
        let mut queryable: z_owned_queryable_t = std::mem::zeroed();
        assert_eq!(
            z_declare_queryable(
                z_session_loan(&peer),
                &mut queryable,
                z_view_keyexpr_loan(&qke),
                z_closure_query_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK
        );

        await_log(
            &querier_seen,
            &[true],
            "a remote QUERYABLE must move the querier's matching verdict",
        );
        // The live poll must agree with the listener, exactly as on the
        // publisher side.
        let mut status = z_matching_status_t { matching: false };
        assert_eq!(
            z_querier_get_matching_status(z_querier_loan(&querier), &mut status),
            Z_OK
        );
        assert!(
            status.matching,
            "z_querier_get_matching_status disagrees with the listener it must \
             be computed the same way as"
        );
        assert_log_settles(
            &publisher_seen,
            &[],
            "a remote QUERYABLE must NOT move a PUBLISHER's verdict -- the two \
             scopes are being collapsed",
        );

        // And the departure edge, through the same scope.
        z_undeclare_queryable(z_queryable_move(&mut queryable));
        close_session(&mut peer);
        await_log(
            &querier_seen,
            &[true, false],
            "the querier's verdict must fall when the last remote queryable goes",
        );

        z_undeclare_matching(&mut qmatching);
        z_undeclare_matching(&mut pub_listener);
        z_undeclare_querier(z_querier_move(&mut querier));
        z_undeclare_publisher(z_publisher_move(&mut { pubr }));
        close_session(&mut listener);
    }
}
