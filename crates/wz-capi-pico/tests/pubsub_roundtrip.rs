// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! Round-1 acceptance gate for §5.27 api-compat-pico.
//!
//! Drives the exported `z_*` C ABI symbols end-to-end, exactly as a pico C
//! program would: an acceptor session and a dialer session over loopback TCP,
//! the dialer declaring a subscriber and the acceptor publishing, asserting
//! the C-style closure receives the payload. This proves the async-drive
//! bridge (open → spawn drive loop → dispatch → subscriber callback) and the
//! config / keyexpr / bytes / publish / subscribe surface through the real
//! exported symbols.
//!
//! Owned/view structs are created with `zeroed()` — the null state every type
//! reads as "empty" — mirroring a C program's uninitialised stack allocation.
//! Delivery is proven by a publish-until-received convergence loop (the
//! acceptor republishes until the subscriber's declaration has propagated),
//! bounded so a genuine failure fails fast rather than hanging.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_to_slice, z_close, z_closure_sample, z_config_default,
    z_config_loan_mut, z_config_move, z_declare_subscriber, z_keyexpr_as_view_string,
    z_loaned_bytes_t, z_loaned_sample_t, z_loaned_session_t, z_open, z_owned_config_t,
    z_owned_session_t, z_owned_slice_t, z_owned_subscriber_t, z_put, z_sample_keyexpr,
    z_sample_payload, z_session_drop, z_session_loan, z_session_loan_mut, z_session_move,
    z_slice_data, z_slice_drop, z_slice_len, z_slice_loan, z_slice_move, z_string_data,
    z_string_len, z_undeclare_subscriber, z_view_keyexpr_from_str, z_view_keyexpr_loan,
    z_view_keyexpr_t, z_view_string_loan, z_view_string_t, zp_config_insert, Z_CONFIG_CONNECT_KEY,
    Z_CONFIG_LISTEN_KEY, Z_OK,
};

const PAYLOAD: &[u8] = b"hello-wz-capi-pico";

/// Shared context the subscriber closure writes into.
struct Ctx {
    received: Arc<AtomicBool>,
    payload: Arc<Mutex<Vec<u8>>>,
    keyexpr: Arc<Mutex<String>>,
}

/// The C subscriber callback: read the delivered sample the pico way and
/// record it. Runs on the dialer's drive thread.
unsafe extern "C" fn on_sample(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const Ctx);

    // Payload: z_sample_payload -> z_bytes_to_slice -> z_slice_data/len.
    let payload: *const z_loaned_bytes_t = z_sample_payload(sample);
    let mut slice: z_owned_slice_t = std::mem::zeroed();
    if z_bytes_to_slice(payload, &mut slice) == Z_OK {
        let loaned = z_slice_loan(&slice);
        let data = z_slice_data(loaned);
        let len = z_slice_len(loaned);
        if !data.is_null() {
            let bytes = std::slice::from_raw_parts(data, len).to_vec();
            *ctx.payload.lock().unwrap() = bytes;
        }
        z_slice_drop(z_slice_move(&mut slice));
    }

    // Keyexpr: z_sample_keyexpr -> z_keyexpr_as_view_string -> z_string_data/len.
    let ke = z_sample_keyexpr(sample);
    let mut vs: z_view_string_t = std::mem::zeroed();
    if z_keyexpr_as_view_string(ke, &mut vs) == Z_OK {
        let ls = z_view_string_loan(&vs);
        let kdata = z_string_data(ls);
        let klen = z_string_len(ls);
        if !kdata.is_null() {
            let kbytes = std::slice::from_raw_parts(kdata as *const u8, klen);
            if let Ok(s) = std::str::from_utf8(kbytes) {
                *ctx.keyexpr.lock().unwrap() = s.to_owned();
            }
        }
    }

    ctx.received.store(true, Ordering::SeqCst);
}

/// The C drop callback: free the boxed context.
unsafe extern "C" fn on_drop(ctx: *mut c_void) {
    drop(Box::from_raw(ctx as *const Ctx as *mut Ctx));
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn subscriber_receives_publish_over_loopback_tcp() {
    let port = free_port();
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let connect = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();

    let received = Arc::new(AtomicBool::new(false));
    let received_acc = received.clone();

    // Acceptor thread: open (blocks until the dialer connects), then publish
    // `demo/a` until the subscriber has received it (bounded).
    let (started_tx, started_rx) = mpsc::channel::<()>();
    let acceptor = std::thread::spawn(move || unsafe {
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
        // Signal just before the blocking open so the dialer starts dialing.
        let _ = started_tx.send(());
        let mut session: z_owned_session_t = std::mem::zeroed();
        let rc = z_open(&mut session, z_config_move(&mut cfg), std::ptr::null());
        assert_eq!(rc, Z_OK, "acceptor z_open failed");

        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/a".as_ptr()), Z_OK);

        // Publish until the dialer's subscriber receives, or a bounded cap.
        for _ in 0..250 {
            if received_acc.load(Ordering::SeqCst) {
                break;
            }
            let mut payload = std::mem::zeroed();
            assert_eq!(
                z_bytes_copy_from_str(&mut payload, c"hello-wz-capi-pico".as_ptr()),
                Z_OK
            );
            let _ = z_put(
                z_session_loan(&session),
                z_view_keyexpr_loan(&ke),
                wz_capi_pico::z_bytes_move(&mut payload),
                std::ptr::null(),
            );
            std::thread::sleep(Duration::from_millis(20));
        }

        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
    });

    // Wait until the acceptor is about to bind, then dial with retry to cover
    // the residual bind race (a transport-establishment retry, not a flake).
    started_rx.recv().unwrap();

    let mut session: z_owned_session_t = unsafe { std::mem::zeroed() };
    let mut opened = false;
    for _ in 0..250 {
        unsafe {
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
            if z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()) == Z_OK {
                opened = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(opened, "dialer z_open never succeeded");

    // Declare a subscriber over `demo/**` with the C closure.
    let payload_store = Arc::new(Mutex::new(Vec::new()));
    let keyexpr_store = Arc::new(Mutex::new(String::new()));
    let ctx = Box::into_raw(Box::new(Ctx {
        received: received.clone(),
        payload: payload_store.clone(),
        keyexpr: keyexpr_store.clone(),
    })) as *mut c_void;

    let mut subscriber: z_owned_subscriber_t = unsafe { std::mem::zeroed() };
    unsafe {
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_sample(&mut closure, Some(on_sample), Some(on_drop), ctx),
            Z_OK
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/**".as_ptr()), Z_OK);
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&session),
                &mut subscriber,
                z_view_keyexpr_loan(&ke),
                wz_capi_pico::z_closure_sample_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK,
            "z_declare_subscriber failed"
        );
    }

    // Wait (bounded) for delivery.
    let mut got = false;
    for _ in 0..500 {
        if received.load(Ordering::SeqCst) {
            got = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(got, "subscriber never received the published sample");

    assert_eq!(&*payload_store.lock().unwrap(), PAYLOAD, "payload mismatch");
    assert_eq!(
        &*keyexpr_store.lock().unwrap(),
        "demo/a",
        "keyexpr mismatch"
    );

    // Teardown: undeclare (runs the C drop), close, drop.
    unsafe {
        z_undeclare_subscriber(wz_capi_pico::z_subscriber_move(&mut subscriber));
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
    }

    acceptor.join().expect("acceptor thread panicked");
}

// --- publish-from-callback (echo) --------------------------------------------
// A subscriber callback runs on the drive thread (inside the tokio runtime).
// A common pico pattern is to publish in response to a received sample. This
// test asserts that `z_put` from inside `on_sample` delivers (i.e. does NOT
// panic / poison / kill the session's drive thread).

/// Dialer context: publish an echo back from inside the callback.
struct EchoDialerCtx {
    session: *const z_loaned_session_t,
    got: Arc<AtomicBool>,
}

/// Acceptor context: record that the echo arrived.
struct FlagCtx {
    flag: Arc<AtomicBool>,
}

unsafe extern "C" fn on_sample_echo(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const EchoDialerCtx);
    // Publish an echo from WITHIN the callback (drive thread / in-runtime).
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    if z_view_keyexpr_from_str(&mut ke, c"echo/reply".as_ptr()) == Z_OK {
        let mut payload = std::mem::zeroed();
        if z_bytes_copy_from_str(&mut payload, c"echo-back".as_ptr()) == Z_OK {
            let _ = z_put(
                ctx.session,
                z_view_keyexpr_loan(&ke),
                wz_capi_pico::z_bytes_move(&mut payload),
                std::ptr::null(),
            );
        }
    }
    ctx.got.store(true, Ordering::SeqCst);
}

unsafe extern "C" fn on_echo_at_acceptor(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const FlagCtx);
    ctx.flag.store(true, Ordering::SeqCst);
}

unsafe extern "C" fn on_drop_echo(ctx: *mut c_void) {
    drop(Box::from_raw(
        ctx as *const EchoDialerCtx as *mut EchoDialerCtx,
    ));
}
unsafe extern "C" fn on_drop_flag(ctx: *mut c_void) {
    drop(Box::from_raw(ctx as *const FlagCtx as *mut FlagCtx));
}

#[test]
fn publish_from_subscriber_callback_delivers_echo() {
    let port = free_port();
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let connect = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();

    let echo_received = Arc::new(AtomicBool::new(false));
    let echo_received_acc = echo_received.clone();

    let (started_tx, started_rx) = mpsc::channel::<()>();
    let acceptor = std::thread::spawn(move || unsafe {
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
        let _ = started_tx.send(());
        let mut session: z_owned_session_t = std::mem::zeroed();
        assert_eq!(
            z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
            Z_OK,
            "acceptor z_open failed"
        );

        // Subscribe for the echo the dialer's callback will publish.
        let ctx = Box::into_raw(Box::new(FlagCtx {
            flag: echo_received_acc.clone(),
        })) as *mut c_void;
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_sample(
                &mut closure,
                Some(on_echo_at_acceptor),
                Some(on_drop_flag),
                ctx
            ),
            Z_OK
        );
        let mut eke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut eke, c"echo/**".as_ptr()), Z_OK);
        let mut echo_sub: z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&session),
                &mut echo_sub,
                z_view_keyexpr_loan(&eke),
                wz_capi_pico::z_closure_sample_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK
        );

        // Publish demo/a until the echo comes back (bounded).
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/a".as_ptr()), Z_OK);
        for _ in 0..250 {
            if echo_received_acc.load(Ordering::SeqCst) {
                break;
            }
            let mut payload = std::mem::zeroed();
            assert_eq!(
                z_bytes_copy_from_str(&mut payload, c"trigger".as_ptr()),
                Z_OK
            );
            let _ = z_put(
                z_session_loan(&session),
                z_view_keyexpr_loan(&ke),
                wz_capi_pico::z_bytes_move(&mut payload),
                std::ptr::null(),
            );
            std::thread::sleep(Duration::from_millis(20));
        }

        z_undeclare_subscriber(wz_capi_pico::z_subscriber_move(&mut echo_sub));
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
    });

    started_rx.recv().unwrap();

    let mut session: z_owned_session_t = unsafe { std::mem::zeroed() };
    let mut opened = false;
    for _ in 0..250 {
        unsafe {
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
            if z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()) == Z_OK {
                opened = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(opened, "dialer z_open never succeeded");

    let got = Arc::new(AtomicBool::new(false));
    let ctx = Box::into_raw(Box::new(EchoDialerCtx {
        session: unsafe { z_session_loan(&session) },
        got: got.clone(),
    })) as *mut c_void;
    let mut subscriber: z_owned_subscriber_t = unsafe { std::mem::zeroed() };
    unsafe {
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_sample(&mut closure, Some(on_sample_echo), Some(on_drop_echo), ctx),
            Z_OK
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/**".as_ptr()), Z_OK);
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&session),
                &mut subscriber,
                z_view_keyexpr_loan(&ke),
                wz_capi_pico::z_closure_sample_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK
        );
    }

    // The acceptor sets echo_received only if the dialer's callback z_put
    // actually delivered the echo -- i.e. publish-from-callback worked.
    let mut ok = false;
    for _ in 0..500 {
        if echo_received.load(Ordering::SeqCst) {
            ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        ok,
        "echo from the subscriber callback never reached the acceptor \
         (publish-from-callback failed)"
    );
    assert!(got.load(Ordering::SeqCst), "dialer callback never fired");

    unsafe {
        z_undeclare_subscriber(wz_capi_pico::z_subscriber_move(&mut subscriber));
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
    }

    acceptor.join().expect("acceptor thread panicked");
}

/// R311y549 — the SUBSCRIBER plane's re-entrancy probe: a C callback that
/// undeclares its OWN subscriber must RETURN.
///
/// ## Why this test exists, and why it is not about publishing
///
/// [`publish_from_subscriber_callback_delivers_echo`] above proves a callback
/// may re-enter the session to PUBLISH. That is a different lock: `z_put` fans
/// out through the faces registry and never re-takes the observer mutex the
/// dispatch is holding. Undeclaring does re-take it — `Subscriber::teardown`
/// calls `observer.subscribers.unregister(id)` under
/// `R::with_mutex_mut(&self.observer, ..)`, and `TokioRuntime`'s mutex is a
/// plain `std::sync::Mutex`, which is not reentrant.
///
/// R311y535 fixed exactly this shape on the MATCHING plane, with a thread-local
/// delivery guard that makes a re-entrant retirement DECLINE rather than block
/// on its own frame's lock (`faces.rs::MatchingDeliveryGuard`). The four other
/// SSOT sinks — subscriber, queryable, liveliness-subscriber, advanced
/// subscriber — were left with no equivalent, and the project's own debt ledger
/// carries that as an OPEN QUESTION rather than a cleared one: the matching
/// case was found by a flaky test, and nobody had run the equivalent
/// instrumentation on the other four. This is that instrumentation for the
/// first of them.
///
/// ## A deadlock must FAIL, not hang
///
/// The callback sets `entered` before the undeclare and `returned` after, and
/// the assertion is on `returned` within a deadline. A wedged drive thread is
/// leaked rather than joined — there is nothing to join a deadlocked thread
/// with — but the TEST reports a failure naming the two flags, instead of the
/// suite stalling until the harness is killed. `entered && !returned` is the
/// signature of the deadlock; `!entered` is a different (delivery) failure and
/// says so.
#[test]
fn undeclare_from_inside_a_subscriber_callback_does_not_deadlock() {
    let port = free_port();
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let connect = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();

    let (started_tx, started_rx) = mpsc::channel::<()>();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_acc = stop.clone();
    let acceptor = std::thread::spawn(move || unsafe {
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
        let _ = started_tx.send(());
        let mut session: z_owned_session_t = std::mem::zeroed();
        assert_eq!(
            z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
            Z_OK,
            "acceptor z_open failed"
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/a".as_ptr()), Z_OK);
        // Republish until the dialer says it is done: the subscriber's
        // declaration has to propagate first, and one landing suffices.
        for _ in 0..500 {
            if stop_acc.load(Ordering::SeqCst) {
                break;
            }
            let mut payload = std::mem::zeroed();
            assert_eq!(
                z_bytes_copy_from_str(&mut payload, c"trigger".as_ptr()),
                Z_OK
            );
            let _ = z_put(
                z_session_loan(&session),
                z_view_keyexpr_loan(&ke),
                wz_capi_pico::z_bytes_move(&mut payload),
                std::ptr::null(),
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
    });

    started_rx.recv().unwrap();

    let mut session: z_owned_session_t = unsafe { std::mem::zeroed() };
    let mut opened = false;
    for _ in 0..250 {
        unsafe {
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
            if z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()) == Z_OK {
                opened = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(opened, "dialer z_open never succeeded");

    // The handle the callback will undeclare lives in a Box so its address is
    // stable across the thread boundary — which is what a C program does when
    // it hands a subscriber to its own callback's context.
    let handle: Box<z_owned_subscriber_t> = Box::new(unsafe { std::mem::zeroed() });
    let handle = Box::into_raw(handle);
    let entered = Arc::new(AtomicBool::new(false));
    let returned = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let after = Arc::new(AtomicUsize::new(0));
    let ctx = Box::into_raw(Box::new(SelfUndeclareCtx {
        handle,
        entered: entered.clone(),
        returned: returned.clone(),
        dropped: dropped.clone(),
        after: after.clone(),
        done: AtomicBool::new(false),
    })) as *mut c_void;

    unsafe {
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_sample(
                &mut closure,
                Some(on_sample_self_undeclare),
                Some(on_drop_self_undeclare),
                ctx
            ),
            Z_OK
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/**".as_ptr()), Z_OK);
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&session),
                &mut *handle,
                z_view_keyexpr_loan(&ke),
                wz_capi_pico::z_closure_sample_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK
        );
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if returned.load(Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // The acceptor keeps publishing: the `after` window below needs traffic to
    // still be arriving, or "nothing reached the retired callback" would be
    // true of a silent link and would prove nothing.

    let entered_v = entered.load(Ordering::SeqCst);
    let returned_v = returned.load(Ordering::SeqCst);
    assert!(
        entered_v,
        "the subscriber callback never fired, so this leg measured nothing \
         about re-entrant undeclare — the delivery failed first"
    );
    assert!(
        returned_v,
        "the subscriber callback ENTERED z_undeclare_subscriber and never \
         returned: a C callback undeclaring its own subscriber DEADLOCKS. The \
         dispatch holds the observer mutex across the C call and \
         `Subscriber::teardown` re-takes it on the same thread; \
         `std::sync::Mutex` is not reentrant. R311y535 gave the MATCHING plane \
         a thread-local delivery guard for exactly this and the subscriber \
         plane has none. The drive thread is wedged and is leaked rather than \
         joined."
    );

    // The undeclare must have DONE something, not merely returned: the handle
    // is gravestoned and the C `drop(context)` has run. Without these two a
    // `z_undeclare_subscriber` that returned early would satisfy the deadlock
    // assertion above while proving nothing.
    assert!(
        !unsafe { wz_capi_pico::z_internal_subscriber_check(&*handle) },
        "z_undeclare_subscriber returned without gravestoning the handle, so \
         the no-deadlock result above is about a call that did nothing"
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "the C drop(context) never ran, so the undeclare did not release the \
         last Arc<CClosure> — the context is still owned by something and this \
         leg's `after` assertion is measuring a live registration, not a \
         retired one"
    );

    // Keep the acceptor publishing for a further window and assert NOTHING
    // reaches the retired callback. CALIBRATED: with the undeclare skipped,
    // 24 samples land in this same window, so a zero here is a measurement and
    // not a silent link. This is the R311lh take-call-restore
    // question: the deferred-fire cell is TAKEN while the callback runs, so a
    // restore that put it back after the subscriber was unregistered would
    // deliver again — into a context whose C drop has already run.
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        after.load(Ordering::SeqCst),
        0,
        "a sample reached the subscriber callback AFTER it undeclared itself \
         and its C drop(context) had run. The deferred-fire cell is taken \
         across the C call (R311lh); a restore must not resurrect a cell whose \
         subscriber was unregistered while it was taken."
    );

    stop.store(true, Ordering::SeqCst);
    unsafe {
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
        drop(Box::from_raw(handle));
    }
    acceptor.join().expect("acceptor thread panicked");
}

/// Context for [`undeclare_from_inside_a_subscriber_callback_does_not_deadlock`].
struct SelfUndeclareCtx {
    handle: *mut z_owned_subscriber_t,
    entered: Arc<AtomicBool>,
    returned: Arc<AtomicBool>,
    /// Set by the C drop callback — the observable that the undeclare released
    /// the LAST `Arc<CClosure>` rather than merely returning.
    dropped: Arc<AtomicBool>,
    /// Deliveries seen AFTER the undeclare returned. Must stay 0.
    after: Arc<AtomicUsize>,
    /// The undeclare runs ONCE. A second delivery must not touch a handle the
    /// first one already moved.
    done: AtomicBool,
}

unsafe extern "C" fn on_sample_self_undeclare(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const SelfUndeclareCtx);
    if ctx.done.swap(true, Ordering::SeqCst) {
        // Every delivery past the first one is a delivery to a subscriber that
        // has been undeclared, which is what the `after` assertion reads.
        ctx.after.fetch_add(1, Ordering::SeqCst);
        return;
    }
    ctx.entered.store(true, Ordering::SeqCst);
    z_undeclare_subscriber(wz_capi_pico::z_subscriber_move(&mut *ctx.handle));
    ctx.returned.store(true, Ordering::SeqCst);
}

/// The C `drop(context)` — records that it ran and LEAKS the context.
///
/// The leak is the point, and it is what makes the `after` assertion sound. The
/// property under test is "no delivery reaches this callback once it has been
/// undeclared", and the deferred-fire cell is TAKEN while the callback runs
/// (R311lh take-call-restore), so a restore that resurrected a cell whose
/// subscriber had just been unregistered would deliver again. Freeing the
/// context here would make that case a use-after-free — undefined, and
/// therefore unable to distinguish "did not happen" from "happened and read
/// garbage". One leaked context per test process is the price of a probe whose
/// failure mode is an assertion.
unsafe extern "C" fn on_drop_self_undeclare(ctx: *mut c_void) {
    let ctx = &*(ctx as *const SelfUndeclareCtx);
    ctx.dropped.store(true, Ordering::SeqCst);
}
