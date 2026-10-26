// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A subscriber callback that blocks for longer than the session lease must not
//! cost the C application its session.
//!
//! ## What this pins
//!
//! The serial drive runs every face and every callback of a pico program on one
//! thread, and since the `serial-drive-own-thread` feature the session runtime
//! is that thread's alone. A callback that blocks is therefore the one thing
//! that could stop the thread that emits KEEPALIVE. zenoh-pico does not have
//! this problem (its lease task is a thread of its own), and a measured run of
//! stock pico `z_pub` into a subscriber whose callback slept 15 s and 35 s
//! showed the same delivery on the pico library and on this one.
//!
//! This test turns that measurement into a gate that holds for any drive model:
//! the far end is a wz-native peer on a runtime of its own, so it keeps running
//! while the C side is blocked and reads the lease the way a real peer does.
//! The C listener advertises capi-pico's 10 s lease, so the callback blocks for
//! longer than that and the peer must still be Established afterwards, and the
//! C side must still deliver a sample that arrives after the block.
//!
//! ## What keeps it non-vacuous
//!
//! The callback proves it entered and proves how long it blocked, and the block
//! is asserted to exceed the lease. Without those two a pass could be a callback
//! that never ran, or one that returned before a lease could have expired.

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_pico::{
    z_close, z_closure_sample, z_closure_sample_move, z_config_default, z_config_loan_mut,
    z_config_move, z_declare_subscriber, z_loaned_sample_t, z_open, z_owned_closure_sample_t,
    z_owned_config_t, z_owned_session_t, z_owned_subscriber_t, z_session_drop, z_session_loan,
    z_session_loan_mut, z_session_move, z_view_keyexpr_from_str, z_view_keyexpr_loan,
    z_view_keyexpr_t, zp_config_insert, Z_CONFIG_LISTEN_KEY, Z_OK,
};

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, TokioSession};
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal, IterationEvent, SessionInitParams, SessionTimeouts, SigningKey,
    WhatAmI,
};
use wz_runtime_tokio::session_open::{
    dial_endpoint, initiate_and_open_session, DialConfig, OpenedSessionParts, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::PlainMutex as WzMutex;
use wz_runtime_tokio_test_support::free_port;

const KEYEXPR: &str = "wz/blocking/data";

/// capi-pico's session lease, which the C listener advertises in its OPEN.
const LEASE: Duration = Duration::from_secs(10);

/// Longer than the lease with room to spare, so a stalled KEEPALIVE emitter is
/// caught by the peer's lease check before the callback returns.
const LONG_BLOCK: Duration = Duration::from_secs(13);

/// The control: well inside the lease, so a failure here is the harness's and
/// not the lease's.
const SHORT_BLOCK: Duration = Duration::from_secs(2);

struct Ctx {
    block: Duration,
    received: Arc<AtomicUsize>,
    entered: Arc<AtomicBool>,
    released: Arc<AtomicBool>,
    blocked_for_ms: Arc<AtomicUsize>,
    released_at: Arc<std::sync::Mutex<Option<Instant>>>,
}

/// What one run observed.
struct Run {
    released_in_time: bool,
    blocked_for: Duration,
    /// When the peer's session ended against when the callback returned: negative is during the
    /// block (the C side stopped sending KEEPALIVE), positive is after it (the C side closed
    /// the session on resuming), `None` is that it did not end.
    ended_ms_after_release: Option<i128>,
    ended_while_blocked: bool,
    delivered_after: bool,
    ended_after_release: bool,
    received_at_release: usize,
    received_now: usize,
}

/// The first sample blocks for the context's `block`; every later one counts.
///
/// # Safety
/// `ctx` is the `Ctx` this test leaked into the closure.
unsafe extern "C" fn on_sample_block_once(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const Ctx);
    let first = ctx.received.fetch_add(1, Ordering::SeqCst) == 0;
    if first {
        let began = Instant::now();
        ctx.entered.store(true, Ordering::SeqCst);
        std::thread::sleep(ctx.block);
        ctx.blocked_for_ms
            .store(began.elapsed().as_millis() as usize, Ordering::SeqCst);
        *ctx.released_at.lock().unwrap() = Some(Instant::now());
        ctx.released.store(true, Ordering::SeqCst);
    }
}

fn init_params(whatami: WhatAmI) -> SessionInitParams {
    let mut zid = vec![0u8; 16];
    getrandom::getrandom(&mut zid).expect("OS entropy");
    SessionInitParams {
        whatami,
        zid,
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 65535,
        lease_ms: 10_000,
        keep_alive: wz_runtime_tokio::session_glue::KeepAliveConf::default(),
        initial_sn: 0,
        cookie: Vec::new(),
        tx_queue: wz_runtime_tokio::session_glue::TxQueueConf::default(),
        link_rx: wz_runtime_tokio::session_glue::LinkRxConf::default(),
        cookie_signing_key: SigningKey::new(vec![0xAB; 32]).expect("32-byte key"),
    }
}

/// A wz-native peer that dials the C listener, publishes a sample every 200 ms,
/// and drives its session until told to stop. It records whether its drive loop
/// reached a terminal state, which is what an expired lease ends in.
fn native_peer(
    endpoint: String,
    ready: mpsc::Sender<()>,
    stop: Arc<tokio::sync::Notify>,
    terminated: Arc<AtomicBool>,
    ended_at: Arc<std::sync::Mutex<Option<Instant>>>,
) {
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
        let OpenedSessionParts {
            mut engine,
            actions,
            inbound,
            writer_handle,
            ..
        } = opened.into_parts();

        let observer = Arc::new(WzMutex::new(ApplicationLayerObserver::new()));
        let session = TokioSession::new(actions.clone(), observer, Arc::new(clock));
        let publisher = session.declare_publisher(KEYEXPR, PublishOptions::put());

        let mut driver = inbound;
        let timeouts = SessionTimeouts::spec_defaults();
        let dispatch_session = session.clone();
        let mut dispatch =
            |event: IterationEvent<'_>| dispatch_session.dispatch_iteration_event(event);
        let _ = ready.send(());

        let pump = drive_session_until_terminal(
            &mut driver,
            &actions,
            &mut engine,
            None,
            &clock,
            &timeouts,
            &mut dispatch,
        );
        let publishing = async {
            loop {
                let _ = publisher.put(b"blocking-callback");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        };
        tokio::select! {
            _ = pump => {
                *ended_at.lock().unwrap() = Some(Instant::now());
                terminated.store(true, Ordering::SeqCst);
            }
            _ = publishing => {}
            _ = stop.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
        }
        drop(writer_handle);
    });
}

fn wait_for<F: Fn() -> bool>(cond: F, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// One run at a time: the serial drive is one thread for the whole process, so
/// a callback blocked in one test would stall the other test's session too.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn run_with_block(block: Duration) -> Run {
    let _one_at_a_time = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let port = free_port();
    let received = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(AtomicBool::new(false));
    let released = Arc::new(AtomicBool::new(false));
    let blocked_for_ms = Arc::new(AtomicUsize::new(0));
    let released_at = Arc::new(std::sync::Mutex::new(None));
    let ended_at = Arc::new(std::sync::Mutex::new(None));
    let ctx = Box::into_raw(Box::new(Ctx {
        block,
        received: received.clone(),
        entered: entered.clone(),
        released: released.clone(),
        blocked_for_ms: blocked_for_ms.clone(),
        released_at: released_at.clone(),
    }));

    let mut session: z_owned_session_t = unsafe { std::mem::zeroed() };
    let mut sub: z_owned_subscriber_t = unsafe { std::mem::zeroed() };
    unsafe {
        let listen = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
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
        assert_eq!(
            z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
            Z_OK
        );
        let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
        assert_eq!(
            z_closure_sample(
                &mut closure,
                Some(on_sample_block_once),
                None,
                ctx as *mut c_void
            ),
            Z_OK
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        let pattern = CString::new(KEYEXPR).unwrap();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, pattern.as_ptr()), Z_OK);
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&session),
                &mut sub,
                z_view_keyexpr_loan(&ke),
                z_closure_sample_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK
        );
    }

    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let stop = Arc::new(tokio::sync::Notify::new());
    let terminated = Arc::new(AtomicBool::new(false));
    let peer = {
        let (stop, terminated, ended_at) = (stop.clone(), terminated.clone(), ended_at.clone());
        let endpoint = format!("tcp/127.0.0.1:{port}");
        std::thread::spawn(move || native_peer(endpoint, ready_tx, stop, terminated, ended_at))
    };
    ready_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the native peer never reached Established");

    // PRECONDITION: the callback ran and is now blocked.
    assert!(
        wait_for(|| entered.load(Ordering::SeqCst), Duration::from_secs(10)),
        "no sample ever reached the C subscriber, so there was no callback to block"
    );

    // THE GATE, part one: ride out the whole block and the lease with it.
    let released_in_time = wait_for(
        || released.load(Ordering::SeqCst),
        block + Duration::from_secs(10),
    );
    let received_at_release = received.load(Ordering::SeqCst);

    // THE GATE, part two: a sample that arrives after the release is delivered.
    let delivered_after = wait_for(
        || received.load(Ordering::SeqCst) > received_at_release + 3,
        Duration::from_secs(10),
    );
    let ended_after_release = terminated.load(Ordering::SeqCst);

    stop.notify_one();
    peer.join().expect("native peer thread panicked");
    unsafe {
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
        drop(Box::from_raw(ctx));
    }

    // WHEN the peer's session ended, against when the callback returned. Reading a flag right
    // after the release cannot tell a session that died of the C side's silence during the
    // block from one the C side closed in the moment it resumed.
    let released_instant = *released_at.lock().unwrap();
    let ended_instant = *ended_at.lock().unwrap();
    let ended_ms_after_release = match (ended_instant, released_instant) {
        (Some(ended), Some(released)) if ended >= released => {
            Some(ended.duration_since(released).as_millis() as i128)
        }
        (Some(ended), Some(released)) => {
            Some(-(released.duration_since(ended).as_millis() as i128))
        }
        _ => None,
    };
    let ended_while_blocked = ended_ms_after_release.is_some_and(|ms| ms < 0);

    Run {
        released_in_time,
        blocked_for: Duration::from_millis(blocked_for_ms.load(Ordering::SeqCst) as u64),
        ended_ms_after_release,
        ended_while_blocked,
        delivered_after,
        ended_after_release,
        received_at_release,
        received_now: received.load(Ordering::SeqCst),
    }
}

/// The control. A callback that blocks for well under the lease must leave the
/// session standing and delivering; if this fails the harness is wrong, and the
/// long-block verdict below means nothing.
#[test]
fn a_callback_that_blocks_briefly_keeps_the_session_and_its_delivery() {
    let run = run_with_block(SHORT_BLOCK);
    assert!(run.released_in_time, "the blocked callback never returned");
    assert!(!run.ended_while_blocked, "the peer's session ended");
    assert!(
        run.delivered_after && !run.ended_after_release,
        "no delivery after the callback returned (at release {}, now {})",
        run.received_at_release,
        run.received_now
    );
}

#[test]
fn a_callback_that_blocks_past_the_lease_keeps_the_session_and_its_delivery() {
    assert!(
        LONG_BLOCK > LEASE + Duration::from_secs(2),
        "the block must outlast the lease or the test proves nothing"
    );
    // The failure this pins is a race the loop lost about one run in four, so a single run
    // passes on a build that has the defect three times in four. `WZ_BLOCKING_REPEAT` runs
    // the case that many times in one process (default 1), which is how a change to the
    // drive loop is checked against it; the hosted lanes run it once.
    let repeats = std::env::var("WZ_BLOCKING_REPEAT")
        .ok()
        .and_then(|text| text.parse::<usize>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(1);
    for attempt in 1..=repeats {
        long_block_run(attempt, repeats);
    }
}

fn long_block_run(attempt: usize, repeats: usize) {
    let run = run_with_block(LONG_BLOCK);
    eprintln!(
        "long block {attempt}/{repeats}: ended_ms_after_release {:?}",
        run.ended_ms_after_release
    );
    assert!(run.released_in_time, "the blocked callback never returned");
    assert!(
        run.blocked_for >= LEASE,
        "the callback blocked for less than the lease, so a stalled KEEPALIVE \
         emitter could not have been caught"
    );
    assert!(
        !run.ended_while_blocked,
        "the peer's session ended {:?} ms after the callback returned (negative: during \
         the block, the C side stopped sending KEEPALIVE and the peer's lease expired)",
        run.ended_ms_after_release
    );
    assert!(
        run.delivered_after && !run.ended_after_release,
        "the session did not keep delivering after the callback returned: it ended {:?} ms \
         after the release (positive: the C side closed it on resuming, judging a peer silent \
         whose frames were waiting unread), received at release {}, now {}",
        run.ended_ms_after_release,
        run.received_at_release,
        run.received_now
    );
}
