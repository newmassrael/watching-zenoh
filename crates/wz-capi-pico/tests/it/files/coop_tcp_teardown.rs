// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The teardown of a session of the cooperative engine over `tcp/`, through the exported `z_*`
//! symbols in the order a pico program tears down: two peers on the loopback, one listening and
//! one dialling, exchange round trips (the listener answers each ping from inside its subscriber's
//! callback, as a ponger does), and then the dialling one puts three last messages, closes, drops
//! its publishers and drops the session. Each of those calls must return within
//! [`STEP_DEADLINE`], with its peer still open and with its peer already closed and gone.
//!
//! The steps run on a thread of their own and the test waits for each with a deadline, so a call
//! that never returns fails the test by name instead of holding the test process.
//!
//! The cooperative engine with the peer role and its read task is the build this needs:
//!
//! ```text
//! cargo test -p wz-capi-pico --no-default-features \
//!     --features engine-coop,peer,multi-thread --test it files::coop_tcp_teardown::
//! ```
#![cfg(all(feature = "engine-coop", feature = "peer", feature = "multi-thread"))]

use std::ffi::{c_void, CStr, CString};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_sample, z_closure_sample_move,
    z_config_default, z_config_loan_mut, z_config_move, z_declare_background_subscriber,
    z_declare_publisher, z_loaned_sample_t, z_open, z_owned_config_t, z_owned_publisher_t,
    z_owned_session_t, z_publisher_drop, z_publisher_loan, z_publisher_move, z_publisher_put,
    z_session_drop, z_session_loan, z_session_loan_mut, z_session_move, z_view_keyexpr_from_str,
    z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert, ZResult, Z_CONFIG_CONNECT_KEY,
    Z_CONFIG_LISTEN_KEY, Z_CONFIG_MODE_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// The longest one teardown call may take. A close waits for the read task to finish the step it
/// is in, and a step after the peer has gone may be a dial again of its endpoint, which a host
/// refuses at once on Linux and after its connect retries on Windows (about two seconds), so the
/// bound leaves room for that and for a loaded runner, and is still far below a call that does not
/// return.
const STEP_DEADLINE: Duration = Duration::from_secs(15);

/// The round trips exchanged before the teardown.
const ROUND_TRIPS: u64 = 50;

/// The answers the dialling session has heard.
static PONGS: AtomicU64 = AtomicU64::new(0);

/// A session or a publisher handed to the thread that tears it down: the handles are the C
/// program's, which pico lets it use from any thread.
struct Handles {
    session: z_owned_session_t,
    publishers: Vec<z_owned_publisher_t>,
}

// SAFETY: the ABI's session and publisher handles may be used from any thread, as pico's are; the
// handles are moved to the one thread that tears them down and used by no other.
unsafe impl Send for Handles {}

unsafe fn open(key: u8, endpoint: &str) -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(
            z_config_loan_mut(&mut cfg),
            Z_CONFIG_MODE_KEY,
            c"peer".as_ptr()
        ),
        Z_OK
    );
    let endpoint = CString::new(endpoint).unwrap();
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK,
        "the session opens on {endpoint:?}"
    );
    session
}

unsafe fn publisher(session: &z_owned_session_t, key: &CStr) -> z_owned_publisher_t {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
    let mut publisher: z_owned_publisher_t = std::mem::zeroed();
    assert_eq!(
        z_declare_publisher(
            z_session_loan(session),
            &mut publisher,
            z_view_keyexpr_loan(&ke),
            std::ptr::null(),
        ),
        Z_OK
    );
    publisher
}

unsafe fn put(publisher: &z_owned_publisher_t) -> ZResult {
    let mut payload = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut payload, c"p".as_ptr()), Z_OK);
    z_publisher_put(
        z_publisher_loan(publisher),
        z_bytes_move(&mut payload),
        std::ptr::null(),
    )
}

/// A subscriber with no handle on `key`, calling `call` with `context`, as a pico program
/// declares one it never undeclares.
unsafe fn background(
    session: &z_owned_session_t,
    key: &CStr,
    call: unsafe extern "C" fn(*const z_loaned_sample_t, *mut c_void),
    context: *mut c_void,
) {
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_sample(&mut closure, Some(call), None, context),
        Z_OK
    );
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
    assert_eq!(
        z_declare_background_subscriber(
            z_session_loan(session),
            z_view_keyexpr_loan(&ke),
            z_closure_sample_move(&mut closure),
            std::ptr::null(),
        ),
        Z_OK
    );
}

/// The listener's answer to a ping: a put on the pong key, made from inside the callback.
unsafe extern "C" fn on_ping(_sample: *const z_loaned_sample_t, context: *mut c_void) {
    let pong = &*(context as *const z_owned_publisher_t);
    put(pong);
}

unsafe extern "C" fn on_pong(_sample: *const z_loaned_sample_t, _context: *mut c_void) {
    PONGS.fetch_add(1, Ordering::SeqCst);
}

/// The two peers, after [`ROUND_TRIPS`] round trips: the listener and the dialler, each with its
/// publishers. The listener's pong publisher is boxed, since its callback reads it by address.
struct Pair {
    listener: Handles,
    pong: Box<z_owned_publisher_t>,
    dialler: Handles,
}

unsafe fn pair() -> Pair {
    PONGS.store(0, Ordering::SeqCst);
    let port = free_port();
    let listener = open(Z_CONFIG_LISTEN_KEY, &format!("tcp/127.0.0.1:{port}"));
    let pong = Box::new(publisher(&listener, c"teardown/pong"));
    background(
        &listener,
        c"teardown/ping",
        on_ping,
        &*pong as *const z_owned_publisher_t as *mut c_void,
    );
    let dialler = open(Z_CONFIG_CONNECT_KEY, &format!("tcp/127.0.0.1:{port}"));
    background(&dialler, c"teardown/pong", on_pong, std::ptr::null_mut());
    let ping = publisher(&dialler, c"teardown/ping");
    let stop = publisher(&dialler, c"teardown/stop");
    // Each ping waits for its answer; one sent before the listener's subscriber reached the
    // dialler goes nowhere, so a ping that is not answered soon is sent again.
    for round in 1..=ROUND_TRIPS {
        let deadline = Instant::now() + Duration::from_secs(10);
        'answered: while Instant::now() < deadline {
            assert_eq!(put(&ping), Z_OK);
            let resend = Instant::now() + Duration::from_millis(100);
            while Instant::now() < resend {
                if PONGS.load(Ordering::SeqCst) >= round {
                    break 'answered;
                }
                std::thread::yield_now();
            }
        }
        assert!(
            PONGS.load(Ordering::SeqCst) >= round,
            "round trip {round} was not answered"
        );
    }
    Pair {
        listener: Handles {
            session: listener,
            publishers: Vec::new(),
        },
        pong,
        dialler: Handles {
            session: dialler,
            publishers: vec![ping, stop],
        },
    }
}

impl Handles {
    /// The teardown a pico program makes: three puts on the last publisher, 20 ms apart, when
    /// `puts`; the close; the drop of each publisher; the drop of the session. Each step is told
    /// to `done` as it ends.
    ///
    /// # Safety
    /// The handles are live and used by no other thread.
    unsafe fn tear(mut self, puts: bool, done: &Sender<&'static str>) {
        if puts {
            let last = self.publishers.last().expect("a publisher to put on");
            for _ in 0..3 {
                // Whether the put reached anyone is not this test's question: whether it
                // returned is.
                let _ = put(last);
                let _ = done.send("put");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        z_close(z_session_loan_mut(&mut self.session), std::ptr::null());
        let _ = done.send("z_close");
        for publisher in &mut self.publishers {
            z_publisher_drop(z_publisher_move(publisher));
            let _ = done.send("z_publisher_drop");
        }
        z_session_drop(z_session_move(&mut self.session));
        let _ = done.send("z_session_drop");
    }
}

/// Tear `handles` down on a thread of its own ([`Handles::tear`]); the steps as they end, by
/// name. The thread is handed the whole value through a method that takes it, since a closure that
/// named its fields would capture each field apart, and a field is not `Send`.
fn tear_down(handles: Handles, puts: bool) -> Receiver<&'static str> {
    let (done, steps) = channel();
    // SAFETY: the handles are moved to this thread alone (`Handles`), and each is let go of once.
    std::thread::spawn(move || unsafe { handles.tear(puts, &done) });
    steps
}

/// Wait for each of `expected` in turn, each within [`STEP_DEADLINE`] of the one before.
fn each_step_returns(who: &str, steps: Receiver<&'static str>, expected: &[&str]) {
    for (at, wanted) in expected.iter().enumerate() {
        let started = Instant::now();
        match steps.recv_timeout(STEP_DEADLINE) {
            Ok(step) => assert_eq!(step, *wanted, "{who}: step {at} out of order"),
            Err(_) => panic!(
                "{who}: {wanted} (step {at}) did not return within {:?}",
                started.elapsed()
            ),
        }
    }
}

const DIALLER_STEPS: [&str; 7] = [
    "put",
    "put",
    "put",
    "z_close",
    "z_publisher_drop",
    "z_publisher_drop",
    "z_session_drop",
];

const LISTENER_STEPS: [&str; 2] = ["z_close", "z_session_drop"];

#[test]
fn the_dialling_session_tears_down_in_time_while_its_peer_is_open() {
    // SAFETY: the handles are made here and each is torn down once, on the thread given it.
    let pair = unsafe { pair() };
    each_step_returns(
        "the dialler, its peer open",
        tear_down(pair.dialler, true),
        &DIALLER_STEPS,
    );
    each_step_returns(
        "the listener, after the dialler",
        tear_down(pair.listener, false),
        &LISTENER_STEPS,
    );
    // SAFETY: the listener's session is closed, so no callback reads the pong publisher now.
    unsafe {
        let mut pong = pair.pong;
        z_publisher_drop(z_publisher_move(&mut *pong));
    }
}

#[test]
fn the_dialling_session_tears_down_in_time_after_its_peer_is_gone() {
    // SAFETY: as above.
    let pair = unsafe { pair() };
    each_step_returns(
        "the listener, first",
        tear_down(pair.listener, false),
        &LISTENER_STEPS,
    );
    // SAFETY: as above.
    unsafe {
        let mut pong = pair.pong;
        z_publisher_drop(z_publisher_move(&mut *pong));
    }
    // Long enough for the dialler to read the end of its link and begin to dial again, which is
    // where its teardown then finds it.
    std::thread::sleep(Duration::from_millis(500));
    each_step_returns(
        "the dialler, its peer gone",
        tear_down(pair.dialler, true),
        &DIALLER_STEPS,
    );
}
