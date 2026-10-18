// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! One subscriber session, several peers, each peer on a face of its own: what the drive does
//! when it serves those faces side by side, read through the exported `z_*` symbols.
//!
//! Three claims, one test each:
//!
//! - callbacks of DIFFERENT peers run at the same time. The first callback of each of two peers
//!   waits, inside the callback, for the other peer's first callback to start. A drive that ran
//!   every face on one thread would hold the first callback until its deadline and the second
//!   would never begin, so the wait ending early is the evidence and not a timing guess;
//! - the samples of ONE peer arrive in the order it put them, whatever the other faces do;
//! - closing the session while peers are still putting returns, and once it has returned no
//!   callback is running and none starts: the stop is a barrier over every face, not over one.

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_sample_t, z_moved_bytes_t, z_moved_closure_sample_t, z_moved_config_t,
    z_moved_session_t, z_moved_string_t, z_owned_bytes_t, z_owned_closure_sample_t,
    z_owned_config_t, z_owned_session_t, z_owned_string_t, z_owned_subscriber_t, z_view_keyexpr_t,
};
use wz_capi_c::bytes::{z_bytes_copy_from_str, z_bytes_to_string};
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::publisher::Z_CONGESTION_CONTROL_BLOCK;
use wz_capi_c::put::{z_put, z_put_options_default, z_put_options_t};
use wz_capi_c::result::Z_OK;
use wz_capi_c::sample::z_sample_payload;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::string::{z_string_data, z_string_drop, z_string_len, z_string_loan};
use wz_capi_c::sub::{z_closure_sample, z_declare_subscriber};
use wz_runtime_tokio_test_support::free_port;

/// How long a test waits for something that has to happen.
const PATIENCE: Duration = Duration::from_secs(30);
/// How long a callback waits for its partner in the rendezvous.
const RENDEZVOUS: Duration = Duration::from_secs(10);

/// What the callbacks of one test share.
#[derive(Default)]
struct Shared {
    /// Callbacks running right now.
    in_callback: AtomicUsize,
    /// Callbacks that have finished.
    finished: AtomicUsize,
    /// Per peer: its first `go` callback has started.
    entered: [AtomicBool; 2],
    /// Per peer: its first `go` callback saw the other one start while it waited.
    met: [AtomicBool; 2],
    /// `go` callbacks that have finished. Apart from `finished`, which a late probe sample of the
    /// set-up also moves: counting that one ended the wait before the second callback was done.
    go_done: AtomicUsize,
}

/// A callback's context: one per subscriber, so one per peer.
struct Ctx {
    index: usize,
    shared: Arc<Shared>,
    /// Whether the first `go` sample waits for the other peer's.
    rendezvous: bool,
    /// The numbers the peer put, in the order they arrived.
    seen: Mutex<Vec<u32>>,
    /// How many `p` probe samples arrived.
    probes: AtomicUsize,
}

unsafe fn payload_text(sample: *const z_loaned_sample_t) -> String {
    let bytes = z_sample_payload(sample);
    let mut text: z_owned_string_t = std::mem::zeroed();
    assert_eq!(z_bytes_to_string(bytes, &mut text), Z_OK);
    let loaned = z_string_loan(&text);
    let len = z_string_len(loaned);
    let out = if len == 0 {
        String::new()
    } else {
        String::from_utf8_lossy(std::slice::from_raw_parts(
            z_string_data(loaned).cast::<u8>(),
            len,
        ))
        .into_owned()
    };
    z_string_drop((&mut text as *mut z_owned_string_t).cast::<z_moved_string_t>());
    out
}

unsafe extern "C" fn on_sample(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const Ctx);
    ctx.shared.in_callback.fetch_add(1, Ordering::SeqCst);
    let text = payload_text(sample);
    match text.as_str() {
        "p" => {
            ctx.probes.fetch_add(1, Ordering::SeqCst);
        }
        "go" => {
            let me = ctx.index;
            ctx.shared.entered[me].store(true, Ordering::SeqCst);
            if ctx.rendezvous {
                let other = 1 - me;
                let deadline = Instant::now() + RENDEZVOUS;
                while !ctx.shared.entered[other].load(Ordering::SeqCst) && Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                if ctx.shared.entered[other].load(Ordering::SeqCst) {
                    ctx.shared.met[me].store(true, Ordering::SeqCst);
                }
            }
            ctx.shared.go_done.fetch_add(1, Ordering::SeqCst);
        }
        number => {
            if let Ok(value) = number.parse::<u32>() {
                ctx.seen.lock().unwrap().push(value);
            }
        }
    }
    ctx.shared.finished.fetch_add(1, Ordering::SeqCst);
    ctx.shared.in_callback.fetch_sub(1, Ordering::SeqCst);
}

unsafe fn open_with(entries: &[(&str, String)]) -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (key, value) in entries {
        let key = CString::new(*key).unwrap();
        let value = CString::new(value.as_str()).unwrap();
        assert_eq!(
            zc_config_insert_json5(z_config_loan_mut(&mut cfg), key.as_ptr(), value.as_ptr()),
            Z_OK
        );
    }
    let mut session: z_owned_session_t = std::mem::zeroed();
    let rc = z_open(
        &mut session,
        (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
        std::ptr::null(),
    );
    assert_eq!(rc, Z_OK, "z_open");
    session
}

fn stated(listen: Option<u16>, connect: Option<u16>) -> Vec<(&'static str, String)> {
    let mut entries = vec![
        ("scouting/multicast/enabled", String::from("false")),
        ("mode", String::from("\"peer\"")),
    ];
    if let Some(port) = listen {
        entries.push(("listen/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")));
    }
    if let Some(port) = connect {
        entries.push(("connect/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")));
    }
    entries
}

unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}

unsafe fn subscribe(session: &z_owned_session_t, key: &str, ctx: *mut Ctx) -> z_owned_subscriber_t {
    let mut sub: z_owned_subscriber_t = std::mem::zeroed();
    let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
    z_closure_sample(&mut closure, Some(on_sample), None, ctx.cast());
    let ke = CString::new(key).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    assert_eq!(
        z_declare_subscriber(
            z_session_loan(session),
            &mut sub,
            z_view_keyexpr_loan(&view),
            (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
            std::ptr::null_mut(),
        ),
        Z_OK
    );
    sub
}

/// Put `text` on `key`. `blocking` makes the put wait for room instead of dropping when the link
/// is full: a test that counts samples must not lose any to a policy.
unsafe fn put_text(session: &z_owned_session_t, key: &str, text: &str, blocking: bool) -> i8 {
    let ke = CString::new(key).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    let text = CString::new(text).unwrap();
    let mut payload: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut payload, text.as_ptr()), Z_OK);
    let mut options: z_put_options_t = std::mem::zeroed();
    z_put_options_default(&mut options);
    if blocking {
        options.congestion_control = Z_CONGESTION_CONTROL_BLOCK;
    }
    z_put(
        z_session_loan(session),
        z_view_keyexpr_loan(&view),
        (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
        &mut options,
    )
}

fn key(index: usize) -> String {
    format!("wz/parallel-faces/{index}")
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// One subscriber session with a subscriber per peer, and one session per peer dialling it. A
/// peer is ready once a probe it put on its own key has arrived: the subscription has reached it.
struct Rig {
    listener: Option<z_owned_session_t>,
    peers: Vec<z_owned_session_t>,
    ctxs: Vec<*mut Ctx>,
    _subs: Vec<z_owned_subscriber_t>,
}

impl Rig {
    fn new(peer_count: usize, shared: &Arc<Shared>, rendezvous: bool) -> Rig {
        let port = free_port();
        // SAFETY: fresh configs and sessions, owned by the rig until `finish`.
        let listener = unsafe { open_with(&stated(Some(port), None)) };
        let mut ctxs = Vec::new();
        let mut subs = Vec::new();
        for index in 0..peer_count {
            let ctx = Box::into_raw(Box::new(Ctx {
                index,
                shared: shared.clone(),
                rendezvous,
                seen: Mutex::new(Vec::new()),
                probes: AtomicUsize::new(0),
            }));
            // SAFETY: the listener is live; the context is freed after it closes.
            subs.push(unsafe { subscribe(&listener, &key(index), ctx) });
            ctxs.push(ctx);
        }
        let mut peers = Vec::new();
        for _ in 0..peer_count {
            // SAFETY: a fresh session.
            peers.push(unsafe { open_with(&stated(None, Some(port))) });
        }
        let rig = Rig {
            listener: Some(listener),
            peers,
            ctxs,
            _subs: subs,
        };
        for index in 0..peer_count {
            wait_until("a probe to arrive", || {
                // SAFETY: the peer is live.
                unsafe { put_text(&rig.peers[index], &key(index), "p", false) };
                rig.ctx(index).probes.load(Ordering::SeqCst) > 0
            });
        }
        rig
    }

    fn ctx(&self, index: usize) -> &Ctx {
        // SAFETY: the context is freed only by `finish`, which takes the rig.
        unsafe { &*self.ctxs[index] }
    }

    fn put(&self, index: usize, text: &str, blocking: bool) -> i8 {
        // SAFETY: the peer is live.
        unsafe { put_text(&self.peers[index], &key(index), text, blocking) }
    }

    fn finish(mut self) {
        // SAFETY: every session is live and owned here; the contexts are freed after them.
        unsafe {
            for peer in self.peers.drain(..) {
                close_session(peer);
            }
            if let Some(listener) = self.listener.take() {
                close_session(listener);
            }
            for ctx in self.ctxs.drain(..) {
                drop(Box::from_raw(ctx));
            }
        }
    }
}

#[test]
fn callbacks_of_different_peers_run_at_the_same_time() {
    let shared = Arc::new(Shared::default());
    let rig = Rig::new(2, &shared, true);

    assert_eq!(rig.put(0, "go", true), Z_OK);
    assert_eq!(rig.put(1, "go", true), Z_OK);
    wait_until("both go callbacks to finish", || {
        shared.go_done.load(Ordering::SeqCst) >= 2
    });

    assert!(
        shared.met[0].load(Ordering::SeqCst) && shared.met[1].load(Ordering::SeqCst),
        "each peer's callback must see the other peer's start while it waits: \
         met = [{}, {}]; a drive that serves the faces one after another holds the first callback \
         for the whole {RENDEZVOUS:?} and never starts the second",
        shared.met[0].load(Ordering::SeqCst),
        shared.met[1].load(Ordering::SeqCst),
    );
    rig.finish();
}

#[test]
fn each_peer_keeps_the_order_it_put_in_while_the_others_are_busy() {
    const PEERS: usize = 4;
    const PER_PEER: u32 = 400;
    let shared = Arc::new(Shared::default());
    let rig = Rig::new(PEERS, &shared, false);

    // Interleaved from this thread, so every face has traffic at once.
    for number in 0..PER_PEER {
        for index in 0..PEERS {
            assert_eq!(rig.put(index, &number.to_string(), true), Z_OK);
        }
    }
    wait_until("every sample to arrive", || {
        (0..PEERS).all(|index| rig.ctx(index).seen.lock().unwrap().len() >= PER_PEER as usize)
    });

    for index in 0..PEERS {
        let seen = rig.ctx(index).seen.lock().unwrap().clone();
        let want: Vec<u32> = (0..PER_PEER).collect();
        assert_eq!(
            seen, want,
            "peer {index}: its samples must arrive once each and in the order put"
        );
    }
    rig.finish();
}

/// A raw pointer the flooding thread may hold. The sessions it names outlive the thread.
struct Sessions(Vec<*const z_owned_session_t>);
// SAFETY: a session handle is used through `&` by every door, as a C program shares one.
unsafe impl Send for Sessions {}

#[test]
fn closing_the_session_while_peers_are_putting_leaves_no_callback_behind() {
    const PEERS: usize = 4;
    let shared = Arc::new(Shared::default());
    let mut rig = Rig::new(PEERS, &shared, false);

    let stop = Arc::new(AtomicBool::new(false));
    let sessions = Sessions(rig.peers.iter().map(|peer| peer as *const _).collect());
    let flood = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let sessions = sessions;
            let mut number = 0u32;
            while !stop.load(Ordering::SeqCst) {
                for (index, session) in sessions.0.iter().enumerate() {
                    // SAFETY: the session outlives this thread, which is joined before it closes.
                    // The result is not read: a put to a closed link is an error, and expected.
                    let _ =
                        unsafe { put_text(&**session, &key(index), &number.to_string(), false) };
                }
                number = number.wrapping_add(1);
            }
        })
    };

    wait_until("callbacks to be running", || {
        shared.finished.load(Ordering::SeqCst) > 200
    });

    let listener = rig.listener.take().expect("listener");
    let started = Instant::now();
    // SAFETY: the listener is live and owned here.
    unsafe { close_session(listener) };
    let took = started.elapsed();
    assert!(
        took < Duration::from_secs(10),
        "closing the session took {took:?} while its faces were busy"
    );
    assert_eq!(
        shared.in_callback.load(Ordering::SeqCst),
        0,
        "a callback was still running after the close returned"
    );
    let after_close = shared.finished.load(Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        shared.finished.load(Ordering::SeqCst),
        after_close,
        "a callback started after the close returned"
    );

    stop.store(true, Ordering::SeqCst);
    flood.join().expect("flood thread");
    rig.finish();
}
