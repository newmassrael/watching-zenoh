// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! Round-2 acceptance gate for §5.27 api-compat-pico: the non-blocking,
//! multi-peer listener.
//!
//! Round 1's `z_open(listen)` awaited the first peer before returning, which
//! was both a divergence and an uncancellable hang, and its listener held one
//! peer. Real pico instead binds, spawns an accept task, and returns
//! immediately with zero peers (`~/zenoh-pico/src/api/api.c:882-942`,
//! `src/transport/manager.c:98-130`), supports declaring subscribers before any
//! peer connects (`src/transport/unicast/accept.c:148-149`), and holds up to
//! `Z_LISTEN_MAX_CONNECTION_NB` = 10 CONCURRENT inbound peers in the one
//! session (`accept.c:85-92`, `include/zenoh-pico/config.h.in:213`) — behaviour
//! pico's own conformance test pins (`tests/z_test_peer_unicast.c`: 10
//! concurrent connectors admitted, the 11th refused).
//!
//! These tests drive the exported `z_*` symbols exactly as a pico C program
//! would. Delivery is proven by bounded publish-until-received convergence
//! loops (a subscriber declaration has to propagate first), so a genuine
//! failure fails fast rather than hanging.

use std::collections::BTreeSet;
use std::ffi::{c_void, CStr, CString};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_drop_callback_t, z_closure_sample,
    z_closure_sample_callback_t, z_closure_sample_move, z_config_default, z_config_loan_mut,
    z_config_move, z_declare_subscriber, z_keyexpr_as_view_string, z_loaned_sample_t, z_open,
    z_owned_config_t, z_owned_session_t, z_owned_subscriber_t, z_put, z_sample_keyexpr,
    z_session_drop, z_session_loan, z_session_loan_mut, z_session_move, z_string_data,
    z_string_len, z_subscriber_move, z_undeclare_subscriber, z_view_keyexpr_from_str,
    z_view_keyexpr_loan, z_view_keyexpr_t, z_view_string_loan, z_view_string_t, zp_config_insert,
    Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_OK,
};

// --- closure contexts ------------------------------------------------------

/// Records every delivered sample's keyexpr — used to prove that samples from
/// DISTINCT peers all reach the one C subscriber.
struct SetCtx {
    seen: Arc<Mutex<BTreeSet<String>>>,
}

/// Flags that a sample arrived — used per-dialer to prove a listener put fanned
/// out to every peer.
struct FlagCtx {
    flag: Arc<AtomicBool>,
}

unsafe extern "C" fn on_sample_record_keyexpr(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const SetCtx);
    let ke = z_sample_keyexpr(sample);
    let mut vs: z_view_string_t = std::mem::zeroed();
    if z_keyexpr_as_view_string(ke, &mut vs) == Z_OK {
        let ls = z_view_string_loan(&vs);
        let data = z_string_data(ls);
        let len = z_string_len(ls);
        if !data.is_null() {
            let bytes = std::slice::from_raw_parts(data as *const u8, len);
            if let Ok(s) = std::str::from_utf8(bytes) {
                ctx.seen.lock().unwrap().insert(s.to_owned());
            }
        }
    }
}

unsafe extern "C" fn on_drop_set(ctx: *mut c_void) {
    drop(Box::from_raw(ctx as *const SetCtx as *mut SetCtx));
}

unsafe extern "C" fn on_sample_flag(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const FlagCtx);
    ctx.flag.store(true, Ordering::SeqCst);
}

unsafe extern "C" fn on_drop_flag(ctx: *mut c_void) {
    drop(Box::from_raw(ctx as *const FlagCtx as *mut FlagCtx));
}

// --- helpers ---------------------------------------------------------------

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

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

/// Open a listener. Returns as soon as the endpoint is BOUND — no peer needed.
unsafe fn open_listen(port: u16) -> z_owned_session_t {
    open_role(port, Z_CONFIG_LISTEN_KEY, "listener")
}

/// Dial a listener. Needs no retry: `z_open(listen)` returns only after its
/// bind, so by the time a test dials, the endpoint is already listening and the
/// dial cannot race the bind (Round 1 bound INSIDE its blocking open, which is
/// why its tests had to retry).
unsafe fn open_connect(port: u16) -> z_owned_session_t {
    open_role(port, Z_CONFIG_CONNECT_KEY, "dialer")
}

unsafe fn declare_sub(
    session: &z_owned_session_t,
    keyexpr: &CStr,
    call: z_closure_sample_callback_t,
    dropfn: z_closure_drop_callback_t,
    ctx: *mut c_void,
) -> z_owned_subscriber_t {
    let mut closure = std::mem::zeroed();
    assert_eq!(z_closure_sample(&mut closure, call, dropfn, ctx), Z_OK);
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
        Z_OK,
        "z_declare_subscriber failed"
    );
    sub
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

unsafe fn close_session(session: &mut z_owned_session_t) {
    z_close(z_session_loan_mut(session), std::ptr::null());
    z_session_drop(z_session_move(session));
}

// --- tests -----------------------------------------------------------------

#[test]
fn listen_open_returns_and_closes_with_no_peer_ever_connected() {
    // Guards BOTH Round-1 listener divergences. R1's `z_open(listen)` awaited
    // the first peer, so with no dialer it blocked forever — and because no
    // session handle existed yet, `z_close` could not interrupt it (the
    // uncancellable hang). pico binds, spawns its accept task, and returns with
    // zero peers and no error.
    //
    // Both halves are bounded by `recv_timeout` so a regression FAILS with a
    // clear message rather than hanging the suite.
    let port = free_port();
    let (opened_tx, opened_rx) = mpsc::channel();
    let (closed_tx, closed_rx) = mpsc::channel();

    let listener = std::thread::spawn(move || unsafe {
        let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
        let mut cfg: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut cfg), Z_OK);
        assert_eq!(
            zp_config_insert(
                z_config_loan_mut(&mut cfg),
                Z_CONFIG_LISTEN_KEY,
                endpoint.as_ptr()
            ),
            Z_OK
        );
        let mut session: z_owned_session_t = std::mem::zeroed();
        let rc = z_open(&mut session, z_config_move(&mut cfg), std::ptr::null());
        let _ = opened_tx.send(rc);

        // Close a listener that never saw a peer: the accept pending inside the
        // loop must be cancellable.
        close_session(&mut session);
        let _ = closed_tx.send(());
    });

    let rc = opened_rx.recv_timeout(Duration::from_secs(10)).expect(
        "z_open(listen) never returned with no peer connected \
         -- the Round-1 blocking accept is back",
    );
    assert_eq!(rc, Z_OK, "z_open(listen) must succeed with zero peers");

    closed_rx.recv_timeout(Duration::from_secs(10)).expect(
        "z_close on a listener that never saw a peer never returned \
         -- the pending accept is uncancellable",
    );
    listener.join().expect("listener thread panicked");
}

#[test]
fn declare_before_peer_is_replayed_when_a_peer_connects() {
    // pico supports declaring subscribers before any peer exists: declarations
    // live in the session's local tables and are pushed to each peer as it
    // connects. Here the listener subscribes with ZERO peers and only then does
    // a dialer connect and publish — so the sample can arrive only if the
    // subscription was recorded in the session's SSOT and replayed onto the new
    // face.
    let port = free_port();
    let seen = Arc::new(Mutex::new(BTreeSet::new()));

    unsafe {
        let mut listener = open_listen(port);

        // Subscribe BEFORE any peer connects.
        let ctx = Box::into_raw(Box::new(SetCtx { seen: seen.clone() })) as *mut c_void;
        let mut sub = declare_sub(
            &listener,
            c"demo/**",
            Some(on_sample_record_keyexpr),
            Some(on_drop_set),
            ctx,
        );

        let mut dialer = open_connect(port);

        let mut got = false;
        for _ in 0..250 {
            if seen.lock().unwrap().contains("demo/a") {
                got = true;
                break;
            }
            put(&dialer, c"demo/a", c"payload");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            got,
            "a subscription declared BEFORE the peer connected was never replayed to it"
        );

        z_undeclare_subscriber(z_subscriber_move(&mut sub));
        close_session(&mut dialer);
        close_session(&mut listener);
    }
}

#[test]
fn listener_holds_two_concurrent_peers_and_fans_out() {
    // pico's listener holds up to Z_LISTEN_MAX_CONNECTION_NB = 10 CONCURRENT
    // inbound peers in the ONE session and refuses only the 11th. A single-peer
    // listener would leave the second dialer permanently unserved (its TCP
    // connect lands in the backlog, but the zenoh handshake never runs, so its
    // `z_open` errors after Z_TRANSPORT_CONNECT_TIMEOUT).
    //
    // Both directions are proven:
    //  - listener -> N: ONE `z_put` on the listener reaches BOTH dialers
    //    (publish fan-out across concurrent faces);
    //  - N -> listener: each dialer's put reaches the listener's ONE subscriber
    //    (per-face inbound dispatch into the single C session).
    let port = free_port();
    let seen = Arc::new(Mutex::new(BTreeSet::new()));
    let got_one = Arc::new(AtomicBool::new(false));
    let got_two = Arc::new(AtomicBool::new(false));

    unsafe {
        let mut listener = open_listen(port);
        let lctx = Box::into_raw(Box::new(SetCtx { seen: seen.clone() })) as *mut c_void;
        let mut lsub = declare_sub(
            &listener,
            c"demo/**",
            Some(on_sample_record_keyexpr),
            Some(on_drop_set),
            lctx,
        );

        // BOTH dialers connect and STAY up — concurrently, not sequentially.
        let mut dialer_one = open_connect(port);
        let mut dialer_two = open_connect(port);

        let ctx_one = Box::into_raw(Box::new(FlagCtx {
            flag: got_one.clone(),
        })) as *mut c_void;
        let ctx_two = Box::into_raw(Box::new(FlagCtx {
            flag: got_two.clone(),
        })) as *mut c_void;
        let mut sub_one = declare_sub(
            &dialer_one,
            c"fan/**",
            Some(on_sample_flag),
            Some(on_drop_flag),
            ctx_one,
        );
        let mut sub_two = declare_sub(
            &dialer_two,
            c"fan/**",
            Some(on_sample_flag),
            Some(on_drop_flag),
            ctx_two,
        );

        // listener -> both peers.
        let mut fanned = false;
        for _ in 0..250 {
            if got_one.load(Ordering::SeqCst) && got_two.load(Ordering::SeqCst) {
                fanned = true;
                break;
            }
            put(&listener, c"fan/x", c"fan-payload");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            fanned,
            "a listener z_put did not reach BOTH peers (one={}, two={}) \
             -- fan-out across concurrent faces failed",
            got_one.load(Ordering::SeqCst),
            got_two.load(Ordering::SeqCst)
        );

        // both peers -> listener.
        let mut both = false;
        for _ in 0..250 {
            {
                let seen = seen.lock().unwrap();
                if seen.contains("demo/one") && seen.contains("demo/two") {
                    both = true;
                    break;
                }
            }
            put(&dialer_one, c"demo/one", c"from-one");
            put(&dialer_two, c"demo/two", c"from-two");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            both,
            "the listener's subscriber did not see BOTH peers' puts (saw {:?}) \
             -- a second concurrent peer was not held",
            seen.lock().unwrap()
        );

        z_undeclare_subscriber(z_subscriber_move(&mut sub_one));
        z_undeclare_subscriber(z_subscriber_move(&mut sub_two));
        z_undeclare_subscriber(z_subscriber_move(&mut lsub));
        close_session(&mut dialer_one);
        close_session(&mut dialer_two);
        close_session(&mut listener);
    }
}
