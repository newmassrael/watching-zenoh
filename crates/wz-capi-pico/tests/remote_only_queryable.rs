// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! R311y561 — the QUERYABLE half of the pico ABI's remote-only plane, measured.
//!
//! ## The gap this closes
//!
//! R311y558 measured the pub/sub half (`remote_only_local_delivery.rs`): two
//! independent `Locality::Remote` pins, either alone sufficient, and a probe
//! that ran all three combinations. The query plane has the SAME two-pin
//! structure — `query.rs` declares every queryable `Locality::Remote` (the
//! `Z_FEATURE_LOCAL_QUERYABLE` = 0 default,
//! `vendor/zenoh-pico/CMakeLists.txt:353`) and `get.rs` pins the get's
//! `allowed_destination` to `Locality::Remote` — and NOTHING drove the
//! conjunction. Two comments each citing the other is not a measurement.
//!
//! The get-side pin is additionally load-bearing for SOUNDNESS, not only
//! fidelity: it closes the `allows_local` gate on `Session::query`'s loopback
//! fan, which is what keeps the C application thread out of a reply `call`, and
//! `get.rs` cites this test's subject as half of the `unsafe impl Sync for
//! CReplyClosure` proof. A proof whose premise is unmeasured is a claim.
//!
//! ## What the damage probes measured, and what the FIRST version of this test
//! ## did not measure at all
//!
//! The first version of this file had ARM 1 and ARM 2 only — own-get sees
//! nothing, peer's get is answered — and it passed. It also passed with BOTH
//! `Locality::Remote` pins removed, which means it was measuring something else
//! entirely. The reason is the FACE COUNT: this ABI registers a C queryable as a
//! FACTORY the registry calls per face, so a session with ZERO faces has no
//! queryable instance for a local get to reach and the locality decision is
//! never taken. ARM 1 is a real fidelity assertion, but it is gated by the
//! registry's shape, not by the pins.
//!
//! ARM 3 exists because of that probe. With the peer connected the queryable
//! lives on a face and the locality decision is live, and there the three
//! combinations separate — the same INDEPENDENT / EITHER-ALONE-SUFFICES shape
//! R311y558 found on the pub/sub half:
//!
//! * unpin the get only (`get.rs` `allowed_destination`) -> GREEN (the
//!   queryable's `allowed_origin` filters it);
//! * unpin the queryable only (`query.rs` declare) -> GREEN (the get never
//!   takes the local leg);
//! * unpin BOTH -> RED, the queryable fires one extra time (`left: 2`).
//!
//! So this leg pins the CONJUNCTION, and that is the honest claim: wz's pico ABI
//! does not answer its own get, not that any one line is what stops it.
//!
//! ## Why the arms are in one test
//!
//! "No reply arrived" is satisfied by a broken queryable, a broken get, a broken
//! session and a broken harness alike. The SAME queryable then answers a real
//! peer's get in the same test. Split across two tests, the negative could pass
//! for a reason the positive would have caught, and nothing would relate them.

use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_query, z_closure_query_move,
    z_closure_reply, z_closure_reply_move, z_config_default, z_config_loan_mut, z_config_move,
    z_declare_queryable, z_get, z_get_options_default, z_get_options_t, z_loaned_query_t,
    z_loaned_reply_t, z_open, z_owned_config_t, z_owned_queryable_t, z_owned_session_t,
    z_query_keyexpr, z_query_reply, z_queryable_move, z_session_drop, z_session_loan,
    z_session_loan_mut, z_session_move, z_undeclare_queryable, z_view_keyexpr_from_str,
    z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert, Z_CONFIG_CONNECT_KEY,
    Z_CONFIG_LISTEN_KEY, Z_OK,
};

/// Counts, not flags, on BOTH sides: an over-delivery is visible rather than
/// collapsed into "received", and a queryable that fired without replying is
/// distinguishable from one that never fired.
struct Counters {
    queries: Arc<AtomicUsize>,
    replies: Arc<AtomicUsize>,
}

unsafe extern "C" fn on_query(query: *const z_loaned_query_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const Counters);
    ctx.queries.fetch_add(1, Ordering::SeqCst);
    let ke = z_query_keyexpr(query);
    let mut payload = std::mem::zeroed();
    if z_bytes_copy_from_str(&mut payload, c"queryable-answer".as_ptr()) == Z_OK {
        z_query_reply(query, ke, z_bytes_move(&mut payload), std::ptr::null());
    }
}

unsafe extern "C" fn on_reply(_reply: *mut z_loaned_reply_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const Counters);
    ctx.replies.fetch_add(1, Ordering::SeqCst);
}

use wz_runtime_tokio_test_support::free_port;

unsafe fn open_with(key: u8, endpoint: &std::ffi::CStr) -> Option<z_owned_session_t> {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    if z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()) == Z_OK {
        Some(session)
    } else {
        None
    }
}

/// Issue one `z_get` on `keyexpr` from `session`, counting replies into `ctx`.
unsafe fn get_once(session: &z_owned_session_t, keyexpr: &std::ffi::CStr, ctx: *mut c_void) {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, keyexpr.as_ptr()), Z_OK);
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_reply(&mut closure, Some(on_reply), None, ctx),
        Z_OK
    );
    let mut options: z_get_options_t = std::mem::zeroed();
    z_get_options_default(&mut options);
    assert_eq!(
        z_get(
            z_session_loan(session),
            z_view_keyexpr_loan(&ke),
            std::ptr::null(),
            z_closure_reply_move(&mut closure),
            &mut options,
        ),
        Z_OK
    );
}

/// A pico session's own `z_get` does not reach its own queryable, and the same
/// queryable does answer a real peer.
#[test]
fn a_pico_sessions_own_get_does_not_reach_its_own_queryable() {
    let port = free_port();
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let connect = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();

    unsafe {
        let mut listener = open_with(Z_CONFIG_LISTEN_KEY, &listen).expect("listener z_open failed");

        let queries = Arc::new(AtomicUsize::new(0));
        let replies = Arc::new(AtomicUsize::new(0));
        let ctx = Box::into_raw(Box::new(Counters {
            queries: queries.clone(),
            replies: replies.clone(),
        })) as *mut c_void;

        let mut queryable: z_owned_queryable_t = std::mem::zeroed();
        let mut qclosure = std::mem::zeroed();
        assert_eq!(
            z_closure_query(&mut qclosure, Some(on_query), None, ctx),
            Z_OK
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/qbl".as_ptr()), Z_OK);
        assert_eq!(
            z_declare_queryable(
                z_session_loan(&listener),
                &mut queryable,
                z_view_keyexpr_loan(&ke),
                z_closure_query_move(&mut qclosure),
                std::ptr::null(),
            ),
            Z_OK
        );

        // ARM 1 — the session queries ITSELF, with no peer connected at all.
        get_once(&listener, c"demo/qbl", ctx);
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(
            queries.load(Ordering::SeqCst),
            0,
            "a pico session's own z_get must NOT reach its own queryable: \
             Z_FEATURE_LOCAL_QUERYABLE is 0 in a default zenoh-pico build \
             (vendor/zenoh-pico/CMakeLists.txt:353), so the queryable firing \
             here is a fidelity regression"
        );
        assert_eq!(
            replies.load(Ordering::SeqCst),
            0,
            "and no reply can arrive from a queryable that never fired — \
             asserted separately so a reply synthesised elsewhere would show"
        );

        // ARM 2 — the CALIBRATION. The very same queryable, asked by a real
        // peer over the wire. Without this the two zeros above are satisfied by
        // any broken queryable, get, session or harness.
        let mut dialer = None;
        for _ in 0..250 {
            if let Some(session) = open_with(Z_CONFIG_CONNECT_KEY, &connect) {
                dialer = Some(session);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut dialer = dialer.expect("dialer z_open never succeeded");

        // Re-ask until the declaration has propagated, bounded so a genuine
        // failure fails fast.
        let mut answered = 0usize;
        for _ in 0..250 {
            answered = replies.load(Ordering::SeqCst);
            if answered > 0 {
                break;
            }
            get_once(&dialer, c"demo/qbl", ctx);
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            answered > 0,
            "CALIBRATION FAILED: the queryable answered nothing to a real peer \
             either, so the zeros above measured a broken fixture rather than \
             the Remote-only pins"
        );
        assert!(
            queries.load(Ordering::SeqCst) > 0,
            "and the queryable itself fired for the remote get"
        );

        // ARM 3 — the DISCRIMINATING arm, and the reason ARM 1 alone was not
        // enough. ARM 1 runs against a session with ZERO faces, and a 0-face
        // pico session has no queryable INSTANCE at all: this ABI registers the
        // C queryable as a factory the registry calls per face, so with no face
        // there is nothing for a local get to reach and the `Locality` pins are
        // never consulted. Measured, not reasoned — unpinning both pins leaves
        // ARM 1 green, which is what sent this arm looking for the real gate.
        //
        // Here the peer IS connected, so the queryable exists on a face and the
        // locality decision is live. The dialer declares no queryable, so any
        // firing counted below can only be the listener answering ITSELF.
        let before = queries.load(Ordering::SeqCst);
        get_once(&listener, c"demo/qbl", ctx);
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(
            queries.load(Ordering::SeqCst),
            before,
            "with a face established, a pico session's own z_get STILL must not \
             reach its own queryable — this is the arm the two Locality::Remote \
             pins (query.rs declare + get.rs allowed_destination) actually gate"
        );

        z_undeclare_queryable(z_queryable_move(&mut queryable));
        z_close(z_session_loan_mut(&mut dialer), std::ptr::null());
        z_session_drop(z_session_move(&mut dialer));
        z_close(z_session_loan_mut(&mut listener), std::ptr::null());
        z_session_drop(z_session_move(&mut listener));
        drop(Box::from_raw(ctx as *mut Counters));
    }
}
