// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! R311y557 — the pico ABI's REMOTE-ONLY local delivery, pinned by measurement
//! instead of by prose.
//!
//! ## Why this file exists now
//!
//! zenoh-pico's default build sets `Z_FEATURE_LOCAL_SUBSCRIBER` = 0
//! (`vendor/zenoh-pico/CMakeLists.txt:343`), so a real pico session's own
//! `z_put` does NOT reach its own subscriber. wz matches that, and until this
//! round the match rested entirely on two `Locality::Remote` pins written at
//! `put_options` / the declare sites, argued in comments.
//!
//! R311y557 then put a FACE-INDEPENDENT LOCAL PLANE into `wz-capi-core`, which
//! both C ABIs share. The plane's whole job is to deliver a session's own put to
//! its own subscriber — precisely the behaviour this ABI must NOT have. The
//! zenoh-c side wants it; the pico side would be a fidelity regression. A
//! comment asserting they stay apart is exactly the shape this workspace has
//! watched stay wrong for ~87 rounds before.
//!
//! ## What the damage probes measured, which is not what the comments claimed
//!
//! TWO pins are in play — the publish is `Locality::Remote` (`put_options`) and
//! every subscriber is declared `allowed_origin = Locality::Remote`. They are
//! INDEPENDENT and EITHER ALONE SUFFICES, which was not obvious from either
//! site's own comment:
//!
//! * unpin the publish only -> this test stays GREEN (the origin filters it);
//! * unpin the origin only -> still GREEN (the publish never takes the leg);
//! * unpin BOTH -> RED, `left: 1`.
//!
//! So this leg pins the CONJUNCTION, and that is the honest claim to make: it
//! proves wz's pico ABI does not deliver locally, not that any one line is what
//! stops it. The third probe is also the proof that the local plane really is
//! wired into the shared path — remove pico's reasons to decline and it
//! delivers, exactly as the zenoh-c ABI wants it to.
//!
//! ## The calibration arm is not optional
//!
//! "Nothing arrived" is satisfied by a broken subscriber, a broken session and a
//! broken harness alike. So the SAME subscriber, in the same test, then receives
//! a publish from a real peer. Without that arm the negative assertion proves
//! nothing at all.

use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_sample, z_config_default,
    z_config_loan_mut, z_config_move, z_declare_subscriber, z_loaned_sample_t, z_open,
    z_owned_config_t, z_owned_session_t, z_owned_subscriber_t, z_put, z_session_drop,
    z_session_loan, z_session_loan_mut, z_session_move, z_subscriber_move, z_undeclare_subscriber,
    z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert,
    Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_OK,
};

/// Counts callback invocations — a count, not a flag, so an over-delivery is
/// visible rather than collapsed into "received".
struct CountCtx {
    hits: Arc<AtomicUsize>,
}

unsafe extern "C" fn on_sample_count(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const CountCtx);
    ctx.hits.fetch_add(1, Ordering::SeqCst);
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

unsafe fn put_once(session: &z_owned_session_t, keyexpr: &std::ffi::CStr) {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, keyexpr.as_ptr()), Z_OK);
    let mut payload = std::mem::zeroed();
    assert_eq!(
        z_bytes_copy_from_str(&mut payload, c"remote-only-probe".as_ptr()),
        Z_OK
    );
    // NULL options: pico's `z_put` has no locality field in a default build, so
    // the defaults are the WHOLE of what a pico program can ask for here.
    assert_eq!(
        z_put(
            z_session_loan(session),
            z_view_keyexpr_loan(&ke),
            z_bytes_move(&mut payload),
            std::ptr::null(),
        ),
        Z_OK
    );
}

/// A pico session's own `z_put` does not reach its own subscriber, and the same
/// subscriber does receive from a peer.
///
/// The two arms run against ONE subscriber in ONE test on purpose: split across
/// two tests, the negative could pass for a reason the positive would have
/// caught, and nothing would relate them.
#[test]
fn a_pico_sessions_own_put_does_not_reach_its_own_subscriber() {
    let port = free_port();
    let listen = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let connect = std::ffi::CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();

    unsafe {
        let mut listener = open_with(Z_CONFIG_LISTEN_KEY, &listen).expect("listener z_open failed");

        let hits = Arc::new(AtomicUsize::new(0));
        let ctx = Box::into_raw(Box::new(CountCtx { hits: hits.clone() })) as *mut c_void;
        let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_sample(&mut closure, Some(on_sample_count), None, ctx),
            Z_OK
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(
            z_view_keyexpr_from_str(&mut ke, c"demo/local".as_ptr()),
            Z_OK
        );
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&listener),
                &mut subscriber,
                z_view_keyexpr_loan(&ke),
                wz_capi_pico::z_closure_sample_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK
        );

        // ARM 1 — the session publishes to ITSELF, with no peer connected at
        // all. R311y557's local plane would deliver here on the zenoh-c ABI.
        put_once(&listener, c"demo/local");
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "a pico session's own z_put must NOT reach its own subscriber: \
             Z_FEATURE_LOCAL_SUBSCRIBER is 0 in a default zenoh-pico build \
             (vendor/zenoh-pico/CMakeLists.txt:343), so a delivery here is a \
             fidelity regression, not a feature"
        );

        // ARM 2 — the CALIBRATION. The very same subscriber, fed by a real peer
        // over the wire. Without this the assertion above is satisfied by any
        // broken subscriber, session or harness.
        let mut dialer = None;
        for _ in 0..250 {
            if let Some(session) = open_with(Z_CONFIG_CONNECT_KEY, &connect) {
                dialer = Some(session);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut dialer = dialer.expect("dialer z_open never succeeded");

        // Republish until the declaration has propagated, bounded so a genuine
        // failure fails fast — the idiom the other pico legs use.
        let mut delivered = 0usize;
        for _ in 0..250 {
            delivered = hits.load(Ordering::SeqCst);
            if delivered > 0 {
                break;
            }
            put_once(&dialer, c"demo/local");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            delivered > 0,
            "CALIBRATION FAILED: the subscriber received nothing from a real \
             peer either, so the zero above measured a broken fixture rather \
             than the Remote-only pin"
        );

        z_undeclare_subscriber(z_subscriber_move(&mut subscriber));
        z_close(z_session_loan_mut(&mut dialer), std::ptr::null());
        z_session_drop(z_session_move(&mut dialer));
        z_close(z_session_loan_mut(&mut listener), std::ptr::null());
        z_session_drop(z_session_move(&mut listener));
        drop(Box::from_raw(ctx as *mut CountCtx));
    }
}
