// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A publisher's matching listener the cooperative engine refuses, through the exported `z_*`
//! symbols: the door answers pico's code for the refusal, leaves the handle slot null and has run
//! the closure's `drop(context)` by the time it returns, so a program never holds a listener that
//! would never be called.
//!
//! - Past the session's `MAX_MATCHING_LISTENERS`, lowered by the config's document, a listener is
//!   refused with `Z_ERR_SYSTEM_OUT_OF_MEMORY`, with a handle and in the background alike, as
//!   zenoh-pico refuses one it has no room for.
//! - On a session that is closed, a listener is refused with `Z_ERR_SESSION_CLOSED`.
//!
//! ```text
//! cargo test -p wz-capi-pico --no-default-features \
//!     --features engine-coop,peer,multi-thread,config-document \
//!     --test it files::matching_listener_refused::
//! ```
#![cfg(all(feature = "engine-coop", feature = "peer", feature = "multi-thread"))]

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use wz_capi_pico::matching::{
    z_closure_matching_status, z_closure_matching_status_move, z_internal_matching_listener_check,
    z_matching_status_t, z_owned_closure_matching_status_t, z_owned_matching_listener_t,
    z_publisher_declare_matching_listener,
};
use wz_capi_pico::result::Z_ERR_SESSION_CLOSED;
use wz_capi_pico::{
    z_close, z_config_default, z_config_loan_mut, z_config_move, z_declare_publisher, z_open,
    z_owned_config_t, z_owned_publisher_t, z_owned_session_t, z_publisher_drop, z_publisher_loan,
    z_publisher_move, z_session_drop, z_session_loan, z_session_loan_mut, z_session_move,
    z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert,
    Z_CONFIG_LISTEN_KEY, Z_CONFIG_MODE_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

unsafe extern "C" fn on_status(_status: *const z_matching_status_t, _ctx: *mut c_void) {}

unsafe extern "C" fn on_drop(ctx: *mut c_void) {
    let drops = &*(ctx as *const AtomicUsize);
    drops.fetch_add(1, Ordering::SeqCst);
}

/// A matching closure whose `drop(context)` counts into `drops`.
unsafe fn closure(drops: &Arc<AtomicUsize>) -> z_owned_closure_matching_status_t {
    let mut closure: z_owned_closure_matching_status_t = std::mem::zeroed();
    assert_eq!(
        z_closure_matching_status(
            &mut closure,
            Some(on_status),
            Some(on_drop),
            Arc::as_ptr(drops) as *mut c_void,
        ),
        Z_OK
    );
    closure
}

/// The config of a peer that listens on a port of its own and dials nobody.
unsafe fn listening_config() -> z_owned_config_t {
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
    let endpoint = CString::new(format!("tcp/127.0.0.1:{}", free_port())).unwrap();
    assert_eq!(
        zp_config_insert(
            z_config_loan_mut(&mut cfg),
            Z_CONFIG_LISTEN_KEY,
            endpoint.as_ptr()
        ),
        Z_OK
    );
    cfg
}

unsafe fn open(mut cfg: z_owned_config_t) -> z_owned_session_t {
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK
    );
    session
}

unsafe fn publisher(session: &z_owned_session_t) -> z_owned_publisher_t {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(
        z_view_keyexpr_from_str(&mut ke, c"refused/matching/val".as_ptr()),
        Z_OK
    );
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

/// One listener with a handle on `publisher`, its closure counting into `drops`: the code the
/// door answered, and the handle it left in the slot.
unsafe fn declare(
    publisher: &z_owned_publisher_t,
    drops: &Arc<AtomicUsize>,
) -> (i8, z_owned_matching_listener_t) {
    let mut closure = closure(drops);
    let mut handle: z_owned_matching_listener_t = std::mem::zeroed();
    let code = z_publisher_declare_matching_listener(
        z_publisher_loan(publisher),
        &mut handle,
        z_closure_matching_status_move(&mut closure),
    );
    (code, handle)
}

/// The session's table of matching listeners lowered to one: the second listener is refused with
/// pico's code for an entity it has no room for, its slot is null and its closure's drop has run
/// as the door returns; the background form is refused alike. The CONTROL is the first listener,
/// declared and told apart by a live handle, whose row, given back, takes the next one.
#[cfg(feature = "config-document")]
#[test]
fn a_listener_past_the_sessions_table_is_out_of_memory_and_its_slot_null() {
    use wz_capi_pico::config_policy::wz_ext_config_document;
    use wz_capi_pico::matching::{
        z_matching_listener_move, z_publisher_declare_background_matching_listener,
        z_undeclare_matching_listener,
    };
    use wz_capi_pico::result::{Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_SYSTEM_OUT_OF_MEMORY};
    use wz_capi_pico::z_config_drop;
    use wz_session_core::limit_binding::Quota;
    use wz_session_core::limits::SessionLimits;

    let selectable = SessionLimits::defaults()
        .select_max_matching_listeners(Quota::at_most(1))
        .is_ok();
    let drops = Arc::new(AtomicUsize::new(0));
    // SAFETY: every handle is made here and let go of once; `drops` outlives every closure.
    unsafe {
        let mut cfg = listening_config();
        let stated = wz_ext_config_document(
            z_config_loan_mut(&mut cfg),
            c"{ wz: { limits: { MAX_MATCHING_LISTENERS: 1 } } }".as_ptr(),
        );
        // A build whose domain keeps the limit to its own value refuses the document by name.
        if !selectable {
            assert_eq!(stated, Z_ERR_CONFIG_INVALID_VALUE);
            z_config_drop(z_config_move(&mut cfg));
            return;
        }
        assert_eq!(stated, Z_OK);
        let mut session = open(cfg);
        let mut publisher = publisher(&session);

        let (code, mut first) = declare(&publisher, &drops);
        assert_eq!(code, Z_OK, "CONTROL: a row is free");
        assert!(z_internal_matching_listener_check(&first));

        let (code, refused) = declare(&publisher, &drops);
        assert_eq!(code, Z_ERR_SYSTEM_OUT_OF_MEMORY);
        assert!(
            !z_internal_matching_listener_check(&refused),
            "the refused listener's slot is null"
        );
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "the refused closure's drop ran as the door returned"
        );

        let mut background = closure(&drops);
        assert_eq!(
            z_publisher_declare_background_matching_listener(
                z_publisher_loan(&publisher),
                z_closure_matching_status_move(&mut background),
            ),
            Z_ERR_SYSTEM_OUT_OF_MEMORY
        );
        assert_eq!(drops.load(Ordering::SeqCst), 2);

        z_undeclare_matching_listener(z_matching_listener_move(&mut first));
        assert_eq!(drops.load(Ordering::SeqCst), 3);
        let (code, mut again) = declare(&publisher, &drops);
        assert_eq!(
            code, Z_OK,
            "the row the undeclare gave back takes the next listener"
        );
        z_undeclare_matching_listener(z_matching_listener_move(&mut again));

        z_publisher_drop(z_publisher_move(&mut publisher));
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
    }
    assert_eq!(drops.load(Ordering::SeqCst), 4, "each closure dropped once");
}

/// A listener declared on the publisher of a session that is closed is refused as a closed
/// session's, its slot null and its closure's drop run as the door returns.
#[test]
fn a_listener_on_a_closed_session_is_refused_and_its_slot_null() {
    let drops = Arc::new(AtomicUsize::new(0));
    // SAFETY: every handle is made here and let go of once; `drops` outlives every closure.
    unsafe {
        let mut session = open(listening_config());
        let mut publisher = publisher(&session);
        z_close(z_session_loan_mut(&mut session), std::ptr::null());

        let (code, refused) = declare(&publisher, &drops);
        assert_eq!(code, Z_ERR_SESSION_CLOSED);
        assert!(
            !z_internal_matching_listener_check(&refused),
            "the refused listener's slot is null"
        );
        assert_eq!(
            drops.load(Ordering::SeqCst),
            1,
            "the refused closure's drop ran as the door returned"
        );

        z_publisher_drop(z_publisher_move(&mut publisher));
        z_session_drop(z_session_move(&mut session));
    }
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}
