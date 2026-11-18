// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `z_liveliness_get` on a session that holds tokens of its own, driven through the exported
//! symbols as a C program would drive it, on a session that has no peer.
//!
//! The session of this library tells its own liveliness subscribers of its own tokens and answers
//! its own liveliness gets with them, as upstream's does: the token is in the session's own
//! routing tables, which a current-mode interest is answered from beside the peers'. With no peer
//! the only answers are the session's own, so what arrives is exactly what that leg gives.

#![cfg(all(feature = "peer", feature = "liveliness-get"))]

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_reply_t, z_moved_closure_reply_t, z_moved_config_t, z_moved_liveliness_token_t,
    z_moved_session_t, z_owned_closure_reply_t, z_owned_config_t, z_owned_liveliness_token_t,
    z_owned_session_t, z_view_keyexpr_t,
};
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::get::z_closure_reply;
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::liveliness::{
    z_liveliness_declare_token, z_liveliness_get, z_liveliness_undeclare_token,
};
use wz_capi_c::result::Z_OK;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_runtime_tokio_test_support::free_port;

/// Counts the replies a closure is handed and how often it is dropped; the drop is the end of the
/// snapshot.
struct Counts {
    replies: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
}

unsafe extern "C" fn on_reply(_reply: *mut z_loaned_reply_t, ctx: *mut c_void) {
    (*(ctx as *const Counts))
        .replies
        .fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn on_drop(ctx: *mut c_void) {
    (*(ctx as *const Counts))
        .drops
        .fetch_add(1, Ordering::SeqCst);
}

/// A peer that listens on a port of its own and dials nothing: a session with no face.
unsafe fn open_alone() -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (key, value) in [
        ("scouting/multicast/enabled", "false".to_owned()),
        (
            "listen/endpoints",
            format!("[\"tcp/127.0.0.1:{}\"]", free_port()),
        ),
    ] {
        let key = CString::new(key).unwrap();
        let value = CString::new(value).unwrap();
        assert_eq!(
            zc_config_insert_json5(z_config_loan_mut(&mut cfg), key.as_ptr(), value.as_ptr()),
            Z_OK
        );
    }
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(
            &mut session,
            (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
            std::ptr::null()
        ),
        Z_OK
    );
    session
}

unsafe fn view_of(text: &CString) -> z_view_keyexpr_t {
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, text.as_ptr()), Z_OK);
    view
}

/// One liveliness get on `key` with a 1 s timeout, waited for until its closure is dropped.
/// Returns the replies it was handed.
unsafe fn snapshot(session: &z_owned_session_t, key: &str) -> usize {
    let replies = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let ctx = Box::into_raw(Box::new(Counts {
        replies: replies.clone(),
        drops: drops.clone(),
    }));
    let mut closure: z_owned_closure_reply_t = std::mem::zeroed();
    z_closure_reply(&mut closure, Some(on_reply), Some(on_drop), ctx.cast());
    let key = CString::new(key).unwrap();
    let view = view_of(&key);
    let mut options: wz_capi_c::liveliness::z_liveliness_get_options_t = std::mem::zeroed();
    wz_capi_c::liveliness::z_liveliness_get_options_default(&mut options);
    options.timeout_ms = 1000;
    assert_eq!(
        z_liveliness_get(
            z_session_loan(session),
            z_view_keyexpr_loan(&view),
            (&mut closure as *mut z_owned_closure_reply_t).cast::<z_moved_closure_reply_t>(),
            &mut options,
        ),
        Z_OK
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while drops.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "the snapshot ends, and its closure is dropped once"
    );
    let got = replies.load(Ordering::SeqCst);
    drop(Box::from_raw(ctx));
    got
}

/// A liveliness get finds the token the session itself declared, once, and a get on a key the
/// token does not meet finds nothing; once the token is retracted the same get finds nothing.
#[test]
fn a_liveliness_get_finds_the_sessions_own_token() {
    unsafe {
        let mut session = open_alone();
        let ke = CString::new("wz/own-token/a").unwrap();
        let view = view_of(&ke);
        let mut token: z_owned_liveliness_token_t = std::mem::zeroed();
        assert_eq!(
            z_liveliness_declare_token(
                z_session_loan(&session),
                &mut token,
                z_view_keyexpr_loan(&view),
                std::ptr::null(),
            ),
            Z_OK
        );

        assert_eq!(
            snapshot(&session, "wz/own-token/*"),
            1,
            "the session's own token answers its get"
        );
        assert_eq!(
            snapshot(&session, "wz/elsewhere/**"),
            0,
            "a get on another key is not answered by it"
        );

        z_liveliness_undeclare_token(
            (&mut token as *mut z_owned_liveliness_token_t).cast::<z_moved_liveliness_token_t>(),
        );
        assert_eq!(
            snapshot(&session, "wz/own-token/*"),
            0,
            "a retracted token answers nothing"
        );

        let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
        z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
    }
}
