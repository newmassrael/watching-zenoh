// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A get addressed to one node through the C door (`wz_ext_get_to_peer`): a session that listens,
//! and two peers that dial it and each answer on the same key.
//!
//! What is held, in the build the test runs in: a plain `z_get` reaches both answering peers (the
//! control, without which a silent queryable would pass every arm below); with the
//! `targeted-query` policy on, a get addressed to one of them asks that one and not the other, and
//! one addressed to a node with no link asks nobody and completes; with the policy off, the door
//! answers `WZ_EXT_ERR_POLICY_OFF`, sends nothing, and has completed the get (the callback's drop
//! ran) before it returns.

#![cfg(all(
    feature = "engine-tokio",
    feature = "peer",
    feature = "query",
    feature = "queryable"
))]

use std::ffi::{c_void, CStr, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_pico::get_to_peer::wz_ext_get_to_peer;
use wz_capi_pico::result::WZ_EXT_ERR_POLICY_OFF;
use wz_capi_pico::zid::{z_id_t, z_info_zid};
use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_query, z_closure_query_move,
    z_closure_reply, z_closure_reply_move, z_config_default, z_config_loan_mut, z_config_move,
    z_declare_queryable, z_get, z_get_options_default, z_get_options_t, z_loaned_query_t,
    z_loaned_reply_t, z_open, z_owned_config_t, z_owned_queryable_t, z_owned_session_t,
    z_query_keyexpr, z_query_reply, z_queryable_move, z_session_drop, z_session_loan,
    z_session_loan_mut, z_session_move, z_undeclare_queryable, z_view_keyexpr_from_str,
    z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert, Z_CONFIG_CONNECT_KEY,
    Z_CONFIG_LISTEN_KEY, Z_CONFIG_MODE_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;
use wz_session_core::policy::SessionPolicy;

const KEY: &CStr = c"demo/target/q";
const BARRIER: Duration = Duration::from_secs(10);

/// How many queries one answering peer's queryable was asked.
unsafe extern "C" fn on_query(query: *const z_loaned_query_t, context: *mut c_void) {
    let asked = &*(context as *const AtomicUsize);
    asked.fetch_add(1, Ordering::SeqCst);
    let mut payload = std::mem::zeroed();
    if z_bytes_copy_from_str(&mut payload, c"answer".as_ptr()) == Z_OK {
        z_query_reply(
            query,
            z_query_keyexpr(query),
            z_bytes_move(&mut payload),
            std::ptr::null(),
        );
    }
}

unsafe extern "C" fn on_query_drop(context: *mut c_void) {
    drop(Arc::from_raw(context as *const AtomicUsize));
}

/// One get's replies, and whether it is over (its callback's drop ran).
#[derive(Clone, Default)]
struct Get {
    replies: Arc<AtomicUsize>,
    done: Arc<AtomicUsize>,
}

unsafe extern "C" fn on_reply(_reply: *mut z_loaned_reply_t, context: *mut c_void) {
    (*(context as *const Get))
        .replies
        .fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn on_reply_drop(context: *mut c_void) {
    let get = Box::from_raw(context as *mut Get);
    get.done.fetch_add(1, Ordering::SeqCst);
}

unsafe fn open(entries: &[(u8, &CStr)]) -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (key, value) in entries {
        assert_eq!(
            zp_config_insert(z_config_loan_mut(&mut cfg), *key, value.as_ptr()),
            Z_OK
        );
    }
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK
    );
    session
}

unsafe fn close(session: &mut z_owned_session_t) {
    z_close(z_session_loan_mut(session), std::ptr::null());
    z_session_drop(z_session_move(session));
}

/// A peer that dials `endpoint` and answers on [`KEY`], counting the queries into `asked`.
unsafe fn answering_peer(
    endpoint: &CStr,
    asked: &Arc<AtomicUsize>,
) -> (z_owned_session_t, z_owned_queryable_t) {
    let session = open(&[
        (Z_CONFIG_CONNECT_KEY, endpoint),
        (Z_CONFIG_MODE_KEY, c"peer"),
    ]);
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_query(
            &mut closure,
            Some(on_query),
            Some(on_query_drop),
            Arc::into_raw(Arc::clone(asked)) as *mut c_void,
        ),
        Z_OK
    );
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, KEY.as_ptr()), Z_OK);
    let mut queryable: z_owned_queryable_t = std::mem::zeroed();
    assert_eq!(
        z_declare_queryable(
            z_session_loan(&session),
            &mut queryable,
            z_view_keyexpr_loan(&view),
            z_closure_query_move(&mut closure),
            std::ptr::null(),
        ),
        Z_OK
    );
    (session, queryable)
}

/// Ask [`KEY`] from `session`, addressed to `peer` through the door or, with `None`, through
/// `z_get`; the code the call answered and the get's counters.
unsafe fn ask(session: &z_owned_session_t, peer: Option<&z_id_t>) -> (i8, Get) {
    let get = Get::default();
    let mut closure = std::mem::zeroed();
    assert_eq!(
        z_closure_reply(
            &mut closure,
            Some(on_reply),
            Some(on_reply_drop),
            Box::into_raw(Box::new(get.clone())).cast::<c_void>(),
        ),
        Z_OK
    );
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, KEY.as_ptr()), Z_OK);
    let mut options: z_get_options_t = std::mem::zeroed();
    z_get_options_default(&mut options);
    let rc = match peer {
        Some(peer) => wz_ext_get_to_peer(
            z_session_loan(session),
            z_view_keyexpr_loan(&view),
            std::ptr::null(),
            z_closure_reply_move(&mut closure),
            &mut options,
            peer,
        ),
        None => z_get(
            z_session_loan(session),
            z_view_keyexpr_loan(&view),
            std::ptr::null(),
            z_closure_reply_move(&mut closure),
            &mut options,
        ),
    };
    (rc, get)
}

/// Wait for the get to be over: its callback's drop ran.
fn finished(get: &Get) {
    let deadline = Instant::now() + BARRIER;
    while get.done.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline, "the get never completed");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_get_addressed_to_one_peer_asks_that_peer_alone_or_is_refused_while_the_policy_is_off() {
    let policy_on = SessionPolicy::from_build().targeted_query();
    let port = free_port();
    let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    // SAFETY: fresh configs, sessions and handles, each closed before the test ends; every
    // context is freed once by its drop.
    unsafe {
        let mut asker = open(&[(Z_CONFIG_LISTEN_KEY, endpoint.as_c_str())]);
        let (asked_a, asked_b) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let (mut a, mut qbl_a) = answering_peer(&endpoint, &asked_a);
        let (mut b, mut qbl_b) = answering_peer(&endpoint, &asked_b);
        let zid_a = z_info_zid(z_session_loan(&a));

        // The control: once both queryables are heard, a plain get reaches both peers.
        let deadline = Instant::now() + BARRIER;
        loop {
            let (rc, get) = ask(&asker, None);
            assert_eq!(rc, Z_OK);
            finished(&get);
            if asked_a.load(Ordering::SeqCst) > 0 && asked_b.load(Ordering::SeqCst) > 0 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "a plain get never reached both peers"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let (before_a, before_b) = (
            asked_a.load(Ordering::SeqCst),
            asked_b.load(Ordering::SeqCst),
        );

        let (rc, get) = ask(&asker, Some(&zid_a));
        if policy_on {
            assert_eq!(rc, Z_OK);
            finished(&get);
            assert!(
                asked_a.load(Ordering::SeqCst) > before_a,
                "the named peer was asked"
            );
            assert!(get.replies.load(Ordering::SeqCst) > 0, "and answered");
            assert_eq!(
                asked_b.load(Ordering::SeqCst),
                before_b,
                "the other peer was not asked"
            );

            // A node the session has no link to is asked by nobody, and the get still completes.
            let nobody = z_id_t { id: [0xee; 16] };
            let (before_a, before_b) = (
                asked_a.load(Ordering::SeqCst),
                asked_b.load(Ordering::SeqCst),
            );
            let (rc, get) = ask(&asker, Some(&nobody));
            assert_eq!(rc, Z_OK);
            finished(&get);
            assert_eq!(get.replies.load(Ordering::SeqCst), 0);
            assert_eq!(asked_a.load(Ordering::SeqCst), before_a);
            assert_eq!(asked_b.load(Ordering::SeqCst), before_b);
        } else {
            assert_eq!(
                rc, WZ_EXT_ERR_POLICY_OFF,
                "refused by name with the policy off"
            );
            assert_eq!(
                get.done.load(Ordering::SeqCst),
                1,
                "the get was reported over before the door returned"
            );
            std::thread::sleep(Duration::from_millis(500));
            assert_eq!(get.replies.load(Ordering::SeqCst), 0);
            assert_eq!(
                (
                    asked_a.load(Ordering::SeqCst),
                    asked_b.load(Ordering::SeqCst)
                ),
                (before_a, before_b),
                "nothing was sent to either peer"
            );
        }

        z_undeclare_queryable(z_queryable_move(&mut qbl_a));
        z_undeclare_queryable(z_queryable_move(&mut qbl_b));
        close(&mut a);
        close(&mut b);
        close(&mut asker);
    }
}

/// A null peer is refused, and the get's callback is consumed all the same.
#[test]
fn a_get_to_no_peer_is_refused_and_consumes_its_callback() {
    let port = free_port();
    let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    // SAFETY: as the test above.
    unsafe {
        let mut asker = open(&[(Z_CONFIG_LISTEN_KEY, endpoint.as_c_str())]);
        let get = Get::default();
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_reply(
                &mut closure,
                Some(on_reply),
                Some(on_reply_drop),
                Box::into_raw(Box::new(get.clone())).cast::<c_void>(),
            ),
            Z_OK
        );
        let mut view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut view, KEY.as_ptr()), Z_OK);
        assert_eq!(
            wz_ext_get_to_peer(
                z_session_loan(&asker),
                z_view_keyexpr_loan(&view),
                std::ptr::null(),
                z_closure_reply_move(&mut closure),
                std::ptr::null_mut(),
                std::ptr::null(),
            ),
            wz_capi_pico::Z_ERR_NULL
        );
        assert_eq!(
            get.done.load(Ordering::SeqCst),
            1,
            "the callback was consumed"
        );
        close(&mut asker);
    }
}
