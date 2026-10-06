// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A session that SCOUTS: `z_open` of a config that states no endpoint and leaves multicast
//! scouting on, driven through the exported `z_*` symbols as a C program would.
//!
//! A node that is not told where to connect looks for peers and routers on the multicast group
//! and opens a session to the first it finds (a client) or to each it is willing to (a peer).
//! The node to be found here is a bare responder from the runtime, answering with the locator of
//! a wz listener, on a group of its own, so no node outside the test can answer.
//!
//! The real library's rows for the same shapes are diffed in
//! `wz-integration-tests/tests/zenoh_c_scouting_twice_and_diff.rs`; this file holds the rows
//! where no oracle is needed, so a lane without one still reads them.

use std::ffi::{c_void, CString};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_sample_t, z_moved_bytes_t, z_moved_closure_sample_t, z_moved_config_t,
    z_moved_session_t, z_owned_bytes_t, z_owned_closure_sample_t, z_owned_config_t,
    z_owned_session_t, z_owned_subscriber_t, z_view_keyexpr_t,
};
use wz_capi_c::bytes::z_bytes_copy_from_str;
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::put::z_put;
use wz_capi_c::result::{Z_ENETWORK, Z_OK};
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::sub::{z_closure_sample, z_declare_subscriber};
use wz_capi_c::zid::z_info_zid;
use wz_runtime_tokio::scouting_responder::{serve, ResponderIdentity, ScoutingResponder};
use wz_runtime_tokio::{McastSocketConfig, UdpDriver};
use wz_runtime_tokio_test_support::free_port;

const KEYEXPR: &str = "wz/scouting-open/demo";

/// A group of this file's own: the one the default config scouts on is shared with every zenoh
/// node on the host, and these tests are to meet only the responder they start.
fn group(n: u16) -> (Ipv4Addr, u16, String) {
    (
        Ipv4Addr::new(224, 0, 0, 231),
        7480 + n,
        format!("\"224.0.0.231:{}\"", 7480 + n),
    )
}

/// Open with `entries` inserted as json5 values, returning the result code and the session.
unsafe fn open_with(entries: &[(&str, String)]) -> (i8, z_owned_session_t) {
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
    (rc, session)
}

unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}

struct CountCtx {
    hits: Arc<AtomicUsize>,
}

unsafe extern "C" fn on_sample(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    (*(ctx as *const CountCtx))
        .hits
        .fetch_add(1, Ordering::SeqCst);
}

unsafe fn count_samples(session: &z_owned_session_t) -> (Arc<AtomicUsize>, *mut CountCtx) {
    let hits = Arc::new(AtomicUsize::new(0));
    let ctx = Box::into_raw(Box::new(CountCtx { hits: hits.clone() }));
    let mut sub: z_owned_subscriber_t = std::mem::zeroed();
    let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
    z_closure_sample(&mut closure, Some(on_sample), None, ctx.cast());
    let ke = CString::new(KEYEXPR).unwrap();
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
    (hits, ctx)
}

unsafe fn put_until_it_arrives(publisher: &z_owned_session_t, hits: &Arc<AtomicUsize>) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while hits.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        let ke = CString::new(KEYEXPR).unwrap();
        let mut view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
        let text = CString::new("found").unwrap();
        let mut payload: z_owned_bytes_t = std::mem::zeroed();
        assert_eq!(z_bytes_copy_from_str(&mut payload, text.as_ptr()), Z_OK);
        assert_eq!(
            z_put(
                z_session_loan(publisher),
                z_view_keyexpr_loan(&view),
                (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
                std::ptr::null_mut(),
            ),
            Z_OK
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    hits.load(Ordering::SeqCst) > 0
}

/// A responder on `group` that answers every Scout with the Hello of the node `zid` listening at
/// `locator`, until dropped. It is the runtime's own, on a runtime of its own thread.
struct Responder {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Responder {
    fn start(group: Ipv4Addr, port: u16, zid: Vec<u8>, locator: String) -> Self {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, ready) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime for the responder");
            runtime.block_on(async move {
                let driver = UdpDriver::bind_multicast(group, port, McastSocketConfig::default())
                    .await
                    .expect("the responder joins its group");
                let identity = ResponderIdentity::try_new(
                    0x09,
                    wz_runtime_tokio::session_glue::WhatAmI::Peer,
                    zid,
                    vec![locator],
                )
                .expect("a responder identity");
                let responder = ScoutingResponder::new(driver, identity);
                // The group is joined: a Scout sent from here on is heard.
                let _ = ready_tx.send(());
                tokio::select! {
                    _ = serve(responder, |_| {}) => {}
                    _ = stopped => {}
                }
            });
        });
        ready.recv().expect("the responder is up");
        Self {
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A peer that is told nothing finds the node that answers its Scout, opens a session to it,
/// and a sample the found node publishes reaches the peer: the open returns when the connection
/// is up and not after the whole scouting delay, which is what a scouted open is for.
#[test]
fn a_peer_that_scouts_connects_to_the_node_that_answers() {
    let (group_ip, group_port, group_text) = group(1);
    let port = free_port();
    // SAFETY: fresh configs and sessions; `found` is the node the responder names.
    let (rc, found) = unsafe {
        open_with(&[
            ("mode", String::from("\"peer\"")),
            ("scouting/multicast/enabled", String::from("false")),
            ("listen/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
        ])
    };
    assert_eq!(rc, Z_OK);
    // The zid the INIT carries is the one with its trailing zeros trimmed, which is what a
    // Hello names and what the dial checks the link it opened against.
    let padded = unsafe { z_info_zid(z_session_loan(&found)) }.id;
    let wire_len = padded.iter().rposition(|b| *b != 0).map_or(1, |at| at + 1);
    let _responder = Responder::start(
        group_ip,
        group_port,
        padded[..wire_len].to_vec(),
        format!("tcp/127.0.0.1:{port}"),
    );

    let started = Instant::now();
    // SAFETY: a fresh config and session.
    let (rc, finder) = unsafe {
        open_with(&[
            ("mode", String::from("\"peer\"")),
            ("scouting/multicast/address", group_text),
            ("scouting/delay", String::from("5000")),
        ])
    };
    let opened_in = started.elapsed();
    assert_eq!(rc, Z_OK);
    assert!(
        opened_in < Duration::from_secs(4),
        "the open waited its whole scouting delay ({opened_in:?}): it did not connect to the node \
         that answered"
    );
    // SAFETY: the finder is live; `ctx` is freed after it closes.
    let (hits, ctx) = unsafe { count_samples(&finder) };
    // SAFETY: `found` is live.
    assert!(
        unsafe { put_until_it_arrives(&found, &hits) },
        "a sample the found node published never reached the node that found it"
    );
    // SAFETY: both sessions are live and owned here; `ctx` is freed after its session.
    unsafe {
        close_session(finder);
        close_session(found);
        drop(Box::from_raw(ctx));
    }
}

/// A peer with an endpoint of its own whose connection is live opens at once, though it scouts:
/// its start window is its endpoints', and a scouting window beside it would make every such open
/// wait `scouting/delay` for a node nothing owes it. (Measured on the real library: 10 ms.)
#[test]
fn a_peer_with_a_live_endpoint_opens_at_once_though_it_scouts() {
    let (_, _, group_text) = group(5);
    let port = free_port();
    // SAFETY: fresh configs and sessions.
    let (rc, listener) = unsafe {
        open_with(&[
            ("mode", String::from("\"peer\"")),
            ("scouting/multicast/enabled", String::from("false")),
            ("listen/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
        ])
    };
    assert_eq!(rc, Z_OK);
    let started = Instant::now();
    // SAFETY: a fresh config and session.
    let (rc, dialler) = unsafe {
        open_with(&[
            ("mode", String::from("\"peer\"")),
            ("scouting/multicast/address", group_text),
            ("scouting/delay", String::from("3000")),
            ("connect/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
        ])
    };
    let opened_in = started.elapsed();
    assert_eq!(rc, Z_OK);
    assert!(
        opened_in < Duration::from_secs(2),
        "the open took {opened_in:?} with a live endpoint and a 3 s scouting delay: it waited \
         for a scouted node it was not owed"
    );
    // SAFETY: both sessions are live and owned here.
    unsafe {
        close_session(dialler);
        close_session(listener);
    }
}

/// A client that is told nothing finds the node that answers and holds a session to it.
#[test]
fn a_client_that_scouts_connects_to_the_node_that_answers() {
    let (group_ip, group_port, group_text) = group(2);
    let port = free_port();
    // SAFETY: fresh configs and sessions.
    let (rc, found) = unsafe {
        open_with(&[
            ("mode", String::from("\"peer\"")),
            ("scouting/multicast/enabled", String::from("false")),
            ("listen/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
        ])
    };
    assert_eq!(rc, Z_OK);
    let padded = unsafe { z_info_zid(z_session_loan(&found)) }.id;
    let wire_len = padded.iter().rposition(|b| *b != 0).map_or(1, |at| at + 1);
    let _responder = Responder::start(
        group_ip,
        group_port,
        padded[..wire_len].to_vec(),
        format!("tcp/127.0.0.1:{port}"),
    );

    // SAFETY: a fresh config and session.
    let (rc, finder) = unsafe {
        open_with(&[
            ("mode", String::from("\"client\"")),
            ("scouting/multicast/address", group_text),
        ])
    };
    assert_eq!(
        rc, Z_OK,
        "a client that scouts opens once it has found a node"
    );
    // SAFETY: the finder is live; `ctx` is freed after it closes.
    let (hits, ctx) = unsafe { count_samples(&finder) };
    // SAFETY: `found` is live.
    assert!(
        unsafe { put_until_it_arrives(&found, &hits) },
        "a sample the found node published never reached the client that found it"
    );
    // SAFETY: both sessions are live and owned here; `ctx` is freed after its session.
    unsafe {
        close_session(finder);
        close_session(found);
        drop(Box::from_raw(ctx));
    }
}

/// A link that opens to ANOTHER node than the one that answered is not the connection that was
/// wanted: the Hello names a zid, the dial checks the node it reached against it, and a client
/// whose only answer leads to a stranger does not hold a session to it. (Upstream's
/// `open_transport_unicast_with_zid`.)
#[test]
fn a_client_does_not_hold_a_link_to_a_node_other_than_the_one_that_answered() {
    let (group_ip, group_port, group_text) = group(4);
    let port = free_port();
    // SAFETY: fresh configs and sessions; `stranger` listens where the responder points.
    let (rc, stranger) = unsafe {
        open_with(&[
            ("mode", String::from("\"peer\"")),
            ("scouting/multicast/enabled", String::from("false")),
            ("listen/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
        ])
    };
    assert_eq!(rc, Z_OK);
    // The Hello names a zid the listener does not have.
    let _responder = Responder::start(
        group_ip,
        group_port,
        vec![0x42; 8],
        format!("tcp/127.0.0.1:{port}"),
    );
    // SAFETY: a fresh config and session.
    let (rc, session) = unsafe {
        open_with(&[
            ("mode", String::from("\"client\"")),
            ("scouting/multicast/address", group_text),
            ("scouting/timeout", String::from("1500")),
        ])
    };
    assert_eq!(
        rc, Z_ENETWORK,
        "the only node that answered was reached at a locator that holds a different node"
    );
    // SAFETY: a gravestone and a live session, both owned here.
    unsafe {
        close_session(session);
        close_session(stranger);
    }
}

/// A node that answers with a locator nothing listens at is not a node the client can open to:
/// the search goes on until its timeout and the open fails, as it does with no answer at all.
#[test]
fn a_client_does_not_open_to_a_node_whose_locator_refuses() {
    let (group_ip, group_port, group_text) = group(3);
    let dead = free_port();
    let _responder = Responder::start(
        group_ip,
        group_port,
        vec![0x7e; 8],
        format!("tcp/127.0.0.1:{dead}"),
    );
    // SAFETY: a fresh config and session.
    let (rc, session) = unsafe {
        open_with(&[
            ("mode", String::from("\"client\"")),
            ("scouting/multicast/address", group_text),
            ("scouting/timeout", String::from("1500")),
        ])
    };
    assert_eq!(rc, Z_ENETWORK);
    // SAFETY: a gravestone drops as a no-op.
    unsafe { close_session(session) };
}
