// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! `scouting/multicast/autoconnect` through `z_open`: which roles a scouting node opens a session
//! to when they answer its Scout, driven through the exported `z_*` symbols as a C program would.
//!
//! The runtime's sink-level rows (`scouting_autoconnect_loopback.rs`) hand the policy to the
//! scouting loop as a value. This file starts at the key: the same peer, the same node answering
//! it, and the key as the only thing that differs, so that what is measured is whether the config
//! reaches the policy the session scouts under.
//!
//! The node that answers is the runtime's bare responder, naming a wz session that listens and
//! does not scout itself, so no path other than the scouting peer's own dial can connect the two:
//! a sample the listener publishes reaches the peer only if the peer dialled it.
//!
//! ## Which of these run where
//!
//! The row needs a multicast datagram to be DELIVERED, and its refused arms assert that a node was
//! NOT dialled, which a host that delivers nothing would pass for the wrong reason. It is
//! `#[ignore]`d and owned by Layer M for the reason `scouting_open.rs` states, and its first arm
//! is the control that shows the host delivers.

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
use wz_capi_c::result::Z_OK;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::sub::{z_closure_sample, z_declare_subscriber};
use wz_capi_c::zid::z_info_zid;
use wz_runtime_tokio::scouting_responder::{serve, ResponderIdentity, ScoutingResponder};
use wz_runtime_tokio::{McastSocketConfig, UdpDriver};
use wz_runtime_tokio_test_support::free_port;

const KEYEXPR: &str = "wz/scouting-autoconnect/demo";

/// A group of this file's own, apart from the ones `scouting_open.rs`, `session_roles.rs` and
/// `scouting_ttl.rs` use: the peer is to meet only the responder the test starts.
fn group(n: u16) -> (Ipv4Addr, u16, String) {
    (
        Ipv4Addr::new(224, 0, 0, 231),
        7660 + n,
        format!("\"224.0.0.231:{}\"", 7660 + n),
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

/// Put from `publisher` every 50 ms until a sample arrives or `span` runs out, and say whether one
/// did. The span of an arm that expects nothing is the time the dial would have taken, with room.
unsafe fn put_for(publisher: &z_owned_session_t, hits: &Arc<AtomicUsize>, span: Duration) -> bool {
    let deadline = Instant::now() + span;
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

/// A peer that scouts opens a session to the node that answers its Scout unless
/// `scouting/multicast/autoconnect` leaves that role out for it.
///
/// Each arm is the same peer, on a group and a listener of its own, with the key as the only
/// difference, and the observable is a sample the listener publishes reaching the peer: nothing
/// but the peer's own dial connects them.
///
/// - Key absent: the control. A peer's default admits peers, so it dials, and the host is shown
///   to deliver the Scout and its answer.
/// - `[]`: an empty list is an instruction and not an absence, so the peer scouts for nobody and
///   dials nobody.
/// - `{ peer: [] }`: the same instruction in the table form, selected by this node's own role.
/// - `{ router: [] }`: a row for another role is no instruction to this node, so the default
///   stays and the peer dials, which keeps the refusals above from being a table that refuses
///   whatever it reads.
#[test]
#[ignore = "multicast loopback e2e; Layer M runs via --layer M / WZ_RUN_LAYER_M=1 --ignored"]
fn a_peer_dials_the_node_that_answers_unless_autoconnect_leaves_its_role_out() {
    let arms: [(u16, Option<&str>, bool); 4] = [
        (1, None, true),
        (2, Some("[]"), false),
        (3, Some("{ peer: [] }"), false),
        (4, Some("{ router: [] }"), true),
    ];
    for (n, autoconnect, dials) in arms {
        let (group_ip, group_port, group_text) = group(n);
        let port = free_port();
        // SAFETY: fresh configs and sessions; `found` is the node the responder names. It does
        // not scout, so it dials nobody.
        let (rc, found) = unsafe {
            open_with(&[
                ("mode", String::from("\"peer\"")),
                ("scouting/multicast/enabled", String::from("false")),
                ("listen/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
            ])
        };
        assert_eq!(rc, Z_OK, "the listener opens ({autoconnect:?})");
        // The zid the INIT carries is the one with its trailing zeros trimmed, which is what a
        // Hello names and what the dial checks the link it opened against.
        // SAFETY: `found` is live.
        let padded = unsafe { z_info_zid(z_session_loan(&found)) }.id;
        let wire_len = padded.iter().rposition(|b| *b != 0).map_or(1, |at| at + 1);
        let _responder = Responder::start(
            group_ip,
            group_port,
            padded[..wire_len].to_vec(),
            format!("tcp/127.0.0.1:{port}"),
        );

        let mut peer = vec![
            ("mode", String::from("\"peer\"")),
            ("scouting/multicast/address", group_text),
            ("scouting/delay", String::from("300")),
        ];
        if let Some(value) = autoconnect {
            peer.push(("scouting/multicast/autoconnect", String::from(value)));
        }
        // SAFETY: a fresh config and session.
        let (rc, finder) = unsafe { open_with(&peer) };
        assert_eq!(rc, Z_OK, "the scouting peer opens ({autoconnect:?})");
        // SAFETY: the finder is live; `ctx` is freed after it closes.
        let (hits, ctx) = unsafe { count_samples(&finder) };
        let span = if dials {
            Duration::from_secs(10)
        } else {
            Duration::from_secs(3)
        };
        // SAFETY: `found` is live.
        let arrived = unsafe { put_for(&found, &hits, span) };
        assert_eq!(
            arrived,
            dials,
            "a peer with `scouting/multicast/autoconnect` = {autoconnect:?} {} the node that \
             answered its Scout",
            if dials {
                "never connected to"
            } else {
                "connected to"
            }
        );
        // SAFETY: both sessions are live and owned here; `ctx` is freed after its session.
        unsafe {
            close_session(finder);
            close_session(found);
            drop(Box::from_raw(ctx));
        }
    }
}
