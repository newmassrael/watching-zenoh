// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A session that GOSSIPS: two peers that each connected to a third come to dial each other,
//! driven through the exported `z_*` symbols as a C program would.
//!
//! A hub listens. Two leaves each connect to the hub and to nothing else, with multicast
//! scouting off on all three, so nothing but what the hub tells them can introduce one leaf to
//! the other. A leaf that listens tells the hub where it is when it connects; the hub tells the
//! other leaf; the other leaf dials it. A peer does not route what it hears from one peer to
//! another, so a sample one leaf publishes reaches the other only through a link of their own:
//! that it arrives IS the introduction.
//!
//! The control is the same shape with leaves that have no listener. Neither can be dialled, so
//! nothing introduces them, and the sample never arrives.
//!
//! Every node here is a wz session. The rows that put the real library in each place are in
//! `wz-integration-tests/tests/zenoh_c_scouting_twice_and_diff.rs`; this file holds the rows
//! where no oracle is needed, so a lane without one still reads them.
//!
//! ## Which of these run where
//!
//! The leaf that listens binds `tcp/[::]:0`, which a peer binds when its config states no
//! listener, and tells the hub the addresses of the host that stands for, without the loopback
//! ones, as upstream does. Reading them needs `getifaddrs`, which only a unix host has here, so
//! the row that needs the leaf to be dialled is unix-only. The control needs no address and runs
//! everywhere.

use std::ffi::{c_void, CString};
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
use wz_runtime_tokio_test_support::free_port;

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

/// Subscribe `session` to `key`; the returned counter is how many samples it has been given.
/// The subscriber and its context live for the rest of the process: a test ends by closing its
/// sessions, which is when the callbacks stop.
unsafe fn count_samples(session: &z_owned_session_t, key: &str) -> Arc<AtomicUsize> {
    let hits = Arc::new(AtomicUsize::new(0));
    let ctx = Box::into_raw(Box::new(CountCtx { hits: hits.clone() }));
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
    hits
}

/// Publish on `key` from `publisher` every 50 ms until `hits` is not zero or `within` has
/// passed. Whether a sample arrived.
unsafe fn put_until_it_arrives(
    publisher: &z_owned_session_t,
    key: &str,
    hits: &Arc<AtomicUsize>,
    within: Duration,
) -> bool {
    let deadline = Instant::now() + within;
    while hits.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        let ke = CString::new(key).unwrap();
        let mut view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
        let text = CString::new("introduced").unwrap();
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

/// A hub that listens on loopback and two leaves that each connect to it and to nothing else,
/// scouting off on all three. `b_listens` says whether the leaf that subscribes has a listener
/// (the default one a peer binds); the other leaf, which publishes, never has.
///
/// Returns whether a sample the publishing leaf put reached the subscribing one within `within`.
unsafe fn leaves_meet(
    key: &str,
    b_listens: bool,
    hub_extra: &[(&str, &str)],
    within: Duration,
) -> bool {
    let port = free_port();
    // What else the hub's config states: the gossip keys a row sets on it.
    let mut hub_entries = vec![
        ("mode", String::from("\"peer\"")),
        ("scouting/multicast/enabled", String::from("false")),
        ("listen/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
    ];
    hub_entries.extend(hub_extra.iter().map(|(k, v)| (*k, (*v).to_owned())));
    let (rc, hub) = open_with(&hub_entries);
    assert_eq!(rc, Z_OK, "the hub opens");

    let mut leaf_entries = vec![
        ("mode", String::from("\"peer\"")),
        ("scouting/multicast/enabled", String::from("false")),
        ("connect/endpoints", format!("[\"tcp/127.0.0.1:{port}\"]")),
    ];
    let mut b_entries = leaf_entries.clone();
    if !b_listens {
        b_entries.push(("listen/endpoints", String::from("[]")));
    }
    // The publishing leaf states an empty listener list: it is what can be dialled by nobody, so
    // the only dial there can be is its own, to the leaf that listens.
    leaf_entries.push(("listen/endpoints", String::from("[]")));

    let (rc, b) = open_with(&b_entries);
    assert_eq!(rc, Z_OK, "the subscribing leaf opens");
    let (rc, c) = open_with(&leaf_entries);
    assert_eq!(rc, Z_OK, "the publishing leaf opens");

    let hits = count_samples(&b, key);
    let arrived = put_until_it_arrives(&c, key, &hits, within);

    close_session(c);
    close_session(b);
    close_session(hub);
    arrived
}

/// A leaf that listens is introduced to a leaf that does not, by the hub both connected to, and
/// the leaf with no listener dials it: what the second publishes, the first hears.
///
/// MEASURED on the real library before this was built: three real peers in this shape hear each
/// other, and a wz peer in any of the three places does too (the differential rows).
#[cfg(unix)]
#[test]
fn a_leaf_with_a_listener_is_introduced_to_a_leaf_that_has_none() {
    // SAFETY: fresh configs and sessions, each closed before the function returns.
    let arrived = unsafe {
        leaves_meet(
            "wz/gossip/introduces/listening",
            true,
            &[],
            Duration::from_secs(10),
        )
    };
    assert!(
        arrived,
        "a sample the leaf with no listener put never reached the leaf with one: nothing \
         introduced them, so the hub did not tell the one where the other is, or the one did not \
         dial it"
    );
}

/// THE CONTROL: with no listener on either leaf there is nobody to dial, and the sample never
/// arrives. It is what makes the row above a measurement of the introduction and not of some
/// other path between the leaves.
#[test]
fn leaves_that_cannot_be_dialled_are_not_introduced() {
    // SAFETY: fresh configs and sessions, each closed before the function returns.
    let arrived = unsafe {
        leaves_meet(
            "wz/gossip/introduces/silent",
            false,
            &[],
            Duration::from_secs(3),
        )
    };
    assert!(
        !arrived,
        "a sample reached a leaf that no one could have dialled and that was told of no one \
         else: it came by a path that is not gossip"
    );
}

/// A hub whose config turns gossip off introduces no one, though the leaf that listens CAN be
/// dialled: the same shape as the row above that meets, with one key on the hub, so the key is
/// what the leaves' apartness is read from. Unix only, for the reason the meeting row is: on a
/// host with no `getifaddrs` the leaf advertises nothing, and this row would hold for that.
#[cfg(unix)]
#[test]
fn a_hub_told_not_to_gossip_introduces_no_one() {
    // SAFETY: fresh configs and sessions, each closed before the function returns.
    let arrived = unsafe {
        leaves_meet(
            "wz/gossip/introduces/hub-off",
            true,
            &[("scouting/gossip/enabled", "false")],
            Duration::from_secs(3),
        )
    };
    assert!(
        !arrived,
        "the hub's config says gossip is off and the leaves met anyway: the key is read and \
         not obeyed"
    );
}

/// A hub whose gossip target is empty tells no one and so introduces no one, though it takes in
/// what its leaves send; the same shape again with a different key on the hub.
#[cfg(unix)]
#[test]
fn a_hub_that_tells_nobody_introduces_no_one() {
    // SAFETY: fresh configs and sessions, each closed before the function returns.
    let arrived = unsafe {
        leaves_meet(
            "wz/gossip/introduces/hub-target-empty",
            true,
            &[("scouting/gossip/target", "{router:[],peer:[]}")],
            Duration::from_secs(3),
        )
    };
    assert!(
        !arrived,
        "the hub's gossip target is empty and the leaves met anyway: the key is read and not \
         obeyed"
    );
}

/// A gossip target that names `client` fails the open, as the real library's does (`-4`,
/// `"client" is not allowed as gossip target`), and one that names only routers and peers, or no
/// one, does not.
#[test]
fn a_gossip_target_that_names_clients_fails_the_open() {
    for (target, opens) in [
        (r#"{peer:["client"]}"#, false),
        (r#"{router:["router"],peer:["router","client"]}"#, false),
        (r#"{peer:["router","peer"]}"#, true),
        ("{peer:[]}", true),
    ] {
        // SAFETY: a fresh config and session, closed before the loop turns.
        let (rc, session) = unsafe {
            open_with(&[
                ("mode", String::from("\"peer\"")),
                ("scouting/multicast/enabled", String::from("false")),
                ("scouting/gossip/target", target.to_owned()),
            ])
        };
        if opens {
            assert_eq!(rc, Z_OK, "a target `{target}` opens a session");
            // SAFETY: the session just opened.
            unsafe { close_session(session) };
        } else {
            assert_eq!(rc, Z_ENETWORK, "a target `{target}` fails the open with -4");
        }
    }
}
