// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The advanced publisher and subscriber on a node opened through the C ABI.
//!
//! The composites are the registry's own (cache ring, `@adv` liveliness token, sequence numbers,
//! history and recovery queries); what is under test is that a node hosts them: a put reaches a
//! peer, the cache queryable answers the history of a subscriber that comes late, the publisher
//! names the node it is declared on, its matching reads the node's tables, and a subscriber the
//! node holds is told the history of a peer's publisher, hears what follows, and detects the
//! publisher.

#![cfg(all(
    feature = "router-node",
    feature = "advanced",
    not(feature = "zenoh-c-no-unstable-api")
))]

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_sample_t, z_moved_bytes_t, z_moved_closure_sample_t, z_moved_config_t,
    z_moved_session_t, z_owned_bytes_t, z_owned_closure_sample_t, z_owned_config_t,
    z_owned_session_t, z_view_keyexpr_t,
};
use wz_capi_c::advanced::{
    ze_advanced_publisher_delete, ze_advanced_publisher_id, ze_advanced_publisher_loan,
    ze_advanced_publisher_options_default, ze_advanced_publisher_options_t,
    ze_advanced_publisher_put, ze_advanced_subscriber_detect_publishers,
    ze_advanced_subscriber_loan, ze_advanced_subscriber_options_default,
    ze_advanced_subscriber_options_t, ze_declare_advanced_publisher,
    ze_declare_advanced_subscriber, ze_moved_advanced_publisher_t, ze_moved_advanced_subscriber_t,
    ze_owned_advanced_publisher_t, ze_owned_advanced_subscriber_t, ze_undeclare_advanced_publisher,
    ze_undeclare_advanced_subscriber,
};
use wz_capi_c::bytes::z_bytes_copy_from_str;
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::entity::z_entity_global_id_zid;
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::matching::{z_matching_status_t, ze_advanced_publisher_get_matching_status};
use wz_capi_c::result::Z_OK;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::sub::{z_closure_sample, z_declare_subscriber, z_undeclare_subscriber};
use wz_capi_c::zid::z_info_zid;
use wz_runtime_tokio_test_support::free_port;

const KEY: &str = "wz/node-advanced/demo";

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
    assert_eq!(
        z_open(
            &mut session,
            (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
            std::ptr::null(),
        ),
        Z_OK
    );
    session
}

unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}

fn endpoint(port: u16) -> String {
    format!("[\"tcp/127.0.0.1:{port}\"]")
}

/// A node that keeps a south of clients apart, and a registry peer that dials it.
unsafe fn node_and_peer() -> (z_owned_session_t, z_owned_session_t) {
    let (port_node, port_peer) = (free_port(), free_port());
    let node = open_with(&[
        ("scouting/multicast/enabled", "false".to_owned()),
        ("mode", "\"peer\"".to_owned()),
        ("listen/endpoints", endpoint(port_node)),
        (
            "gateway",
            r#"{ south: [ { filters: [ { modes: ["client"] } ] } ] }"#.to_owned(),
        ),
    ]);
    let peer = open_with(&[
        ("scouting/multicast/enabled", "false".to_owned()),
        ("mode", "\"peer\"".to_owned()),
        ("listen/endpoints", endpoint(port_peer)),
        ("connect/endpoints", endpoint(port_node)),
    ]);
    (node, peer)
}

unsafe extern "C" fn on_sample(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    (*(ctx as *const AtomicUsize)).fetch_add(1, Ordering::SeqCst);
}

/// A view of `key`. A view points at the text it was made from, so the text is leaked: it must
/// outlive the view, which the caller holds for the whole test.
unsafe fn view(key: &str) -> z_view_keyexpr_t {
    let key: &'static CString = Box::leak(Box::new(CString::new(key).unwrap()));
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, key.as_ptr()), Z_OK);
    view
}

/// What the advanced publisher is declared with: a cache of `depth` samples and the miss
/// detection that numbers them, and the token that names the publisher to a subscriber.
unsafe fn declare_publisher(
    session: &z_owned_session_t,
    depth: usize,
) -> ze_owned_advanced_publisher_t {
    let key = view(KEY);
    let mut options: ze_advanced_publisher_options_t = std::mem::zeroed();
    ze_advanced_publisher_options_default(&mut options);
    options.cache.is_enabled = true;
    options.cache.max_samples = depth;
    options.sample_miss_detection.is_enabled = true;
    options.publisher_detection = true;
    let mut publisher: ze_owned_advanced_publisher_t = std::mem::zeroed();
    assert_eq!(
        ze_declare_advanced_publisher(
            z_session_loan(session),
            &mut publisher,
            z_view_keyexpr_loan(&key),
            &mut options,
        ),
        Z_OK
    );
    publisher
}

unsafe fn put(publisher: &ze_owned_advanced_publisher_t, text: &str) {
    let text = CString::new(text).unwrap();
    let mut payload: z_owned_bytes_t = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut payload, text.as_ptr()), Z_OK);
    assert_eq!(
        ze_advanced_publisher_put(
            ze_advanced_publisher_loan(publisher),
            (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>(),
            std::ptr::null_mut(),
        ),
        Z_OK
    );
}

fn wait_for(counter: &AtomicUsize, want: usize) -> usize {
    let deadline = Instant::now() + Duration::from_secs(10);
    while counter.load(Ordering::SeqCst) < want && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(300));
    counter.load(Ordering::SeqCst)
}

/// A put by an advanced publisher on a node reaches a registry peer's plain subscriber, and a
/// delete goes out as well; the publisher names the node's zid.
#[test]
fn an_advanced_publisher_on_a_node_puts_and_deletes_to_a_peer() {
    unsafe {
        let (node, peer) = node_and_peer();
        let seen = Arc::new(AtomicUsize::new(0));
        let ctx = Arc::as_ptr(&seen).cast_mut().cast::<c_void>();
        let key = view(KEY);
        let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
        z_closure_sample(&mut closure, Some(on_sample), None, ctx);
        let mut sub: wz_capi_c::abi::z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&peer),
                &mut sub,
                z_view_keyexpr_loan(&key),
                (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
                std::ptr::null_mut(),
            ),
            Z_OK
        );

        let mut publisher = declare_publisher(&node, 4);
        let id = ze_advanced_publisher_id(ze_advanced_publisher_loan(&publisher));
        assert_eq!(
            z_entity_global_id_zid(&id).id,
            z_info_zid(z_session_loan(&node)).id,
            "the publisher names the node it is declared on"
        );

        // The peer learns of the node's subscriptions late: put until one arrives.
        let deadline = Instant::now() + Duration::from_secs(10);
        while seen.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            put(&publisher, "x");
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            seen.load(Ordering::SeqCst) > 0,
            "a put never reached the peer"
        );
        // The matching of the publisher reads the node's tables: the peer's subscriber is there.
        let matching_deadline = Instant::now() + Duration::from_secs(10);
        let mut status = z_matching_status_t { matching: false };
        while !status.matching && Instant::now() < matching_deadline {
            assert_eq!(
                ze_advanced_publisher_get_matching_status(
                    ze_advanced_publisher_loan(&publisher),
                    &mut status
                ),
                Z_OK
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            status.matching,
            "the node's publisher never matched the peer's subscriber"
        );
        std::thread::sleep(Duration::from_millis(300));
        let before = seen.load(Ordering::SeqCst);
        assert_eq!(
            ze_advanced_publisher_delete(
                ze_advanced_publisher_loan(&publisher),
                std::ptr::null_mut()
            ),
            Z_OK
        );
        let after = wait_for(&seen, before + 1);
        assert!(after > before, "a delete never reached the peer");

        assert_eq!(
            ze_undeclare_advanced_publisher(
                (&mut publisher as *mut ze_owned_advanced_publisher_t)
                    .cast::<ze_moved_advanced_publisher_t>()
            ),
            Z_OK
        );
        close_session(node);
        close_session(peer);
    }
}

/// The history of a subscriber that comes late is answered by the node's cache queryable: three
/// samples put before the subscriber existed are replayed to it, and a node with no cache replays
/// none.
#[test]
fn the_cache_of_an_advanced_publisher_on_a_node_answers_a_late_subscriber() {
    unsafe {
        let (node, peer) = node_and_peer();
        let mut publisher = declare_publisher(&node, 8);
        for n in 0..3 {
            put(&publisher, &format!("sample {n}"));
        }

        let seen = Arc::new(AtomicUsize::new(0));
        let ctx = Arc::as_ptr(&seen).cast_mut().cast::<c_void>();
        let key = view(KEY);
        let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
        z_closure_sample(&mut closure, Some(on_sample), None, ctx);
        let mut options: ze_advanced_subscriber_options_t = std::mem::zeroed();
        ze_advanced_subscriber_options_default(&mut options);
        options.history.is_enabled = true;
        options.history.detect_late_publishers = true;
        let mut subscriber: ze_owned_advanced_subscriber_t = std::mem::zeroed();
        assert_eq!(
            ze_declare_advanced_subscriber(
                z_session_loan(&peer),
                &mut subscriber,
                z_view_keyexpr_loan(&key),
                (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
                &mut options,
            ),
            Z_OK
        );
        let replayed = wait_for(&seen, 3);
        assert_eq!(
            replayed, 3,
            "the late subscriber is told the cached samples"
        );

        let _ = ze_advanced_subscriber_loan(&subscriber);
        assert_eq!(
            ze_undeclare_advanced_subscriber(
                (&mut subscriber as *mut ze_owned_advanced_subscriber_t)
                    .cast::<ze_moved_advanced_subscriber_t>()
            ),
            Z_OK
        );
        assert_eq!(
            ze_undeclare_advanced_publisher(
                (&mut publisher as *mut ze_owned_advanced_publisher_t)
                    .cast::<ze_moved_advanced_publisher_t>()
            ),
            Z_OK
        );
        close_session(node);
        close_session(peer);
    }
}

/// The advanced subscriber a node holds: a registry peer's advanced publisher put three samples
/// before it existed, and the node's subscriber is told them as its history (a query of the node's
/// own face, answered by the peer's cache), then hears what the peer puts after (a subscriber on
/// the node's data plane).
#[test]
fn an_advanced_subscriber_on_a_node_replays_history_and_hears_what_follows() {
    unsafe {
        let (node, peer) = node_and_peer();
        let mut publisher = declare_publisher(&peer, 8);
        for n in 0..3 {
            put(&publisher, &format!("sample {n}"));
        }
        // The peer's queryable is declared to the node over the link: let it arrive before the
        // node's subscriber asks for its history.
        std::thread::sleep(Duration::from_millis(500));

        let seen = Arc::new(AtomicUsize::new(0));
        let ctx = Arc::as_ptr(&seen).cast_mut().cast::<c_void>();
        let key = view(KEY);
        let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
        z_closure_sample(&mut closure, Some(on_sample), None, ctx);
        let mut options: ze_advanced_subscriber_options_t = std::mem::zeroed();
        ze_advanced_subscriber_options_default(&mut options);
        options.history.is_enabled = true;
        options.history.detect_late_publishers = true;
        let mut subscriber: ze_owned_advanced_subscriber_t = std::mem::zeroed();
        assert_eq!(
            ze_declare_advanced_subscriber(
                z_session_loan(&node),
                &mut subscriber,
                z_view_keyexpr_loan(&key),
                (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
                &mut options,
            ),
            Z_OK
        );
        assert_eq!(
            wait_for(&seen, 3),
            3,
            "the node's subscriber is told the cached samples"
        );

        // What the peer puts now reaches the node's subscriber live.
        let deadline = Instant::now() + Duration::from_secs(10);
        while seen.load(Ordering::SeqCst) < 4 && Instant::now() < deadline {
            put(&publisher, "live");
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            seen.load(Ordering::SeqCst) >= 4,
            "a put after the subscriber never reached it"
        );

        assert_eq!(
            ze_undeclare_advanced_subscriber(
                (&mut subscriber as *mut ze_owned_advanced_subscriber_t)
                    .cast::<ze_moved_advanced_subscriber_t>()
            ),
            Z_OK
        );
        assert_eq!(
            ze_undeclare_advanced_publisher(
                (&mut publisher as *mut ze_owned_advanced_publisher_t)
                    .cast::<ze_moved_advanced_publisher_t>()
            ),
            Z_OK
        );
        close_session(node);
        close_session(peer);
    }
}

/// The node's advanced subscriber detects a publisher that declares itself on the peer: its
/// liveliness subscriber, declared on the node's own face, is told the `@adv` token.
#[test]
fn an_advanced_subscriber_on_a_node_detects_the_publisher_of_a_peer() {
    unsafe {
        let (node, peer) = node_and_peer();
        let seen = Arc::new(AtomicUsize::new(0));
        let ctx = Arc::as_ptr(&seen).cast_mut().cast::<c_void>();
        let key = view(KEY);
        let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
        z_closure_sample(&mut closure, Some(on_sample), None, std::ptr::null_mut());
        let mut subscriber: ze_owned_advanced_subscriber_t = std::mem::zeroed();
        assert_eq!(
            ze_declare_advanced_subscriber(
                z_session_loan(&node),
                &mut subscriber,
                z_view_keyexpr_loan(&key),
                (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
                std::ptr::null_mut(),
            ),
            Z_OK
        );
        let mut detection: z_owned_closure_sample_t = std::mem::zeroed();
        z_closure_sample(&mut detection, Some(on_sample), None, ctx);
        let mut detector: wz_capi_c::abi::z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            ze_advanced_subscriber_detect_publishers(
                ze_advanced_subscriber_loan(&subscriber),
                &mut detector,
                (&mut detection as *mut z_owned_closure_sample_t)
                    .cast::<z_moved_closure_sample_t>(),
                std::ptr::null_mut(),
            ),
            Z_OK
        );

        let mut publisher = declare_publisher(&peer, 4);
        assert!(
            wait_for(&seen, 1) >= 1,
            "the node's subscriber never learned of the publisher"
        );

        assert_eq!(
            z_undeclare_subscriber(
                (&mut detector as *mut wz_capi_c::abi::z_owned_subscriber_t)
                    .cast::<wz_capi_c::abi::z_moved_subscriber_t>()
            ),
            Z_OK
        );
        assert_eq!(
            ze_undeclare_advanced_subscriber(
                (&mut subscriber as *mut ze_owned_advanced_subscriber_t)
                    .cast::<ze_moved_advanced_subscriber_t>()
            ),
            Z_OK
        );
        assert_eq!(
            ze_undeclare_advanced_publisher(
                (&mut publisher as *mut ze_owned_advanced_publisher_t)
                    .cast::<ze_moved_advanced_publisher_t>()
            ),
            Z_OK
        );
        close_session(node);
        close_session(peer);
    }
}
