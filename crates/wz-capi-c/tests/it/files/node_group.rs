// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A group a node opened through the C ABI joins.
//!
//! A registry peer and a node (a peer that keeps a south of clients apart) are members of one
//! group, and each must find the other. The two orders are two paths: a member that joins first
//! is heard by the one that joins after through its keep-alive beacon alone, which asks for the
//! record the member's own queryable serves; a member that joins after announces itself, and is
//! heard at once. The lease of a member that goes away runs out, and the view says so.

#![cfg(all(
    feature = "router-node",
    feature = "group",
    not(feature = "zenoh-c-no-unstable-api")
))]

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_moved_config_t, z_moved_session_t, z_owned_config_t, z_owned_session_t, z_view_keyexpr_t,
    z_view_string_t,
};
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::group::{
    wz_capi_c_closure_group_event, wz_capi_c_closure_member, wz_capi_c_group_drop,
    wz_capi_c_group_event_kind, wz_capi_c_group_join, wz_capi_c_group_leader, wz_capi_c_group_loan,
    wz_capi_c_group_size, wz_capi_c_group_subscribe, wz_capi_c_group_view,
    wz_capi_c_group_wait_for_view_size, wz_capi_c_loaned_group_event_t, wz_capi_c_loaned_member_t,
    wz_capi_c_member_drop, wz_capi_c_member_id, wz_capi_c_member_loan, wz_capi_c_member_new,
    wz_capi_c_member_options_default, wz_capi_c_member_options_t,
    wz_capi_c_moved_closure_group_event_t, wz_capi_c_moved_closure_member_t,
    wz_capi_c_moved_group_t, wz_capi_c_moved_member_t, wz_capi_c_owned_closure_group_event_t,
    wz_capi_c_owned_closure_member_t, wz_capi_c_owned_group_t, wz_capi_c_owned_member_t,
    WZ_CAPI_C_GROUP_EVENT_KIND_JOIN, WZ_CAPI_C_GROUP_EVENT_KIND_LEASE_EXPIRED,
};
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::result::Z_OK;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::string::{z_string_data, z_string_len, z_view_string_loan};
use wz_runtime_tokio_test_support::free_port;

const GROUP: &str = "wz/node-group/demo";

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

#[derive(Default)]
struct Seen {
    joins: AtomicUsize,
    expired: AtomicUsize,
}

unsafe extern "C" fn on_event(event: *const wz_capi_c_loaned_group_event_t, ctx: *mut c_void) {
    let seen = &*(ctx as *const Seen);
    let kind = wz_capi_c_group_event_kind(event);
    if kind == WZ_CAPI_C_GROUP_EVENT_KIND_JOIN {
        seen.joins.fetch_add(1, Ordering::SeqCst);
    } else if kind == WZ_CAPI_C_GROUP_EVENT_KIND_LEASE_EXPIRED {
        seen.expired.fetch_add(1, Ordering::SeqCst);
    }
}

/// Join `GROUP` as member `id` on `session`. A short lease and a ratio of one half make the
/// beacon come every half second and a member that stops be missed within a few seconds.
unsafe fn join(session: &z_owned_session_t, id: &str) -> wz_capi_c_owned_group_t {
    let id = CString::new(id).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, id.as_ptr()), Z_OK);
    let mut options: wz_capi_c_member_options_t = std::mem::zeroed();
    wz_capi_c_member_options_default(&mut options);
    options.lease_ms = 1_000;
    options.refresh_ratio = 0.5;
    let mut member: wz_capi_c_owned_member_t = std::mem::zeroed();
    assert_eq!(
        wz_capi_c_member_new(&mut member, z_view_keyexpr_loan(&view), &mut options),
        Z_OK
    );
    let _ = wz_capi_c_member_loan(&member);
    let group = CString::new(GROUP).unwrap();
    let mut group_view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(
        z_view_keyexpr_from_str(&mut group_view, group.as_ptr()),
        Z_OK
    );
    let mut joined: wz_capi_c_owned_group_t = std::mem::zeroed();
    assert_eq!(
        wz_capi_c_group_join(
            &mut joined,
            z_session_loan(session),
            z_view_keyexpr_loan(&group_view),
            (&mut member as *mut wz_capi_c_owned_member_t).cast::<wz_capi_c_moved_member_t>(),
        ),
        Z_OK
    );
    joined
}

unsafe fn watch(group: &wz_capi_c_owned_group_t, seen: &Arc<Seen>) {
    let mut closure: wz_capi_c_owned_closure_group_event_t = std::mem::zeroed();
    wz_capi_c_closure_group_event(
        &mut closure,
        Some(on_event),
        None,
        Arc::as_ptr(seen).cast_mut().cast::<c_void>(),
    );
    assert_eq!(
        wz_capi_c_group_subscribe(
            wz_capi_c_group_loan(group),
            (&mut closure as *mut wz_capi_c_owned_closure_group_event_t)
                .cast::<wz_capi_c_moved_closure_group_event_t>(),
        ),
        Z_OK
    );
}

unsafe fn leave(mut group: wz_capi_c_owned_group_t) {
    wz_capi_c_group_drop(
        (&mut group as *mut wz_capi_c_owned_group_t).cast::<wz_capi_c_moved_group_t>(),
    );
}

fn eventually(check: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    check()
}

/// The node joins first, and the peer after: the peer is heard by the node at once (it announces
/// itself), and the node is heard by the peer through its beacon and the record its own queryable
/// serves, which the peer asks for.
#[test]
fn a_node_that_joined_first_is_found_by_a_peer_through_its_beacon_and_its_record() {
    unsafe {
        let (node, peer) = node_and_peer();
        let node_seen = Arc::new(Seen::default());
        let node_group = join(&node, "a-node");
        watch(&node_group, &node_seen);
        assert_eq!(wz_capi_c_group_size(wz_capi_c_group_loan(&node_group)), 1);
        // The node's data plane learns the peer's subscriptions over the link as they are declared.
        std::thread::sleep(Duration::from_millis(500));

        let peer_group = join(&peer, "z-peer");
        assert!(
            wz_capi_c_group_wait_for_view_size(wz_capi_c_group_loan(&node_group), 2, 15_000),
            "the node never heard the peer announce itself"
        );
        assert!(
            wz_capi_c_group_wait_for_view_size(wz_capi_c_group_loan(&peer_group), 2, 15_000),
            "the peer never found the node through its beacon and its record"
        );
        // The view grows before the event is delivered, so the count is waited for.
        assert!(
            eventually(|| node_seen.joins.load(Ordering::SeqCst) >= 1),
            "the node was never told of the join"
        );

        leave(peer_group);
        leave(node_group);
        close_session(node);
        close_session(peer);
    }
}

/// The peer joins first, and the node after: the node hears the peer's beacon and asks it for its
/// record by a query of its own face, and when the peer is gone the lease runs out and the view
/// says so.
#[test]
fn a_node_that_joined_second_finds_a_peer_by_asking_and_misses_it_when_it_is_gone() {
    unsafe {
        let (node, peer) = node_and_peer();
        let peer_group = join(&peer, "z-peer");
        // The peer's queryable is declared to the node over the link: let it arrive.
        std::thread::sleep(Duration::from_millis(500));

        let node_seen = Arc::new(Seen::default());
        let node_group = join(&node, "a-node");
        watch(&node_group, &node_seen);
        // An event reaches the callback from the subscription on, as upstream's `subscribe` has
        // it, and the peer's beacon runs on its own clock: one that lands between the join and
        // the subscription puts the peer in the view with no callback to tell. Read after the
        // subscription, a view of one means the peer is still to come, and its join is told.
        let peer_still_to_come = wz_capi_c_group_size(wz_capi_c_group_loan(&node_group)) == 1;
        assert!(
            wz_capi_c_group_wait_for_view_size(wz_capi_c_group_loan(&node_group), 2, 15_000),
            "the node never learned of the peer from its beacon"
        );
        // The view grows before the event is delivered, so the count is waited for.
        if peer_still_to_come {
            assert!(
                eventually(|| node_seen.joins.load(Ordering::SeqCst) >= 1),
                "the node was never told of the join"
            );
        }

        // The peer goes: its group is left and its session closed, so no beacon comes, and the
        // lease of one second runs out under the node's watchdog.
        leave(peer_group);
        close_session(peer);
        assert!(
            eventually(|| node_seen.expired.load(Ordering::SeqCst) >= 1),
            "the node never missed the peer"
        );
        assert_eq!(wz_capi_c_group_size(wz_capi_c_group_loan(&node_group)), 1);

        leave(node_group);
        close_session(node);
    }
}

/// A node that keeps a south of clients apart, and two registry clients that dial it: the two
/// clients share no link, so all they hear of one another passes through the node.
unsafe fn node_and_two_clients() -> (z_owned_session_t, z_owned_session_t, z_owned_session_t) {
    let port_node = free_port();
    let node = open_with(&[
        ("scouting/multicast/enabled", "false".to_owned()),
        ("mode", "\"peer\"".to_owned()),
        ("listen/endpoints", endpoint(port_node)),
        (
            "gateway",
            r#"{ south: [ { filters: [ { modes: ["client"] } ] } ] }"#.to_owned(),
        ),
    ]);
    let client = || {
        open_with(&[
            ("scouting/multicast/enabled", "false".to_owned()),
            ("mode", "\"client\"".to_owned()),
            ("connect/endpoints", endpoint(port_node)),
        ])
    };
    let (first, second) = (client(), client());
    (node, first, second)
}

unsafe fn view_text(view: &z_view_string_t) -> String {
    let loaned = z_view_string_loan(view);
    let bytes =
        std::slice::from_raw_parts(z_string_data(loaned).cast::<u8>(), z_string_len(loaned));
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// The ids the group's view reports, in the order it reports them.
unsafe fn view_ids(group: &wz_capi_c_owned_group_t) -> Vec<String> {
    unsafe extern "C" fn push(member: *const wz_capi_c_loaned_member_t, ctx: *mut c_void) {
        let mut id: z_view_string_t = std::mem::zeroed();
        assert_eq!(wz_capi_c_member_id(member, &mut id), Z_OK);
        (*(ctx as *mut Vec<String>)).push(view_text(&id));
    }
    let mut ids: Vec<String> = Vec::new();
    let mut closure: wz_capi_c_owned_closure_member_t = std::mem::zeroed();
    wz_capi_c_closure_member(
        &mut closure,
        Some(push),
        None,
        (&mut ids as *mut Vec<String>).cast::<c_void>(),
    );
    assert_eq!(
        wz_capi_c_group_view(
            wz_capi_c_group_loan(group),
            (&mut closure as *mut wz_capi_c_owned_closure_member_t)
                .cast::<wz_capi_c_moved_closure_member_t>(),
        ),
        Z_OK
    );
    ids
}

unsafe fn leader_id(group: &wz_capi_c_owned_group_t) -> String {
    let mut leader: wz_capi_c_owned_member_t = std::mem::zeroed();
    assert_eq!(
        wz_capi_c_group_leader(wz_capi_c_group_loan(group), &mut leader),
        Z_OK
    );
    let mut id: z_view_string_t = std::mem::zeroed();
    assert_eq!(
        wz_capi_c_member_id(wz_capi_c_member_loan(&leader), &mut id),
        Z_OK
    );
    let text = view_text(&id);
    wz_capi_c_member_drop(
        (&mut leader as *mut wz_capi_c_owned_member_t).cast::<wz_capi_c_moved_member_t>(),
    );
    text
}

/// The node and two clients that never share a link are one group of three. Each member's
/// announcement, beacon and record cross the node (the clients hear of one another through it
/// alone), every view lists the three ids in order and every one names the greatest id its
/// leader. When that leader goes, its lease runs out on the node and on the other client, and the
/// leader falls to the next greatest.
#[test]
fn a_node_and_two_clients_are_one_group_of_three_and_lose_their_leader_together() {
    unsafe {
        let (node, first, second) = node_and_two_clients();
        let node_seen = Arc::new(Seen::default());
        let node_group = join(&node, "m-node");
        watch(&node_group, &node_seen);
        // The node's data plane learns the clients' subscriptions over their links.
        std::thread::sleep(Duration::from_millis(500));
        let first_group = join(&first, "a-first");
        let second_group = join(&second, "z-second");

        let members = [
            ("the node", &node_group),
            ("the first client", &first_group),
            ("the second client", &second_group),
        ];
        for (who, group) in members {
            assert!(
                wz_capi_c_group_wait_for_view_size(wz_capi_c_group_loan(group), 3, 15_000),
                "{who} never saw all three members"
            );
        }
        let ids = ["a-first", "m-node", "z-second"];
        for (who, group) in members {
            assert_eq!(view_ids(group), ids, "the view of {who}");
            assert_eq!(leader_id(group), "z-second", "the leader {who} names");
        }
        // The view grows before the event is delivered, so the count is waited for.
        assert!(
            eventually(|| node_seen.joins.load(Ordering::SeqCst) >= 2),
            "the node was not told of both joins"
        );

        // The leader goes: its group is left and its session closed, so no beacon comes.
        leave(second_group);
        close_session(second);
        for (who, group) in [
            ("the node", &node_group),
            ("the first client", &first_group),
        ] {
            assert!(
                eventually(|| wz_capi_c_group_size(wz_capi_c_group_loan(group)) == 2),
                "{who} never missed the leader"
            );
            assert_eq!(view_ids(group), ["a-first", "m-node"], "the view of {who}");
            assert_eq!(leader_id(group), "m-node", "the leader {who} names");
        }
        assert!(
            eventually(|| node_seen.expired.load(Ordering::SeqCst) >= 1),
            "the node was never told the leader's lease ran out"
        );

        leave(first_group);
        leave(node_group);
        close_session(first);
        close_session(node);
    }
}
