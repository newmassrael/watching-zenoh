// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a node opened through the C ABI tells of the sessions it holds: the peers and routers it
//! is linked to, the transports and links it lists, and the listeners that hear of one coming and
//! going. They read the faces of the node, where on the registry they read its sessions, and a
//! registry peer that dials the node is the session the node must name.
//!
//! The listing, the history of a listener and the live events are separate paths, so each is
//! asserted on its own. The events name the peer by its zid, which is what shows that the node
//! reads the face that came and not a face the test made up.

// The two event planes are unstable upstream and so is wz's `events` module; the peers listing is
// stable but is asserted here beside them, so the whole file follows the unstable arm.
#![cfg(all(feature = "router-node", not(feature = "zenoh-c-no-unstable-api")))]

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_moved_config_t, z_moved_session_t, z_owned_config_t, z_owned_session_t, Z_SAMPLE_KIND_DELETE,
    Z_SAMPLE_KIND_PUT,
};
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::events::{
    z_closure_link, z_closure_link_event, z_closure_transport, z_closure_transport_event,
    z_declare_link_events_listener, z_declare_transport_events_listener, z_info_links,
    z_info_links_options_default, z_info_links_options_t, z_info_transports, z_link_event_kind,
    z_link_event_link, z_link_events_listener_options_default, z_link_events_listener_options_t,
    z_link_zid, z_loaned_link_event_t, z_loaned_link_t, z_loaned_transport_event_t,
    z_loaned_transport_t, z_moved_closure_link_event_t, z_moved_closure_link_t,
    z_moved_closure_transport_event_t, z_moved_closure_transport_t, z_moved_link_events_listener_t,
    z_moved_transport_events_listener_t, z_owned_closure_link_event_t, z_owned_closure_link_t,
    z_owned_closure_transport_event_t, z_owned_closure_transport_t, z_owned_link_events_listener_t,
    z_owned_transport_events_listener_t, z_transport_event_kind, z_transport_event_transport,
    z_transport_events_listener_options_t, z_transport_zid, z_undeclare_link_events_listener,
    z_undeclare_transport_events_listener,
};
use wz_capi_c::result::Z_OK;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::zid::{
    z_closure_zid, z_id_t, z_info_peers_zid, z_info_routers_zid, z_info_zid, z_moved_closure_zid_t,
    z_owned_closure_zid_t,
};
use wz_runtime_tokio_test_support::free_port;

/// What the callbacks saw, shared with them through a raw context pointer.
#[derive(Default)]
struct Seen {
    puts: AtomicUsize,
    deletes: AtomicUsize,
    /// The zids the callbacks read back, in the order they came.
    zids: Mutex<Vec<[u8; 16]>>,
}

impl Seen {
    fn note(&self, kind: u32, zid: [u8; 16]) {
        if kind == Z_SAMPLE_KIND_PUT as u32 {
            self.puts.fetch_add(1, Ordering::SeqCst);
        } else if kind == Z_SAMPLE_KIND_DELETE as u32 {
            self.deletes.fetch_add(1, Ordering::SeqCst);
        }
        self.zids.lock().unwrap().push(zid);
    }
}

unsafe extern "C" fn on_transport_event(event: *mut z_loaned_transport_event_t, ctx: *mut c_void) {
    let seen = &*(ctx as *const Seen);
    let kind = z_transport_event_kind(event);
    let transport = z_transport_event_transport(event);
    seen.note(kind as u32, z_transport_zid(transport).id);
}

unsafe extern "C" fn on_link_event(event: *mut z_loaned_link_event_t, ctx: *mut c_void) {
    let seen = &*(ctx as *const Seen);
    let kind = z_link_event_kind(event);
    let link = z_link_event_link(event);
    seen.note(kind as u32, z_link_zid(link).id);
}

/// A listed transport counts as a put, as the events do, so one `Seen` reads the three.
unsafe extern "C" fn on_transport(transport: *mut z_loaned_transport_t, ctx: *mut c_void) {
    (&*(ctx as *const Seen)).note(Z_SAMPLE_KIND_PUT as u32, z_transport_zid(transport).id);
}

unsafe extern "C" fn on_link(link: *mut z_loaned_link_t, ctx: *mut c_void) {
    (&*(ctx as *const Seen)).note(Z_SAMPLE_KIND_PUT as u32, z_link_zid(link).id);
}

unsafe extern "C" fn on_zid(zid: *const z_id_t, ctx: *mut c_void) {
    (&*(ctx as *const Seen)).note(Z_SAMPLE_KIND_PUT as u32, (*zid).id);
}

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

/// Wait up to 10 s for `counter` to reach `want`, and settle; the count it ends on.
fn settle(counter: &AtomicUsize, want: usize) -> usize {
    let deadline = Instant::now() + Duration::from_secs(10);
    while counter.load(Ordering::SeqCst) < want && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(200));
    counter.load(Ordering::SeqCst)
}

unsafe fn transport_listener(
    session: &z_owned_session_t,
    ctx: *mut c_void,
    history: bool,
) -> z_owned_transport_events_listener_t {
    let mut closure: z_owned_closure_transport_event_t = std::mem::zeroed();
    z_closure_transport_event(&mut closure, Some(on_transport_event), None, ctx);
    let options = z_transport_events_listener_options_t { history };
    let mut listener: z_owned_transport_events_listener_t = std::mem::zeroed();
    assert_eq!(
        z_declare_transport_events_listener(
            z_session_loan(session),
            &mut listener,
            (&mut closure as *mut z_owned_closure_transport_event_t)
                .cast::<z_moved_closure_transport_event_t>(),
            &options,
        ),
        Z_OK
    );
    listener
}

unsafe fn link_listener(
    session: &z_owned_session_t,
    ctx: *mut c_void,
) -> z_owned_link_events_listener_t {
    let mut closure: z_owned_closure_link_event_t = std::mem::zeroed();
    z_closure_link_event(&mut closure, Some(on_link_event), None, ctx);
    let mut options: z_link_events_listener_options_t = std::mem::zeroed();
    z_link_events_listener_options_default(&mut options);
    let mut listener: z_owned_link_events_listener_t = std::mem::zeroed();
    assert_eq!(
        z_declare_link_events_listener(
            z_session_loan(session),
            &mut listener,
            (&mut closure as *mut z_owned_closure_link_event_t)
                .cast::<z_moved_closure_link_event_t>(),
            &mut options,
        ),
        Z_OK
    );
    listener
}

/// The zids `list` read, where `list` is one of the enumerations of the ABI.
unsafe fn zids_of(list: impl FnOnce(*mut c_void) -> i8) -> Vec<[u8; 16]> {
    let seen = Seen::default();
    assert_eq!(list((&seen as *const Seen).cast_mut().cast()), Z_OK);
    let zids = seen.zids.lock().unwrap().clone();
    zids
}

/// A node (a peer that keeps a south of clients apart) that a registry peer dials: the node must
/// name that peer in every listing and event, as a peer and not a router, and name it gone when
/// it leaves.
#[test]
fn a_node_lists_and_tells_of_the_peer_that_dials_it() {
    let (port_node, port_peer) = (free_port(), free_port());
    unsafe {
        let node = open_with(&[
            ("scouting/multicast/enabled", "false".to_owned()),
            ("mode", "\"peer\"".to_owned()),
            ("listen/endpoints", endpoint(port_node)),
            (
                "gateway",
                r#"{ south: [ { filters: [ { modes: ["client"] } ] } ] }"#.to_owned(),
            ),
        ]);
        assert!(
            zids_of(|ctx| list_peers(&node, ctx)).is_empty(),
            "nothing is linked yet"
        );

        // The listeners are declared before the peer comes, so what they hear is live.
        let transports = Arc::new(Seen::default());
        let links = Arc::new(Seen::default());
        let mut transport_events =
            transport_listener(&node, Arc::as_ptr(&transports).cast_mut().cast(), false);
        let mut link_events = link_listener(&node, Arc::as_ptr(&links).cast_mut().cast());

        let peer = open_with(&[
            ("scouting/multicast/enabled", "false".to_owned()),
            ("mode", "\"peer\"".to_owned()),
            ("listen/endpoints", endpoint(port_peer)),
            ("connect/endpoints", endpoint(port_node)),
        ]);
        let peer_zid = z_info_zid(z_session_loan(&peer)).id;

        assert!(
            settle(&transports.puts, 1) >= 1,
            "no transport event for the peer"
        );
        assert!(settle(&links.puts, 1) >= 1, "no link event for the peer");
        assert_eq!(
            transports.zids.lock().unwrap().first(),
            Some(&peer_zid),
            "the transport event names the peer"
        );
        assert_eq!(
            links.zids.lock().unwrap().first(),
            Some(&peer_zid),
            "the link event names the peer"
        );
        assert_eq!(transports.deletes.load(Ordering::SeqCst), 0);

        assert_eq!(
            zids_of(|ctx| list_peers(&node, ctx)),
            vec![peer_zid],
            "the peer the node holds"
        );
        assert!(
            zids_of(|ctx| list_routers(&node, ctx)).is_empty(),
            "a peer is not a router"
        );
        assert_eq!(
            zids_of(|ctx| list_transports(&node, ctx)),
            vec![peer_zid],
            "the one transport"
        );
        let listed_links = zids_of(|ctx| list_links(&node, ctx));
        assert!(
            !listed_links.is_empty() && listed_links.iter().all(|zid| *zid == peer_zid),
            "the links of that transport"
        );

        // A listener declared now, with its history, is told of the peer already held.
        let late = Arc::new(Seen::default());
        let mut late_events = transport_listener(&node, Arc::as_ptr(&late).cast_mut().cast(), true);
        assert_eq!(late.puts.load(Ordering::SeqCst), 1, "the history");
        assert_eq!(late.zids.lock().unwrap().first(), Some(&peer_zid));

        close_session(peer);
        assert!(
            settle(&transports.deletes, 1) >= 1,
            "no event for the peer leaving"
        );
        assert!(
            settle(&links.deletes, 1) >= 1,
            "no link event for the peer leaving"
        );
        assert!(zids_of(|ctx| list_peers(&node, ctx)).is_empty());

        assert_eq!(
            z_undeclare_transport_events_listener(
                (&mut transport_events as *mut z_owned_transport_events_listener_t)
                    .cast::<z_moved_transport_events_listener_t>()
            ),
            Z_OK
        );
        assert_eq!(
            z_undeclare_transport_events_listener(
                (&mut late_events as *mut z_owned_transport_events_listener_t)
                    .cast::<z_moved_transport_events_listener_t>()
            ),
            Z_OK
        );
        assert_eq!(
            z_undeclare_link_events_listener(
                (&mut link_events as *mut z_owned_link_events_listener_t)
                    .cast::<z_moved_link_events_listener_t>()
            ),
            Z_OK
        );
        close_session(node);
    }
}

unsafe fn list_peers(node: &z_owned_session_t, ctx: *mut c_void) -> i8 {
    let mut closure: z_owned_closure_zid_t = std::mem::zeroed();
    z_closure_zid(&mut closure, Some(on_zid), None, ctx);
    z_info_peers_zid(
        z_session_loan(node),
        (&mut closure as *mut z_owned_closure_zid_t).cast::<z_moved_closure_zid_t>(),
    )
}

unsafe fn list_routers(node: &z_owned_session_t, ctx: *mut c_void) -> i8 {
    let mut closure: z_owned_closure_zid_t = std::mem::zeroed();
    z_closure_zid(&mut closure, Some(on_zid), None, ctx);
    z_info_routers_zid(
        z_session_loan(node),
        (&mut closure as *mut z_owned_closure_zid_t).cast::<z_moved_closure_zid_t>(),
    )
}

unsafe fn list_transports(node: &z_owned_session_t, ctx: *mut c_void) -> i8 {
    let mut closure: z_owned_closure_transport_t = std::mem::zeroed();
    z_closure_transport(&mut closure, Some(on_transport), None, ctx);
    z_info_transports(
        z_session_loan(node),
        (&mut closure as *mut z_owned_closure_transport_t).cast::<z_moved_closure_transport_t>(),
    )
}

unsafe fn list_links(node: &z_owned_session_t, ctx: *mut c_void) -> i8 {
    let mut closure: z_owned_closure_link_t = std::mem::zeroed();
    z_closure_link(&mut closure, Some(on_link), None, ctx);
    let mut options: z_info_links_options_t = std::mem::zeroed();
    z_info_links_options_default(&mut options);
    z_info_links(
        z_session_loan(node),
        (&mut closure as *mut z_owned_closure_link_t).cast::<z_moved_closure_link_t>(),
        &mut options,
    )
}
