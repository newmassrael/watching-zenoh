// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The node's admin GET fits its bound or is refused and counted, with nothing
//! allocated (fixed-memory step S9b, exhaustion row R7), through the node's own
//! queryable, status and host (`admin_fixed`) and the session's own tables
//! (`PeerTables`).
//!
//! A GET is dispatched through the real query path, a session's stage and `Final`
//! table receive what the admin queryable replies, and the heap is counted over the
//! whole dispatch:
//!
//! - the whole admin surface answered by one wildcard GET (the root document with its
//!   session row, the config document, the connection status, the manifest) costs
//!   the heap nothing, and every leg is the document the `String` path writes;
//! - with a reply buffer smaller than most of the legs, each leg that does not fit
//!   is refused and counted, the querier gets a typed Err for it, the legs that fit
//!   are served, and none of it costs the heap anything;
//! - what one session was refused does not move another's: a second session asked
//!   the leg that fits is served;
//! - the status table refuses a row past its bound and counts it, allocating
//!   nothing, and the identity refuses what does not fit at startup.
//!
//! What a staged reply costs when DRAINED to the wire is the codec mirrors' step and
//! is not claimed. Compiles only on the slot profile.
#![cfg(all(
    feature = "session-slot",
    feature = "adminspace-core",
    feature = "adminspace-write"
))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use wz_session_core::adminspace::{AdminLink, AdminSession};
use wz_session_core::caps;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::peer_tables::PeerTables;
use wz_session_core::query::{QueryReply, QueryableRegistry, ReplyBody};
use wz_session_core::request_build::RequestQueryBuilder;
use wz_session_mcu::admin_fixed::{
    host_admin_queryable_fixed, AdminHost, AdminQuerySink, FixedNodeIdentity, FixedNodeStatus,
    IdentityRefused,
};
use wz_session_mcu::admin_host::ConnectControl;
use wz_session_mcu::admin_status::DialStatus;

/// Counts the allocations made BY THE CURRENT THREAD.
struct CountingAllocator;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call forwards to `System` unchanged; the only addition is a
// thread-local counter bump, which neither allocates nor unwinds.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn allocations_during<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let before = ALLOCATIONS.with(Cell::get);
    let out = f();
    (out, ALLOCATIONS.with(Cell::get) - before)
}

const ZID: &str = "a1b2";

fn identity() -> FixedNodeIdentity {
    FixedNodeIdentity::new(ZID, "peer", "wz-test", &["udp/10.0.0.1:7447"]).expect("identity fits")
}

/// A session row as the AP's owned type, to be given to the status as a view.
fn peer_row() -> AdminSession {
    AdminSession {
        peer_zid_hex: String::from("c3d4"),
        whatami: Some(String::from("router")),
        links: vec![AdminLink {
            src: String::from("udp/10.0.0.1:7447"),
            dst: String::from("udp/10.0.0.9:50000"),
        }],
        region: Some(String::from("router")),
        ..AdminSession::default()
    }
}

fn get(rid: u64, keyexpr: &str) -> NetworkMessage {
    NetworkMessage::Request(Box::new(
        RequestQueryBuilder::new(rid, 0, Some(keyexpr))
            .build()
            .expect("build"),
    ))
}

/// What a session's stage holds, as `(key, Put body as text)`; an Err reply as
/// `(key, "ERR " + body)`.
fn staged(peers: &PeerTables) -> Vec<(String, String)> {
    peers
        .replies
        .iter()
        .map(|reply| match reply {
            QueryReply::Reply {
                keyexpr_literal,
                body: ReplyBody::Put(payload),
                ..
            } => (keyexpr_literal, String::from_utf8(payload).expect("text")),
            QueryReply::Err {
                keyexpr_literal,
                payload,
                ..
            } => (
                keyexpr_literal,
                format!("ERR {}", String::from_utf8(payload).expect("text")),
            ),
            other => panic!("an admin reply, got {other:?}"),
        })
        .collect()
}

/// A Box of the session's tables: they are large, and a session owns them in its slot.
fn session() -> Box<PeerTables> {
    Box::new(PeerTables::new())
}

#[test]
fn the_whole_admin_surface_is_served_by_one_get_with_zero_allocations() {
    static STATUS: FixedNodeStatus<3> = FixedNodeStatus::new(true);
    static HOST: AdminHost<1024> = AdminHost::new();
    static CONTROL: ConnectControl = ConnectControl::new(true);

    let mut registry: QueryableRegistry<AdminQuerySink<1024, 3>> =
        QueryableRegistry::with_sink_backing();
    host_admin_queryable_fixed(
        &mut registry,
        identity(),
        &STATUS,
        &HOST,
        Some(&CONTROL),
        Some(&CONTROL),
    )
    .expect("a fresh registry takes the admin queryable");
    let rows = [peer_row()];
    // The shell's update of what the node reports costs the heap nothing either.
    let (_, status_allocations) = allocations_during(|| {
        STATUS.set_sessions(rows.iter().map(AdminSession::view));
        STATUS.set_endpoints([(
            "udp/10.0.0.3:7447",
            DialStatus::Refused {
                reason: "multi_link_group",
            },
        )]);
    });

    let mut peers = session();
    let messages = [get(1, "@/a1b2/peer/**")];
    let (_, allocations) = allocations_during(|| {
        registry.dispatch_messages(
            &messages,
            peers.subscribers.mapping_spaces(),
            &mut peers.replies,
            &mut peers.finals,
        );
    });
    let replies = staged(&peers);
    let keys: Vec<&str> = replies.iter().map(|(key, _)| key.as_str()).collect();
    assert_eq!(
        (status_allocations, allocations, peers.finals.len()),
        (0, 0, 1),
        "(heap allocations of the status update, of the GET, Finals owed)"
    );
    assert_eq!(
        keys,
        vec![
            "@/a1b2/peer/status/connect",
            "@/a1b2/peer",
            "@/a1b2/peer/config",
            "@/a1b2/peer/wz/surface"
        ],
        "every leg a wildcard reaches, the connection status first as the node orders it"
    );
    let root = &replies[1].1;
    assert!(
        root.contains("\"peer\":\"c3d4\"") && root.contains("\"whatami\":\"router\""),
        "the status's session is in `sessions`: {root}"
    );
    assert!(
        replies[0].1.contains("\"reason\":\"multi_link_group\""),
        "the endpoint status is on its own leg: {}",
        replies[0].1
    );
    assert_eq!(HOST.refusals(), Default::default());
    assert_eq!(HOST.busy_refusals(), 0);
    assert_eq!(peers.replies.refusals(), Default::default());
}

#[test]
fn a_leg_past_the_reply_buffer_is_refused_counted_and_typed_while_the_others_are_served() {
    static STATUS: FixedNodeStatus<3> = FixedNodeStatus::new(true);
    // 96 bytes holds the config document and not the root, status or manifest ones.
    static HOST: AdminHost<96> = AdminHost::new();
    static CONTROL: ConnectControl = ConnectControl::new(true);

    let mut registry: QueryableRegistry<AdminQuerySink<96, 3>> =
        QueryableRegistry::with_sink_backing();
    host_admin_queryable_fixed(
        &mut registry,
        identity(),
        &STATUS,
        &HOST,
        Some(&CONTROL),
        Some(&CONTROL),
    )
    .expect("registered");
    let rows = [peer_row()];
    STATUS.set_sessions(rows.iter().map(AdminSession::view));
    STATUS.set_endpoints([(
        "udp/10.0.0.3:7447",
        DialStatus::Refused {
            reason: "multi_link_group",
        },
    )]);

    let (mut a, mut b) = (session(), session());
    let wildcard = [get(1, "@/a1b2/peer/**")];
    let config_only = [get(2, "@/a1b2/peer/config")];
    let (_, allocations) = allocations_during(|| {
        registry.dispatch_messages(
            &wildcard,
            a.subscribers.mapping_spaces(),
            &mut a.replies,
            &mut a.finals,
        );
        // A second session asks the leg that fits, after the first was refused.
        registry.dispatch_messages(
            &config_only,
            b.subscribers.mapping_spaces(),
            &mut b.replies,
            &mut b.finals,
        );
    });
    let a_replies = staged(&a);
    let b_replies = staged(&b);
    let served = |replies: &[(String, String)]| -> Vec<String> {
        replies
            .iter()
            .filter(|(_, body)| !body.starts_with("ERR "))
            .map(|(key, _)| key.clone())
            .collect()
    };
    let refused = |replies: &[(String, String)]| -> Vec<String> {
        replies
            .iter()
            .filter(|(_, body)| body.starts_with("ERR "))
            .map(|(_, body)| body.clone())
            .collect()
    };
    assert_eq!(allocations, 0, "heap allocations of both sessions' GETs");
    assert_eq!(
        served(&a_replies),
        vec!["@/a1b2/peer/config".to_string()],
        "the leg that fits is served to the session that was refused the others"
    );
    assert_eq!(
        served(&b_replies),
        vec!["@/a1b2/peer/config".to_string()],
        "and to the second session"
    );
    let a_refused = refused(&a_replies);
    assert_eq!(a_refused.len(), 3, "root, status and manifest are refused");
    assert!(
        a_refused.iter().all(|body| body
            .starts_with("ERR {\"error\":\"admin_reply_too_large\",\"needed\":")
            && body.ends_with(",\"capacity\":96}")),
        "each refusal is typed and names both sizes: {a_refused:?}"
    );
    assert!(refused(&b_replies).is_empty());
    assert_eq!(
        (HOST.refusals().too_large, HOST.refusals().key_too_long),
        (3, 0)
    );
    assert_eq!((a.finals.len(), b.finals.len()), (1, 1));
}

#[test]
fn a_status_row_past_the_table_is_refused_counted_and_allocates_nothing() {
    static STATUS: FixedNodeStatus<2> = FixedNodeStatus::new(true);
    let rows: Vec<AdminSession> = (0..3).map(|_| peer_row()).collect();
    let (_, allocations) =
        allocations_during(|| STATUS.set_sessions(rows.iter().map(AdminSession::view)));
    assert_eq!(
        (
            allocations,
            STATUS.session_count(),
            STATUS.refusals().sessions_full
        ),
        (0, 2, 1),
        "(heap allocations, rows held, rows refused past the table)"
    );

    let wide = AdminSession {
        peer_zid_hex: "f".repeat(33),
        ..AdminSession::default()
    };
    let (_, allocations) = allocations_during(|| {
        STATUS.set_sessions([wide.view()]);
    });
    assert_eq!(
        (
            allocations,
            STATUS.session_count(),
            STATUS.refusals().session_rows_refused
        ),
        (0, 0, 1),
        "a row with a zid wider than a zenoh id is refused whole and counted"
    );

    let endpoints: Vec<String> = (0..caps::MAX_STATIC_CONNECT + 1)
        .map(|i| format!("udp/10.0.0.{i}:7447"))
        .collect();
    let (_, allocations) = allocations_during(|| {
        STATUS.set_endpoints(
            endpoints
                .iter()
                .map(|endpoint| (endpoint.as_str(), DialStatus::Live { established: true })),
        );
    });
    assert_eq!(
        (allocations, STATUS.refusals().endpoints_full),
        (0, 1),
        "one endpoint past the table is refused and counted"
    );
}

#[test]
fn an_identity_that_does_not_fit_is_refused_when_it_is_built() {
    let locator = "udp/10.0.0.1:7447";
    let too_many: Vec<&str> = vec![locator; caps::MAX_ADMIN_LOCATORS + 1];
    assert!(matches!(
        FixedNodeIdentity::new(ZID, "peer", "v", &too_many),
        Err(IdentityRefused::TooManyLocators)
    ));
    let at_the_bound: Vec<&str> = vec![locator; caps::MAX_ADMIN_LOCATORS];
    assert!(FixedNodeIdentity::new(ZID, "peer", "v", &at_the_bound).is_ok());
    let wide_locator = "u".repeat(caps::MAX_LOCATOR_LEN + 1);
    assert!(matches!(
        FixedNodeIdentity::new(ZID, "peer", "v", &[wide_locator.as_str()]),
        Err(IdentityRefused::Locator)
    ));
    assert!(matches!(
        FixedNodeIdentity::new(&"a".repeat(33), "peer", "v", &[]),
        Err(IdentityRefused::Zid)
    ));
    assert!(matches!(
        FixedNodeIdentity::new(ZID, "peer", &"v".repeat(33), &[]),
        Err(IdentityRefused::Version)
    ));
}
