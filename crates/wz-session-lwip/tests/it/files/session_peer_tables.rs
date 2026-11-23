// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The tables a PEER writes live in the session slot (fixed-memory step S9a,
//! decision Q7: per session), and one session's peer cannot touch another's.
//!
//! Two real sessions are built in two slots of one table, over lwIP sockets, the
//! way an image builds them. The tables themselves, their limits and their
//! refusals are proved at the registry level (`wz-session-core`'s
//! `bounded_heapless_backing` and `reply_budget_refusal`); what only a slot can
//! show is that:
//!
//! - each session HAS its own set, at a distinct place, so a table filled through
//!   one handle is not filled through the other;
//! - a flooded session's table is refused and counted, while the other session's
//!   table, asked the same, still takes the entry (the reason the tables are per
//!   session and not one observer-wide table, which a flood would fill for both);
//! - a slot that comes back is empty: what a departed peer said is not inherited
//!   by the session the slot holds next;
//! - the tables count in the slot's size, which the deploy `limits` keys state.
//!
//! Compiles only on the slot profile. Host-test level: no board runs it.

#![cfg(feature = "session-slot")]
#![allow(clippy::result_large_err)]
// Fixed-memory step S9a -- the tables a peer writes live in the session slot: two
// real sessions in two slots, a flood through one handle refused and counted
// there and not in the other, and a slot that comes back empty. It needs the slot
// (the file is empty without it) and the session halves a pair of sessions is
// built from.
#![cfg(all(
    feature = "session-unicast-open",
    feature = "session-unicast-accept",
    feature = "pubsub-put",
    feature = "declare-subscriber",
    feature = "session-slot"
))]

use std::rc::Rc;

// The binder of `test_bind`: the constructor itself by default, and with
// `static-link-storage` also on (`--all-features` turns both selectors on) a socket
// claimed from a pool of one cell that the test leaks. The binds are outside any
// count, so the leak is not read as a cost.
#[cfg(not(feature = "static-link-storage"))]
use wz_link_lwip::rx_sockets::bind_session_rx;
#[cfg(feature = "static-link-storage")]
use wz_link_lwip::test_bind::session_rx as bind_session_rx;
use wz_link_lwip::{ipv4_addr_from_octets, LwipLink};
use wz_runtime_coop::session_runtime::new_session_in_slot;
use wz_runtime_coop::{ClockSource, CoopRuntime, CoopTime};
use wz_session_core::caps;
use wz_session_core::entropy::{EntropySource, EntropyUnavailable};
use wz_session_core::peer_tables::PeerTables;
use wz_session_core::pubsub::SubscriberTable;
use wz_session_core::reply_stage::FinalStaging;
use wz_session_core::sample::QosLevel;
use wz_session_core::session_init_params::{cookie_bytes, zid_bytes, SessionInitParams};
use wz_session_core::session_slot::SessionSlots;
use wz_session_core::signing_key::SigningKey;
use wz_session_core::sink::BoxedSink;
use wz_session_core::WhatAmI;
use wz_session_lwip::driver::{share_socket, LwipUdpDriver};

/// A clock that never moves.
#[derive(Clone, Default)]
struct Frozen;
impl ClockSource for Frozen {
    fn now_us(&self) -> u64 {
        0
    }
}

/// A board's TRNG, stood in for.
struct Fill;
impl EntropySource for Fill {
    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), EntropyUnavailable> {
        buf.fill(0x42);
        Ok(())
    }
}

type Rt = CoopRuntime<Frozen, LwipUdpDriver>;
type Table = SessionSlots<Rt, CoopTime<Frozen>, LwipUdpDriver, Fill, 2>;

fn params(zid: u8) -> SessionInitParams {
    SessionInitParams {
        whatami: WhatAmI::Peer,
        zid: zid_bytes(&[zid; 4]),
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 1024,
        lease_ms: 10_000,
        keep_alive: wz_session_core::session_init_params::KeepAliveConf::PICO,
        initial_sn: 0,
        cookie: cookie_bytes(&[]),
        tx_queue: wz_session_core::session_init_params::TxQueueConf::of_snapshot(
            &wz_session_core::policy::SessionPolicy::defaults(),
            &wz_session_core::limits::SessionLimits::BUILD,
        ),
        link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
        policy: wz_session_core::policy::SessionPolicy::defaults(),
        limits: wz_session_core::limits::SessionLimits::BUILD,
        cookie_signing_key: SigningKey::from_slice(&[7u8; 32]).expect("key"),
    }
}

fn driver_on(link: &Rc<LwipLink>, port: u16) -> LwipUdpDriver {
    let socket = bind_session_rx(link, port).expect("bind");
    LwipUdpDriver::new(
        share_socket(socket),
        ipv4_addr_from_octets([127, 0, 0, 1]),
        port,
    )
}

/// One FUTURE-only subscriber interest from the peer on the interest id `id`.
fn interest(table: &mut SubscriberTable<BoxedSink>, peers: &mut PeerTables, id: u64) {
    let ke = format!("peer/{id}");
    table.respond_to_subscriber_interest_borrowed(
        &mut peers.subscribers,
        id,
        Some(&ke),
        false,
        false,
        true,
    );
}

#[test]
fn each_session_has_peer_tables_of_its_own_and_a_flood_stays_with_the_flooded() {
    static TABLE: Table = SessionSlots::new();
    static RUNTIME: wz_runtime_coop::RuntimeCell<Frozen, 1, 64, 1> =
        wz_runtime_coop::RuntimeCell::new();
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    let runtime = RUNTIME
        .start::<LwipUdpDriver>(Frozen)
        .expect("the runtime is started once");

    let claim_a = TABLE
        .claim(driver_on(&link, 7741), Fill)
        .ok()
        .expect("slot");
    let claim_b = TABLE
        .claim(driver_on(&link, 7742), Fill)
        .ok()
        .expect("slot");
    let (a, _) = new_session_in_slot(claim_a, || params(0xa1), CoopTime::new(&runtime));
    let (b, _) = new_session_in_slot(claim_b, || params(0xb1), CoopTime::new(&runtime));
    assert!(
        !core::ptr::eq(a.peers(), b.peers()),
        "two sessions, two sets of peer tables"
    );

    // The application's registry: ONE table for both sessions. What a peer wrote is
    // in the session's own set.
    let mut subscribers: SubscriberTable<BoxedSink> = SubscriberTable::new();

    // Session A's peer floods its interests and its queries.
    {
        let mut peers = a.peers().borrow_mut();
        for id in 1..=(caps::MAX_INBOUND_SUB_INTERESTS as u64 + 5) {
            interest(&mut subscribers, &mut peers, id);
        }
        let finals = wz_session_core::wire_id::RequestId::try_from(caps::MAX_PENDING_FINALS)
            .expect("the finals table's bound is a wire id");
        for rid in 0..finals {
            assert!(peers.finals.has_room());
            peers.finals.owe(rid, QosLevel::DEFAULT);
        }
        assert!(
            !peers.finals.has_room(),
            "A's finals table is full: its next query is refused"
        );
        peers.finals.refuse_request();
    }

    // Session B's peer asks the same, with the same ids, and is served.
    {
        let mut peers = b.peers().borrow_mut();
        interest(&mut subscribers, &mut peers, 3);
        assert!(
            peers.finals.has_room(),
            "B's finals table is untouched by A's"
        );
        peers.finals.owe(0, QosLevel::DEFAULT);
    }

    let (a_peers, b_peers) = (a.peers().borrow(), b.peers().borrow());
    assert_eq!(
        (
            a_peers.subscribers.interest_count(),
            a_peers.subscribers.interest_staging_refusals().future_interests,
            a_peers.finals.refusals(),
            b_peers.subscribers.interest_count(),
            b_peers.subscribers.interest_staging_refusals().future_interests,
            b_peers.finals.refusals(),
            b_peers.finals.len(),
        ),
        (caps::MAX_INBOUND_SUB_INTERESTS, 5, 1, 1, 0, 0, 1),
        "(A rows, A refused interests, A refused requests, B rows, B refused interests, B refused requests, B finals owed)"
    );
}

#[test]
fn a_slot_comes_back_with_empty_peer_tables() {
    static TABLE: Table = SessionSlots::new();
    static RUNTIME: wz_runtime_coop::RuntimeCell<Frozen, 1, 64, 1> =
        wz_runtime_coop::RuntimeCell::new();
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    let runtime = RUNTIME
        .start::<LwipUdpDriver>(Frozen)
        .expect("the runtime is started once");
    let mut subscribers: SubscriberTable<BoxedSink> = SubscriberTable::new();

    let claim = TABLE
        .claim(driver_on(&link, 7743), Fill)
        .ok()
        .expect("slot");
    let (first, _) = new_session_in_slot(claim, || params(0xc1), CoopTime::new(&runtime));
    {
        let mut peers = first.peers().borrow_mut();
        for id in 1..=4u64 {
            interest(&mut subscribers, &mut peers, id);
        }
        peers.finals.owe(9, QosLevel::DEFAULT);
        assert_eq!(peers.subscribers.interest_count(), 4);
    }
    drop(first);
    assert_eq!(TABLE.in_use(), 0, "the slot came back");

    // The next session in the same slot hears nothing of the departed peer.
    let claim = TABLE
        .claim(driver_on(&link, 7744), Fill)
        .ok()
        .expect("slot");
    let (second, _) = new_session_in_slot(claim, || params(0xc2), CoopTime::new(&runtime));
    let peers = second.peers().borrow();
    assert_eq!(
        (
            peers.subscribers.interest_count(),
            peers.subscribers.alias_count(),
            peers.finals.len(),
            peers.replies.len()
        ),
        (0, 0, 0, 0),
        "(interests, aliases, finals, replies) of the session that took the slot over"
    );
}

/// A session opened in a slot holds the slot's peer tables to the limits of the parameters it was
/// opened with: with `MAX_PENDING_FINALS` stated as two, the third request finds no room and is
/// refused and counted, and the refusal leaves the two `Final`s owed. The CONTROL is the next
/// session in the same slot, opened under the build's limits, which owes the third: the quota is
/// each session's own and is not left behind by the one before.
#[test]
fn a_stated_quota_of_two_finals_refuses_the_third_in_a_slot_built_session() {
    use wz_session_core::limit_binding::{LimitSpec, Quota};
    use wz_session_core::limits::{MaxPendingFinals, SessionLimits};
    let mut stated = SessionLimits::BUILD;
    if stated.select_max_pending_finals(Quota::at_most(2)).is_err() {
        // A build of one value refuses two: it has no other snapshot to hand the session.
        assert!(MaxPendingFinals::DOMAIN.is_singleton());
        return;
    }
    // A build whose finals table holds fewer than three cannot compile the control.
    const { assert!(caps::MAX_PENDING_FINALS >= 3) };
    static TABLE: Table = SessionSlots::new();
    static RUNTIME: wz_runtime_coop::RuntimeCell<Frozen, 1, 64, 1> =
        wz_runtime_coop::RuntimeCell::new();
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    let runtime = RUNTIME
        .start::<LwipUdpDriver>(Frozen)
        .expect("the runtime is started once");

    let claim = TABLE
        .claim(driver_on(&link, 7745), Fill)
        .ok()
        .expect("slot");
    let (held, _) = new_session_in_slot(
        claim,
        || SessionInitParams {
            limits: stated,
            ..params(0xd1)
        },
        CoopTime::new(&runtime),
    );
    {
        let mut peers = held.peers().borrow_mut();
        for rid in 0..2 {
            assert!(peers.finals.has_room(), "under the stated quota");
            peers.finals.owe(rid, QosLevel::DEFAULT);
        }
        assert!(
            !peers.finals.has_room(),
            "the third request finds no room under the stated quota"
        );
        peers.finals.refuse_request();
        assert_eq!(
            (peers.finals.len(), peers.finals.refusals()),
            (2, 1),
            "(finals owed, requests refused) after the refusal"
        );
    }
    drop(held);
    assert_eq!(TABLE.in_use(), 0, "the slot came back");

    // CONTROL: the next session in the slot, under the build's limits, owes the third.
    let claim = TABLE
        .claim(driver_on(&link, 7746), Fill)
        .ok()
        .expect("slot");
    let (built, _) = new_session_in_slot(claim, || params(0xd2), CoopTime::new(&runtime));
    let mut peers = built.peers().borrow_mut();
    for rid in 0..3 {
        assert!(peers.finals.has_room(), "under the build's limits");
        peers.finals.owe(rid, QosLevel::DEFAULT);
    }
    assert_eq!(peers.finals.len(), 3);
}

/// The dispatch of a session opened in a slot holds the requesters it is handed to the limits the
/// session was opened with: with `MAX_PENDING_QUERIES` stated as two, the third pending query is
/// refused as a full table and leaves the two pending. The CONTROL is the next session in the same
/// slot, opened under the build's limits, whose dispatch takes the third.
#[test]
fn a_stated_quota_of_two_pending_queries_refuses_the_third_on_a_slot_sessions_dispatch() {
    use wz_session_core::limit_binding::{LimitSpec, Quota};
    use wz_session_core::limits::{MaxPendingQueries, SessionLimits};
    use wz_session_core::registry_error::RegisterError;
    use wz_session_core::reply_acceptance::ReplyAcceptance;
    use wz_session_core::session_slot::SlotRef;
    use wz_session_core::slot_observer::{DefaultSinks, ObserverCell, Requesters};
    use wz_session_mcu::app_layer::{NoReplies, SlotDispatch};

    /// Three pending queries asked on the requesters of a dispatch over `handle`, which the
    /// dispatch is made with as a layer makes them, with no limit of its own.
    fn three_pending_queries(
        observer: &'static ObserverCell<DefaultSinks>,
        handle: SlotRef<Rt, CoopTime<Frozen>>,
    ) -> Vec<Result<(), RegisterError>> {
        let mut dispatch: SlotDispatch<Frozen, NoReplies, NoReplies, DefaultSinks, LwipUdpDriver> =
            SlotDispatch::new(observer, handle, Requesters::new());
        (0..3)
            .map(|rid| {
                dispatch
                    .requesters_mut()
                    .replies
                    .register_sink(rid, 1, None, ReplyAcceptance::Any, NoReplies)
                    .map(|_| ())
            })
            .collect()
    }

    // A build whose pending-query table holds fewer than three cannot compile the control.
    const { assert!(caps::MAX_PENDING_QUERIES >= 3) };
    let mut stated = SessionLimits::BUILD;
    if stated
        .select_max_pending_queries(Quota::at_most(2))
        .is_err()
    {
        // A build of one value refuses two: it has no other snapshot to hand the session.
        assert!(MaxPendingQueries::DOMAIN.is_singleton());
        return;
    }
    static TABLE: Table = SessionSlots::new();
    static RUNTIME: wz_runtime_coop::RuntimeCell<Frozen, 1, 64, 1> =
        wz_runtime_coop::RuntimeCell::new();
    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link = Rc::new(link);
    let runtime = RUNTIME
        .start::<LwipUdpDriver>(Frozen)
        .expect("the runtime is started once");
    let observer: &'static ObserverCell<DefaultSinks> = Box::leak(Box::new(ObserverCell::new()));

    let claim = TABLE
        .claim(driver_on(&link, 7747), Fill)
        .ok()
        .expect("slot");
    let (held, _) = new_session_in_slot(
        claim,
        || SessionInitParams {
            limits: stated,
            ..params(0xe1)
        },
        CoopTime::new(&runtime),
    );
    assert_eq!(
        three_pending_queries(observer, held),
        [Ok(()), Ok(()), Err(RegisterError::TableFull)]
    );
    assert_eq!(TABLE.in_use(), 0, "the slot came back");

    // CONTROL: the next session in the slot, under the build's limits, takes the third.
    let claim = TABLE
        .claim(driver_on(&link, 7748), Fill)
        .ok()
        .expect("slot");
    let (built, _) = new_session_in_slot(claim, || params(0xe2), CoopTime::new(&runtime));
    assert_eq!(
        three_pending_queries(observer, built),
        [Ok(()), Ok(()), Ok(())]
    );
}

#[test]
fn the_peer_tables_count_in_the_slot_size() {
    let slot = Table::slot_bytes();
    let peers = PeerTables::bytes();
    println!("slot {slot} B, of which peer tables {peers} B");
    assert!(slot >= peers, "a slot holds its peer tables");
}
