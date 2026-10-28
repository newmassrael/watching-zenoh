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
        tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
        link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
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
    let runtime = RUNTIME.start(Frozen).expect("the runtime is started once");

    let claim_a = TABLE
        .claim(driver_on(&link, 7741), Fill)
        .ok()
        .expect("slot");
    let claim_b = TABLE
        .claim(driver_on(&link, 7742), Fill)
        .ok()
        .expect("slot");
    let a = new_session_in_slot(claim_a, params(0xa1), CoopTime::new(&runtime));
    let b = new_session_in_slot(claim_b, params(0xb1), CoopTime::new(&runtime));
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
        for rid in 0..caps::MAX_PENDING_FINALS as u64 {
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
    let runtime = RUNTIME.start(Frozen).expect("the runtime is started once");
    let mut subscribers: SubscriberTable<BoxedSink> = SubscriberTable::new();

    let claim = TABLE
        .claim(driver_on(&link, 7743), Fill)
        .ok()
        .expect("slot");
    let first = new_session_in_slot(claim, params(0xc1), CoopTime::new(&runtime));
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
    let second = new_session_in_slot(claim, params(0xc2), CoopTime::new(&runtime));
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

#[test]
fn the_peer_tables_count_in_the_slot_size() {
    let slot = Table::slot_bytes();
    let peers = PeerTables::bytes();
    println!("slot {slot} B, of which peer tables {peers} B");
    assert!(slot >= peers, "a slot holds its peer tables");
}
