// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The multicast pump on the `session-slot` profile (fixed-memory step S9c): its
//! reply queue is a table that refuses and counts, and the pump lives in a cell of
//! a table the image declares, claimed before it runs and given back when it ends.
//!
//! Before this step the multicast loop's reply queue was an `Rc<RefCell<VecDeque>>`
//! that grew for as long as a peer kept asking, and the pump was built into the
//! future of its task, so a session on the slot profile could not be spawned at all
//! (a task cell has a size, and a peer table and a router are bigger). Four claims,
//! each counted by one counting `#[global_allocator]`:
//!
//! - THE QUEUE: filled to its capacity it takes every reply; the reply past it is
//!   dropped and counted, nothing is heard of it again, the others keep their order,
//!   a drained queue takes replies again, and none of it costs the heap anything (the
//!   items here are the inline kind: a `ResponseFinal` is a request id and a QoS
//!   word; the boxed kinds' bodies are the codec owned mirrors' step);
//! - THE CELL: a pump claimed from the table costs the heap nothing, a claim on a
//!   full table is refused, counted, and gives back the group socket the refused
//!   session held, and a cell is claimable again once its pump is gone;
//! - THE RUN: the pump in its cell admits a peer from the group over the lwIP
//!   loopback, as the heap profile's pump does, as a task of a static runtime.
//!
//! What a beacon or a framed reply costs on the way out is NOT claimed: the JOIN and
//! the data frames are still built into `Vec`s by `wz-session-core`'s multicast
//! encoders, which is that crate's step.
//!
//! Host-test level: no board runs it, and the stack the pump takes is not measured.

use wz_link_lwip::rx_sockets::{bind_session_multicast_rx_in, SessionMulticastRxPool};
use wz_link_lwip::LwipLink;
use wz_runtime_coop::{ClockSource, CoopLocalSet, RuntimeCell};
use wz_session_core::multicast_dispatch::{MulticastConfig, MulticastDispatcher};
use wz_session_core::multicast_join::encode_join;
use wz_session_core::multicast_params::{zid_vec, MulticastOutcome, MulticastParams};
use wz_session_core::multicast_tx::MulticastTxItem;
use wz_session_core::sample::QosLevel;
use wz_session_core::sn::{self, MulticastTxConduits};
use wz_session_core::WhatAmI;
use wz_session_lwip::multicast_drive::{
    spawn_multicast_pump, LwipMulticastDriver, MulticastReplyQueue, MulticastSession,
    MulticastSlots, MulticastSpawnRefused,
};

#[path = "support/alloc_count.rs"]
mod alloc_count;
use alloc_count::Measurement;

#[global_allocator]
static GLOBAL: alloc_count::CountingAllocator = alloc_count::CountingAllocator;

/// A clock that never moves, so no JOIN interval or lease deadline advances and the
/// run is the same on every host.
#[derive(Clone, Default)]
struct Frozen;
impl ClockSource for Frozen {
    fn now_us(&self) -> u64 {
        0
    }
}

fn params(zid: &[u8]) -> MulticastParams {
    MulticastParams {
        whatami: WhatAmI::Peer,
        zid: zid_vec(zid),
        lease_ms: 5_000,
        join_interval_ms: 1,
        seq_num_res: 0x02,
        req_id_res: 0x02,
        batch_size: 2_048,
        is_qos: false,
        tx_queue: wz_session_core::session_init_params::TxQueueConf::default(),
    }
}

fn final_for(request_id: u64) -> MulticastTxItem {
    MulticastTxItem::ResponseFinal {
        request_id,
        qos: QosLevel::default(),
    }
}

fn id_of(item: MulticastTxItem) -> u64 {
    match item {
        MulticastTxItem::ResponseFinal { request_id, .. } => request_id,
        other => panic!("only finals were queued, got {other:?}"),
    }
}

/// The queue takes `N` replies, drops the `N+1`th and counts it, keeps FIFO order,
/// takes replies again once drained, and allocates nothing for any of it.
#[test]
fn the_reply_queue_refuses_the_reply_it_has_no_room_for_and_counts_it() {
    use wz_session_core::multicast_reply_sink::MulticastReplyEnqueue;

    static REPLIES: MulticastReplyQueue<3> = MulticastReplyQueue::new();
    let sink: &'static MulticastReplyQueue<3> = &REPLIES;
    let items: Vec<MulticastTxItem> = (1..=6).map(final_for).collect();
    let mut items = items.into_iter();
    let m = Measurement::new();

    let ((), n) = m.count("fill to capacity", || {
        for _ in 0..3 {
            sink.enqueue(items.next().expect("an item"));
        }
    });
    assert_eq!(n, 0, "three replies into a queue of three cost the heap 0");
    assert_eq!(
        (REPLIES.len(), REPLIES.dropped()),
        (3, 0),
        "full, none dropped"
    );

    let ((), n) = m.count("past capacity", || {
        sink.enqueue(items.next().expect("an item"));
        sink.enqueue(items.next().expect("an item"));
    });
    assert_eq!(n, 0, "a refused reply costs the heap nothing either");
    assert_eq!(
        (REPLIES.len(), REPLIES.dropped()),
        (3, 2),
        "two replies past the bound were dropped and counted, the queue still holds three"
    );

    let (order, n) = m.count("drain", || {
        let mut order = [0u64; 3];
        for slot in &mut order {
            *slot = id_of(REPLIES.pop().expect("a queued reply"));
        }
        order
    });
    assert_eq!(n, 0, "draining costs the heap nothing");
    assert_eq!(order, [1, 2, 3], "FIFO, and the dropped ones are not in it");
    assert!(REPLIES.pop().is_none() && REPLIES.is_empty());

    // The count only rises, and a drained queue takes replies again.
    sink.enqueue(items.next().expect("an item"));
    assert_eq!((REPLIES.len(), REPLIES.dropped()), (1, 2));
    assert_eq!(id_of(REPLIES.pop().expect("the reply")), 6);
}

type Groups = MulticastSlots<Frozen, 4, 1>;
type Sockets = SessionMulticastRxPool<2>;

/// A group session over a socket claimed out of `pool`, with the `peer` JOIN
/// already queued on the group, built OUTSIDE any window (the session's `Vec`
/// zid is the test's, not the pump's).
fn session(
    link: &LwipLink,
    pool: &'static Sockets,
    port: u16,
    max_iters: Option<usize>,
) -> MulticastSession<4> {
    let group = wz_link_lwip::rx_sockets::SESSION_MULTICAST_GROUP_DEFAULT;
    let socket = bind_session_multicast_rx_in(link, group, port, pool).expect("bind + join");
    MulticastSession {
        dispatcher: MulticastDispatcher::<4>::new(MulticastConfig::new(5_000)),
        driver: LwipMulticastDriver::new(socket, group, port),
        params: params(&[0xAA, 0xBB, 0xCC, 0xDD]),
        tick_ms: 5,
        max_iters,
    }
}

/// A pump claimed from a table costs the heap nothing; a claim on a full table is
/// refused, counted, and its socket goes back to its pool; the cell is claimable
/// again once its pump is gone.
#[test]
fn a_claim_on_a_full_table_is_refused_counted_and_gives_back_its_socket() {
    static GROUPS: Groups = MulticastSlots::new();
    static SOCKETS: Sockets = SessionMulticastRxPool::new();
    static RUNTIME: RuntimeCell<Frozen, 2, 256, 4> = RuntimeCell::new();

    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link: &'static LwipLink = Box::leak(Box::new(link));
    let runtime = RUNTIME.start(Frozen).expect("the runtime starts once");
    let first = session(link, &SOCKETS, 7491, None);
    let second = session(link, &SOCKETS, 7492, None);
    assert_eq!(SOCKETS.in_use(), 2, "a socket for each session offered");
    let m = Measurement::new();

    let (claimed, n) = m.count("claim", || GROUPS.claim(runtime.clone(), link, first));
    let pump = claimed.expect("a free cell takes the pump");
    assert_eq!(n, 0, "building the pump in its cell costs the heap nothing");
    assert_eq!((GROUPS.in_use(), GROUPS.refused()), (1, 0));
    assert_eq!(
        pump.dispatcher().active_peers(),
        0,
        "up, with no member yet"
    );

    let (refused, n) = m.count("refused claim", || {
        GROUPS.claim(runtime.clone(), link, second)
    });
    assert_eq!(
        refused.err(),
        Some(MulticastSpawnRefused::NoCell),
        "a full table says so by name"
    );
    assert_eq!(n, 0, "a refusal costs the heap nothing");
    assert_eq!((GROUPS.in_use(), GROUPS.refused()), (1, 1), "counted once");
    assert_eq!(
        SOCKETS.in_use(),
        1,
        "the refused session's socket went back to its pool"
    );

    drop(pump);
    assert_eq!(GROUPS.in_use(), 0, "the cell is free once its pump is gone");
    assert_eq!(SOCKETS.in_use(), 0, "and its socket is back too");
    let again = GROUPS
        .claim(runtime.clone(), link, session(link, &SOCKETS, 7493, None))
        .expect("the freed cell takes the next pump");
    assert_eq!((GROUPS.in_use(), GROUPS.refused()), (1, 1));
    drop(again);
}

/// The pump in its cell does what the heap profile's pump does: a peer's JOIN, put on
/// the group, is delivered over the lwIP loopback and admitted into the peer table
/// (our own beacon, echoed back, is zid-filtered), and it runs as a task of a
/// static runtime until its budget ends it, which frees the cell.
#[test]
fn the_pump_in_its_cell_admits_a_peer_over_the_loopback_as_a_task() {
    static GROUPS: Groups = MulticastSlots::new();
    static SOCKETS: Sockets = SessionMulticastRxPool::new();
    static RUNTIME: RuntimeCell<Frozen, 2, 256, 4> = RuntimeCell::new();

    let (_serial, link) = wz_link_lwip::lwip_test_link();
    let link: &'static LwipLink = Box::leak(Box::new(link));
    let group = wz_link_lwip::rx_sockets::SESSION_MULTICAST_GROUP_DEFAULT;
    let port = 7494;
    let runtime = RUNTIME.start(Frozen).expect("the runtime starts once");
    let local = CoopLocalSet::new(&runtime);

    // The peer's JOIN is on the group before the pump exists, so the first pass reads it.
    let socket = bind_session_multicast_rx_in(link, group, port, &SOCKETS).expect("bind");
    let peer = params(&[0x01, 0x02, 0x03, 0x04]);
    let join = encode_join(
        &peer,
        &MulticastTxConduits::new(sn::mask_from_res(peer.seq_num_res)),
    );
    socket.send_to(group, port, &join).expect("inject the JOIN");
    let hand_session = MulticastSession {
        dispatcher: MulticastDispatcher::<4>::new(MulticastConfig::new(5_000)),
        driver: LwipMulticastDriver::new(socket, group, port),
        params: params(&[0xAA, 0xBB, 0xCC, 0xDD]),
        tick_ms: 5,
        max_iters: Some(12),
    };

    // Driven by hand first: the member is admitted and the table says so.
    let mut hand = GROUPS
        .claim(runtime.clone(), link, hand_session)
        .expect("a cell");
    let mut outcome = None;
    for _ in 0..20 {
        outcome = hand.step(&mut |_| {}, &mut || None, None);
        if outcome.is_some() {
            break;
        }
    }
    assert_eq!(outcome, Some(MulticastOutcome::IterationLimit));
    assert_eq!(
        hand.dispatcher().active_peers(),
        1,
        "the JOIN admitted the peer"
    );
    drop(hand);
    assert_eq!(GROUPS.in_use(), 0);

    // And as a task of the static runtime, with a reply queue the loop pops from.
    let task_session = session(link, &SOCKETS, port, Some(6));
    let pump = GROUPS
        .claim(runtime.clone(), link, task_session)
        .expect("a cell");
    let handle = spawn_multicast_pump(&local, pump, |_event| {}, || None, || false)
        .expect("the task table has a cell");
    for _ in 0..40 {
        local.run_until_idle();
        if handle.is_finished() {
            break;
        }
    }
    assert!(handle.is_finished(), "the budget ends the task");
    drop(handle);
    local.run_until_idle();
    assert_eq!(GROUPS.in_use(), 0, "the ended task gave its cell back");
    assert_eq!(SOCKETS.in_use(), 0, "and its socket");
    link.leave_multicast_group(group).expect("leave group");
}
