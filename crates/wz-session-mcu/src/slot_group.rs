// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The group plane of the client node on the slot profile: a multicast group the node is a member
//! of, beside the sessions it dials and accepts, with no allocator.
//!
//! A group has no handshake and no session with anyone: a member announces itself with a JOIN
//! beacon, admits the members whose beacons it hears, and puts what it publishes on the group for
//! all of them. So the node's plane is one task, [`crate::group_drive`]'s pump over a
//! [`GroupTransport`] in a cell of a [`MulticastSlots`] table the image declared, and what the
//! node does with what the group carries is what it does with what a session carries: the
//! datagrams of the group become the same [`IterationEvent`]s, fanned to the same observer (the
//! subscriptions the image registered), and the node's publishers put on the group by the same
//! [`Schedule`] that puts on a session.
//!
//! ## What the group carries
//!
//! In a build with no allocator the group's outbound vocabulary is the literal Put (the offer of
//! `multicast_tx_offer_put_literal`): the replies a queryable writes, the request a querier asks
//! with and the answer a token gives to an interest are heap-only forms in the shared emit, so a
//! node that has a group carries PUBLISHERS and SUBSCRIPTIONS and no more (the node declaration
//! refuses the rest, by name, where it is written). Inbound, a group's Frame is a lent record
//! like a session's, so a subscription keeps the latest sample of any member's put.
//!
//! One group is one set of peer tables for every member: an alias a member declares
//! (`DeclKexpr`) is an id of the whole group, not of that member. A put that names its key in full
//! (a literal, which is what a member that declares nothing sends, as zenoh-pico's multicast
//! peer does) is unaffected; two members that alias different keys under one id are not told
//! apart, which is the shared table's limit and is stated here rather than discovered.
//!
//! ## What it owns
//!
//! The members the group has, counted from the arrivals and departures the pump reports
//! ([`GroupState::members`]); how many puts each publisher offered (counted in the
//! [`PublishCounts`] the image gives it, the node's sessions' own); and when the group is lost (its receiver failed) or could not be joined, the node tries again a
//! second later, as the connect manager does for a dial.
//!
//! This module does not link `alloc`.

use core::cell::{Cell, RefCell};

use wz_runtime_coop::group_transport::GroupTransport;
use wz_runtime_coop::session_drive::LinkOpenError;
use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopRuntime, CoopTime};
use wz_runtime_core::TimeSource;
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::multicast_dispatch::{MulticastConfig, MulticastDispatcher};
use wz_session_core::multicast_params::{zid_vec, MulticastOutcome, MulticastParams};
use wz_session_core::multicast_tx::multicast_tx_offer_put_literal;
use wz_session_core::peer_tables::PeerTables;
use wz_session_core::session_init_params::{LinkRxConf, TxQueueConf};
use wz_session_core::slot_observer::{ObserverCell, Requesters};
use wz_session_core::WhatAmI;

use crate::app_layer::NoReplies;
use crate::group_drive::{spawn_multicast_pump, MulticastSession, MulticastSlots};
use crate::slot_client::DocumentSinks;
use crate::slot_node::ZID_MAX;
use crate::slot_plane::{Plane, PlaneContext, PlaneRunning};
use crate::slot_publisher::{Publication, PublishCounts};
use crate::slot_schedule::{Outcome, Schedule};

/// How long after a group was lost, or could not be joined, the node tries to join it again.
pub const REJOIN_MS: u64 = 1_000;

/// The sequence-number resolution a group's members agree on, as its JOINs advertise it. There is
/// no negotiation on a group: a JOIN that advertises another is refused, so this is the value the
/// stock peers share (zenoh-pico's `Z_SN_RESOLUTION`, `0x02`, the 28-bit ring).
pub const GROUP_SN_RESOLUTION: u8 = 0x02;

/// The batch a group's members agree on, in bytes: a JOIN that advertises another is refused, and
/// a put whose frame is longer leaves as a fragment chain. zenoh-pico's `BATCH_MULTICAST_SIZE`.
pub const GROUP_BATCH_BYTES: u16 = 2_048;

/// What the group plane keeps between its task and the program's loop, in storage the image
/// declares: the peer tables its pump dispatches against and the members it has. One `static`
/// whose initial value is all zero bytes, so it is `.bss`.
pub struct GroupState {
    peers: RefCell<PeerTables>,
    members: Cell<u32>,
    joins: Cell<u32>,
    refused: Cell<u32>,
    turned_away: Cell<u32>,
}

// SAFETY: the profile's rule: one thread drives the node, and the pump task (which writes) and the
// program's loop (which reads) run on it, never at the same moment.
unsafe impl Sync for GroupState {}

impl GroupState {
    /// A state with no members and empty peer tables.
    pub const fn new() -> Self {
        Self {
            peers: RefCell::new(PeerTables::new_static()),
            members: Cell::new(0),
            joins: Cell::new(0),
            refused: Cell::new(0),
            turned_away: Cell::new(0),
        }
    }

    /// The members the group has now: the peers whose JOIN was admitted and who have neither said
    /// Close nor outlived their lease.
    pub fn members(&self) -> u32 {
        self.members.get()
    }

    /// How many times the group was joined: once at the start, and again after each loss.
    pub fn joins(&self) -> u32 {
        self.joins.get()
    }

    /// How many times a join was refused (no socket, no route, no cell, no task).
    pub fn join_refused(&self) -> u32 {
        self.refused.get()
    }

    /// How many JOINs the group's member table turned away because every row held a member, in the
    /// group's current join (it starts again at none with each join, as the members do). A peer
    /// that is turned away announces itself again each join interval, so this counts beacons: a
    /// number above none is the table being full, which nothing else says.
    pub fn members_turned_away(&self) -> u32 {
        self.turned_away.get()
    }

    fn member_arrived(&self) {
        self.members.set(self.members.get().saturating_add(1));
    }

    fn member_lost(&self) {
        self.members.set(self.members.get().saturating_sub(1));
    }
}

impl Default for GroupState {
    fn default() -> Self {
        Self::new()
    }
}

/// How a stack opens the transport of the group: the socket bound and joined, out of whatever the
/// stack keeps for it. The group's counterpart of `Bind`, which takes the locator a dial names;
/// the group a node joins is the one the image states, so there is nothing to pass.
pub trait GroupBind<T> {
    /// A transport joined to the group, or why the stack could not give one
    /// ([`LinkOpenError::Exhausted`] for no socket, [`LinkOpenError::Refused`] for a group the
    /// kernel would not let it join).
    fn bind(&mut self) -> Result<T, LinkOpenError>;
}

/// The timing of a group session, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupTiming {
    /// The lease the node advertises in its JOIN and holds the other members for.
    pub lease_ms: u64,
    /// The time between two JOIN beacons.
    pub join_interval_ms: u64,
    /// The cadence of the sweep that evicts members past their lease.
    pub tick_ms: u64,
}

impl GroupTiming {
    /// zenoh's own: a lease of ten seconds, a beacon every 2.5 s, a sweep every second.
    pub const ZENOH: Self = Self {
        lease_ms: 10_000,
        join_interval_ms: 2_500,
        tick_ms: 1_000,
    };
}

/// The publishers of a group, due at their periods.
struct GroupPublisher<const P: usize> {
    schedule: Schedule<P>,
    /// The publications found due and not yet offered, one bit each.
    queued: u32,
}

impl<const P: usize> GroupPublisher<P> {
    const FITS: () = assert!(P <= 32, "a group's publishers are queued in one word");

    const fn new() -> Self {
        let () = Self::FITS;
        Self {
            schedule: Schedule::new(),
            queued: 0,
        }
    }

    /// The next publication to offer at `now_ms`, if any is due: the schedule is asked only when
    /// nothing is queued, so each due put is offered once, in the order of the declaration.
    fn next(&mut self, now_ms: u64, items: &[Publication]) -> Option<usize> {
        if self.queued == 0 {
            let queued = &mut self.queued;
            self.schedule.poll(now_ms, items, |at, _| {
                *queued |= 1u32 << at;
                Outcome::Sent
            });
        }
        if self.queued == 0 {
            return None;
        }
        let at = self.queued.trailing_zeros() as usize;
        self.queued &= self.queued - 1;
        Some(at)
    }
}

/// A node's group: the table its pump lives in, the state it shares with the loop, how the stack
/// joins the group, what the node publishes on it, and its timing.
pub struct SlotGroup<C, T, B, const MEMBERS: usize, const P: usize>
where
    C: ClockSource + 'static,
    T: GroupTransport + 'static,
    B: GroupBind<T>,
{
    /// The table the group's session is put in: one cell, the group's.
    pub slots: &'static MulticastSlots<C, T, MEMBERS, 1>,
    /// What the group keeps for the loop.
    pub state: &'static GroupState,
    /// How the group is joined.
    pub bind: B,
    /// What the node puts on the group, and how often.
    pub publications: [Publication; P],
    /// Where the puts are counted: the counts of the node's sessions' puts, so a publication that
    /// goes out on a session and on the group is one count of puts that went out.
    pub counts: &'static PublishCounts<P>,
    /// The timing of the session.
    pub timing: GroupTiming,
}

/// A [`SlotGroup`] that has started: it holds the group's task and joins again when it ends.
pub struct SlotGroupRunning<C, T, B, const MEMBERS: usize, const P: usize>
where
    C: ClockSource + 'static,
    T: GroupTransport + 'static,
    B: GroupBind<T>,
{
    plane: SlotGroup<C, T, B, MEMBERS, P>,
    runtime: CoopRuntime<C>,
    observer: &'static ObserverCell<DocumentSinks>,
    zid: [u8; ZID_MAX],
    zid_len: usize,
    task: Option<CoopLocalJoinHandle<MulticastOutcome>>,
    join_at_ms: u64,
}

impl<C, T, B, const MEMBERS: usize, const P: usize> Plane<C> for SlotGroup<C, T, B, MEMBERS, P>
where
    C: ClockSource + 'static,
    T: GroupTransport + 'static,
    B: GroupBind<T>,
{
    type Running = SlotGroupRunning<C, T, B, MEMBERS, P>;

    fn start(self, context: PlaneContext<'_, C>) -> Self::Running {
        let mut zid = [0u8; ZID_MAX];
        let zid_len = context.zid.len().min(zid.len());
        zid[..zid_len].copy_from_slice(&context.zid[..zid_len]);
        SlotGroupRunning {
            plane: self,
            runtime: context.runtime,
            observer: context.observer,
            zid,
            zid_len,
            task: None,
            // The first tick joins.
            join_at_ms: 0,
        }
    }
}

impl<C, T, B, const MEMBERS: usize, const P: usize> SlotGroupRunning<C, T, B, MEMBERS, P>
where
    C: ClockSource + 'static,
    T: GroupTransport + 'static,
    B: GroupBind<T>,
{
    /// The parameters the node advertises on the group.
    fn params(&self) -> MulticastParams {
        MulticastParams {
            whatami: WhatAmI::Peer,
            zid: zid_vec(&self.zid[..self.zid_len]),
            lease_ms: self.plane.timing.lease_ms,
            join_interval_ms: self.plane.timing.join_interval_ms,
            seq_num_res: GROUP_SN_RESOLUTION,
            req_id_res: GROUP_SN_RESOLUTION,
            batch_size: GROUP_BATCH_BYTES,
            is_qos: false,
            tx_queue: TxQueueConf::default(),
            link_rx: LinkRxConf::default(),
        }
    }

    // Not inlined into the tick that calls it, for the reason `SlotDialer::dial` is not: the
    // session (a peer table, the parameters) is built by value on the way into its cell, and that
    // frame should exist for the length of one join.
    #[inline(never)]
    fn join(&mut self) -> bool {
        let state = self.plane.state;
        let Ok(transport) = self.plane.bind.bind() else {
            return false;
        };
        let session = MulticastSession {
            dispatcher: MulticastDispatcher::new(MulticastConfig::new(self.plane.timing.lease_ms)),
            transport,
            params: self.params(),
            tick_ms: self.plane.timing.tick_ms,
            max_iters: None,
        };
        let Ok(pump) = self.plane.slots.claim(self.runtime.clone(), session) else {
            // The table counted the refusal, and dropped the session with its socket.
            return false;
        };
        let observer = self.observer;
        let mut requesters = Requesters::<NoReplies, NoReplies>::new();
        let on_event = move |event: IterationEvent<'_>| {
            match event {
                IterationEvent::MulticastPeerArrived(_) => state.member_arrived(),
                IterationEvent::MulticastPeerLost(_) => state.member_lost(),
                _ => {}
            }
            let mut peers = state.peers.borrow_mut();
            observer
                .borrow_mut()
                .dispatch_event(&mut peers, &mut requesters, event);
        };
        let clock = CoopTime::new(&self.runtime);
        let publications = self.plane.publications;
        let counts = self.plane.counts;
        let mut publisher = GroupPublisher::<P>::new();
        let next_tx = move || {
            let at = publisher.next(clock.now_monotonic_ms(), &publications)?;
            let publication = publications.get(at)?;
            let (key, body) = (publication.key, publication.body);
            let offer = multicast_tx_offer_put_literal(key, body.as_bytes())?;
            counts.record_sent(at);
            Some(offer)
        };
        let local = CoopLocalSet::new(&self.runtime);
        match spawn_multicast_pump(&local, pump, on_event, next_tx, || false) {
            Ok(task) => {
                // The table of a fresh session holds nobody and has turned nobody away.
                state.members.set(0);
                state.turned_away.set(0);
                state.joins.set(state.joins.get().saturating_add(1));
                self.task = Some(task);
                true
            }
            // The runtime's task table refused it, and counted that; the pump went with it.
            Err(_) => false,
        }
    }
}

impl<C, T, B, const MEMBERS: usize, const P: usize> PlaneRunning
    for SlotGroupRunning<C, T, B, MEMBERS, P>
where
    C: ClockSource + 'static,
    T: GroupTransport + 'static,
    B: GroupBind<T>,
{
    fn tick(&mut self, now_ms: u64) {
        if let Some(task) = &self.task {
            if !task.is_finished() {
                self.plane
                    .state
                    .turned_away
                    .set(self.plane.slots.join_refusals());
                return;
            }
            // The group ended (its receiver failed): its members went with it.
            self.task = None;
            self.plane.state.members.set(0);
            self.join_at_ms = now_ms.saturating_add(REJOIN_MS);
            return;
        }
        if now_ms < self.join_at_ms {
            return;
        }
        if !self.join() {
            let state = self.plane.state;
            state.refused.set(state.refused.get().saturating_add(1));
            self.join_at_ms = now_ms.saturating_add(REJOIN_MS);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const ITEMS: [Publication; 2] = [
        Publication {
            key: "lab/a",
            period_ms: 100,
            body: "",
        },
        Publication {
            key: "lab/b",
            period_ms: 250,
            body: "",
        },
    ];

    /// Everything the publisher offers at `now_ms`, in the order it offers it.
    fn offered(publisher: &mut GroupPublisher<2>, now_ms: u64) -> Vec<usize> {
        let mut out = Vec::new();
        while let Some(at) = publisher.next(now_ms, &ITEMS) {
            out.push(at);
            assert!(
                out.len() <= 2,
                "a put offered over and over is a loop that never yields"
            );
        }
        out
    }

    #[test]
    fn each_due_put_is_offered_once_in_the_order_of_the_declaration() {
        let mut publisher = GroupPublisher::<2>::new();
        assert_eq!(
            offered(&mut publisher, 1_000),
            [0, 1],
            "both are due at the start"
        );
        assert!(
            offered(&mut publisher, 1_050).is_empty(),
            "and neither again within a period"
        );
        assert_eq!(
            offered(&mut publisher, 1_100),
            [0],
            "the shorter period is due on its own"
        );
        assert_eq!(offered(&mut publisher, 1_250), [0, 1]);
    }

    #[test]
    fn a_publisher_that_polls_late_offers_once_and_counts_again_from_there() {
        let mut publisher = GroupPublisher::<2>::new();
        assert_eq!(offered(&mut publisher, 0), [0, 1]);
        // A loop that was away for a long time owes one put of each, not the periods it missed.
        assert_eq!(offered(&mut publisher, 10_000), [0, 1]);
        assert!(offered(&mut publisher, 10_050).is_empty());
    }

    #[test]
    fn the_members_follow_the_arrivals_and_departures_and_never_go_below_none() {
        let state = GroupState::new();
        assert_eq!(state.members(), 0);
        state.member_lost();
        assert_eq!(
            state.members(),
            0,
            "a departure with nobody there leaves nobody"
        );
        state.member_arrived();
        state.member_arrived();
        state.member_lost();
        assert_eq!(state.members(), 1);
        assert_eq!((state.joins(), state.join_refused()), (0, 0));
        assert_eq!(state.members_turned_away(), 0);
    }
}
