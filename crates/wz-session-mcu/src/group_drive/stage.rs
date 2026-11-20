// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A multicast group's transmission stage, pushed onto by the group's producers and written by
//! its pump, on a host whose producers and pump take turns on one thread.
//!
//! The tokio engine's producer pushes a message onto its group's pipeline on its own thread
//! (`wz_runtime_tokio::multicast_pipeline`): the session core's `multicast_tx_push` asks the lane
//! for room, mints the sequence number, frames the message and enqueues it, and asks again before
//! each further fragment of a chain, which a lane that stays full cuts with the drop marker. The
//! pump that writes the lanes advertises in its JOIN the sequence numbers it has written, not the
//! ones minted. [`GroupTxStage`] is that pipeline for a group whose pump is a task of a
//! cooperative host: a producer calls the same `multicast_tx_push` against the stage, and the
//! pump, given the stage ([`MulticastPump::attach_tx_stage`](super::MulticastPump::attach_tx_stage)),
//! writes the datagrams it holds and advertises what it wrote.
//!
//! The waiting is the host's: a producer whose lane is full runs the host's tasks, in which the
//! group's pump writes what its socket takes, and waits on the socket ([`GroupTxPace`]).
//!
//! The minter is held for the whole of one push, as the tokio engine holds a conduit's stage, so a
//! chain's sequence numbers stay consecutive while its producer waits between two fragments. What
//! is pushed while it is held (a reply the group's own dispatch stages inside that wait) is
//! pushed when the holder lets go, behind its message, as a push behind a held stage lock is.
//!
//! A reply (what comes in through `MulticastReplyEnqueue::enqueue`: what the group's dispatch
//! stages for a member's interest or query, and what the group answers a member's ask with) is
//! put on its lane without waiting, since it is staged inside the pump it would wait for, and
//! holds one of [`MAX_MULTICAST_REPLIES`] slots until the pump takes it, as every reply queue of
//! a group does (`MulticastReplyQueue`): the reply past them is dropped and counted apart from
//! the lanes' drops, so a member that asks faster than the group's socket writes cannot grow the
//! stage for as long as it keeps asking.

use alloc::collections::VecDeque;
use alloc::rc::Rc;
use core::cell::{Cell, RefCell};

use wz_runtime_coop::group_transport::{GroupSend, GroupTransport};
use wz_session_core::caps::MAX_MULTICAST_REPLIES;
use wz_session_core::link::{LinkRoom, RoomAnswer, RoomWait};
use wz_session_core::multicast_params::MulticastParams;
use wz_session_core::multicast_reply_sink::MulticastReplyEnqueue;
use wz_session_core::multicast_tx::{
    multicast_tx_conduit, multicast_tx_push, MulticastTxDatagram, MulticastTxItem,
    MulticastTxLanes, MulticastTxQueue,
};
use wz_session_core::qos::Priority;
use wz_session_core::sn::{self, MulticastTxConduits};
use wz_session_core::tx_deadline::PushOutcome;

/// What a producer that may wait for room does while the lane its message takes is full: the
/// host runs its tasks, the group's pump among them, which writes what the group's socket takes;
/// the socket is waited on; and the wait is spent on the host's clock.
pub trait GroupTxPace {
    /// One pass of the host's tasks.
    fn pass(&self);

    /// The host's clock, in microseconds.
    fn now_us(&self) -> u64;

    /// Wait at most `wait_us` for the group's socket to take another datagram: whether it will.
    /// A host whose socket cannot tell answers `true`.
    fn wait_writable(&self, wait_us: u64) -> bool;

    /// Whether the group's session ended, after which nothing writes the stage.
    fn ended(&self) -> bool;
}

/// A group's transmission stage: the sequence numbers its producers mint, the datagrams they put
/// on its lanes, bounded as the tokio engine bounds its group's pipeline
/// (`MulticastTxLanes::of_group`), and what each lane dropped for want of room; and the replies it
/// holds, bounded by [`MAX_MULTICAST_REPLIES`], and how many it dropped for want of a slot. The
/// two drop counts are kept apart because they answer different questions: [`Self::drops`] is
/// the lanes' (messages of the session that found their lane full within their wait, by
/// priority, as the tokio group counts a congestion drop), and [`Self::dropped`] is the reply
/// limit's (which tells a deployment its declared limit is too small). Cloned, it is the same
/// stage: the producers hold one clone and the group's pump another.
#[derive(Clone)]
pub struct GroupTxStage {
    inner: Rc<Inner>,
}

struct Inner {
    params: MulticastParams,
    /// The sequence numbers of the group's conduits, held by one push at a time.
    minted: RefCell<MulticastTxConduits>,
    lanes: RefCell<Lanes>,
    /// What was pushed while another push held the conduits, in the order it was pushed, each
    /// with whether it holds a reply slot.
    deferred: RefCell<VecDeque<(MulticastTxItem, bool)>>,
    /// How many reply slots are held: by a reply deferred, or by the first datagram of a reply
    /// queued on a lane.
    replies: Cell<usize>,
    /// How many replies were dropped for want of a slot.
    dropped: Cell<u32>,
}

/// The lanes' bound and congestion marks, and the datagrams queued on them in the order they were
/// queued.
struct Lanes {
    bound: MulticastTxLanes,
    queued: VecDeque<Queued>,
}

/// A datagram queued on a lane, and whether it holds the slot of the reply it begins.
struct Queued {
    datagram: MulticastTxDatagram,
    reply: bool,
}

impl GroupTxStage {
    /// An empty stage of the group `params` describes: its conduits from sequence number 0, and
    /// its lanes its queue's sizes in batches of its batch size, one lane when it runs no QoS.
    pub fn new(params: &MulticastParams) -> Self {
        Self {
            inner: Rc::new(Inner {
                params: params.clone(),
                minted: RefCell::new(MulticastTxConduits::new(sn::mask_from_res(
                    params.seq_num_res,
                ))),
                lanes: RefCell::new(Lanes {
                    bound: MulticastTxLanes::of_group(params),
                    queued: VecDeque::new(),
                }),
                deferred: RefCell::new(VecDeque::new()),
                replies: Cell::new(0),
                dropped: Cell::new(0),
            }),
        }
    }

    /// Push `item`, a message of the session, as the tokio engine's producer pushes it: its lane
    /// is asked for room before its sequence number is minted and again before each further
    /// fragment, within the message's deadline, and while the lane is full `pace` runs the host
    /// and waits on the socket. A message that finds no room is a congestion drop, counted on its
    /// lane whether it may block or not, as a multicast transport closes nothing on one; a chain
    /// that runs out of room between two fragments is stopped by the drop marker.
    pub fn push(&self, item: MulticastTxItem, pace: &dyn GroupTxPace) -> PushOutcome {
        let outcome = self.push_held(item, Some(pace), false);
        self.push_deferred();
        outcome
    }

    /// Put `item`, a reply, on the stage without waiting, whatever its lane holds, counted on the
    /// lane: a reply the group's own dispatch stages runs inside the pump it would wait for. It
    /// takes a reply slot, or is dropped and counted ([`Self::dropped`]) when none is free.
    fn admit_reply(&self, item: MulticastTxItem) {
        let inner = &*self.inner;
        if inner.replies.get() >= MAX_MULTICAST_REPLIES {
            inner.dropped.set(inner.dropped.get().saturating_add(1));
            // Freed here, with nothing of the stage borrowed.
            drop(item);
            return;
        }
        inner.replies.set(inner.replies.get() + 1);
        let _ = self.push_held(item, None, true);
        self.push_deferred();
    }

    /// Push `item` holding the conduits, or keep it for the holder's release when another push
    /// holds them (it then counts as pushed). `pace` is `None` for a push that does not wait;
    /// `reply` is a reply whose slot is taken already, which its first datagram holds.
    fn push_held(
        &self,
        item: MulticastTxItem,
        pace: Option<&dyn GroupTxPace>,
        reply: bool,
    ) -> PushOutcome {
        let inner = &*self.inner;
        let Ok(mut minted) = inner.minted.try_borrow_mut() else {
            inner.deferred.borrow_mut().push_back((item, reply));
            return PushOutcome::Pushed;
        };
        let conduit = multicast_tx_conduit(&item, &inner.params);
        let mut queue = StageQueue {
            lanes: &inner.lanes,
            pace,
            reply,
        };
        let outcome = multicast_tx_push(
            item,
            &mut *minted,
            &inner.params,
            &inner.params.tx_queue,
            &mut queue,
        );
        drop(minted);
        // A reply that put no datagram on a lane (one its codec could not frame) holds no slot.
        if queue.reply {
            inner.replies.set(inner.replies.get() - 1);
        }
        if outcome == PushOutcome::Congested {
            inner.lanes.borrow_mut().bound.dropped(conduit);
        }
        outcome
    }

    /// Push what was kept while the conduits were held, once nothing holds them.
    fn push_deferred(&self) {
        loop {
            if self.inner.minted.try_borrow_mut().is_err() {
                return;
            }
            let next = self.inner.deferred.borrow_mut().pop_front();
            let Some((item, reply)) = next else {
                return;
            };
            let _ = self.push_held(item, None, reply);
        }
    }

    /// Take the datagram the group's pump writes next: the oldest of the most urgent lane, a
    /// Control datagram behind what the other lanes queued before it. What it held of its lane is
    /// room again, as the tokio group's lane has room once its writer takes a batch, and the first
    /// datagram of a reply frees the reply's slot.
    pub(super) fn take(&self) -> Option<MulticastTxDatagram> {
        let mut lanes = self.inner.lanes.borrow_mut();
        let at = next_out(&lanes.queued)?;
        let Queued { datagram, reply } = lanes.queued.remove(at)?;
        lanes.bound.written(datagram.priority, datagram.bytes.len());
        if reply {
            self.inner.replies.set(self.inner.replies.get() - 1);
        }
        Some(datagram)
    }

    /// Whether a reply slot is free.
    pub(super) fn has_reply_slot(&self) -> bool {
        self.inner.replies.get() < MAX_MULTICAST_REPLIES
    }

    /// How many replies the stage holds at most: [`MAX_MULTICAST_REPLIES`].
    pub const fn capacity(&self) -> usize {
        MAX_MULTICAST_REPLIES
    }

    /// How many replies were dropped for want of a reply slot since the stage was made. A message
    /// of the session dropped for want of room on its lane is not among them ([`Self::drops`]).
    pub fn dropped(&self) -> u32 {
        self.inner.dropped.get()
    }

    /// The ring mask of the group's sequence numbers.
    pub(super) fn mask(&self) -> u64 {
        sn::mask_from_res(self.inner.params.seq_num_res)
    }

    /// Whether nothing is queued on the stage for the group's pump to write.
    pub fn is_empty(&self) -> bool {
        self.inner.lanes.borrow().queued.is_empty() && self.inner.deferred.borrow().is_empty()
    }

    /// How many messages of `priority` the stage dropped for want of room on their lane; a reply
    /// dropped for want of a slot is not among them ([`Self::dropped`]).
    pub fn drops(&self, priority: Priority) -> u32 {
        self.inner.lanes.borrow().bound.drops(priority)
    }
}

impl MulticastReplyEnqueue for GroupTxStage {
    fn enqueue(&self, item: MulticastTxItem) {
        self.admit_reply(item);
    }
}

/// Which queued datagram the group's pump takes next: the oldest of the most urgent lane, as the
/// tokio engine's group writer serves its lanes, highest first. A Control datagram waits behind
/// what the other lanes queued before it, as that writer's fence holds a control datagram behind
/// the data queued ahead of it, so a declaration never passes a put it was queued after. A group
/// that runs no QoS puts every datagram on one band, and is written in the order it was queued.
fn next_out(queued: &VecDeque<Queued>) -> Option<usize> {
    let band = |at: usize| queued[at].datagram.priority;
    // `min_by_key` keeps the first of equals: the oldest of a lane.
    let at = (0..queued.len()).min_by_key(|&at| band(at).wire_byte())?;
    if band(at) == Priority::Control && at > 0 {
        // Nothing before `at` is a Control datagram, so the fence holds: the other lanes are
        // served, highest first, until what they queued before it has left.
        return (0..queued.len())
            .filter(|&other| band(other) != Priority::Control)
            .min_by_key(|&other| band(other).wire_byte());
    }
    Some(at)
}

/// The stage's lanes as one push asks them for room and enqueues on them.
struct StageQueue<'a> {
    lanes: &'a RefCell<Lanes>,
    /// What the push waits with; `None` for one that does not wait, which every lane admits.
    pace: Option<&'a dyn GroupTxPace>,
    /// Whether the push is a reply whose slot no datagram holds yet: its first datagram takes it.
    reply: bool,
}

impl StageQueue<'_> {
    fn has_room(&self, priority: Priority) -> bool {
        self.lanes.borrow().bound.has_room(priority)
    }
}

impl MulticastTxQueue for StageQueue<'_> {
    fn wait_for_room(&mut self, priority: Priority, wait: RoomWait) -> RoomAnswer {
        let Some(pace) = self.pace else {
            return RoomAnswer::at_once(LinkRoom::Free);
        };
        let mut at_once = self.lanes.borrow_mut().bound.room_at_once(priority, wait);
        // A lane answers congested at once on what its writer last did: a droppable message meets
        // the mark of a drop, or one that may not wait meets the lane full. A writer on a thread of
        // its own drains the moment its socket takes again, lowering the mark before the next
        // producer reads it; this stage's writer runs only in a pass of the host, so once the
        // socket takes again the pass is given first, and the lane is asked again on what it wrote.
        // A socket that is still full leaves the answer standing, with nothing run.
        if at_once == Some(LinkRoom::Congested) && !pace.ended() && pace.wait_writable(0) {
            pace.pass();
            at_once = self.lanes.borrow_mut().bound.room_at_once(priority, wait);
        }
        if let Some(room) = at_once {
            return RoomAnswer::at_once(room);
        }
        let mut waited_us = 0u64;
        loop {
            // Nothing writes the stage of a group whose session ended: what is put on it is lost
            // with the group's link, as the tokio group treats a link that went.
            if pace.ended() {
                return RoomAnswer {
                    room: LinkRoom::Gone,
                    waited_us,
                };
            }
            let wait_us = wait.wait_us().saturating_sub(waited_us);
            let started = pace.now_us();
            pace.pass();
            // Room the pass made is taken now; a socket that has none is waited on, and one that
            // stays full spends the whole wait.
            let room = self.has_room(priority) || pace.wait_writable(wait_us);
            let spent = pace.now_us().saturating_sub(started);
            waited_us = waited_us.saturating_add(if room { spent } else { spent.max(wait_us) });
            if self.has_room(priority) {
                return RoomAnswer {
                    room: LinkRoom::Free,
                    waited_us,
                };
            }
            if waited_us >= wait.wait_us() {
                return RoomAnswer {
                    room: LinkRoom::Congested,
                    waited_us,
                };
            }
        }
    }

    fn enqueue(&mut self, datagram: MulticastTxDatagram) {
        let reply = core::mem::take(&mut self.reply);
        let mut lanes = self.lanes.borrow_mut();
        lanes.bound.taken(datagram.priority, datagram.bytes.len());
        lanes.queued.push_back(Queued { datagram, reply });
    }
}

/// The pump's side of a stage: the datagram it took and its socket had no room for, and the
/// conduits as written, which its JOIN advertises.
pub(super) struct StageWriter {
    stage: GroupTxStage,
    /// Taken from the stage and refused by a full socket: offered again before anything else.
    held: Option<MulticastTxDatagram>,
    /// Each conduit past the last sequence number written on it.
    on_wire: MulticastTxConduits,
}

impl StageWriter {
    /// The writer of `stage`, nothing written yet.
    pub(super) fn new(stage: GroupTxStage) -> Self {
        let on_wire = MulticastTxConduits::new(stage.mask());
        Self {
            stage,
            held: None,
            on_wire,
        }
    }

    /// The conduits as written: what the JOIN advertises. A member re-seeds what it expects from
    /// every JOIN, so a JOIN that advertised a sequence number minted and not yet written would
    /// have the member drop that datagram as stale when it came.
    pub(super) fn on_wire(&self) -> &MulticastTxConduits {
        &self.on_wire
    }

    /// Whether the stage has a reply slot for another offer of the pump's pull seam: the pump
    /// stops pulling when it has none, so what the seam holds waits there, under its own bound.
    pub(super) fn takes_offer(&self) -> bool {
        self.stage.has_reply_slot()
    }

    /// Whether the writer holds a datagram its socket had no room for.
    pub(super) fn holds(&self) -> bool {
        self.held.is_some()
    }

    /// Put `item`, an offer of the pump's pull seam, on the stage as a reply is put on it, so its
    /// sequence number comes from the stage's one minter.
    pub(super) fn admit(&self, item: MulticastTxItem) {
        self.stage.admit_reply(item);
    }

    /// Offer the socket the datagram it had no room for at an earlier step: whether it still has
    /// none. `lost` counts a datagram whose send failed.
    pub(super) fn offer_held<T: GroupTransport + ?Sized>(
        &mut self,
        transport: &mut T,
        lost: &mut u32,
    ) -> bool {
        match self.held.take() {
            Some(datagram) => self.offer(transport, datagram, lost),
            None => false,
        }
    }

    /// Take what the stage holds and offer it to the socket, until the stage is empty or the
    /// socket has no room. `lost` counts a datagram whose send failed.
    pub(super) fn write<T: GroupTransport + ?Sized>(&mut self, transport: &mut T, lost: &mut u32) {
        while self.held.is_none() {
            let Some(datagram) = self.stage.take() else {
                return;
            };
            self.offer(transport, datagram, lost);
        }
    }

    /// Offer `datagram` to the socket: whether it had no room, in which case the writer holds the
    /// datagram for the next step.
    fn offer<T: GroupTransport + ?Sized>(
        &mut self,
        transport: &mut T,
        datagram: MulticastTxDatagram,
        lost: &mut u32,
    ) -> bool {
        match transport.try_send_to_group(&datagram.bytes) {
            GroupSend::Full => {
                self.held = Some(datagram);
                return true;
            }
            GroupSend::Failed => *lost = lost.saturating_add(1),
            GroupSend::Sent => {}
        }
        // A datagram whose send failed is done with too: its sequence number will never arrive,
        // and advertising past it keeps a member from waiting for it.
        self.on_wire
            .written(datagram.priority, datagram.reliable, datagram.sn);
        false
    }
}

#[cfg(test)]
mod tests {
    use alloc::rc::Rc;
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::cell::{Cell, RefCell};
    use core::net::SocketAddr;

    use wz_runtime_coop::group_transport::{GroupSend, GroupTransport};
    use wz_runtime_coop::{ClockSource, CoopRuntime};
    use wz_session_core::driver_loop::IterationEvent;
    use wz_session_core::join_decode::decode_join;
    use wz_session_core::multicast_dispatch::{MulticastConfig, MulticastDispatcher};
    use wz_session_core::multicast_params::{
        zid_vec, GroupJoinRule, MulticastDriveConfig, MulticastParams,
    };
    use wz_session_core::multicast_reply_sink::MulticastReplyEnqueue;
    use wz_session_core::multicast_tx::{
        multicast_put_literal, MulticastTxDatagram, MulticastTxItem,
    };
    use wz_session_core::policy::SessionPolicy;
    use wz_session_core::qos::Priority;
    use wz_session_core::session_init_params::{LinkRxConf, TxQueueConf};
    use wz_session_core::tx_deadline::PushOutcome;
    use wz_session_core::wire_const::T_MID_JOIN;
    use wz_session_core::WhatAmI;

    use super::{next_out, GroupTxPace, GroupTxStage, Queued};
    use crate::group_drive::MulticastPump;

    /// A clock that never moves: the beacon, due at every step, is what moves the pump.
    #[derive(Clone, Default)]
    struct Frozen;

    impl ClockSource for Frozen {
        fn now_us(&self) -> u64 {
            0
        }
    }

    /// The payloads the tests put on the group, by which a datagram is told apart.
    const PAYLOADS: [&str; 3] = ["first", "second", "third"];

    /// What the group's socket took, in order, and how many more it takes before it is full.
    #[derive(Default)]
    struct Wire {
        seen: Vec<Vec<u8>>,
        room: usize,
    }

    struct Socket(Rc<RefCell<Wire>>);

    impl GroupTransport for Socket {
        fn open(&mut self) -> bool {
            true
        }

        fn close(&mut self) {}

        fn service(&self) {}

        fn carrier_up(&self) -> bool {
            true
        }

        // The beacon leaves this way, whatever room there is: what it advertises is what is read.
        fn send_to_group(&mut self, datagram: &[u8]) {
            self.0.borrow_mut().seen.push(datagram.to_vec());
        }

        fn try_send_to_group(&mut self, datagram: &[u8]) -> GroupSend {
            let mut wire = self.0.borrow_mut();
            if wire.room == 0 {
                return GroupSend::Full;
            }
            wire.room -= 1;
            wire.seen.push(datagram.to_vec());
            GroupSend::Sent
        }

        fn recv_with(&mut self, _f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
            false
        }
    }

    /// A group whose beacon is due at every step.
    fn params() -> MulticastParams {
        MulticastParams {
            whatami: WhatAmI::Peer,
            zid: zid_vec(&[0xAA, 0xBB, 0xCC, 0xDD]),
            lease_ms: 5_000,
            join_interval_ms: 0,
            seq_num_res: 0x02,
            req_id_res: 0x02,
            batch_size: 2_048,
            is_qos: false,
            compression: false,
            tx_queue: TxQueueConf::of_policy(&SessionPolicy::defaults()),
            link_rx: LinkRxConf::default(),
            join_rule: GroupJoinRule::Pico,
            max_sessions: None,
            policy: SessionPolicy::defaults(),
        }
    }

    fn put(payload: &str) -> MulticastTxItem {
        multicast_put_literal("demo/stage", payload.as_bytes()).expect("a put")
    }

    /// A group whose lanes hold one batch of 256 bytes each, so that two [`fill`]s, each of which
    /// fits a batch, fill a lane; a message that waits may wait a millisecond if it may be dropped
    /// and ten if not.
    fn one_batch_lanes() -> MulticastParams {
        let mut params = params();
        params.batch_size = 256;
        params.tx_queue.sizes = [1; Priority::NUM];
        params.tx_queue.wait_before_drop_us = 1_000;
        params.tx_queue.wait_before_close_us = 10_000;
        params.tx_queue.no_progress_us = None;
        params
    }

    /// A put whose frame takes more than half of a [`one_batch_lanes`] lane and fits its batch.
    fn fill() -> MulticastTxItem {
        put(&"y".repeat(150))
    }

    /// What the socket took, each as `join` or the payload of the put it carried.
    fn taken(wire: &RefCell<Wire>) -> Vec<&'static str> {
        wire.borrow()
            .seen
            .iter()
            .map(|datagram| {
                if datagram.first().is_some_and(|h| h & 0x1f == T_MID_JOIN) {
                    return "join";
                }
                PAYLOADS
                    .into_iter()
                    .find(|payload| datagram.ends_with(payload.as_bytes()))
                    .unwrap_or("other")
            })
            .collect()
    }

    /// The next reliable sequence number each JOIN the socket took advertises, in order.
    fn advertised(wire: &RefCell<Wire>) -> Vec<u64> {
        wire.borrow()
            .seen
            .iter()
            .filter_map(|datagram| decode_join(datagram).map(|join| join.next_sn_reliable))
            .collect()
    }

    /// A host whose socket has no room unless it is `writable`, on a clock it moves by the whole
    /// of each wait: what a push that waits spends is that wait. `on_pass` is what a pass of its
    /// tasks does.
    struct FullHost<'a> {
        passes: Cell<usize>,
        now_us: Cell<u64>,
        ended: bool,
        writable: bool,
        on_pass: &'a dyn Fn(),
    }

    impl<'a> FullHost<'a> {
        fn new(on_pass: &'a dyn Fn()) -> Self {
            Self {
                passes: Cell::new(0),
                now_us: Cell::new(0),
                ended: false,
                writable: false,
                on_pass,
            }
        }
    }

    impl GroupTxPace for FullHost<'_> {
        fn pass(&self) {
            self.passes.set(self.passes.get() + 1);
            (self.on_pass)();
        }

        fn now_us(&self) -> u64 {
            self.now_us.get()
        }

        fn wait_writable(&self, wait_us: u64) -> bool {
            if self.writable {
                return true;
            }
            self.now_us.set(self.now_us.get() + wait_us);
            false
        }

        fn ended(&self) -> bool {
            self.ended
        }
    }

    /// Push `item` onto `stage` as a message of the session whose lane has room: it is queued
    /// with no pass of the host.
    fn push_at_once(stage: &GroupTxStage, item: MulticastTxItem) {
        let nothing = || {};
        let host = FullHost::new(&nothing);
        assert_eq!(stage.push(item, &host), PushOutcome::Pushed);
        assert_eq!(
            host.passes.get(),
            0,
            "a lane with room is waited on by nothing"
        );
    }

    /// A JOIN advertises the sequence numbers the socket took, not the ones minted: three puts
    /// are minted before the first step, the socket takes one of them, and the beacon of the next
    /// step, sent once a second one is written, advertises the third as the next to come although
    /// all three were minted.
    #[test]
    fn the_join_advertises_what_the_socket_took_and_not_what_was_minted() {
        let wire = Rc::new(RefCell::new(Wire {
            room: 1,
            ..Wire::default()
        }));
        let mut socket = Socket(Rc::clone(&wire));
        let params = params();
        let runtime = CoopRuntime::new(Frozen);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let stage = GroupTxStage::new(&params);
        for payload in PAYLOADS {
            push_at_once(&stage, put(payload));
        }
        let mut quiet = |_event: IterationEvent<'_, '_>| {};
        let mut nothing = || None;
        let mut pump = MulticastPump::new(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &params,
                tick_ms: 5,
                max_iters: None,
            },
            &SessionPolicy::defaults(),
            &runtime,
            &mut socket,
        );
        pump.attach_tx_stage(stage);

        // The beacon first, with nothing written; then the first put, which takes the room there
        // is, and the second, which the writer holds for the next step.
        assert!(pump.step(&mut quiet, &mut nothing, None).is_none());
        assert_eq!(taken(&wire), ["join", "first"]);
        assert_eq!(advertised(&wire), [0]);

        // Still full: the beacon that is due waits behind the datagram held.
        assert!(pump.step(&mut quiet, &mut nothing, None).is_none());
        assert_eq!(taken(&wire), ["join", "first"]);

        // Room: the held datagram leaves, then the beacon, which advertises the one after it,
        // then the third.
        wire.borrow_mut().room = 2;
        assert!(pump.step(&mut quiet, &mut nothing, None).is_none());
        assert_eq!(taken(&wire), ["join", "first", "second", "join", "third"]);
        assert_eq!(advertised(&wire), [0, 2], "written, not minted (3)");
        assert_eq!(pump.tx_lost(), 0);
    }

    /// Each datagram asks its lane for room by its own bytes: a push on a lane with room is
    /// queued at once, one on a full lane runs the host and waits on the socket for its whole
    /// `wait_before_drop`, and is dropped and counted; the lane's mark then drops the next
    /// droppable one at once, with no pass. Each datagram the pump takes makes room.
    #[test]
    fn a_full_lane_waits_out_a_message_and_counts_it_dropped() {
        let params = one_batch_lanes();
        let stage = GroupTxStage::new(&params);
        let nothing = || {};
        let host = FullHost::new(&nothing);
        let best_effort = |item: MulticastTxItem| match item {
            MulticastTxItem::Push { push, priority, .. } => MulticastTxItem::Push {
                push,
                reliable: false,
                priority,
            },
            other => other,
        };

        assert!(stage.is_empty());
        assert_eq!(stage.push(best_effort(fill()), &host), PushOutcome::Pushed);
        assert!(!stage.is_empty(), "a datagram queued for the pump");
        assert_eq!(
            stage.push(best_effort(fill()), &host),
            PushOutcome::Pushed,
            "a lane that holds less than its bound takes a datagram that carries it past it"
        );
        assert_eq!(host.passes.get(), 0, "neither waited");

        assert_eq!(
            stage.push(best_effort(put("second")), &host),
            PushOutcome::Congested
        );
        assert_eq!(host.passes.get(), 1, "the full lane had the host run");
        assert_eq!(
            host.now_us.get(),
            params.tx_queue.wait_before_drop_us,
            "and the whole wait spent"
        );
        assert_eq!(stage.drops(Priority::DEFAULT), 1);

        assert_eq!(
            stage.push(best_effort(put("second")), &host),
            PushOutcome::Congested
        );
        assert_eq!(host.passes.get(), 1, "the lane's mark answers at once");
        assert_eq!(stage.drops(Priority::DEFAULT), 2);

        assert!(stage.take().is_some());
        assert_eq!(
            stage.push(best_effort(put("second")), &host),
            PushOutcome::Pushed,
            "what the pump took is room again, and lowers the mark"
        );
        assert_eq!(stage.drops(Priority::DEFAULT), 2);
    }

    /// A push that waits for a group whose session ended finds no writer: what it puts on the
    /// stage is lost with the group's link, as the tokio group's push onto a link that went, and is
    /// not a congestion drop.
    #[test]
    fn a_push_on_a_group_whose_session_ended_is_not_a_congestion_drop() {
        let stage = GroupTxStage::new(&one_batch_lanes());
        let nothing = || {};
        let mut host = FullHost::new(&nothing);
        push_at_once(&stage, fill());
        push_at_once(&stage, fill());
        host.ended = true;
        assert_eq!(stage.push(put("second"), &host), PushOutcome::Pushed);
        assert_eq!(host.passes.get(), 0, "nothing was waited for");
        assert_eq!(stage.drops(Priority::DEFAULT), 0);
    }

    /// A reply the group's dispatch stages while a message of the session holds the conduits,
    /// waiting for room, is pushed once that message lets go, behind it: the message's sequence
    /// number comes first, and the two are consecutive.
    #[test]
    fn a_reply_staged_while_a_push_waits_is_pushed_behind_it() {
        let stage = GroupTxStage::new(&one_batch_lanes());
        push_at_once(&stage, fill());
        push_at_once(&stage, fill());
        // The pass is the host's tasks: the group's dispatch stages a reply, and its pump takes
        // the oldest datagram of the full lane.
        let in_pass = stage.clone();
        let on_pass = move || {
            in_pass.enqueue(put("third"));
            let _ = in_pass.take();
        };
        let host = FullHost::new(&on_pass);
        assert_eq!(stage.push(put("second"), &host), PushOutcome::Pushed);
        assert_eq!(host.passes.get(), 1);
        let mut order: Vec<(u64, String)> = Vec::new();
        while let Some(datagram) = stage.take() {
            if let Some(payload) = PAYLOADS
                .into_iter()
                .find(|payload| datagram.bytes.ends_with(payload.as_bytes()))
            {
                order.push((datagram.sn, String::from(payload)));
            }
        }
        assert_eq!(
            order,
            [(2, String::from("second")), (3, String::from("third"))]
        );
    }

    /// A message that may not wait, on a lane that holds its bound, is answered congested at once,
    /// with no pass of the host, and is counted.
    #[test]
    fn a_message_that_may_not_wait_is_answered_at_once() {
        let mut params = one_batch_lanes();
        params.tx_queue.wait_before_drop_us = 0;
        params.tx_queue.wait_before_close_us = 0;
        let stage = GroupTxStage::new(&params);
        let nothing = || {};
        let host = FullHost::new(&nothing);
        push_at_once(&stage, fill());
        push_at_once(&stage, fill());
        assert_eq!(stage.push(put("second"), &host), PushOutcome::Congested);
        assert_eq!(host.passes.get(), 0, "a wait of zero asks without waiting");
        assert_eq!(stage.drops(Priority::DEFAULT), 1);
    }

    /// The pump takes the oldest datagram of the most urgent lane first, as the tokio group's
    /// writer serves its lanes; a Control datagram waits behind what other lanes queued before
    /// it, while a lane more urgent than that data is still served first.
    #[test]
    fn the_pump_takes_the_most_urgent_lane_first_and_control_waits_behind_earlier_data() {
        fn order(priorities: &[Priority]) -> Vec<Priority> {
            let mut queued: alloc::collections::VecDeque<Queued> = priorities
                .iter()
                .enumerate()
                .map(|(sn, priority)| Queued {
                    datagram: MulticastTxDatagram {
                        priority: *priority,
                        reliable: true,
                        sn: sn as u64,
                        bytes: Vec::new(),
                    },
                    reply: false,
                })
                .collect();
            let mut out = Vec::new();
            while let Some(at) = next_out(&queued) {
                out.push(
                    queued
                        .remove(at)
                        .expect("the datagram chosen")
                        .datagram
                        .priority,
                );
            }
            out
        }
        use Priority::{Background, Control, Data, RealTime};
        assert_eq!(
            order(&[Data, RealTime, Background]),
            [RealTime, Data, Background]
        );
        assert_eq!(
            order(&[Data, Control, RealTime]),
            [RealTime, Data, Control],
            "the Control datagram waits for the data queued before it"
        );
        assert_eq!(order(&[Control, Data]), [Control, Data]);
        assert_eq!(
            order(&[Data, Data, Data]),
            [Data, Data, Data],
            "CONTROL: one lane"
        );
    }

    /// The stage holds at most `MAX_MULTICAST_REPLIES` replies, whatever room their lanes have:
    /// the reply past them is dropped and counted in `dropped`, takes nothing of its lane and is
    /// no congestion drop; a message of the session that finds its lane full is counted in
    /// `drops` and not in `dropped`; and the pump taking a reply frees its slot.
    #[test]
    fn a_reply_past_the_limit_is_dropped_and_counted_apart_from_the_lanes() {
        use wz_session_core::caps::MAX_MULTICAST_REPLIES;

        let stage = GroupTxStage::new(&one_batch_lanes());
        assert_eq!(stage.capacity(), MAX_MULTICAST_REPLIES);
        for _ in 0..MAX_MULTICAST_REPLIES {
            stage.enqueue(fill());
        }
        assert_eq!(
            stage.dropped(),
            0,
            "a reply is let on whatever its lane holds"
        );

        stage.enqueue(put("second"));
        assert_eq!(
            stage.dropped(),
            1,
            "the reply past the limit is dropped and counted"
        );
        assert_eq!(
            stage.drops(Priority::DEFAULT),
            0,
            "and is no congestion drop"
        );
        let mut queued = 0;
        while stage.take().is_some() {
            queued += 1;
        }
        assert_eq!(
            queued, MAX_MULTICAST_REPLIES,
            "the dropped reply took nothing"
        );

        // Each reply taken freed its slot.
        stage.enqueue(put("third"));
        assert_eq!(stage.dropped(), 1, "a reply taken frees its slot");

        // A message of the session on a full lane is the lanes' drop, not the limit's.
        let full = GroupTxStage::new(&one_batch_lanes());
        push_at_once(&full, fill());
        push_at_once(&full, fill());
        let nothing = || {};
        let host = FullHost::new(&nothing);
        assert_eq!(full.push(put("second"), &host), PushOutcome::Congested);
        assert_eq!((full.drops(Priority::DEFAULT), full.dropped()), (1, 0));
    }

    /// The pump pulls an offer of its pull seam onto the stage only while the stage has a reply
    /// slot for it: with every slot held, what the seam holds stays there, under the seam's own
    /// bound, and is pulled once the pump has taken a reply off the stage, with nothing dropped.
    #[test]
    fn the_pump_leaves_on_its_seam_what_the_stage_has_no_reply_slot_for() {
        use wz_session_core::caps::MAX_MULTICAST_REPLIES;

        let wire = Rc::new(RefCell::new(Wire::default()));
        let mut socket = Socket(Rc::clone(&wire));
        let params = params();
        let runtime = CoopRuntime::new(Frozen);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let stage = GroupTxStage::new(&params);
        for _ in 0..MAX_MULTICAST_REPLIES {
            stage.enqueue(put("first"));
        }
        let seam: RefCell<alloc::collections::VecDeque<MulticastTxItem>> =
            RefCell::new(core::iter::once(put("second")).collect());
        let mut next_tx = || seam.borrow_mut().pop_front();
        let mut quiet = |_event: IterationEvent<'_, '_>| {};
        let mut pump = MulticastPump::new(
            &mut dispatcher,
            MulticastDriveConfig {
                params: &params,
                tick_ms: 5,
                max_iters: None,
            },
            &SessionPolicy::defaults(),
            &runtime,
            &mut socket,
        );
        pump.attach_tx_stage(stage.clone());

        // Every slot is held: the offer stays on the seam. The socket, full, has the writer hold
        // the first reply it took, which frees that reply's slot.
        assert!(pump.step(&mut quiet, &mut next_tx, None).is_none());
        assert_eq!(
            seam.borrow().len(),
            1,
            "no slot: the offer stays on the seam"
        );

        // A slot is free: the offer is pulled, and nothing was dropped.
        assert!(pump.step(&mut quiet, &mut next_tx, None).is_none());
        assert!(seam.borrow().is_empty(), "a free slot: the offer is pulled");
        assert_eq!(stage.dropped(), 0);
    }

    /// A lane's mark is its writer's word that it could not drain the lane. A droppable push that
    /// meets it while the socket is still full is answered at once, with nothing run; one that
    /// meets it once the socket takes again gives the pump a pass first, as a writer on a thread
    /// of its own drains the moment its socket takes: the pump's take lowers the mark and makes
    /// room, and the push is queued without waiting and is no drop.
    #[test]
    fn a_mark_is_read_after_the_pump_had_a_pass_on_a_socket_that_takes_again() {
        let stage = GroupTxStage::new(&one_batch_lanes());
        let best_effort = |item: MulticastTxItem| match item {
            MulticastTxItem::Push { push, priority, .. } => MulticastTxItem::Push {
                push,
                reliable: false,
                priority,
            },
            other => other,
        };
        push_at_once(&stage, fill());
        push_at_once(&stage, fill());
        let nothing = || {};
        let full = FullHost::new(&nothing);
        assert_eq!(
            stage.push(best_effort(put("second")), &full),
            PushOutcome::Congested
        );
        assert_eq!(
            stage.push(best_effort(put("second")), &full),
            PushOutcome::Congested,
            "a socket still full leaves the mark standing"
        );
        assert_eq!(full.passes.get(), 1, "only the first push waited");
        assert_eq!(stage.drops(Priority::DEFAULT), 2);

        // The socket takes again: a pass of this host is the pump writing what the lane holds.
        let pump = stage.clone();
        let writes = move || while pump.take().is_some() {};
        let mut taking = FullHost::new(&writes);
        taking.writable = true;
        assert_eq!(
            stage.push(best_effort(put("third")), &taking),
            PushOutcome::Pushed
        );
        assert_eq!(taking.passes.get(), 1, "the pump had its pass first");
        assert_eq!(taking.now_us.get(), 0, "and nothing was waited for");
        assert_eq!(stage.drops(Priority::DEFAULT), 2, "the put is no drop");
        assert!(!stage.is_empty(), "the put is queued for the pump");
    }
}
