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
//! What the producers push is written by whoever holds the session, as well as by the pump: a
//! holder that shares the group's transport with the pump ([`GroupLink`]) writes what the stage
//! holds on its own thread once its push returns ([`GroupLink::write_staged`]), as zenoh-pico's
//! put writes a multicast message on the caller's thread, and the pump writes what is left to it (a
//! datagram a full socket refused, a reply its own dispatch staged). Both write through the stage's
//! one writer, so a JOIN advertises what either wrote.
//!
//! A batch window ([`GroupTxStage::batch_start`]) holds each conduit's messages in one open frame
//! until the frame fills, an express message takes it, the window is flushed, or the pump sends
//! the group's JOIN or its Close, as the tokio engine's group producer batches: until then nothing
//! of it is on a lane for either writer.
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
//! holds one of `MAX_MULTICAST_REPLIES` slots until the pump takes it, as every reply queue of
//! a group does (`MulticastReplyQueue`): the reply past them is dropped and counted apart from
//! the lanes' drops, so a member that asks faster than the group's socket writes cannot grow the
//! stage for as long as it keeps asking.

use alloc::collections::VecDeque;
use alloc::rc::Rc;
use core::cell::{Cell, Ref, RefCell};
use core::net::SocketAddr;

use wz_runtime_coop::group_transport::{GroupSend, GroupTransport};
use wz_runtime_coop::session_drive::{LinkReadiness, LinkWritability};
use wz_session_core::limits::{MaxMulticastRepliesHeld, SessionLimits};
use wz_session_core::link::{LinkRoom, RoomAnswer, RoomWait};
use wz_session_core::multicast_params::MulticastParams;
use wz_session_core::multicast_reply_sink::MulticastReplyEnqueue;
use wz_session_core::multicast_tx::{
    multicast_tx_conduit, multicast_tx_push, multicast_tx_push_batched, MulticastBatch,
    MulticastTxDatagram, MulticastTxItem, MulticastTxLanes, MulticastTxQueue,
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
/// holds, bounded by `MAX_MULTICAST_REPLIES`, and how many it dropped for want of a slot. The
/// two drop counts are kept apart because they answer different questions: [`Self::drops`] is
/// the lanes' (messages of the session that found their lane full within their wait, by
/// priority, as the tokio group counts a congestion drop), and [`Self::dropped`] is the reply
/// limit's (which tells a deployment its declared limit is too small). Cloned, it is the same
/// stage: the producers hold one clone and the group's pump another.
#[derive(Clone)]
pub struct GroupTxStage {
    inner: Rc<Inner>,
    /// The most replies the stage holds (`MAX_MULTICAST_REPLIES`): what the creator of the
    /// session resolved ([`Self::with_limits`]), the build's value for a stage made by
    /// [`Self::new`]. Every clone holds the same.
    quota: MaxMulticastRepliesHeld,
}

struct Inner {
    params: MulticastParams,
    /// The group's conduits, held by one push, or one flush of the batch window, at a time.
    conduits: RefCell<Conduits>,
    /// Whether the batch window is open ([`GroupTxStage::batch_start`]).
    window_open: Cell<bool>,
    lanes: RefCell<Lanes>,
    /// What was pushed while another push held the conduits, in the order it was pushed, each
    /// with whether it holds a reply slot.
    deferred: RefCell<VecDeque<(MulticastTxItem, bool)>>,
    /// How many reply slots are held: by a reply deferred, or by the first datagram of a reply
    /// queued on a lane.
    replies: Cell<usize>,
    /// How many replies were dropped for want of a slot.
    dropped: Cell<u32>,
    /// What was written of the stage, by the pump or by the holder.
    writer: RefCell<Writer>,
}

/// The sequence numbers each conduit mints, and each conduit's open frame while the batch window
/// is open: the two a push of the conduit changes together, as the tokio engine's group keeps a
/// conduit's minter and its window under the conduit's one lock.
struct Conduits {
    minted: MulticastTxConduits,
    windows: [MulticastBatch; Priority::NUM],
}

/// The writing side of the stage: the datagram a full socket refused, offered again before
/// anything else; each conduit past the last sequence number written on it, which the JOIN
/// advertises; and how many datagrams a failed send lost.
struct Writer {
    held: Option<MulticastTxDatagram>,
    on_wire: MulticastTxConduits,
    lost: u32,
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
    /// its lanes its queue's sizes in batches of its batch size, one lane when it runs no QoS. Its
    /// replies are held to the build's `MAX_MULTICAST_REPLIES`.
    pub fn new(params: &MulticastParams) -> Self {
        Self::held_to(params, MaxMulticastRepliesHeld::default())
    }

    /// [`Self::new`], its replies held to the `MAX_MULTICAST_REPLIES` of `limits`, the snapshot
    /// the creator of the group's session resolved.
    pub fn with_limits(params: &MulticastParams, limits: &SessionLimits) -> Self {
        Self::held_to(params, limits.max_multicast_replies_held())
    }

    fn held_to(params: &MulticastParams, quota: MaxMulticastRepliesHeld) -> Self {
        let mask = sn::mask_from_res(params.seq_num_res);
        Self {
            inner: Rc::new(Inner {
                params: params.clone(),
                conduits: RefCell::new(Conduits {
                    minted: MulticastTxConduits::new(mask),
                    windows: core::array::from_fn(|_| MulticastBatch::new()),
                }),
                window_open: Cell::new(false),
                lanes: RefCell::new(Lanes {
                    bound: MulticastTxLanes::of_group(params),
                    queued: VecDeque::new(),
                }),
                deferred: RefCell::new(VecDeque::new()),
                replies: Cell::new(0),
                dropped: Cell::new(0),
                writer: RefCell::new(Writer {
                    held: None,
                    on_wire: MulticastTxConduits::new(mask),
                    lost: 0,
                }),
            }),
            quota,
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
    pub(super) fn admit_reply(&self, item: MulticastTxItem) {
        let inner = &*self.inner;
        if !self.quota.get().admits(inner.replies.get() + 1) {
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
        let Ok(mut conduits) = inner.conduits.try_borrow_mut() else {
            inner.deferred.borrow_mut().push_back((item, reply));
            return PushOutcome::Pushed;
        };
        let conduit = multicast_tx_conduit(&item, &inner.params);
        let Conduits { minted, windows } = &mut *conduits;
        let window = &mut windows[conduit as usize];
        let windowed = inner.window_open.get();
        if !windowed {
            // A frame the window left open leaves ahead of the message, which keeps its order; it
            // is no reply's, so it is put on its lane apart from the reply's walk.
            window.flush(
                conduit,
                &inner.params,
                &mut StageQueue {
                    lanes: &inner.lanes,
                    pace: None,
                    reply: false,
                },
            );
        }
        let mut queue = StageQueue {
            lanes: &inner.lanes,
            pace,
            reply,
        };
        let outcome = if windowed {
            multicast_tx_push_batched(
                item,
                minted,
                &inner.params,
                &inner.params.tx_queue,
                &mut queue,
                window,
            )
        } else {
            multicast_tx_push(
                item,
                minted,
                &inner.params,
                &inner.params.tx_queue,
                &mut queue,
            )
        };
        drop(conduits);
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
            if self.inner.conduits.try_borrow_mut().is_err() {
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
        self.quota.get().admits(self.inner.replies.get() + 1)
    }

    /// How many replies the stage holds at most: its `MAX_MULTICAST_REPLIES`, `usize::MAX` where
    /// it holds no bound.
    pub const fn capacity(&self) -> usize {
        super::quota_count(self.quota.get())
    }

    /// How many replies were dropped for want of a reply slot since the stage was made. A message
    /// of the session dropped for want of room on its lane is not among them ([`Self::drops`]).
    pub fn dropped(&self) -> u32 {
        self.inner.dropped.get()
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

    /// Open the batch window (zenoh-pico `zp_batch_start` on a multicast transport): from now on a
    /// message joins its conduit's open frame instead of leaving as a datagram of its own, until
    /// the frame fills, an express message takes it, or the window is flushed or closed
    /// (`vendor/zenoh-pico/src/transport/common/tx.c` @ `static z_result_t _z_transport_tx_send_n_msg_inner(`).
    /// Opening an open window changes nothing.
    pub fn batch_start(&self) {
        self.inner.window_open.set(true);
    }

    /// Put every conduit's open frame on its lane, the most urgent conduit first, and keep the
    /// window open (zenoh-pico `zp_batch_flush`). No room is asked: a frame was given its room
    /// when it was opened. A flush asked while a push holds the conduits, which only a pass of the
    /// host inside that push's wait for room could ask, leaves the frames to the next flush.
    pub fn batch_flush(&self) {
        let inner = &*self.inner;
        let Ok(mut conduits) = inner.conduits.try_borrow_mut() else {
            return;
        };
        let mut queue = StageQueue {
            lanes: &inner.lanes,
            pace: None,
            reply: false,
        };
        for (wire, window) in conduits.windows.iter_mut().enumerate() {
            window.flush(Priority::from_wire(wire as u8), &inner.params, &mut queue);
        }
    }

    /// Close the batch window and put every conduit's open frame on its lane (zenoh-pico
    /// `zp_batch_stop`): closed before the flush, as pico stops batching before it sends the
    /// batch, so a push after this sends its message alone.
    pub fn batch_stop(&self) {
        self.inner.window_open.set(false);
        self.batch_flush();
    }

    /// Whether the writer holds a datagram the socket had no room for: what is queued after it
    /// waits behind it.
    pub fn holds(&self) -> bool {
        self.inner.writer.borrow().held.is_some()
    }

    /// How many datagrams of the stage a send the stack failed lost, whoever wrote them.
    pub(super) fn lost(&self) -> u32 {
        self.inner.writer.borrow().lost
    }

    /// The conduits as written: what the JOIN advertises. A member re-seeds what it expects from
    /// every JOIN, so a JOIN that advertised a sequence number minted and not yet written would
    /// have the member drop that datagram as stale when it came.
    pub(super) fn on_wire(&self) -> Ref<'_, MulticastTxConduits> {
        Ref::map(self.inner.writer.borrow(), |writer| &writer.on_wire)
    }

    /// Offer the socket the datagram it had no room for at an earlier write: whether it still has
    /// none.
    pub(super) fn offer_held<T: GroupTransport + ?Sized>(&self, transport: &mut T) -> bool {
        let held = self.inner.writer.borrow_mut().held.take();
        match held {
            Some(datagram) => self.offer(transport, datagram),
            None => false,
        }
    }

    /// Take what the lanes hold and offer it to the socket, until the lanes are empty or the
    /// socket has no room.
    pub(super) fn write<T: GroupTransport + ?Sized>(&self, transport: &mut T) {
        while !self.holds() {
            let Some(datagram) = self.take() else {
                return;
            };
            self.offer(transport, datagram);
        }
    }

    /// Offer `datagram` to the socket: whether it had no room, in which case the writer holds the
    /// datagram for the next write.
    fn offer<T: GroupTransport + ?Sized>(
        &self,
        transport: &mut T,
        datagram: MulticastTxDatagram,
    ) -> bool {
        let sent = transport.try_send_to_group(&datagram.bytes);
        let mut writer = self.inner.writer.borrow_mut();
        match sent {
            GroupSend::Full => {
                writer.held = Some(datagram);
                return true;
            }
            GroupSend::Failed => writer.lost = writer.lost.saturating_add(1),
            GroupSend::Sent => {}
        }
        // A datagram whose send failed is done with too: its sequence number will never arrive,
        // and advertising past it keeps a member from waiting for it.
        writer
            .on_wire
            .written(datagram.priority, datagram.reliable, datagram.sn);
        false
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
        // producer reads it; this stage's writer runs only when a push returns or in a pass of the
        // host, so once the socket takes again the pass is given first, and the lane is asked
        // again on what it wrote.
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

/// A group's transport, shared by the group's session task and the holder of the session: the
/// task opens it as the session's link, reads it, beacons on it and lets it go; the holder writes
/// on it what the session's producers put on the group's stage ([`Self::write_staged`]), on the
/// thread that holds the session, as zenoh-pico's put writes a multicast message on its caller's
/// thread (`vendor/zenoh-pico/src/transport/common/tx.c` @ `static z_result_t _z_transport_tx_send_n_msg_inner(`).
/// The task is handed one clone as its transport and the holder keeps another; both are the same
/// transport.
pub struct GroupLink<T>(Rc<LinkCell<T>>);

/// What the clones of a [`GroupLink`] share: the transport, and whether the session holds it open
/// as its link.
struct LinkCell<T> {
    transport: RefCell<T>,
    open: Cell<bool>,
}

impl<T> Clone for GroupLink<T> {
    fn clone(&self) -> Self {
        Self(Rc::clone(&self.0))
    }
}

impl<T: GroupTransport> GroupLink<T> {
    /// `transport`, to be shared: not open until the session's task opens it.
    pub fn new(transport: T) -> Self {
        Self(Rc::new(LinkCell {
            transport: RefCell::new(transport),
            open: Cell::new(false),
        }))
    }

    /// Write what `stage` holds to the group, on the caller's thread: the datagram the socket
    /// refused at an earlier write first, then what the lanes hold, until they are empty or the
    /// socket has no room, the rest left to the next write. Nothing is written on a link the
    /// session has not opened or has let go of, where the session's own JOIN would not have gone
    /// ahead of it, nor while the session's task has the transport in hand, which only a callback
    /// of its read could ask from: the task's next step writes it.
    pub fn write_staged(&self, stage: &GroupTxStage) {
        if !self.0.open.get() {
            return;
        }
        let Ok(mut transport) = self.0.transport.try_borrow_mut() else {
            return;
        };
        if !stage.offer_held(&mut *transport) {
            stage.write(&mut *transport);
        }
    }
}

impl<T: GroupTransport> GroupTransport for GroupLink<T> {
    fn open(&mut self) -> bool {
        let opened = self.0.transport.borrow_mut().open();
        self.0.open.set(opened);
        opened
    }

    fn close(&mut self) {
        self.0.open.set(false);
        self.0.transport.borrow_mut().close();
    }

    fn service(&self) {
        self.0.transport.borrow().service();
    }

    fn carrier_up(&self) -> bool {
        self.0.transport.borrow().carrier_up()
    }

    fn send_to_group(&mut self, datagram: &[u8]) {
        self.0.transport.borrow_mut().send_to_group(datagram);
    }

    fn try_send_to_group(&mut self, datagram: &[u8]) -> GroupSend {
        self.0.transport.borrow_mut().try_send_to_group(datagram)
    }

    fn wait_for_room(&self, timeout_us: u64) -> bool {
        self.0.transport.borrow().wait_for_room(timeout_us)
    }

    fn writability(&self) -> Option<alloc::boxed::Box<dyn LinkWritability>> {
        self.0.transport.borrow().writability()
    }

    fn readiness(&self) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
        self.0.transport.borrow().readiness()
    }

    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
        self.0.transport.borrow_mut().recv_with(f)
    }

    fn keeps_input(&self) -> bool {
        self.0.transport.borrow().keeps_input()
    }

    fn keep(&mut self) {
        self.0.transport.borrow_mut().keep();
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

    use super::{next_out, GroupLink, GroupTxPace, GroupTxStage, Queued};
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
            tx_queue: TxQueueConf::of_snapshot(
                &SessionPolicy::defaults(),
                &wz_session_core::limits::SessionLimits::BUILD,
            ),
            link_rx: LinkRxConf::default(),
            join_rule: GroupJoinRule::Pico,
            max_sessions: None,
            policy: SessionPolicy::defaults(),
            limits: wz_session_core::limits::SessionLimits::BUILD,
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

    /// `MAX_MULTICAST_REPLIES` with nothing stated: a stage held to the session's snapshot holds
    /// the build's number of replies and drops the next, as a stage made with none does.
    #[test]
    fn max_multicast_replies_with_nothing_stated_admits_what_the_build_admitted() {
        use wz_session_core::caps::MAX_MULTICAST_REPLIES;
        use wz_session_core::limits::SessionLimits;

        let stage = GroupTxStage::with_limits(&one_batch_lanes(), &SessionLimits::defaults());
        assert_eq!(stage.capacity(), MAX_MULTICAST_REPLIES);
        for _ in 0..MAX_MULTICAST_REPLIES {
            stage.enqueue(fill());
        }
        assert_eq!(stage.dropped(), 0);
        stage.enqueue(put("second"));
        assert_eq!(
            stage.dropped(),
            1,
            "the reply past the build's value is dropped"
        );
    }

    /// `MAX_MULTICAST_REPLIES` stated as two: the third reply is dropped and counted, takes
    /// nothing of its lane and is no congestion drop, and a reply the pump takes frees its slot.
    /// A heap reply queue held to the same snapshot drops the third the same.
    #[test]
    fn max_multicast_replies_stated_refuses_the_next() {
        use wz_session_core::limit_binding::{LimitSpec, Quota};
        use wz_session_core::limits::{MaxMulticastReplies, SessionLimits};

        let mut limits = SessionLimits::defaults();
        let stated = limits.select_max_multicast_replies(Quota::at_most(2));
        if MaxMulticastReplies::DOMAIN.is_singleton() {
            assert!(stated.is_err(), "a build of one value refuses two");
            return;
        }
        stated.expect("two is inside the domain");

        let stage = GroupTxStage::with_limits(&one_batch_lanes(), &limits);
        assert_eq!(stage.capacity(), 2);
        stage.enqueue(put("first"));
        stage.enqueue(put("first"));
        stage.enqueue(put("second"));
        assert_eq!(stage.dropped(), 1, "the third reply is dropped and counted");
        assert_eq!(
            stage.drops(Priority::DEFAULT),
            0,
            "and is no congestion drop"
        );
        assert!(stage.take().is_some());
        stage.enqueue(put("third"));
        assert_eq!(stage.dropped(), 1, "a reply taken frees its slot");
        let mut queued = 0;
        while stage.take().is_some() {
            queued += 1;
        }
        assert_eq!(queued, 2, "the dropped reply took nothing");

        let queue = crate::group_drive::MulticastReplyQueue::with_limits(&limits);
        assert_eq!(queue.capacity(), 2);
        for _ in 0..3 {
            queue.enqueue(put("first"));
        }
        assert_eq!((queue.len(), queue.dropped()), (2, 1));
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

    /// The holder's write goes only on a link the session holds open: on one not yet opened, and
    /// while the session's task has the transport in hand, nothing is written and the stage keeps
    /// it; once opened, the write takes what the stage holds on to the socket; once the session
    /// let the link go, nothing more is written.
    #[test]
    fn the_holder_writes_only_on_a_link_the_session_holds_open() {
        let wire = Rc::new(RefCell::new(Wire {
            room: 4,
            ..Wire::default()
        }));
        let link = GroupLink::new(Socket(Rc::clone(&wire)));
        let stage = GroupTxStage::new(&params());
        push_at_once(&stage, put("first"));
        link.write_staged(&stage);
        assert!(
            taken(&wire).is_empty(),
            "a link not yet opened is not written"
        );
        assert!(!stage.is_empty(), "and the stage keeps what it holds");

        let mut session_side = link.clone();
        assert!(session_side.open());
        {
            let _in_hand = link.0.transport.borrow_mut();
            link.write_staged(&stage);
        }
        assert!(
            taken(&wire).is_empty(),
            "a transport the task has in hand is left to the task"
        );

        link.write_staged(&stage);
        assert_eq!(taken(&wire), ["first"], "the open link is written");
        assert!(stage.is_empty());

        session_side.close();
        push_at_once(&stage, put("second"));
        link.write_staged(&stage);
        assert_eq!(taken(&wire), ["first"], "a link let go of is not written");
    }

    /// The holder writes what the stage holds on the session's open link, on its own: what the
    /// socket has room for leaves at once, what it refuses is held, which the pump then sees and
    /// puts its JOIN behind, and offered first at the next write; and the pump's next JOIN
    /// advertises what the holder wrote.
    #[test]
    fn the_holder_writes_the_stage_and_the_join_advertises_what_it_wrote() {
        let wire = Rc::new(RefCell::new(Wire::default()));
        let link = GroupLink::new(Socket(Rc::clone(&wire)));
        let params = params();
        let runtime = CoopRuntime::new(Frozen);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let stage = GroupTxStage::new(&params);
        let mut session_side = link.clone();
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
            &mut session_side,
        );
        pump.attach_tx_stage(stage.clone());

        // The session's first step: its JOIN, with nothing written.
        assert!(pump.step(&mut quiet, &mut nothing, None).is_none());
        assert_eq!(taken(&wire), ["join"]);

        wire.borrow_mut().room = 1;
        push_at_once(&stage, put("first"));
        push_at_once(&stage, put("second"));
        link.write_staged(&stage);
        assert_eq!(taken(&wire), ["join", "first"], "what the socket took");
        assert!(stage.holds(), "and what it refused, held");
        assert!(pump.tx_held(), "which the pump sees");

        // Still full: the held datagram and the JOIN behind it wait.
        assert!(pump.step(&mut quiet, &mut nothing, None).is_none());
        assert_eq!(taken(&wire), ["join", "first"]);

        wire.borrow_mut().room = 1;
        link.write_staged(&stage);
        assert_eq!(taken(&wire), ["join", "first", "second"]);
        assert!(!stage.holds());

        assert!(pump.step(&mut quiet, &mut nothing, None).is_none());
        assert_eq!(taken(&wire), ["join", "first", "second", "join"]);
        assert_eq!(advertised(&wire), [0, 2], "what the holder wrote");
        assert_eq!(pump.tx_lost(), 0);
    }

    /// Inside a batch window a conduit's messages join one open frame and nothing is on a lane;
    /// the flush puts that frame on its lane as one datagram, with the window still open, so the
    /// next message opens a frame of its own; the stop puts that one on its lane and closes the
    /// window, after which a message is a datagram of its own at once. Each frame took one
    /// sequence number.
    #[test]
    fn a_batch_window_holds_a_conduits_messages_in_one_frame_until_it_is_flushed() {
        let carries = |bytes: &[u8], payload: &str| {
            bytes
                .windows(payload.len())
                .any(|window| window == payload.as_bytes())
        };
        let stage = GroupTxStage::new(&params());
        stage.batch_start();
        push_at_once(&stage, put("first"));
        push_at_once(&stage, put("second"));
        assert!(stage.is_empty(), "the window holds both, on no lane");

        stage.batch_flush();
        let both = stage.take().expect("the window's frame");
        assert!(stage.take().is_none(), "one datagram for both");
        assert!(carries(&both.bytes, "first") && both.bytes.ends_with(b"second"));

        push_at_once(&stage, put("third"));
        assert!(stage.is_empty(), "the window is still open");
        stage.batch_stop();
        let third = stage.take().expect("the stop's frame");
        assert!(third.bytes.ends_with(b"third"));
        assert!(stage.take().is_none());

        push_at_once(&stage, put("first"));
        let alone = stage.take().expect("a closed window holds nothing back");
        assert!(alone.bytes.ends_with(b"first"));
        assert_eq!([both.sn, third.sn, alone.sn], [0, 1, 2]);
    }

    /// A batch window the program leaves open leaves at the session's next beacon, as zenoh-pico
    /// sends its batch before a transport message: the step that sends the JOIN puts the window's
    /// frame on its lane and writes it behind the JOIN, which advertises it as the next to come,
    /// and the window stays open for the puts after it.
    #[test]
    fn a_window_left_open_leaves_at_the_next_beacon_and_stays_open() {
        let wire = Rc::new(RefCell::new(Wire {
            room: 8,
            ..Wire::default()
        }));
        let mut socket = Socket(Rc::clone(&wire));
        let params = params();
        let runtime = CoopRuntime::new(Frozen);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let stage = GroupTxStage::new(&params);
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
        pump.attach_tx_stage(stage.clone());

        stage.batch_start();
        push_at_once(&stage, put("first"));
        push_at_once(&stage, put("second"));
        assert!(stage.is_empty(), "the window holds both");

        assert!(pump.step(&mut quiet, &mut nothing, None).is_none());
        assert_eq!(
            taken(&wire),
            ["join", "second"],
            "the window's frame left with the beacon"
        );
        assert!(wire.borrow().seen[1]
            .windows(b"first".len())
            .any(|window| window == b"first"));
        assert_eq!(advertised(&wire), [0], "the frame's number, as the next");

        push_at_once(&stage, put("third"));
        assert!(stage.is_empty(), "the window is still open");
        assert!(pump.step(&mut quiet, &mut nothing, None).is_none());
        assert_eq!(taken(&wire), ["join", "second", "join", "third"]);
        assert_eq!(advertised(&wire), [0, 1]);
        assert_eq!(pump.tx_lost(), 0);
    }

    /// What a batch window holds when the session stops is written ahead of its Close, as
    /// zenoh-pico sends its batch before a transport message: it is not lost with the link.
    #[test]
    fn a_window_open_at_the_stop_is_written_ahead_of_the_close() {
        let wire = Rc::new(RefCell::new(Wire {
            room: 8,
            ..Wire::default()
        }));
        let mut socket = Socket(Rc::clone(&wire));
        let mut params = params();
        // A beacon at the first step only, so that the stop is what writes the window.
        params.join_interval_ms = 60_000;
        let runtime = CoopRuntime::new(Frozen);
        let mut dispatcher = MulticastDispatcher::<4>::new(MulticastConfig::new(5_000));
        let stage = GroupTxStage::new(&params);
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
        pump.attach_tx_stage(stage.clone());
        assert!(pump.step(&mut quiet, &mut nothing, None).is_none());
        assert_eq!(taken(&wire), ["join"]);

        stage.batch_start();
        push_at_once(&stage, put("first"));
        assert!(pump.step(&mut quiet, &mut nothing, None).is_none());
        assert_eq!(
            taken(&wire),
            ["join"],
            "CONTROL: no beacon due, the window holds"
        );

        let mut stop = || true;
        assert!(pump
            .step(&mut quiet, &mut nothing, Some(&mut stop))
            .is_some());
        assert_eq!(
            taken(&wire),
            ["join", "first", "other"],
            "the window's frame, then the Close"
        );
    }
}
