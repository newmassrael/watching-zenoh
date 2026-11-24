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
//! cooperative host: a producer calls the same walk (`multicast_tx_push_encoded`) against the stage, and the
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
use wz_session_core::frame_encode::BodyEncoder;
use wz_session_core::limits::{MaxMulticastRepliesHeld, SessionLimits};
use wz_session_core::link::{LinkRoom, RoomAnswer, RoomWait};
use wz_session_core::multicast_params::MulticastParams;
use wz_session_core::multicast_reply_sink::MulticastReplyEnqueue;
use wz_session_core::multicast_tx::{
    multicast_tx_bytes, multicast_tx_encode_into, multicast_tx_encoded_conduit,
    multicast_tx_item_body, multicast_tx_push_encoded, multicast_tx_push_meta,
    multicast_tx_push_staged, MulticastBatch, MulticastTxDatagram, MulticastTxEncoded,
    MulticastTxItem, MulticastTxLanes, MulticastTxMeta, MulticastTxQueue,
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
    /// What was pushed while another push held the conduits, encoded, waiting for its sequence
    /// number.
    staged: RefCell<Staged>,
    /// How many reply slots are held: by a reply staged, or by the first datagram of a reply
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
    held: Option<Taken>,
    on_wire: MulticastTxConduits,
    lost: u32,
}

/// What was pushed while another push held the conduits, kept until they are let go, in the order
/// it was pushed: each message's body encoded into storage taken when the group opens, beside how
/// it is framed, so that it is framed when its sequence number can be minted, into the frame it
/// would have had at once, and nothing of it is kept on the heap. It holds as many messages as the
/// stage holds replies, each of up to a batch.
struct Staged {
    bytes: LaneRing,
    held: VecDeque<StagedMessage>,
    /// The most messages it holds.
    most: usize,
}

/// One message [`Staged`] holds: how it is framed, the length of its body, and whether it holds a
/// reply slot.
#[derive(Clone, Copy)]
struct StagedMessage {
    meta: MulticastTxMeta,
    len: usize,
    reply: bool,
}

/// Why [`Staged::keep`] kept nothing of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unkept {
    /// It holds its most messages, or has no run free as long as the message's body may be.
    Full,
    /// The message's encoder refused it.
    Unencodable,
}

impl Staged {
    /// Storage for `most` messages of up to `batch` bytes each.
    fn new(most: usize, batch: usize) -> Self {
        Self {
            bytes: LaneRing::new(most.saturating_mul(batch)),
            held: VecDeque::with_capacity(most),
            most,
        }
    }

    /// Encode a message of at most `size` bytes framed as `meta` says, behind the ones held.
    fn keep(
        &mut self,
        meta: MulticastTxMeta,
        size: usize,
        body: &BodyEncoder<'_>,
        reply: bool,
    ) -> Result<(), Unkept> {
        if self.held.len() >= self.most {
            return Err(Unkept::Full);
        }
        let (at, wraps) = self.bytes.room(size).ok_or(Unkept::Full)?;
        let out = self
            .bytes
            .buf
            .get_mut(at..at.saturating_add(size))
            .ok_or(Unkept::Full)?;
        let len = multicast_tx_encode_into(body, out).ok_or(Unkept::Unencodable)?;
        self.bytes.commit(at, len, wraps);
        self.held.push_back(StagedMessage { meta, len, reply });
        Ok(())
    }

    /// The oldest message held.
    fn front(&self) -> Option<StagedMessage> {
        self.held.front().copied()
    }

    /// The body of the oldest message, `len` bytes long.
    fn front_bytes(&self, len: usize) -> &[u8] {
        self.bytes.front_run(0, len)
    }

    /// Let go of the oldest message, of `len` bytes.
    fn pop(&mut self, len: usize) {
        if self.held.pop_front().is_some() {
            self.bytes.pop(len);
        }
    }
}

/// The lanes' bound and congestion marks, and each lane's storage, taken when the group opens,
/// which holds the datagrams queued on the lane, each behind a record of what it is, in the order
/// they were queued. A frame is encoded straight into it; a datagram built on the heap (a fragment,
/// a window's frame) is copied into it and the vector let go.
struct Lanes {
    bound: MulticastTxLanes,
    rings: [LaneRing; Priority::NUM],
    /// The order the next datagram is queued in, across the lanes.
    order: u64,
    /// The run a push is let on a lane by: a record and a batch for its frame, and a record and a
    /// drop marker behind it, which a chain that runs out of room ends with.
    reserve: usize,
}

/// The most bytes a fragment chain's drop marker takes: its header, a sequence number of at most
/// ten bytes, its marker and a QoS extension.
const MARKER_BYTES: usize = 16;

/// What the storage of a lane records of each datagram ahead of its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Record {
    /// The order the datagram was queued in, across the lanes.
    order: u64,
    priority: Priority,
    reliable: bool,
    sn: u64,
    /// Whether the datagram holds the slot of the reply it begins.
    reply: bool,
    /// How many bytes the datagram is.
    len: usize,
}

impl Record {
    /// The bytes a record takes ahead of its datagram's: its order (8), priority (1), channel (1),
    /// sequence number (8), reply mark (1) and length (4).
    const BYTES: usize = 23;

    /// The record as the storage holds it.
    fn bytes(&self) -> [u8; Self::BYTES] {
        let [o0, o1, o2, o3, o4, o5, o6, o7] = self.order.to_le_bytes();
        let [s0, s1, s2, s3, s4, s5, s6, s7] = self.sn.to_le_bytes();
        // A datagram is at most its lane's storage, which is held far below 4 GiB.
        let [l0, l1, l2, l3] = u32::try_from(self.len).unwrap_or(u32::MAX).to_le_bytes();
        [
            o0,
            o1,
            o2,
            o3,
            o4,
            o5,
            o6,
            o7,
            self.priority.wire_byte(),
            u8::from(self.reliable),
            s0,
            s1,
            s2,
            s3,
            s4,
            s5,
            s6,
            s7,
            u8::from(self.reply),
            l0,
            l1,
            l2,
            l3,
        ]
    }

    /// The record at the front of `at`, `None` where `at` holds less than one.
    fn read(at: &[u8]) -> Option<Self> {
        let head: [u8; Self::BYTES] = at.get(..Self::BYTES)?.try_into().ok()?;
        let [o0, o1, o2, o3, o4, o5, o6, o7, priority, reliable, s0, s1, s2, s3, s4, s5, s6, s7, reply, l0, l1, l2, l3] =
            head;
        Some(Self {
            order: u64::from_le_bytes([o0, o1, o2, o3, o4, o5, o6, o7]),
            priority: Priority::from_wire(priority),
            reliable: reliable != 0,
            sn: u64::from_le_bytes([s0, s1, s2, s3, s4, s5, s6, s7]),
            reply: reply != 0,
            len: usize::try_from(u32::from_le_bytes([l0, l1, l2, l3])).unwrap_or(usize::MAX),
        })
    }
}

/// The datagram the writer took from a lane and has not finished: its record, and the lane whose
/// storage still holds its bytes, at the front.
#[derive(Clone, Copy)]
struct Taken {
    lane: usize,
    record: Record,
}

impl Lanes {
    /// Empty lanes of a group of `params`, each lane's storage taken now: its bound, a batch more
    /// (a lane lets a message on while it holds less than its bound) and, since a reply is put on
    /// its lane whatever the lane holds, a batch for each reply `quota` lets the stage hold.
    fn of_group(params: &MulticastParams, quota: MaxMulticastRepliesHeld) -> Self {
        let bound = MulticastTxLanes::of_group(params);
        let reserve = Record::BYTES
            .saturating_mul(2)
            .saturating_add(usize::from(params.batch_size))
            .saturating_add(MARKER_BYTES);
        let replies = match super::quota_count(quota.get()) {
            usize::MAX => 0,
            count => count,
        };
        let rings = core::array::from_fn(|at| {
            let lane = bound.own_lane_bytes(Priority::from_wire(at as u8));
            LaneRing::new(lane.map_or(0, |bytes| {
                bytes.saturating_add(reserve.saturating_mul(replies.saturating_add(1)))
            }))
        });
        Self {
            bound,
            rings,
            order: 0,
            reserve,
        }
    }

    /// Queue a datagram of `record`'s conduit whose bytes `fill` writes into the slice it is
    /// handed, of up to `want` bytes, and answers the length of: whether its lane had room for it
    /// (`fill` answering `None` queues nothing).
    fn queue(
        &mut self,
        mut record: Record,
        want: usize,
        fill: &mut dyn FnMut(&mut [u8]) -> Option<usize>,
    ) -> bool {
        let lane = self.bound.lane_index(record.priority);
        let Some(ring) = self.rings.get_mut(lane) else {
            return false;
        };
        let Some((at, wraps)) = ring.room(Record::BYTES.saturating_add(want)) else {
            return false;
        };
        let body = at.saturating_add(Record::BYTES);
        let Some(len) = ring
            .buf
            .get_mut(body..body.saturating_add(want))
            .and_then(&mut *fill)
        else {
            return false;
        };
        record.order = self.order;
        record.len = len;
        if let Some(head) = ring.buf.get_mut(at..body) {
            for (to, from) in head.iter_mut().zip(record.bytes()) {
                *to = from;
            }
        }
        ring.commit(at, Record::BYTES.saturating_add(len), wraps);
        self.order = self.order.wrapping_add(1);
        self.bound.taken(record.priority, len);
        true
    }

    /// The record at the front of each lane.
    fn front(&self, lane: usize) -> Option<Record> {
        self.rings.get(lane)?.front().and_then(Record::read)
    }

    /// The bytes of the datagram at the front of `lane`.
    fn front_bytes(&self, lane: usize, len: usize) -> &[u8] {
        self.rings
            .get(lane)
            .map_or(&[][..], |ring| ring.front_run(Record::BYTES, len))
    }

    /// Let go of the datagram at the front of `lane`, written or lost.
    fn pop(&mut self, lane: usize, len: usize) {
        if let Some(ring) = self.rings.get_mut(lane) {
            ring.pop(Record::BYTES.saturating_add(len));
        }
    }

    /// Whether `priority`'s lane has storage for one more push: one run of its `reserve`.
    fn ring_room(&self, priority: Priority) -> bool {
        self.rings
            .get(self.bound.lane_index(priority))
            .is_some_and(|ring| ring.cursor.fits(1, self.reserve))
    }

    /// Whether `priority`'s lane has storage for a reply of `bytes`, one push's run for each
    /// datagram it is cut into.
    fn reply_room(&self, priority: Priority, bytes: usize, batch: usize) -> bool {
        let runs = bytes.div_ceil(batch.max(1)).max(1);
        self.rings
            .get(self.bound.lane_index(priority))
            .is_some_and(|ring| ring.cursor.fits(runs, self.reserve))
    }

    /// Whether no lane holds a datagram.
    fn is_empty(&self) -> bool {
        self.rings.iter().all(LaneRing::is_empty)
    }
}

/// One lane's storage: runs of bytes, each a record and its datagram, contiguous, leaving in the
/// order they came, as a lane's datagrams are written; a run that does not fit before the end of
/// the storage starts again at its front.
struct LaneRing {
    buf: alloc::vec::Vec<u8>,
    cursor: Cursor,
}

/// Where a [`LaneRing`]'s runs lie, apart from its bytes, so a question of room can be tried on a
/// copy.
#[derive(Clone, Copy)]
struct Cursor {
    /// The storage's length.
    len: usize,
    /// Where the oldest run starts.
    head: usize,
    /// Where the next run starts.
    tail: usize,
    /// Where the runs before the wrap end, while the newest runs have started again at the front.
    wrap_end: Option<usize>,
    /// How many runs the storage holds.
    runs: usize,
}

impl Cursor {
    /// Where a run of up to `want` bytes can start, and whether it starts again at the front.
    fn room(&self, want: usize) -> Option<(usize, bool)> {
        if self.runs == 0 {
            return (want <= self.len).then_some((0, false));
        }
        match self.wrap_end {
            None if self.len.saturating_sub(self.tail) >= want => Some((self.tail, false)),
            None => (self.head >= want).then_some((0, true)),
            Some(_) => (self.head.saturating_sub(self.tail) >= want).then_some((self.tail, false)),
        }
    }

    /// The run that starts at `at` holds `len` bytes; `wraps` as [`Self::room`] answered.
    fn commit(&mut self, at: usize, len: usize, wraps: bool) {
        if self.runs == 0 {
            self.head = at;
            self.wrap_end = None;
        } else if wraps {
            self.wrap_end = Some(self.tail);
        }
        // A run lies within the storage, so its end is at most the storage's length.
        self.tail = at.saturating_add(len);
        self.runs = self.runs.saturating_add(1);
    }

    /// Whether `runs` more runs of `each` bytes fit, one after the other.
    fn fits(&self, runs: usize, each: usize) -> bool {
        let mut probe = *self;
        (0..runs).all(|_| match probe.room(each) {
            Some((at, wraps)) => {
                probe.commit(at, each, wraps);
                true
            }
            None => false,
        })
    }

    /// The oldest run, of `len` bytes, has left.
    fn pop(&mut self, len: usize) {
        debug_assert!(self.runs > 0, "a run is held");
        self.runs = self.runs.saturating_sub(1);
        self.head = self.head.saturating_add(len);
        if self.wrap_end == Some(self.head) {
            self.head = 0;
            self.wrap_end = None;
        }
        if self.runs == 0 {
            self.head = 0;
            self.tail = 0;
            self.wrap_end = None;
        }
    }
}

impl LaneRing {
    fn new(capacity: usize) -> Self {
        Self {
            buf: alloc::vec![0; capacity],
            cursor: Cursor {
                len: capacity,
                head: 0,
                tail: 0,
                wrap_end: None,
                runs: 0,
            },
        }
    }

    fn is_empty(&self) -> bool {
        self.cursor.runs == 0
    }

    fn room(&self, want: usize) -> Option<(usize, bool)> {
        self.cursor.room(want)
    }

    fn commit(&mut self, at: usize, len: usize, wraps: bool) {
        self.cursor.commit(at, len, wraps);
    }

    /// The oldest run's bytes from its start, as far as they reach.
    fn front(&self) -> Option<&[u8]> {
        match self.cursor.runs {
            0 => None,
            _ => self.buf.get(self.cursor.head..),
        }
    }

    /// `len` bytes of the oldest run, `skip` bytes in.
    fn front_run(&self, skip: usize, len: usize) -> &[u8] {
        let from = self.cursor.head.saturating_add(skip);
        self.buf
            .get(from..from.saturating_add(len))
            .unwrap_or_default()
    }

    /// The oldest run, of `len` bytes, has left.
    fn pop(&mut self, len: usize) {
        self.cursor.pop(len);
    }
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
                    // Each conduit's window frame is written into storage taken now.
                    windows: core::array::from_fn(|_| {
                        MulticastBatch::with_budget(params.frame_budget())
                    }),
                }),
                window_open: Cell::new(false),
                lanes: RefCell::new(Lanes::of_group(params, quota)),
                // What is kept for a push's release is mostly a reply of the group's own dispatch:
                // as many as the stage holds replies, the build's number where the stage holds no
                // bound, since the storage is taken now.
                staged: RefCell::new(Staged::new(
                    match super::quota_count(quota.get()) {
                        usize::MAX => wz_session_core::caps::MAX_MULTICAST_REPLIES,
                        count => count,
                    },
                    usize::from(params.batch_size),
                )),
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

    /// Push `message`, a message of the session lent for the call (its body written by its encoder
    /// where the frame is built), as the tokio engine's producer pushes one: its lane is asked for
    /// room before its sequence number is minted and again before each further fragment, within the
    /// message's deadline, and while the lane is full `pace` runs the host and waits on the socket.
    /// A message that finds no room is a congestion drop, counted on its lane whether it may block
    /// or not, as a multicast transport closes nothing on one; a chain that runs out of room between
    /// two fragments is stopped by the drop marker. Pushed while another push holds the conduits
    /// (from inside that push's wait for room), its body is kept encoded and it is framed when they
    /// are let go; one the kept storage has no room for is a congestion drop of its lane, counted.
    pub fn push_encoded(
        &self,
        message: &MulticastTxEncoded<'_>,
        pace: &dyn GroupTxPace,
    ) -> PushOutcome {
        let inner = &*self.inner;
        let Ok(mut conduits) = inner.conduits.try_borrow_mut() else {
            let meta = MulticastTxMeta::of_encoded(message, &inner.params);
            return self.stage(meta, message.size, message.body, false);
        };
        let conduit = multicast_tx_encoded_conduit(message, &inner.params);
        let params = &inner.params;
        let outcome = self.push_on(
            &mut conduits,
            conduit,
            Some(pace),
            false,
            |minted, queue, window| {
                multicast_tx_push_encoded(message, minted, params, &params.tx_queue, queue, window)
            },
        );
        drop(conduits);
        self.push_deferred();
        outcome
    }

    /// Put `item`, a reply, on the stage without waiting, whatever its lane holds, counted on the
    /// lane: a reply the group's own dispatch stages runs inside the pump it would wait for. It
    /// takes a reply slot, or is dropped and counted ([`Self::dropped`]) when none is free.
    pub(super) fn admit_reply(&self, item: MulticastTxItem) {
        let meta = MulticastTxMeta::of_item(&item, &self.inner.params);
        let size = multicast_tx_bytes(&item);
        multicast_tx_item_body(&item, |body| self.admit_reply_body(meta, size, body));
    }

    /// [`Self::admit_reply`] of a reply framed as `meta` says, whose body `body` encodes in at
    /// most `size` bytes: framed at once, or kept encoded ([`Staged`]) while another push holds
    /// the conduits.
    fn admit_reply_body(&self, meta: MulticastTxMeta, size: usize, body: &BodyEncoder<'_>) {
        let inner = &*self.inner;
        // A lane's storage holds the replies the limit lets the stage hold; one its storage has no
        // room for is past that limit, and is refused by it.
        let room = inner.lanes.borrow().reply_room(
            meta.conduit(),
            size,
            usize::from(inner.params.batch_size),
        );
        if !room
            || !self
                .quota
                .get()
                .admits(inner.replies.get().saturating_add(1))
        {
            inner.dropped.set(inner.dropped.get().saturating_add(1));
            return;
        }
        inner.replies.set(inner.replies.get().saturating_add(1));
        let Ok(mut conduits) = inner.conduits.try_borrow_mut() else {
            let _ = self.stage(meta, size, body, true);
            return;
        };
        let params = &inner.params;
        let _ = self.push_on(
            &mut conduits,
            meta.conduit(),
            None,
            true,
            |minted, queue, window| {
                multicast_tx_push_meta(
                    meta,
                    size,
                    body,
                    minted,
                    params,
                    &params.tx_queue,
                    queue,
                    window,
                )
            },
        );
        drop(conduits);
        self.push_deferred();
    }

    /// Keep a message pushed while another push holds the conduits, framed once they are let go
    /// ([`Self::push_deferred`]). One the staged storage cannot keep is refused as its kind is: a
    /// reply by the reply limit, counted in [`Self::dropped`], a message of the session as a
    /// congestion drop of its lane; a reply its encoder refuses holds no slot, as one put on no lane
    /// does.
    fn stage(
        &self,
        meta: MulticastTxMeta,
        size: usize,
        body: &BodyEncoder<'_>,
        reply: bool,
    ) -> PushOutcome {
        let inner = &*self.inner;
        let kept = inner.staged.borrow_mut().keep(meta, size, body, reply);
        let Err(unkept) = kept else {
            return PushOutcome::Pushed;
        };
        if reply {
            inner.replies.set(inner.replies.get().saturating_sub(1));
            if unkept == Unkept::Full {
                inner.dropped.set(inner.dropped.get().saturating_add(1));
            }
        } else {
            inner.lanes.borrow_mut().bound.dropped(meta.conduit());
        }
        PushOutcome::Congested
    }

    /// One push onto `conduit`, whose conduits the caller holds: what `push` frames, owned or lent,
    /// put on the lanes the way every message of the stage goes onto them. `push` is handed the
    /// minter, the lanes and, inside a batch window, the conduit's open frame. `pace` is `None`
    /// for a push that does not wait; `reply` is a reply whose slot is taken already, which its
    /// first datagram holds.
    fn push_on(
        &self,
        conduits: &mut Conduits,
        conduit: Priority,
        pace: Option<&dyn GroupTxPace>,
        reply: bool,
        push: impl FnOnce(
            &mut MulticastTxConduits,
            &mut StageQueue<'_>,
            Option<&mut MulticastBatch>,
        ) -> PushOutcome,
    ) -> PushOutcome {
        let inner = &*self.inner;
        let Conduits { minted, windows } = conduits;
        // A priority's wire byte is below `Priority::NUM`, so its conduit's window is there.
        let Some(window) = windows.get_mut(usize::from(conduit.wire_byte())) else {
            return PushOutcome::Congested;
        };
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
        let outcome = push(minted, &mut queue, windowed.then_some(window));
        // A reply that put no datagram on a lane (one its codec could not frame) holds no slot.
        if queue.reply {
            inner.replies.set(inner.replies.get().saturating_sub(1));
        }
        if outcome == PushOutcome::Congested {
            inner.lanes.borrow_mut().bound.dropped(conduit);
        }
        outcome
    }

    /// Frame what was kept while the conduits were held, oldest first, once nothing holds them: its
    /// sequence number is minted now.
    fn push_deferred(&self) {
        let inner = &*self.inner;
        loop {
            let Ok(mut conduits) = inner.conduits.try_borrow_mut() else {
                return;
            };
            let Some(next) = inner.staged.borrow().front() else {
                return;
            };
            let params = &inner.params;
            {
                // A push that does not wait runs nothing of the host, so nothing keeps a message
                // while these bytes are lent.
                let staged = inner.staged.borrow();
                let body = staged.front_bytes(next.len);
                let _ = self.push_on(
                    &mut conduits,
                    next.meta.conduit(),
                    None,
                    next.reply,
                    |minted, queue, window| {
                        multicast_tx_push_staged(next.meta, body, minted, params, queue, window)
                    },
                );
            }
            inner.staged.borrow_mut().pop(next.len);
        }
    }

    /// Take the datagram the group's pump writes next: the oldest of the most urgent lane, a
    /// Control datagram behind what the other lanes queued before it. What it held of its lane is
    /// room again, as the tokio group's lane has room once its writer takes a batch, and the first
    /// datagram of a reply frees the reply's slot. Its bytes stay at the front of its lane's
    /// storage until the writer lets them go ([`Self::finish`]).
    fn take_front(&self) -> Option<Taken> {
        let mut lanes = self.inner.lanes.borrow_mut();
        let lane = next_out(&lanes)?;
        let record = lanes.front(lane)?;
        lanes.bound.written(record.priority, record.len);
        if record.reply {
            self.inner
                .replies
                .set(self.inner.replies.get().saturating_sub(1));
        }
        Some(Taken { lane, record })
    }

    /// Let go of the bytes of the datagram the writer took, written or lost.
    fn finish(&self, taken: Taken) {
        self.inner
            .lanes
            .borrow_mut()
            .pop(taken.lane, taken.record.len);
    }

    /// [`Self::take_front`] for a reader of the datagram's bytes, which it is given a copy of, the
    /// datagram let go.
    #[cfg(test)]
    pub(super) fn take(&self) -> Option<MulticastTxDatagram> {
        let taken = self.take_front()?;
        let bytes = self
            .inner
            .lanes
            .borrow()
            .front_bytes(taken.lane, taken.record.len)
            .to_vec();
        self.finish(taken);
        Some(MulticastTxDatagram {
            priority: taken.record.priority,
            reliable: taken.record.reliable,
            sn: taken.record.sn,
            bytes,
        })
    }

    /// Whether a reply slot is free.
    pub(super) fn has_reply_slot(&self) -> bool {
        self.quota
            .get()
            .admits(self.inner.replies.get().saturating_add(1))
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
        self.inner.lanes.borrow().is_empty() && self.inner.staged.borrow().held.is_empty()
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
            let Some(taken) = self.take_front() else {
                return;
            };
            self.offer(transport, taken);
        }
    }

    /// Offer `datagram` to the socket: whether it had no room, in which case the writer holds the
    /// datagram for the next write.
    fn offer<T: GroupTransport + ?Sized>(&self, transport: &mut T, taken: Taken) -> bool {
        let sent = {
            let lanes = self.inner.lanes.borrow();
            transport.try_send_to_group(lanes.front_bytes(taken.lane, taken.record.len))
        };
        let mut writer = self.inner.writer.borrow_mut();
        match sent {
            GroupSend::Full => {
                writer.held = Some(taken);
                return true;
            }
            GroupSend::Failed => writer.lost = writer.lost.saturating_add(1),
            GroupSend::Sent => {}
        }
        // A datagram whose send failed is done with too: its sequence number will never arrive,
        // and advertising past it keeps a member from waiting for it.
        let Record {
            priority,
            reliable,
            sn,
            ..
        } = taken.record;
        writer.on_wire.written(priority, reliable, sn);
        drop(writer);
        self.finish(taken);
        false
    }
}

impl MulticastReplyEnqueue for GroupTxStage {
    fn enqueue(&self, item: MulticastTxItem) {
        self.admit_reply(item);
    }

    // Written from where the reply lies, into the lane or the staged storage: no copy of it is
    // made on the heap.
    #[cfg(any(feature = "codec-response", feature = "liveliness-token"))]
    fn enqueue_reply(&self, reply: wz_session_core::multicast_tx::MulticastTxReply<'_>) {
        let meta = reply.meta(&self.inner.params);
        reply.with_body(|body| self.admit_reply_body(meta, reply.bytes(), body));
    }
}

/// Which lane the group's pump takes its next datagram from: the most urgent lane that holds one,
/// its oldest first, as the tokio engine's group writer serves its lanes, highest first. A Control
/// datagram waits behind what the other lanes queued before it, as that writer's fence holds a
/// control datagram behind the data queued ahead of it, so a declaration never passes a put it was
/// queued after. A group that runs no QoS puts every datagram on one lane, and is written in the
/// order it was queued.
fn next_out(lanes: &Lanes) -> Option<usize> {
    let fronts = || (0..Priority::NUM).filter_map(|lane| Some((lane, lanes.front(lane)?)));
    let (lane, first) = fronts().min_by_key(|(_, record)| record.priority.wire_byte())?;
    if first.priority == Priority::Control && fronts().any(|(_, record)| record.order < first.order)
    {
        // Something of another lane was queued before it, so the fence holds: the other lanes are
        // served, highest first, until what they queued before it has left.
        return fronts()
            .filter(|(_, record)| record.priority != Priority::Control)
            .min_by_key(|(_, record)| record.priority.wire_byte())
            .map(|(lane, _)| lane);
    }
    Some(lane)
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
    /// What a push of `priority` asking with `wait` is answered before it waits: the lane's own
    /// answer, and a wait where the lane has room and its storage has none, which only the writer
    /// frees.
    fn at_once(&self, priority: Priority, wait: RoomWait) -> Option<LinkRoom> {
        let mut lanes = self.lanes.borrow_mut();
        match lanes.bound.room_at_once(priority, wait) {
            Some(LinkRoom::Free) if !lanes.ring_room(priority) => None,
            answer => answer,
        }
    }

    /// Whether `priority`'s lane takes another push: it holds less than its bound, and its
    /// storage has a push's run free.
    fn has_room(&self, priority: Priority) -> bool {
        let lanes = self.lanes.borrow();
        lanes.bound.has_room(priority) && lanes.ring_room(priority)
    }
}

impl MulticastTxQueue for StageQueue<'_> {
    fn wait_for_room(&mut self, priority: Priority, wait: RoomWait) -> RoomAnswer {
        let Some(pace) = self.pace else {
            // A push that does not wait is let on whatever its lane holds, but not past its
            // lane's storage: there it is a congestion drop, counted on its lane.
            let room = if self.lanes.borrow().ring_room(priority) {
                LinkRoom::Free
            } else {
                LinkRoom::Congested
            };
            return RoomAnswer::at_once(room);
        };
        let mut at_once = self.at_once(priority, wait);
        // A lane answers congested at once on what its writer last did: a droppable message meets
        // the mark of a drop, or one that may not wait meets the lane full. A writer on a thread of
        // its own drains the moment its socket takes again, lowering the mark before the next
        // producer reads it; this stage's writer runs only when a push returns or in a pass of the
        // host, so once the socket takes again the pass is given first, and the lane is asked
        // again on what it wrote.
        // A socket that is still full leaves the answer standing, with nothing run.
        if at_once == Some(LinkRoom::Congested) && !pace.ended() && pace.wait_writable(0) {
            pace.pass();
            at_once = self.at_once(priority, wait);
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
        let record = Record {
            order: 0,
            priority: datagram.priority,
            reliable: datagram.reliable,
            sn: datagram.sn,
            reply,
            len: 0,
        };
        let bytes = &datagram.bytes;
        let queued = self
            .lanes
            .borrow_mut()
            .queue(record, bytes.len(), &mut |slot| {
                slot.copy_from_slice(bytes);
                Some(bytes.len())
            });
        // Every datagram was let on by a push's run free in its lane's storage, and a reply by
        // the runs of its datagrams (`GroupTxStage::admit_reply`): one finds room by the sizing.
        debug_assert!(
            queued,
            "a datagram let on its lane finds room in its storage"
        );
        if !queued {
            self.reply = reply;
        }
    }

    fn enqueue_lent(
        &mut self,
        priority: Priority,
        reliable: bool,
        sn: u64,
        want: usize,
        fill: &mut dyn FnMut(&mut wz_session_core::tx_buf::SliceTxBuf<'_>) -> bool,
    ) -> bool {
        let reply = core::mem::take(&mut self.reply);
        let record = Record {
            order: 0,
            priority,
            reliable,
            sn,
            reply,
            len: 0,
        };
        let queued = self.lanes.borrow_mut().queue(record, want, &mut |slot| {
            let mut slot = wz_session_core::tx_buf::SliceTxBuf::new(slot);
            fill(&mut slot).then(|| wz_session_core::tx_buf::TxBuf::len(&slot))
        });
        if !queued {
            // No room in the lane's storage: the push builds the frame on the heap and offers it
            // to `enqueue`, still the reply's first datagram.
            self.reply = reply;
        }
        queued
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

    fn room_wait(&self) -> Option<wz_runtime_coop::session_drive::WaitOn> {
        self.0.transport.borrow().room_wait()
    }

    fn input_wait(&self) -> Option<wz_runtime_coop::session_drive::WaitOn> {
        self.0.transport.borrow().input_wait()
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
    use wz_session_core::multicast_params::{GroupJoinRule, MulticastDriveConfig, MulticastParams};
    use wz_session_core::multicast_reply_sink::MulticastReplyEnqueue;
    use wz_session_core::multicast_tx::{
        multicast_put_literal, multicast_tx_encoded_conduit, MulticastTxEncoded,
        MulticastTxFraming, MulticastTxItem,
    };
    use wz_session_core::policy::SessionPolicy;
    use wz_session_core::qos::Priority;
    use wz_session_core::session_init_params::{LinkRxConf, TxQueueConf};
    use wz_session_core::tx_deadline::PushOutcome;
    use wz_session_core::wire_const::T_MID_JOIN;
    use wz_session_core::WhatAmI;

    use super::{next_out, GroupLink, GroupTxPace, GroupTxStage, Lanes, Record};
    use crate::group_drive::MulticastPump;
    use wz_session_core::limits::MaxMulticastRepliesHeld;

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
            zid: wz_session_core::session_zid::SessionZid::from_array([0xAA, 0xBB, 0xCC, 0xDD]),
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

    /// A put of the session on the group's test key, written from its parts when it is pushed
    /// ([`push_put`]), reliable unless it is made best effort.
    struct Put {
        payload: String,
        reliable: bool,
    }

    impl Put {
        fn of(payload: &str) -> Self {
            Self {
                payload: String::from(payload),
                reliable: true,
            }
        }

        /// A put whose frame takes more than half of a [`one_batch_lanes`] lane and fits its batch.
        fn fill() -> Self {
            Self::of(&"y".repeat(150))
        }

        fn best_effort(self) -> Self {
            Self {
                reliable: false,
                ..self
            }
        }
    }

    /// Push `put` onto `stage` as the group's publish pushes it, written from its parts, waiting
    /// with `pace`.
    fn push_put(stage: &GroupTxStage, put: Put, pace: &dyn GroupTxPace) -> PushOutcome {
        wz_session_core::multicast_tx::multicast_tx_publication(
            0,
            Some("demo/stage"),
            wz_session_core::sample::SampleKind::Put,
            put.payload.as_bytes(),
            &wz_session_core::metadata::PushMetadata::default(),
            put.reliable,
            Priority::DEFAULT,
            |message| stage.push_encoded(message, pace),
        )
        .expect("a put")
    }

    /// Push `put` onto `stage` as a message of the session whose lane has room: it is queued
    /// with no pass of the host.
    fn push_at_once(stage: &GroupTxStage, put: Put) {
        let nothing = || {};
        let host = FullHost::new(&nothing);
        assert_eq!(push_put(stage, put, &host), PushOutcome::Pushed);
        assert_eq!(
            host.passes.get(),
            0,
            "a lane with room is waited on by nothing"
        );
    }

    /// Fill the DEFAULT lane's storage of `stage` up to `left` free bytes with one datagram that
    /// holds nothing of the lane's bound: the storage, and not the bound, is what a push then meets.
    fn occupy(stage: &GroupTxStage, left: usize) {
        let mut lanes = stage.inner.lanes.borrow_mut();
        let lane = lanes.bound.lane_index(Priority::DEFAULT);
        let ring = &mut lanes.rings[lane];
        let len = ring.buf.len() - left;
        let record = Record {
            order: 0,
            priority: Priority::DEFAULT,
            reliable: true,
            sn: 0,
            reply: false,
            len: len - Record::BYTES,
        };
        ring.buf[..Record::BYTES].copy_from_slice(&record.bytes());
        ring.commit(0, len, false);
    }

    /// A push its lane's bound lets on and its lane's storage has no room for follows its
    /// congestion control: a blocking one waits for the writer and is pushed once the writer frees
    /// the storage, or is a congestion drop, counted, once its whole wait runs out; a droppable one
    /// waits out its drop wait and is dropped and counted.
    #[test]
    fn a_push_its_lane_storage_has_no_room_for_follows_its_congestion_control() {
        use wz_session_core::qos::CongestionControl;
        let params = one_batch_lanes();
        let push = wz_session_core::lent_push::literal_put("demo/stage", b"first").expect("a put");
        let body = |sink: &mut wz_session_core::tx_buf::TxSink<'_>| push.encode(sink);
        let message = |congestion: CongestionControl| MulticastTxEncoded {
            framing: MulticastTxFraming::OwnBand {
                qos: wz_session_core::sample::QosLevel::DEFAULT.with_congestion(congestion),
                reliable: true,
            },
            size: 64,
            body: &body,
        };

        let stage = GroupTxStage::new(&params);
        occupy(&stage, 0);
        let pump = stage.clone();
        let writes = move || while pump.take().is_some() {};
        let mut freeing = FullHost::new(&writes);
        freeing.writable = true;
        assert_eq!(
            stage.push_encoded(&message(CongestionControl::Block), &freeing),
            PushOutcome::Pushed
        );
        assert!(freeing.passes.get() > 0, "it waited for the writer");

        let nothing = || {};
        let stage = GroupTxStage::new(&params);
        occupy(&stage, 0);
        let host = FullHost::new(&nothing);
        assert_eq!(
            stage.push_encoded(&message(CongestionControl::Block), &host),
            PushOutcome::Congested
        );
        assert_eq!(host.now_us.get(), params.tx_queue.wait_before_close_us);
        assert_eq!(stage.drops(Priority::DEFAULT), 1);

        let stage = GroupTxStage::new(&params);
        occupy(&stage, 0);
        let host = FullHost::new(&nothing);
        assert_eq!(
            stage.push_encoded(&message(CongestionControl::Drop), &host),
            PushOutcome::Congested
        );
        assert_eq!(host.now_us.get(), params.tx_queue.wait_before_drop_us);
        assert_eq!(stage.drops(Priority::DEFAULT), 1);
    }

    /// A reply its lane's storage has no room for is past the reply limit the storage is sized by,
    /// and is refused by it: dropped and counted in `dropped`, no congestion drop, and nothing of
    /// it queued.
    #[test]
    fn a_reply_its_lane_storage_has_no_room_for_is_refused_by_the_reply_limit() {
        let stage = GroupTxStage::new(&one_batch_lanes());
        occupy(&stage, 100);
        stage.enqueue(put("third"));
        assert_eq!(stage.dropped(), 1);
        assert_eq!(stage.drops(Priority::DEFAULT), 0);
        assert!(
            stage.take().is_some(),
            "the datagram that filled the storage"
        );
        assert!(stage.take().is_none(), "and nothing of the reply");
    }

    /// A record reads back as it was written, and a run shorter than a record reads as none.
    #[test]
    fn a_record_reads_back_as_written_and_a_short_run_as_none() {
        let record = Record {
            order: 7,
            priority: Priority::Control,
            reliable: false,
            sn: 0x0102_0304_0506,
            reply: true,
            len: 513,
        };
        let bytes = record.bytes();
        assert_eq!(Record::read(&bytes), Some(record));
        assert_eq!(Record::read(&bytes[..Record::BYTES - 1]), None);
    }

    /// A lane's storage gives each datagram one contiguous run, takes a run that does not fit
    /// before its end at its front once the front is free, and hands the runs out in the order
    /// they came.
    #[test]
    fn a_lane_storage_keeps_its_runs_in_order_where_it_wraps() {
        use super::LaneRing;
        let put = |ring: &mut LaneRing, byte: u8, len: usize| -> bool {
            let Some((at, wraps)) = ring.room(len) else {
                return false;
            };
            ring.buf[at..at + len].fill(byte);
            ring.commit(at, len, wraps);
            true
        };
        let mut ring = LaneRing::new(10);
        assert!(put(&mut ring, 1, 4));
        assert!(put(&mut ring, 2, 4));
        assert!(
            !put(&mut ring, 3, 4),
            "two bytes left at the end, none at the front"
        );
        assert_eq!(ring.front_run(0, 4), &[1u8; 4][..]);
        ring.pop(4);
        assert!(put(&mut ring, 3, 4), "the front is free again");
        assert_eq!(ring.front_run(0, 4), &[2u8; 4][..]);
        ring.pop(4);
        assert_eq!(
            ring.front_run(0, 4),
            &[3u8; 4][..],
            "past the wrap, the run at the front"
        );
        ring.pop(4);
        assert!(ring.is_empty());
        assert!(
            put(&mut ring, 4, 10),
            "an empty storage takes a run of its whole length"
        );
    }

    /// A message lent for the call is put on its lane as an owned one is; one pushed while another
    /// push holds the conduits is kept encoded and framed behind it once they are let go, with no
    /// drop counted.
    #[test]
    fn a_lent_message_is_queued_and_one_pushed_inside_another_push_is_kept() {
        let params = params();
        let stage = GroupTxStage::new(&params);
        let nothing = || {};
        let host = FullHost::new(&nothing);
        let push = wz_session_core::lent_push::literal_put("demo/stage", b"first").expect("a put");
        let body = |sink: &mut wz_session_core::tx_buf::TxSink<'_>| push.encode(sink);
        let lent = MulticastTxEncoded {
            framing: MulticastTxFraming::OwnBand {
                qos: wz_session_core::sample::QosLevel::DEFAULT,
                reliable: true,
            },
            size: 64,
            body: &body,
        };
        assert_eq!(stage.push_encoded(&lent, &host), PushOutcome::Pushed);
        {
            let _held = stage.inner.conduits.borrow_mut();
            assert_eq!(stage.push_encoded(&lent, &host), PushOutcome::Pushed);
        }
        stage.push_deferred();
        assert_eq!(stage.drops(multicast_tx_encoded_conduit(&lent, &params)), 0);
        let first = stage.take().expect("the lent message is on its lane");
        let kept = stage.take().expect("the kept one is framed behind it");
        assert!(first.bytes.ends_with(b"first") && kept.bytes.ends_with(b"first"));
        assert_eq!((first.sn, kept.sn), (0, 1));
    }

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
            push_at_once(&stage, Put::of(payload));
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

        assert!(stage.is_empty());
        assert_eq!(
            push_put(&stage, Put::fill().best_effort(), &host),
            PushOutcome::Pushed
        );
        assert!(!stage.is_empty(), "a datagram queued for the pump");
        assert_eq!(
            push_put(&stage, Put::fill().best_effort(), &host),
            PushOutcome::Pushed,
            "a lane that holds less than its bound takes a datagram that carries it past it"
        );
        assert_eq!(host.passes.get(), 0, "neither waited");

        assert_eq!(
            push_put(&stage, Put::of("second").best_effort(), &host),
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
            push_put(&stage, Put::of("second").best_effort(), &host),
            PushOutcome::Congested
        );
        assert_eq!(host.passes.get(), 1, "the lane's mark answers at once");
        assert_eq!(stage.drops(Priority::DEFAULT), 2);

        assert!(stage.take().is_some());
        assert_eq!(
            push_put(&stage, Put::of("second").best_effort(), &host),
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
        push_at_once(&stage, Put::fill());
        push_at_once(&stage, Put::fill());
        host.ended = true;
        assert_eq!(
            push_put(&stage, Put::of("second"), &host),
            PushOutcome::Pushed
        );
        assert_eq!(host.passes.get(), 0, "nothing was waited for");
        assert_eq!(stage.drops(Priority::DEFAULT), 0);
    }

    /// A reply the group's dispatch stages while a message of the session holds the conduits,
    /// waiting for room, is pushed once that message lets go, behind it: the message's sequence
    /// number comes first, and the two are consecutive.
    #[test]
    fn a_reply_staged_while_a_push_waits_is_pushed_behind_it() {
        let stage = GroupTxStage::new(&one_batch_lanes());
        push_at_once(&stage, Put::fill());
        push_at_once(&stage, Put::fill());
        // The pass is the host's tasks: the group's dispatch stages a reply, and its pump takes
        // the oldest datagram of the full lane.
        let in_pass = stage.clone();
        let on_pass = move || {
            in_pass.enqueue(put("third"));
            let _ = in_pass.take();
        };
        let host = FullHost::new(&on_pass);
        assert_eq!(
            push_put(&stage, Put::of("second"), &host),
            PushOutcome::Pushed
        );
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

    /// A message of the session pushed while another push holds the conduits is kept encoded,
    /// with nothing framed, and is framed once they are let go into the datagram it would have
    /// been at once. Turned red by a staged body that is framed apart from the at-once walk, or
    /// one framed while the conduits are still held.
    #[test]
    fn a_push_made_while_the_conduits_are_held_is_framed_as_it_would_have_been_at_once() {
        let at_once = GroupTxStage::new(&one_batch_lanes());
        push_at_once(&at_once, Put::of("first"));
        let expected = at_once.take().expect("the put").bytes;
        let stage = GroupTxStage::new(&one_batch_lanes());
        let nothing = || {};
        let host = FullHost::new(&nothing);
        {
            let _held = stage.inner.conduits.borrow_mut();
            assert_eq!(
                push_put(&stage, Put::of("first"), &host),
                PushOutcome::Pushed
            );
            assert!(
                stage.take().is_none(),
                "nothing is framed while they are held"
            );
            assert!(!stage.is_empty(), "the message is kept");
        }
        stage.push_deferred();
        let datagram = stage.take().expect("framed once they are let go");
        assert_eq!(datagram.bytes, expected);
        assert_eq!(
            datagram.sn, 0,
            "its sequence number is minted when it is framed"
        );
        assert!(stage.is_empty());
        assert_eq!(stage.drops(Priority::DEFAULT), 0);
    }

    /// The staged storage keeps as many messages as the stage holds replies: a message of the
    /// session pushed past them while the conduits are held is a congestion drop of its lane,
    /// counted, and not a reply-limit drop; the ones kept are framed in order once the conduits are
    /// let go. Turned red by a storage that grows past its count, or a refusal that is not counted.
    #[test]
    fn a_push_the_staged_storage_cannot_keep_is_a_counted_congestion_drop() {
        use wz_session_core::caps::MAX_MULTICAST_REPLIES;
        let mut params = one_batch_lanes();
        params.tx_queue.sizes = [MAX_MULTICAST_REPLIES + 1; Priority::NUM];
        let stage = GroupTxStage::new(&params);
        let nothing = || {};
        let host = FullHost::new(&nothing);
        {
            let _held = stage.inner.conduits.borrow_mut();
            for _ in 0..MAX_MULTICAST_REPLIES {
                assert_eq!(
                    push_put(&stage, Put::of("first"), &host),
                    PushOutcome::Pushed
                );
            }
            assert_eq!(
                push_put(&stage, Put::of("second"), &host),
                PushOutcome::Congested
            );
        }
        assert_eq!(stage.drops(Priority::DEFAULT), 1);
        assert_eq!(stage.dropped(), 0, "no reply was refused");
        stage.push_deferred();
        let mut sns = Vec::new();
        while let Some(datagram) = stage.take() {
            assert!(datagram.bytes.ends_with(b"first"));
            sns.push(datagram.sn);
        }
        assert_eq!(sns, (0..MAX_MULTICAST_REPLIES as u64).collect::<Vec<_>>());
    }

    /// A reply lent for the call is framed as its owned copy is, at once and when it is kept while
    /// the conduits are held, and holds a reply slot until its datagram is taken. Turned red by a
    /// lent reply framed with another band, channel or body than the owned one.
    #[cfg(feature = "liveliness-token")]
    #[test]
    fn a_reply_lent_for_the_call_is_framed_as_its_owned_copy() {
        use wz_session_core::multicast_tx::MulticastTxReply;
        let declare = wz_session_core::declare_build::build_declare_final_reply(7);
        let owned = GroupTxStage::new(&params());
        owned.enqueue(MulticastTxReply::DeclareReply(&declare).to_item());
        let lent = GroupTxStage::new(&params());
        lent.enqueue_reply(MulticastTxReply::DeclareReply(&declare));
        let staged = GroupTxStage::new(&params());
        {
            let _held = staged.inner.conduits.borrow_mut();
            staged.enqueue_reply(MulticastTxReply::DeclareReply(&declare));
            assert!(staged.take().is_none(), "kept while the conduits are held");
            assert_eq!(
                staged.inner.replies.get(),
                1,
                "the kept reply holds its slot"
            );
        }
        staged.push_deferred();
        let bytes = |stage: &GroupTxStage| stage.take().expect("the reply").bytes;
        let expected = bytes(&owned);
        assert_eq!(bytes(&lent), expected);
        assert_eq!(bytes(&staged), expected);
        assert_eq!(staged.inner.replies.get(), 0, "its slot is free once taken");
        assert_eq!((lent.dropped(), staged.dropped()), (0, 0));
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
        push_at_once(&stage, Put::fill());
        push_at_once(&stage, Put::fill());
        assert_eq!(
            push_put(&stage, Put::of("second"), &host),
            PushOutcome::Congested
        );
        assert_eq!(host.passes.get(), 0, "a wait of zero asks without waiting");
        assert_eq!(stage.drops(Priority::DEFAULT), 1);
    }

    /// The pump takes the oldest datagram of the most urgent lane first, as the tokio group's
    /// writer serves its lanes; a Control datagram waits behind what other lanes queued before
    /// it, while a lane more urgent than that data is still served first.
    #[test]
    fn the_pump_takes_the_most_urgent_lane_first_and_control_waits_behind_earlier_data() {
        fn order(priorities: &[Priority]) -> Vec<Priority> {
            let mut params = params();
            params.is_qos = true;
            let mut lanes = Lanes::of_group(&params, MaxMulticastRepliesHeld::default());
            for (sn, priority) in priorities.iter().enumerate() {
                let record = Record {
                    order: 0,
                    priority: *priority,
                    reliable: true,
                    sn: sn as u64,
                    reply: false,
                    len: 0,
                };
                assert!(lanes.queue(record, 1, &mut |slot| {
                    slot[0] = 0;
                    Some(1)
                }));
            }
            let mut out = Vec::new();
            while let Some(lane) = next_out(&lanes) {
                let record = lanes.front(lane).expect("the datagram chosen");
                out.push(record.priority);
                lanes.pop(lane, record.len);
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
        push_at_once(&full, Put::fill());
        push_at_once(&full, Put::fill());
        let nothing = || {};
        let host = FullHost::new(&nothing);
        assert_eq!(
            push_put(&full, Put::of("second"), &host),
            PushOutcome::Congested
        );
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
        push_at_once(&stage, Put::fill());
        push_at_once(&stage, Put::fill());
        let nothing = || {};
        let full = FullHost::new(&nothing);
        assert_eq!(
            push_put(&stage, Put::of("second").best_effort(), &full),
            PushOutcome::Congested
        );
        assert_eq!(
            push_put(&stage, Put::of("second").best_effort(), &full),
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
            push_put(&stage, Put::of("third").best_effort(), &taking),
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
        push_at_once(&stage, Put::of("first"));
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
        push_at_once(&stage, Put::of("second"));
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
        push_at_once(&stage, Put::of("first"));
        push_at_once(&stage, Put::of("second"));
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
        push_at_once(&stage, Put::of("first"));
        push_at_once(&stage, Put::of("second"));
        assert!(stage.is_empty(), "the window holds both, on no lane");

        stage.batch_flush();
        let both = stage.take().expect("the window's frame");
        assert!(stage.take().is_none(), "one datagram for both");
        assert!(carries(&both.bytes, "first") && both.bytes.ends_with(b"second"));

        push_at_once(&stage, Put::of("third"));
        assert!(stage.is_empty(), "the window is still open");
        stage.batch_stop();
        let third = stage.take().expect("the stop's frame");
        assert!(third.bytes.ends_with(b"third"));
        assert!(stage.take().is_none());

        push_at_once(&stage, Put::of("first"));
        let alone = stage.take().expect("a closed window holds nothing back");
        assert!(alone.bytes.ends_with(b"first"));
        assert_eq!([both.sn, third.sn, alone.sn], [0, 1, 2]);
    }

    /// Puts of one size inside a batch window fill each frame as zenoh-pico fills its batch: a
    /// frame goes on its lane as one datagram in the put it has no room for, holding as many puts
    /// as the group's batch takes, with no pass of the host and no wait while it has room; the
    /// stop puts the rest on its lane. N puts are N over what a frame holds, rounded up, datagrams.
    #[test]
    fn a_batch_window_puts_a_frame_on_its_lane_each_time_it_fills() {
        let params = params();
        let budget = params.frame_budget();
        let payload = |at: usize| alloc::format!("{at:08}");
        // The bytes one put adds to a frame, and the frame's head: a frame of one and one of two.
        let frame_of = |count: usize| {
            let stage = GroupTxStage::new(&params);
            stage.batch_start();
            for at in 0..count {
                push_at_once(&stage, Put::of(&payload(at)));
            }
            stage.batch_stop();
            stage.take().expect("the window's frame").bytes.len()
        };
        let (one, two) = (frame_of(1), frame_of(2));
        let each = two - one;
        let head = one - each;
        let fits = (budget - head) / each;
        assert!(
            fits > 1,
            "a frame of the group's batch holds several such puts"
        );

        let stage = GroupTxStage::new(&params);
        stage.batch_start();
        let puts = 2 * fits + 3;
        let mut frames = Vec::new();
        for at in 0..puts {
            push_at_once(&stage, Put::of(&payload(at)));
            frames.extend(core::iter::from_fn(|| stage.take()));
            assert_eq!(frames.len(), at / fits, "after put {at}");
        }
        stage.batch_stop();
        frames.extend(core::iter::from_fn(|| stage.take()));
        assert_eq!(frames.len(), puts.div_ceil(fits));
        for (at, frame) in frames.iter().enumerate() {
            let first = at * fits;
            let last = (first + fits).min(puts) - 1;
            assert_eq!(frame.bytes.len(), head + (last + 1 - first) * each);
            let opens = payload(first);
            assert!(frame.bytes.windows(8).any(|w| w == opens.as_bytes()));
            assert!(frame.bytes.ends_with(payload(last).as_bytes()));
            assert_eq!(frame.sn, at as u64, "one sequence number a frame");
        }
        assert!(head + fits * each <= budget && head + (fits + 1) * each > budget);
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
        push_at_once(&stage, Put::of("first"));
        push_at_once(&stage, Put::of("second"));
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

        push_at_once(&stage, Put::of("third"));
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
        push_at_once(&stage, Put::of("first"));
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
