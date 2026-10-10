// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y519 — the outbound writer's lifecycle: a SEALABLE queue, and the handle
//! that seals it.
//!
//! ## Why this exists
//!
//! Every stream / datagram pipeline hands its outbound frames to a spawned
//! writer task over an unbounded channel, and teardown has to answer one
//! question: *when has the writer finished?* Until R311y519 the answer was a
//! wall-clock budget — `drain_to_close` dropped the `Arc<SessionLinkActions>`
//! holders and awaited the task under a 50 ms timeout.
//!
//! That budget cannot tell a WEDGED peer from a SLOW one. On a loaded host it
//! expires while the writer is still making progress, and the frames still in
//! the channel are discarded — including frames the C ABI's `z_put` already
//! answered `Z_OK` for. That is a data-loss defect, and it is what made
//! `a_put_immediately_before_z_close_is_drained_not_discarded` red on hosted CI
//! while every local run won the race.
//!
//! Awaiting the writer WITHOUT a budget is not the fix on its own, because the
//! channel closes only when the last sender clone drops and on the accept path
//! one survives: `accept_loop::drive_face` drains as soon as the drive loop
//! returns, while the forwarder's `FaceEntry` — which holds a `TokioSession`,
//! hence a clone of the sender — is released later, in the loop's `Step::Driven`
//! arm. Deregistering earlier is not available either: under
//! `transport-multilink` that release is CONDITIONAL, because the session
//! survives while at least one link remains.
//!
//! So the close signal has to stop being sender liveness. A SEAL is that signal:
//!
//! - **Seal** = *finish the queue, then exit*. It closes the receiving half, so
//!   no further enqueue can land and the queue is finite; the writer then drains
//!   what is already in it and terminates on its own — regardless of how many
//!   sender clones the routing lifecycle still holds.
//! - It is deliberately NOT
//!   [`close_blocking`](crate::stream_link::StreamWriteDriver::close_blocking),
//!   whose no-op body documents why *close now* is wrong: it would race
//!   in-flight enqueues. *Finish the queue, then exit* races nothing, which is
//!   the whole reason it can be a new signal rather than a re-use of that one.
//!
//! ## The wedged-peer defence moves, it does not disappear
//!
//! The 50 ms budget was also what stopped a peer that has stopped reading
//! entirely from holding teardown open forever. That defence moves onto ONE
//! write, and is armed only once the queue is sealed — steady state keeps its
//! unbounded await, because there the peer's backpressure IS the flow control
//! and cutting a write short would be the same data loss in a different place.
//! [`OutboundQueue::guarded`] arms the bound even under a write already in
//! flight when the seal lands, since that is precisely the write a wedged peer
//! stalls on. Expiry ends the writer rather than skipping one frame, so a wedged
//! teardown costs [`WRITER_STALL_MS`] once, not once per queued frame.
//!
//! ## Why the handle is the only constructor
//!
//! [`WriterHandle::spawn`] is the sole way to obtain a handle, and it is what
//! builds the queue. A new pipeline therefore cannot spawn a writer that no one
//! can seal — the seal wiring is not a step to remember, it is the only step
//! available.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{watch, Notify};
use tokio::time::timeout;
use wz_session_core::link::RoomWait;
use wz_session_core::qos::Priority;

use crate::runtime_impl::TokioJoinHandle;
use crate::runtime_pool::WzRuntime;

#[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
use crate::link_tx_pool::{TxPool, TxPoolStats};
#[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
use crate::session_tx_pool_ap::{CpuMut, Slot, SlotState, SLOT_SIZE};

/// R2919 — the outbound channel between a session's emit and its link's
/// writer: one FIFO LANE per `Priority`, drained in strict ascending priority.
///
/// zenoh's transmission pipeline keeps a queue per priority and its consumer
/// pulls the lowest non-empty one first, so a RealTime batch enqueued behind a
/// backlog of Background batches leaves before them
/// (`io/zenoh-transport/src/common/pipeline.rs` @ `fn get_pending(&self) -> Option<Priority> {`).
/// wz's writer used to read one unbounded FIFO, so a frame's priority decided
/// only the frame header byte, never when the frame left: whatever was queued
/// first went first. Inside a batch window the session already staged per
/// priority, but once a frame was handed to the writer its place was fixed.
///
/// Each lane is FIFO, which is what keeps one conduit's SN order intact: a
/// conduit is one `(priority, reliability)` pair, and both reliabilities of a
/// priority share the lane, in the order they were minted.
///
/// A session that negotiated no QoS sends every data frame at
/// `Priority::DEFAULT`, so its data is one lane and FIFO, as zenoh's
/// single-queue pipeline is for such a transport.
///
/// R2921 — each lane is BOUNDED, at zenoh's defaults
/// ([`DEFAULT_QUEUE_SIZE`] batches of [`BATCH_BYTES`]); see
/// [`outbound_channel_with_capacity`].
pub fn outbound_channel() -> (OutboundTx, OutboundRx) {
    outbound_channel_with_capacity([DEFAULT_QUEUE_SIZE; Priority::NUM], BATCH_BYTES)
}

/// zenoh's default queue size per priority, in batches: 2 for every band
/// (`commons/zenoh-config/src/defaults.rs` @ `impl Default for QueueSizeConf {`).
pub const DEFAULT_QUEUE_SIZE: usize = 2;

/// zenoh's default batch size, the unit a queue size counts in
/// (`BatchSize::MAX`).
///
/// R2925 — only until the session is established: its shape
/// ([`OutboundTx::reshape`]) replaces the unit with the link's negotiated
/// batch MTU, as upstream's pipeline batches are the link's `batch.mtu`.
pub const BATCH_BYTES: usize = u16::MAX as usize;

/// R2921 — [`outbound_channel`] with each lane holding at most
/// `queue_size[priority]` batches of `batch_bytes`.
///
/// zenoh bounds each priority queue by a pool of `queue_size` batches: a
/// producer that finds no free batch waits for the consumer to return one
/// (`io/zenoh-transport/src/common/pipeline.rs` @ `// Wait for an available batch until deadline`).
/// wz hands the writer FRAMES, and outside a batch window every network
/// message is its own frame, where zenoh coalesces a burst of small messages
/// into one batch; counting the bound in frames would therefore congest a
/// burst zenoh absorbs. The bound is counted in BYTES instead —
/// `queue_size * batch_bytes` — which is the room zenoh's batches hold.
///
/// A frame occupies its lane from enqueue until the writer asks for the NEXT
/// frame, which is when the one it was given has been written: zenoh returns
/// a batch to the pool after the tx task writes it, so a batch in flight
/// still counts against the bound.
///
/// Only [`OutboundTx::wait_for_room`] consults the bound. [`OutboundTx::send`]
/// always enqueues: the frames that must never wait (a keepalive, a close)
/// take it as they are, and a sender that must honour congestion asks for
/// room first.
pub fn outbound_channel_with_capacity(
    queue_size: [usize; Priority::NUM],
    batch_bytes: usize,
) -> (OutboundTx, OutboundRx) {
    let shared = Arc::new(Lanes {
        state: Mutex::new(LaneState {
            lanes: std::array::from_fn(|_| VecDeque::new()),
            capacity: queue_size.map(|n| n * batch_bytes),
            batch_bytes,
            single_lane: false,
            occupied: [0; Priority::NUM],
            congested: [false; Priority::NUM],
            block_first: [false; Priority::NUM],
            in_flight: None,
            closed: false,
            senders: 1,
            spare: Vec::new(),
            #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
            pool: None,
            #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
            next_batch: 0,
            #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
            receiver_gone: false,
        }),
        ready: Notify::new(),
        room: Condvar::new(),
    });
    (
        OutboundTx {
            shared: shared.clone(),
        },
        OutboundRx { shared },
    )
}

/// R3250 — [`outbound_channel`] over the link's own TRANSMIT POOL
/// (`sources/network/session_tx_pool_ap.scxml`), ARCHITECTURE section 9.1:
/// every frame a sender hands this queue, lent or copied, lies in a slot of the
/// pool until the writer has written it, so the transmit path allocates nothing
/// per frame, in a burst, or for a frame of any size a stream link can carry.
///
/// The lanes, their byte bounds, their priority order and their congestion
/// marks are [`outbound_channel`]'s, unchanged; the pool adds one condition to
/// "room" (a free slot) and is back-pressure when it is dry. The pool is
/// allocated once here, zeroed, about 1 MiB of address space per link.
#[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
pub fn outbound_channel_pooled() -> (OutboundTx, OutboundRx) {
    outbound_channel_pooled_with_capacity([DEFAULT_QUEUE_SIZE; Priority::NUM], BATCH_BYTES)
}

/// R3250 — [`outbound_channel_pooled`] with each lane's bound, as
/// [`outbound_channel_with_capacity`].
#[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
pub fn outbound_channel_pooled_with_capacity(
    queue_size: [usize; Priority::NUM],
    batch_bytes: usize,
) -> (OutboundTx, OutboundRx) {
    let (tx, rx) = outbound_channel_with_capacity(queue_size, batch_bytes);
    tx.shared
        .state
        .lock()
        .expect("outbound lanes poisoned")
        .pool = Some(TxPool::new());
    (tx, rx)
}

struct Lanes {
    state: Mutex<LaneState>,
    /// Wakes the (single) writer when a frame lands or the last sender goes.
    ready: Notify,
    /// Wakes senders waiting for room when the writer frees some, or the
    /// queue closes.
    room: Condvar,
}

struct LaneState {
    /// Each lane's frames, each with the priority it was sent at.
    lanes: [VecDeque<Entry>; Priority::NUM],
    /// Each lane's bound, in bytes.
    capacity: [usize; Priority::NUM],
    /// The bytes one batch holds, the unit a queue size counts in.
    batch_bytes: usize,
    /// R2924 — every frame goes to the `Priority::DEFAULT` lane: the session
    /// negotiated no QoS, and zenoh gives such a transport one queue.
    single_lane: bool,
    /// Each lane's bytes queued or in flight.
    occupied: [usize; Priority::NUM],
    /// R2923 — each lane's CONGESTED mark, zenoh's per-priority
    /// `set_congested`: raised when a wait for room on the lane runs out,
    /// lowered when the writer frees some of it (zenoh's `refill`) or a later
    /// wait finds room. While it stands a droppable message is dropped without
    /// waiting.
    congested: [bool; Priority::NUM],
    /// R2952 (open-debt item 835) — each priority's BLOCK-FIRST slot, zenoh's
    /// per-link `block_first_waiters`: taken while a block-first message is
    /// being pushed in the background, so a second one at the same priority
    /// waits `wait_before_drop` for it and is dropped if it stays taken.
    /// Indexed by the message's own priority, as zenoh indexes it — not by
    /// lane, which a no-QoS session collapses to one.
    block_first: [bool; Priority::NUM],
    /// The frame the writer holds, as `(lane, bytes)`: still occupying its
    /// lane until the writer asks for the next one.
    in_flight: Option<(usize, usize)>,
    /// No further enqueue lands — set by the receiver's `close` (the seal).
    closed: bool,
    /// Live `OutboundTx` clones; the queue is finished once this reaches 0
    /// and the lanes are empty.
    senders: usize,
    /// ARCHITECTURE section 9.1 — frame buffers the writer is done with, kept to
    /// be lent again so a link in steady state allocates none. Bounded in count
    /// and in size ([`SPARE_MAX`], [`SPARE_CAPACITY_MAX`]) so a burst of large
    /// frames cannot make a link hoard memory.
    spare: Vec<Vec<u8>>,
    /// R3250 — ARCHITECTURE section 9.1 under `runtime-zero-copy`: the link's
    /// transmit pool, on a queue built by [`outbound_channel_pooled`]. While it
    /// is here every frame a sender hands this queue lies in one of its slots
    /// ([`Entry::Batch`]), and a dry pool is back-pressure.
    #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
    pool: Option<TxPool>,
    /// The id the next batch is given, so a lend can find its batch again.
    #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
    next_batch: u64,
    /// The receiving half has been DROPPED (not merely sealed): nothing will
    /// ever write what is queued, so a batch a lend gives back goes home
    /// whatever it holds.
    #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
    receiver_gone: bool,
}

/// One queued item of a lane.
enum Entry {
    /// A frame in a vector of its own, with the priority it was sent at.
    Heap(Priority, Vec<u8>),
    /// R3250 — a slot of the link's transmit pool holding frames back to back.
    #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
    Batch(Batch),
}

/// R3250 — a slot of a pooled queue while it is on its lane: the frames
/// written into it so far, and whether a lend is writing the next one.
///
/// A sender appends to its lane's NEWEST batch while it has room and no lend is
/// in it, so frames pack into few slots and a slot is written by one write; on
/// a byte stream the concatenation is the wire. The slot is cpu-mut for as long
/// as it is here, which is the state the generated lifecycle gives a slot the
/// CPU is still writing.
#[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
struct Batch {
    /// The priority of the first frame in it (all of them, on a QoS lane).
    priority: Priority,
    id: u64,
    slot: Slot<CpuMut>,
    /// First byte of the slot, from the pool (`TxPool::base_of`).
    base: usize,
    /// Bytes of whole frames written into it.
    fill: usize,
    /// A lend is encoding a frame at `fill`: nothing else may write the slot,
    /// and the writer may not take it until the lend is committed or given back.
    lent: bool,
}

/// What [`LaneState::take_next`] found.
enum Taken {
    /// A frame (or a batch of frames) for the writer, with its priority.
    Frame(Priority, Out),
    /// The highest lane with anything in it is waiting on a lend in progress.
    #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
    Blocked,
    /// Nothing is queued.
    Empty,
}

/// The parts of a taken item; [`OutboundRx`] makes the [`WireFrame`].
enum Out {
    Heap(Vec<u8>),
    #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
    Slot {
        idx: usize,
        base: usize,
        len: usize,
    },
}

/// How many spare frame buffers a lane set keeps.
const SPARE_MAX: usize = 4;

/// The largest buffer worth keeping spare. A frame buffer past it is rare (a
/// frame is bounded by the link's batch size, which an ordinary session sets
/// well under it) and is freed instead, so the pool's worst case is
/// `SPARE_MAX * SPARE_CAPACITY_MAX` bytes per link.
const SPARE_CAPACITY_MAX: usize = 16 * 1024;

impl LaneState {
    /// A spare buffer with room for `min` bytes, if one is kept: the smallest
    /// that fits, so a small frame does not take the one a large frame needs.
    fn take_spare(&mut self, min: usize) -> Option<Vec<u8>> {
        let best = self
            .spare
            .iter()
            .enumerate()
            .filter(|(_, buf)| buf.capacity() >= min)
            .min_by_key(|(_, buf)| buf.capacity())
            .map(|(i, _)| i)?;
        Some(self.spare.swap_remove(best))
    }

    /// Keep `buf` to be lent again, emptied, unless the pool is full or the buffer
    /// is not worth keeping.
    fn give_spare(&mut self, mut buf: Vec<u8>) {
        if buf.capacity() == 0
            || buf.capacity() > SPARE_CAPACITY_MAX
            || self.spare.len() >= SPARE_MAX
        {
            return;
        }
        buf.clear();
        self.spare.push(buf);
    }

    /// R2924 — the lane a frame of `priority` takes: its own, or the one lane
    /// a non-QoS session has.
    fn lane_of(&self, priority: Priority) -> usize {
        if self.single_lane {
            Priority::DEFAULT.wire_byte() as usize
        } else {
            priority.wire_byte() as usize
        }
    }

    /// R2924 — take the shape an established session gives its link. Frames
    /// already queued keep their lanes and drain as before; only the bounds
    /// and where new frames go change.
    fn reshape(&mut self, shape: wz_session_core::link::TxQueueShape) {
        self.single_lane = !shape.qos;
        self.batch_bytes = shape.batch_bytes;
        self.capacity = shape.sizes.map(|n| n * self.batch_bytes);
        if self.single_lane {
            // zenoh sizes a non-QoS transport's one queue by the DEFAULT
            // priority's size.
            let default = Priority::DEFAULT.wire_byte() as usize;
            self.capacity = [self.capacity[default]; Priority::NUM];
        }
    }

    /// Take the next frame, highest priority first, after releasing the one
    /// the writer held. Returns whether room was freed, so the caller wakes
    /// senders waiting for it.
    ///
    /// R2929 — the frame comes with the priority it was sent at, which is not
    /// its lane's when the lanes are one.
    fn take_next(&mut self) -> (Taken, bool) {
        let freed = self.release_in_flight();
        for lane in 0..Priority::NUM {
            match self.take_from(lane) {
                Taken::Empty => continue,
                taken => return (taken, freed),
            }
        }
        (Taken::Empty, freed)
    }

    /// The next item of `lane`, made the writer's.
    ///
    /// R3250 — on a pooled queue a batch a lend is writing into is not the
    /// writer's yet. One with nothing committed holds no frame, so the items
    /// behind it are taken past it (they are other conduits' frames: the lend's
    /// own conduit cannot have a later frame while its lend is open). One that
    /// already holds frames is waited for, because a later item of the lane may
    /// be a later frame of a conduit whose earlier one is in it.
    fn take_from(&mut self, lane: usize) -> Taken {
        #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
        let at = {
            let mut at = None;
            for (i, entry) in self.lanes[lane].iter().enumerate() {
                match entry {
                    Entry::Batch(batch) if batch.lent && batch.fill == 0 => continue,
                    Entry::Batch(batch) if batch.lent => return Taken::Blocked,
                    _ => {
                        at = Some(i);
                        break;
                    }
                }
            }
            match at {
                Some(i) => i,
                None => return Taken::Empty,
            }
        };
        #[cfg(not(all(feature = "runtime-zero-copy", feature = "transport-link-tcp")))]
        let at = 0;
        let Some(entry) = self.lanes[lane].remove(at) else {
            return Taken::Empty;
        };
        match entry {
            Entry::Heap(priority, frame) => {
                self.in_flight = Some((lane, frame.len()));
                Taken::Frame(priority, Out::Heap(frame))
            }
            #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
            Entry::Batch(batch) => {
                let pool = self
                    .pool
                    .as_mut()
                    .expect("a batch is queued only on a pooled queue");
                // Off its lane: no sender may write it again. Cpu-mut to
                // dma-armed-tx, and its address is the pool's own answer for an
                // armed slot.
                let (idx, base) = pool.arm(batch.slot);
                self.in_flight = Some((lane, batch.fill));
                Taken::Frame(
                    batch.priority,
                    Out::Slot {
                        idx,
                        base: base as usize,
                        len: batch.fill,
                    },
                )
            }
        }
    }

    /// R3250 — whether a frame could be given a slot: always on a heap queue;
    /// on a pooled one, while the pool has a free slot. Conservative by
    /// design: a frame that would have fit behind the newest batch is told
    /// "no room" too when the pool is dry, because the answer is given before
    /// the frame's size is known.
    fn slot_room(&self) -> bool {
        #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
        if let Some(pool) = self.pool.as_ref() {
            return pool.free_count() > 0;
        }
        true
    }

    /// R2923 — the answer to `wait` on `lane` if it needs no waiting: the
    /// queue is closed, a droppable message meets the congested mark, the
    /// lane has room, or the request may not wait at all. `None` means the
    /// caller has to wait for the writer.
    fn room_at_once(&mut self, lane: usize, wait: RoomWait) -> Option<Room> {
        if self.closed {
            return Some(Room::Closed);
        }
        if wait.is_droppable() && self.congested[lane] {
            return Some(Room::Congested);
        }
        if self.occupied[lane] < self.capacity[lane] && self.slot_room() {
            self.congested[lane] = false;
            return Some(Room::Free);
        }
        if wait.wait_us() == 0 {
            self.congested[lane] = true;
            return Some(Room::Congested);
        }
        None
    }

    fn release_in_flight(&mut self) -> bool {
        match self.in_flight.take() {
            Some((lane, bytes)) => {
                self.occupied[lane] = self.occupied[lane].saturating_sub(bytes);
                // zenoh lowers the mark when a written batch returns to its
                // priority's pool (`fn refill(`), room or not.
                self.congested[lane] = false;
                true
            }
            None => false,
        }
    }
}

/// R2921 — what [`OutboundTx::wait_for_room`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Room {
    /// The lane has room; the frame may be enqueued.
    Free,
    /// The lane stayed full for the whole wait.
    Congested,
    /// The queue is closed; nothing more will be written.
    Closed,
}

/// The receiver half of [`outbound_channel`] was closed (the queue sealed),
/// or dropped; the frame was not enqueued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundClosed(pub Vec<u8>);

impl std::fmt::Display for OutboundClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "outbound queue closed")
    }
}

/// The sending half of [`outbound_channel`]. Cloneable; the queue ends when
/// every clone has dropped (or the receiver sealed it).
pub struct OutboundTx {
    shared: Arc<Lanes>,
}

impl OutboundTx {
    /// An empty buffer with room for at least `min_capacity` bytes, to build a
    /// frame in: one the writer has finished with when the lane set keeps one that
    /// fits, a fresh allocation otherwise.
    pub fn take_buffer(&self, min_capacity: usize) -> Vec<u8> {
        let spare = self
            .shared
            .state
            .lock()
            .expect("outbound lanes poisoned")
            .take_spare(min_capacity);
        spare.unwrap_or_else(|| Vec::with_capacity(min_capacity))
    }

    /// Give back a buffer that was taken with [`Self::take_buffer`] and never
    /// sent (a lend that was abandoned), so it is lent again and not freed.
    pub fn return_buffer(&self, buf: Vec<u8>) {
        self.shared
            .state
            .lock()
            .expect("outbound lanes poisoned")
            .give_spare(buf);
    }

    /// How many spare buffers are kept. For a test to wait until the writer has
    /// given one back.
    #[cfg(test)]
    pub(crate) fn spare_count(&self) -> usize {
        self.shared
            .state
            .lock()
            .expect("outbound lanes poisoned")
            .spare
            .len()
    }

    /// Enqueue `frame` on `priority`'s lane, whatever the lane holds.
    pub fn send(&self, priority: Priority, frame: Vec<u8>) -> Result<(), OutboundClosed> {
        let mut st = self.shared.state.lock().expect("outbound lanes poisoned");
        if st.closed {
            return Err(OutboundClosed(frame));
        }
        let lane = st.lane_of(priority);
        st.occupied[lane] += frame.len();
        st.lanes[lane].push_back(Entry::Heap(priority, frame));
        drop(st);
        self.shared.ready.notify_one();
        Ok(())
    }

    /// R2921 — wait for `priority`'s lane to have room, zenoh's "wait for an
    /// available batch until deadline". A lane has room while what it holds is
    /// under its bound; a frame then takes it even if it carries the lane past
    /// the bound, as a batch that exists is filled whole. A wait of zero asks
    /// without waiting.
    ///
    /// R2923 — and the lane's congested mark decides whether a droppable
    /// message waits at all, as zenoh's does
    /// (`io/zenoh-transport/src/common/pipeline.rs` @
    /// `if msg.is_droppable() && self.status.is_congested(priority) {`): while
    /// the mark stands it is answered `Congested` at once. A wait that runs
    /// out raises the mark, whichever kind of message it was; one that finds
    /// room lowers it.
    pub fn wait_for_room(&self, priority: Priority, wait: RoomWait) -> Room {
        let deadline = Instant::now() + Duration::from_micros(wait.wait_us());
        let mut st = self.shared.state.lock().expect("outbound lanes poisoned");
        let lane = st.lane_of(priority);
        if let Some(room) = st.room_at_once(lane, wait) {
            return room;
        }
        // Waiting now: the mark is consulted once, on entry, as zenoh consults
        // it before it waits and not while it does.
        loop {
            if st.closed {
                return Room::Closed;
            }
            if st.occupied[lane] < st.capacity[lane] && st.slot_room() {
                st.congested[lane] = false;
                return Room::Free;
            }
            let now = Instant::now();
            if now >= deadline {
                st.congested[lane] = true;
                return Room::Congested;
            }
            st = self
                .shared
                .room
                .wait_timeout(st, deadline - now)
                .expect("outbound lanes poisoned")
                .0;
        }
    }

    /// R2952 (open-debt item 835) — take `priority`'s block-first slot, waiting
    /// up to `wait_us` for it, as zenoh's
    /// `block_first_waiters[priority].wait_timeout(wait_before_drop)` does.
    /// `false` when it stays taken or the queue closes.
    ///
    /// The wait releases a multi-thread runtime's worker exactly as
    /// [`Self::link_room`] does, and for the same reason: the background push
    /// that would free the slot may be queued behind the waiter.
    pub fn block_first_acquire(&self, priority: Priority, wait_us: u64) -> bool {
        let slot = usize::from(priority.wire_byte());
        let take = || {
            let deadline = Instant::now() + Duration::from_micros(wait_us);
            let mut st = self.shared.state.lock().expect("outbound lanes poisoned");
            loop {
                if st.closed {
                    return false;
                }
                if !st.block_first[slot] {
                    st.block_first[slot] = true;
                    return true;
                }
                let now = Instant::now();
                if now >= deadline {
                    return false;
                }
                st = self
                    .shared
                    .room
                    .wait_timeout(st, deadline - now)
                    .expect("outbound lanes poisoned")
                    .0;
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(take)
            }
            _ => take(),
        }
    }

    /// R2952 — give `priority`'s block-first slot back and wake whoever waits
    /// for it: zenoh's `block_first_notifier.notify()`.
    pub fn block_first_release(&self, priority: Priority) {
        let slot = usize::from(priority.wire_byte());
        let mut st = self.shared.state.lock().expect("outbound lanes poisoned");
        st.block_first[slot] = false;
        drop(st);
        self.shared.room.notify_all();
    }

    /// [`Self::wait_for_room`] in the terms of the session's link seam
    /// (`BoxedLinkDriver::wait_for_room`), which every write driver over this
    /// queue answers with.
    ///
    /// R2926 — with how long the ask waited, measured here, where the waiting
    /// is done.
    pub fn link_room(
        &self,
        priority: Priority,
        wait: RoomWait,
    ) -> wz_session_core::link::RoomAnswer {
        use wz_session_core::link::{LinkRoom, RoomAnswer};
        let started = Instant::now();
        // R2923 — a sender that has to WAIT is usually on a runtime worker, and
        // the writer that would free the lane may be queued behind it on that
        // same worker. On a multi-thread runtime the wait therefore releases
        // the worker (`block_in_place`), as zenoh's blocking put does; a request
        // the lane can answer at once never leaves it. A current-thread runtime
        // has no second worker to hand the task to, so there the wait runs to
        // its deadline — the congestion verdict it was asked for.
        let at_once = {
            let mut st = self.shared.state.lock().expect("outbound lanes poisoned");
            let lane = st.lane_of(priority);
            st.room_at_once(lane, wait)
        };
        let room = match at_once {
            Some(room) => room,
            None => {
                let wait = || self.wait_for_room(priority, wait);
                match tokio::runtime::Handle::try_current() {
                    Ok(handle)
                        if handle.runtime_flavor()
                            == tokio::runtime::RuntimeFlavor::MultiThread =>
                    {
                        tokio::task::block_in_place(wait)
                    }
                    _ => wait(),
                }
            }
        };
        let room = match room {
            Room::Free => LinkRoom::Free,
            Room::Congested => LinkRoom::Congested,
            Room::Closed => LinkRoom::Gone,
        };
        RoomAnswer {
            room,
            waited_us: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        }
    }

    /// R2924 — give the queue the shape its established session needs
    /// (`BoxedLinkDriver::shape_tx_queue`), which every write driver over this
    /// queue answers with. Senders waiting for room re-read the new bounds.
    pub fn reshape(&self, shape: wz_session_core::link::TxQueueShape) {
        self.shared
            .state
            .lock()
            .expect("outbound lanes poisoned")
            .reshape(shape);
        self.shared.room.notify_all();
    }

    /// Whether the receiving side has closed the queue.
    pub fn is_closed(&self) -> bool {
        self.shared
            .state
            .lock()
            .expect("outbound lanes poisoned")
            .closed
    }
}

/// R3250 — why a pooled queue refused a frame.
#[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PooledSendError {
    /// The queue is closed (sealed or its receiver gone): nothing more is
    /// written.
    Closed,
    /// The frame is larger than a slot. A stream frame never is (the slot holds
    /// the largest one, `link_tx_pool::MAX_STREAM_FRAME`), so this is a caller
    /// that bypassed the write half's own length guard.
    TooLarge,
}

#[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
impl std::fmt::Display for PooledSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "outbound queue closed"),
            Self::TooLarge => write!(f, "frame larger than a transmit slot"),
        }
    }
}

/// R3250 — the part of a pooled lane's slot a sender has been lent to encode
/// one frame into. Consumed by [`OutboundTx::commit`] or
/// [`OutboundTx::abort_lend`]; until one of them runs, nothing else writes those
/// bytes and the writer does not take the slot.
#[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
#[derive(Debug)]
pub struct TxLend {
    lane: usize,
    batch: u64,
    base: usize,
    cap: usize,
}

#[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
impl TxLend {
    /// The first byte the frame may be written at.
    pub fn base(&self) -> *mut u8 {
        self.base as *mut u8
    }

    /// How many bytes may be written from [`Self::base`].
    pub fn capacity(&self) -> usize {
        self.cap
    }
}

/// Write `prefix` then `payload` at `at`.
///
/// # Safety
/// `[at, at + prefix.len() + payload.len())` must lie in a slot the caller's
/// lane holds and no one else writes, and neither source may overlap it.
#[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
unsafe fn write_frame_at(at: usize, prefix: &[u8], payload: &[u8]) {
    // SAFETY: the caller's contract.
    unsafe {
        std::ptr::copy_nonoverlapping(prefix.as_ptr(), at as *mut u8, prefix.len());
        std::ptr::copy_nonoverlapping(
            payload.as_ptr(),
            (at + prefix.len()) as *mut u8,
            payload.len(),
        );
    }
}

/// R3250 — the pooled queue's sender side. Every method here is for a queue
/// built by [`outbound_channel_pooled`]; on a heap queue they answer as a link
/// that lends nothing.
#[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
impl OutboundTx {
    /// Whether this queue keeps its frames in a transmit pool.
    pub fn is_pooled(&self) -> bool {
        self.shared
            .state
            .lock()
            .expect("outbound lanes poisoned")
            .pool
            .is_some()
    }

    /// What the pool has done, and how many of its slots are free now, by the
    /// pool's own count. `None` on a heap queue.
    pub fn tx_pool_stats(&self) -> Option<(TxPoolStats, usize)> {
        let st = self.shared.state.lock().expect("outbound lanes poisoned");
        st.pool
            .as_ref()
            .map(|pool| (pool.stats(), pool.free_count()))
    }

    /// The lifecycle state the pool's emit records for slot `idx`.
    pub fn tx_slot_state(&self, idx: usize) -> Option<SlotState> {
        let st = self.shared.state.lock().expect("outbound lanes poisoned");
        st.pool.as_ref().and_then(|pool| pool.slot_state(idx))
    }

    /// Enqueue the frame `prefix` + `payload` on `priority`'s lane by COPYING it
    /// into a slot: behind the frames of the lane's newest batch when it has
    /// room and no lend is in it, else into a fresh slot. This is the byte door
    /// of a pooled queue, and like [`Self::send`] it does not ask for room: a
    /// frame that must not wait for room (a keep-alive, a close) is taken as it
    /// is. When the pool is dry it waits for the writer to free a slot, as
    /// upstream's transport messages wait for a batch, and gives up only when
    /// the queue closes.
    pub fn send_framed(
        &self,
        priority: Priority,
        prefix: &[u8],
        payload: &[u8],
    ) -> Result<(), PooledSendError> {
        let need = prefix.len() + payload.len();
        if need > SLOT_SIZE {
            return Err(PooledSendError::TooLarge);
        }
        loop {
            {
                let mut guard = self.shared.state.lock().expect("outbound lanes poisoned");
                if guard.closed {
                    return Err(PooledSendError::Closed);
                }
                let lane = guard.lane_of(priority);
                let st = &mut *guard;
                let Some(pool) = st.pool.as_mut() else {
                    // A heap queue: the frame becomes a vector of its own.
                    drop(guard);
                    let mut frame = Vec::with_capacity(need);
                    frame.extend_from_slice(prefix);
                    frame.extend_from_slice(payload);
                    return self
                        .send(priority, frame)
                        .map_err(|_| PooledSendError::Closed);
                };
                let appended = match st.lanes[lane].back_mut() {
                    Some(Entry::Batch(batch)) if !batch.lent && SLOT_SIZE - batch.fill >= need => {
                        // SAFETY: `[fill, fill + need)` lies in this batch's slot
                        // (checked), the batch is cpu-mut on its lane with no lend
                        // in it, so nothing else writes it, and the sources are
                        // the caller's slices, which no slot of this lane is.
                        unsafe { write_frame_at(batch.base + batch.fill, prefix, payload) };
                        batch.fill += need;
                        true
                    }
                    _ => false,
                };
                if !appended {
                    let Some(mut slot) = pool.acquire() else {
                        drop(guard);
                        if !self.wait_for_slot() {
                            return Err(PooledSendError::Closed);
                        }
                        continue;
                    };
                    let base = pool.base_of(&mut slot) as usize;
                    // SAFETY: a fresh slot of SLOT_SIZE >= need bytes, held by
                    // this call alone until it is on the lane.
                    unsafe { write_frame_at(base, prefix, payload) };
                    let id = st.next_batch;
                    st.next_batch += 1;
                    st.lanes[lane].push_back(Entry::Batch(Batch {
                        priority,
                        id,
                        slot,
                        base,
                        fill: need,
                        lent: false,
                    }));
                }
                pool.note_copied();
                st.occupied[lane] += need;
            }
            self.shared.ready.notify_one();
            return Ok(());
        }
    }

    /// Lend the sender `need` bytes of `priority`'s lane to encode one frame
    /// into: the room behind the newest batch's frames when it has that much and
    /// no lend is in it, else a fresh slot. `None` when the queue is closed or
    /// `need` is larger than a slot; on a heap queue, always. When the pool is
    /// dry this WAITS for the writer to free a slot: the session asks for room
    /// before it mints the frame's sequence number, and room on a pooled queue
    /// includes a free slot, so the wait is the window between that answer and
    /// this call, and it ends when the writer frees one or the queue closes.
    pub fn lend(&self, priority: Priority, need: usize) -> Option<TxLend> {
        if need > SLOT_SIZE {
            return None;
        }
        loop {
            {
                let mut guard = self.shared.state.lock().expect("outbound lanes poisoned");
                if guard.closed {
                    return None;
                }
                let lane = guard.lane_of(priority);
                let st = &mut *guard;
                let pool = st.pool.as_mut()?;
                if let Some(Entry::Batch(batch)) = st.lanes[lane].back_mut() {
                    if !batch.lent && SLOT_SIZE - batch.fill >= need {
                        batch.lent = true;
                        return Some(TxLend {
                            lane,
                            batch: batch.id,
                            base: batch.base + batch.fill,
                            cap: SLOT_SIZE - batch.fill,
                        });
                    }
                }
                if let Some(mut slot) = pool.acquire() {
                    let base = pool.base_of(&mut slot) as usize;
                    let id = st.next_batch;
                    st.next_batch += 1;
                    // On the lane at once, so its place in the lane's order is
                    // the order the frame was lent in.
                    st.lanes[lane].push_back(Entry::Batch(Batch {
                        priority,
                        id,
                        slot,
                        base,
                        fill: 0,
                        lent: true,
                    }));
                    return Some(TxLend {
                        lane,
                        batch: id,
                        base,
                        cap: SLOT_SIZE,
                    });
                }
            }
            if !self.wait_for_slot() {
                return None;
            }
        }
    }

    /// The sender wrote a frame of `len` bytes (its prefix included) at the
    /// start of `lend`: it is queued behind the batch's earlier frames. Refused
    /// when the queue has closed since the lend, as [`Self::send`] refuses; the
    /// slot then goes home if nothing else is in it.
    pub fn commit(&self, lend: TxLend, len: usize) -> Result<(), PooledSendError> {
        debug_assert!(len <= lend.cap, "a lent frame stays inside its lend");
        let (result, freed) = {
            let mut guard = self.shared.state.lock().expect("outbound lanes poisoned");
            let st = &mut *guard;
            let closed = st.closed;
            let Some(at) = st.find_batch(lend.lane, lend.batch) else {
                debug_assert!(
                    false,
                    "a lend's batch stays on its lane until it is settled"
                );
                return Err(PooledSendError::Closed);
            };
            let Some(Entry::Batch(batch)) = st.lanes[lend.lane].get_mut(at) else {
                unreachable!("find_batch answers the index of a batch");
            };
            batch.lent = false;
            if closed {
                let goes_home = batch.fill == 0 || st.receiver_gone;
                if goes_home {
                    st.unqueue_batch(lend.lane, at);
                }
                (Err(PooledSendError::Closed), goes_home)
            } else {
                batch.fill += len;
                st.occupied[lend.lane] += len;
                if let Some(pool) = st.pool.as_mut() {
                    pool.note_lent();
                }
                (Ok(()), false)
            }
        };
        self.shared.ready.notify_one();
        if freed {
            self.shared.room.notify_all();
        }
        result
    }

    /// The sender is not sending what it was lent: the bytes are not a frame,
    /// and a slot that holds no frame goes home.
    pub fn abort_lend(&self, lend: TxLend) {
        let freed = {
            let mut guard = self.shared.state.lock().expect("outbound lanes poisoned");
            let st = &mut *guard;
            let Some(at) = st.find_batch(lend.lane, lend.batch) else {
                debug_assert!(
                    false,
                    "a lend's batch stays on its lane until it is settled"
                );
                return;
            };
            let Some(Entry::Batch(batch)) = st.lanes[lend.lane].get_mut(at) else {
                unreachable!("find_batch answers the index of a batch");
            };
            batch.lent = false;
            let goes_home = batch.fill == 0 || st.receiver_gone;
            if goes_home {
                st.unqueue_batch(lend.lane, at);
            }
            goes_home
        };
        // The writer may be waiting on this lend.
        self.shared.ready.notify_one();
        if freed {
            self.shared.room.notify_all();
        }
    }

    /// Wait until the pool has a free slot (`true`) or the queue closes
    /// (`false`). On a multi-thread runtime the wait releases the worker, as
    /// [`Self::link_room`]'s does and for the same reason: the writer that frees
    /// the slot may be queued behind the waiter.
    fn wait_for_slot(&self) -> bool {
        let wait = || {
            let mut st = self.shared.state.lock().expect("outbound lanes poisoned");
            loop {
                if st.closed {
                    return false;
                }
                if st.slot_room() {
                    return true;
                }
                st = self.shared.room.wait(st).expect("outbound lanes poisoned");
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(wait)
            }
            _ => wait(),
        }
    }
}

#[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
impl LaneState {
    /// Where batch `id` is on `lane`.
    fn find_batch(&self, lane: usize, id: u64) -> Option<usize> {
        self.lanes[lane]
            .iter()
            .position(|entry| matches!(entry, Entry::Batch(batch) if batch.id == id))
    }

    /// Take the batch at `at` off `lane` and give its slot back to the pool
    /// (cpu-mut to free): it will never be written.
    fn unqueue_batch(&mut self, lane: usize, at: usize) {
        if let Some(Entry::Batch(batch)) = self.lanes[lane].remove(at) {
            if let Some(pool) = self.pool.as_mut() {
                pool.give_back(batch.slot);
            }
        }
    }

    /// The receiving half is gone: every batch no lend is writing into goes
    /// home now, and one a lend is writing into goes home when the lend is
    /// settled (see `receiver_gone`). Heap frames are dropped with the queue.
    fn release_unwritten(&mut self) {
        self.receiver_gone = true;
        let Some(pool) = self.pool.as_mut() else {
            return;
        };
        for lane in self.lanes.iter_mut() {
            let mut kept = VecDeque::new();
            for entry in lane.drain(..) {
                match entry {
                    Entry::Batch(batch) if batch.lent => kept.push_back(Entry::Batch(batch)),
                    Entry::Batch(batch) => pool.give_back(batch.slot),
                    Entry::Heap(..) => {}
                }
            }
            *lane = kept;
        }
    }
}

impl Clone for OutboundTx {
    fn clone(&self) -> Self {
        self.shared
            .state
            .lock()
            .expect("outbound lanes poisoned")
            .senders += 1;
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl Drop for OutboundTx {
    fn drop(&mut self) {
        let last = {
            let mut st = self.shared.state.lock().expect("outbound lanes poisoned");
            st.senders -= 1;
            st.senders == 0
        };
        if last {
            self.shared.ready.notify_one();
        }
    }
}

/// The receiving half of [`outbound_channel`].
pub struct OutboundRx {
    shared: Arc<Lanes>,
}

impl OutboundRx {
    /// The writer is done with `frame`: keep its buffer to be lent again. Called
    /// after the bytes are written, never before — the buffer is overwritten by the
    /// next frame built in it.
    pub fn recycle(&self, frame: Vec<u8>) {
        self.shared
            .state
            .lock()
            .expect("outbound lanes poisoned")
            .give_spare(frame);
    }

    /// The next frame, highest priority first; `None` once the queue is
    /// finished — closed or sender-less, and empty.
    ///
    /// Asking for the next frame is also what says the previous one has been
    /// written: its bytes leave the lane's bound here.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.recv_tagged().await.map(|(_, frame)| frame)
    }

    /// R2929 — [`Self::recv`], with the priority the frame was sent at: a
    /// writer that reports back what it wrote can say which sender's frame it
    /// was, even when the lanes are one.
    pub async fn recv_tagged(&mut self) -> Option<(Priority, Vec<u8>)> {
        self.recv_wire_tagged()
            .await
            .map(|(priority, wire)| (priority, wire.into_vec()))
    }

    /// R3250 — [`Self::recv`] as the [`WireFrame`] the queue holds: on a pooled
    /// queue, a slot of the link's transmit pool armed for the write, which the
    /// writer starts, writes and hands back ([`OutboundQueue::recycle_wire`]).
    pub async fn recv_wire(&mut self) -> Option<WireFrame> {
        self.recv_wire_tagged().await.map(|(_, wire)| wire)
    }

    /// R3250 — [`Self::recv_wire`], with the priority the frame was sent at (a
    /// batch's: the priority of the first frame in it).
    pub async fn recv_wire_tagged(&mut self) -> Option<(Priority, WireFrame)> {
        loop {
            let notified = self.shared.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut st = self.shared.state.lock().expect("outbound lanes poisoned");
                let (taken, freed) = st.take_next();
                let finished = matches!(taken, Taken::Empty) && (st.closed || st.senders == 0);
                drop(st);
                if freed {
                    self.shared.room.notify_all();
                }
                match taken {
                    Taken::Frame(priority, out) => return Some((priority, self.wire(out))),
                    Taken::Empty if finished => return None,
                    // Empty and not finished, or a lend in progress at the head
                    // of the highest lane: a send, a commit, an abort or the
                    // last sender's drop notifies.
                    _ => {}
                }
            }
            notified.await;
        }
    }

    /// The next frame if one is queued right now, highest priority first.
    pub fn try_recv(&mut self) -> Option<Vec<u8>> {
        self.try_recv_tagged().map(|(_, frame)| frame)
    }

    /// R2937 — [`Self::try_recv`], with the priority the frame was sent at.
    pub fn try_recv_tagged(&mut self) -> Option<(Priority, Vec<u8>)> {
        self.try_recv_wire_tagged()
            .map(|(priority, wire)| (priority, wire.into_vec()))
    }

    /// R3250 — [`Self::try_recv_tagged`] as the [`WireFrame`] the queue holds.
    pub fn try_recv_wire_tagged(&mut self) -> Option<(Priority, WireFrame)> {
        let (taken, freed) = self
            .shared
            .state
            .lock()
            .expect("outbound lanes poisoned")
            .take_next();
        if freed {
            self.shared.room.notify_all();
        }
        match taken {
            Taken::Frame(priority, out) => Some((priority, self.wire(out))),
            _ => None,
        }
    }

    /// The writer's handle on what [`LaneState::take_next`] took.
    fn wire(&self, out: Out) -> WireFrame {
        match out {
            Out::Heap(bytes) => WireFrame(Wire::Heap(bytes)),
            #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
            Out::Slot { idx, base, len } => WireFrame(Wire::Slot(SlotWire {
                home: Arc::clone(&self.shared),
                idx,
                base,
                len,
                started: false,
                written: false,
            })),
        }
    }

    /// Stop accepting frames; the ones already queued stay to be received.
    /// A sender waiting for room is told the queue is closed.
    pub fn close(&mut self) {
        self.shared
            .state
            .lock()
            .expect("outbound lanes poisoned")
            .closed = true;
        self.shared.room.notify_all();
    }
}

impl Drop for OutboundRx {
    fn drop(&mut self) {
        // `close`, without its poisoned-lock panic: a destructor that panics
        // while a test unwinds aborts the process.
        if let Ok(mut st) = self.shared.state.lock() {
            st.closed = true;
        }
        self.shared.room.notify_all();
        // R3250 — nothing will write what is still queued, so a pooled queue's
        // slots go home now rather than when the last sender lets go: a closing
        // connection returns its slots.
        #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
        {
            if let Ok(mut st) = self.shared.state.lock() {
                st.release_unwritten();
            }
            self.shared.room.notify_all();
        }
    }
}

/// R3250 — what the writer is handed: a frame (or, on a pooled queue, a run of
/// frames packed into one slot), readable as bytes.
///
/// A heap queue hands over the vector the sender enqueued, as it always did. A
/// pooled queue hands over a SLOT of the link's transmit pool, armed for the
/// write: [`Self::begin_write`] starts it, and the slot goes home through the
/// generated pool's completion edge when the frame is handed back with
/// [`OutboundQueue::recycle_wire`] or dropped, so no path out of a writer can
/// keep it.
pub struct WireFrame(Wire);

enum Wire {
    Heap(Vec<u8>),
    #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
    Slot(SlotWire),
}

impl WireFrame {
    /// The frame as an owned vector: the vector itself for a heap frame, a copy
    /// of the slot's bytes for a pooled one (whose slot then goes home as a
    /// write that never began). For a reader that needs ownership, which no
    /// production writer of a pooled queue is.
    pub fn into_vec(self) -> Vec<u8> {
        match self.0 {
            Wire::Heap(bytes) => bytes,
            #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
            Wire::Slot(slot) => slot.as_bytes().to_vec(),
        }
    }

    /// Whether the bytes lie in a slot of the link's transmit pool.
    pub fn is_pooled(&self) -> bool {
        !matches!(self.0, Wire::Heap(_))
    }

    /// The slot of the link's transmit pool the bytes lie in, if they do.
    pub fn slot_index(&self) -> Option<usize> {
        match &self.0 {
            Wire::Heap(_) => None,
            #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
            Wire::Slot(slot) => Some(slot.idx),
        }
    }

    /// The writer is about to write this frame: a pooled slot moves from armed
    /// to busy. Idempotent, and a no-op for a heap frame.
    pub fn begin_write(&mut self) {
        #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
        if let Wire::Slot(slot) = &mut self.0 {
            slot.begin();
        }
    }
}

impl std::ops::Deref for WireFrame {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match &self.0 {
            Wire::Heap(bytes) => bytes,
            #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
            Wire::Slot(slot) => slot.as_bytes(),
        }
    }
}

impl AsRef<[u8]> for WireFrame {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl From<Vec<u8>> for WireFrame {
    fn from(bytes: Vec<u8>) -> Self {
        Self(Wire::Heap(bytes))
    }
}

impl std::fmt::Debug for WireFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireFrame")
            .field("pooled", &self.is_pooled())
            .field("bytes", &&self[..])
            .finish()
    }
}

impl PartialEq for WireFrame {
    fn eq(&self, other: &Self) -> bool {
        self[..] == other[..]
    }
}

impl PartialEq<[u8]> for WireFrame {
    fn eq(&self, other: &[u8]) -> bool {
        self[..] == *other
    }
}

impl PartialEq<Vec<u8>> for WireFrame {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self[..] == other[..]
    }
}

impl<const N: usize> PartialEq<[u8; N]> for WireFrame {
    fn eq(&self, other: &[u8; N]) -> bool {
        self[..] == other[..]
    }
}

/// R3250 — one slot of a pooled queue, in the writer's hands.
///
/// Armed when the writer took it off its lane; busy once [`Self::begin`] ran.
/// Its `Drop` is the way home in every case, by the edge the state names: a
/// busy slot's write has ended (written, failed, or the writer was stopped in
/// it), so it takes the completion edge; an armed one was never started, so it
/// is un-armed and returned. Holding the queue's shared state is what keeps the
/// pool, and so the slot's bytes, alive while the writer reads them.
#[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
struct SlotWire {
    home: Arc<Lanes>,
    idx: usize,
    /// First byte of the slot, by the pool's own answer for an armed slot.
    base: usize,
    len: usize,
    started: bool,
    /// The write ended with every byte written (`recycle_wire`), as opposed to
    /// a failed or abandoned one; only the counters read it.
    written: bool,
}

#[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
impl SlotWire {
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: `base` is the first byte of a slot of the pool `home` owns,
        // which stays boxed and alive while `home` is held; `len` bytes of it
        // were written by the lane before the writer took it (armed), and an
        // armed or busy slot has no writer on the CPU side, so a shared view of
        // it is sound for as long as this handle lives.
        unsafe { std::slice::from_raw_parts(self.base as *const u8, self.len) }
    }

    fn begin(&mut self) {
        if self.started {
            return;
        }
        let started = {
            let mut st = self.home.state.lock().expect("outbound lanes poisoned");
            st.pool.as_mut().map(|pool| pool.start(self.idx))
        };
        self.started = started == Some(true);
        // With the lock released, for the reason `Drop` gives.
        debug_assert!(started != Some(false), "the slot the writer took is armed");
    }
}

#[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
impl Drop for SlotWire {
    fn drop(&mut self) {
        // A poisoned lock forfeits the slot, as `LinkRxFrame` forfeits one: the
        // code under this lock does bookkeeping that cannot panic, so poisoning
        // means a thread died where a destructor cannot repair it.
        let home = {
            let Ok(mut st) = self.home.state.lock() else {
                return;
            };
            match st.pool.as_mut() {
                Some(pool) if self.started => pool.complete(self.idx, self.written),
                Some(pool) => pool.unarm(self.idx),
                None => true,
            }
        };
        // A freed slot is room: a sender waiting for one may go on.
        self.home.room.notify_all();
        // Checked with the lock released, so a failed check does not poison the
        // queue for every other holder, and not while unwinding, where a second
        // panic in a destructor aborts the process and hides which test failed.
        debug_assert!(
            home || std::thread::panicking(),
            "a slot in the writer's hands goes home once"
        );
    }
}

/// Bound on a SINGLE outbound write once the queue is sealed — the wedged-peer
/// defence that the wall-clock drain budget used to provide, at the one place
/// that can distinguish "the peer is not reading" from "the drain is taking a
/// while".
///
/// It has to outlast a LEGITIMATE peer-side stall, because a peer that is merely
/// slow must still be delivered to: a subscriber callback that blocks its drive
/// task stops the peer reading, fills its receive buffer, fills this side's send
/// buffer behind it, and blocks the write for as long as the callback runs. The
/// `wz-capi-pico` teardown fixture reproduces exactly that with a 200 ms
/// callback, so the bound carries an order of magnitude over it rather than a
/// margin that a loaded CI host can eat.
///
/// Note the granularity is one `write_all`, not one byte: bounding partial
/// writes instead would buy nothing here, because a peer that is not reading
/// stalls a one-byte write exactly as long as a whole-frame one.
pub const WRITER_STALL_MS: u64 = 2_000;

/// The receiving half of a writer's outbound channel, plus the seal that ends
/// it. Constructed by [`WriterHandle::spawn`] and consumed by a writer task.
pub struct OutboundQueue {
    rx: OutboundRx,
    /// `None` once the queue has been sealed — by an explicit
    /// [`WriterHandle::drain`], or by the handle being DROPPED, which R2367
    /// made the same signal. See [`WriterHandle`] for why the two had to
    /// converge once the writer stopped living on its owner's runtime.
    seal: Option<watch::Receiver<bool>>,
    sealed: bool,
}

impl OutboundQueue {
    /// The writer is done with `frame`, which it has written out: keep its buffer
    /// to be lent again (see [`OutboundRx::recycle`]).
    pub fn recycle(&self, frame: Vec<u8>) {
        self.rx.recycle(frame);
    }

    /// R3250 — the writer has written `wire` out: a heap frame's buffer is kept
    /// to be lent again ([`Self::recycle`]); a pooled frame's slot goes home
    /// through the completion edge, counted as written.
    pub fn recycle_wire(&self, wire: WireFrame) {
        match wire.0 {
            Wire::Heap(bytes) => self.rx.recycle(bytes),
            #[cfg(all(feature = "runtime-zero-copy", feature = "transport-link-tcp"))]
            Wire::Slot(mut slot) => slot.written = true,
        }
    }

    /// Take the next frame, or `None` once the queue is finished.
    ///
    /// Before the seal this is the plain channel receive. After it, the channel
    /// is closed, so the remaining frames are handed over and then `None`
    /// arrives — deterministically, with no dependence on who still holds a
    /// sender.
    pub async fn next(&mut self) -> Option<Vec<u8>> {
        self.next_wire().await.map(WireFrame::into_vec)
    }

    /// R3250 — [`Self::next`] as the [`WireFrame`] the queue holds, which is
    /// what a writer of a pooled queue takes: it starts the frame
    /// ([`WireFrame::begin_write`]), writes it, and hands it back
    /// ([`Self::recycle_wire`]) or drops it.
    pub async fn next_wire(&mut self) -> Option<WireFrame> {
        loop {
            if self.sealed || self.seal.is_none() {
                return self.rx.recv_wire().await;
            }
            let seal = self.seal.as_mut().expect("checked directly above");
            let mut sealed_now = false;
            let frame = tokio::select! {
                biased;
                frame = self.rx.recv_wire() => Some(frame),
                changed = seal.changed() => {
                    sealed_now = match changed {
                        Ok(()) => *seal.borrow_and_update(),
                        // The handle is GONE, so no one can ever seal this
                        // queue: its disappearance IS the seal (R2367).
                        Err(_) => true,
                    };
                    None
                }
            };
            if let Some(frame) = frame {
                return frame;
            }
            if sealed_now {
                self.apply_seal();
            }
        }
    }

    /// Run ONE outbound write under the teardown bound.
    ///
    /// Steady state is an unbounded await — the peer's backpressure is the flow
    /// control there, and a bound would drop frames a caller was told were sent.
    /// Once the queue is sealed the write is bounded by [`WRITER_STALL_MS`]. The
    /// seal is watched CONCURRENTLY with the write rather than checked before
    /// it, so a write already blocked on a wedged peer when teardown lands still
    /// gets the bound armed under it; checking first would leave exactly that
    /// write unbounded, which is the one that hangs.
    ///
    /// `None` means the bound expired. Callers end the writer on it rather than
    /// moving to the next frame: a wedged peer does not un-wedge for frame N+1,
    /// and retrying would multiply one bound by the queue depth.
    pub async fn guarded<F>(&mut self, write: F) -> Option<F::Output>
    where
        F: Future,
    {
        tokio::pin!(write);
        while !self.sealed {
            let Some(seal) = self.seal.as_mut() else {
                return Some(write.await);
            };
            let mut sealed_now = false;
            let out = tokio::select! {
                biased;
                out = &mut write => Some(out),
                changed = seal.changed() => {
                    sealed_now = match changed {
                        Ok(()) => *seal.borrow_and_update(),
                        // Same as `next`: a vanished handle seals (R2367), so
                        // the wedged-peer bound arms here too.
                        Err(_) => true,
                    };
                    None
                }
            };
            if let Some(out) = out {
                return Some(out);
            }
            if sealed_now {
                self.apply_seal();
            }
        }
        timeout(Duration::from_millis(WRITER_STALL_MS), write)
            .await
            .ok()
    }

    /// Whether the queue has been sealed — true once teardown has asked the
    /// writer to finish what it holds and exit.
    pub fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// Close the receiving half: no further enqueue can land, so what is already
    /// buffered is a FINITE set the writer can drain to the end. Already-sent
    /// frames survive `close` — that is what makes this "finish the queue" and
    /// not "drop the queue".
    fn apply_seal(&mut self) {
        self.sealed = true;
        self.seal = None;
        self.rx.close();
    }
}

/// A spawned writer task's lifecycle handle: the join handle, plus the seal that
/// lets teardown end the task without depending on sender liveness.
///
/// Dropping it SEALS the queue (R2367): the writer finishes what is already
/// buffered and exits. It is therefore the RAII form of [`Self::drain`] — the
/// same terminal meaning, without the await.
///
/// It used to DETACH instead, falling back to sender liveness, and that was
/// defensible only while [`Self::spawn`] used the ambient runtime: the writer
/// then died with its owner's runtime whatever the senders did, so "detach" had
/// a floor under it. R2366 moved every writer onto the process-wide
/// [`WzRuntime::Tx`] subsystem and removed that floor without noticing —
/// a detached writer now outlives its owner's runtime, and an outstanding sender
/// clone pins it FOREVER, holding the link's write half open. The socket then
/// never closes, so the peer never sees the FIN that tells it the session is
/// gone: measured as `a_vanishing_peer_is_purged_from_the_matching_aggregate`
/// going red, where a peer that had vanished was still credited with a matching
/// subscriber on the far side.
///
/// zenoh reaches the same conclusion at the same seam and for the same reason.
/// Its `tx_task` also runs on a process-wide transmit runtime
/// (`io/zenoh-transport/src/unicast/universal/link.rs`
/// @ `ZRuntime::TX.spawn(async move {`), and link close terminates it EXPLICITLY
/// through a cancellation token rather than by letting a runtime fall
/// (`io/zenoh-transport/src/unicast/universal/link.rs`
/// @ `self.task_controller.terminate_all_async().await;`). A shared TX pool and
/// an implicit close signal do not go together in either implementation.
pub struct WriterHandle {
    join: TokioJoinHandle<()>,
    seal: watch::Sender<bool>,
}

impl WriterHandle {
    /// Wire an outbound channel's receiving half into a sealable queue, spawn
    /// `task` over it, and return the handle that owns both ends of teardown.
    ///
    /// Taking the receiver rather than a ready-made queue is deliberate: it
    /// makes this the only route from a channel to a running writer, so a
    /// pipeline cannot end up with a task no one can seal.
    ///
    /// The writer lands on the TRANSMIT subsystem
    /// ([`WzRuntime::Tx`](crate::runtime_pool::WzRuntime)), which is what makes
    /// this one call the whole of wz's TX partition: every stream and datagram
    /// pipeline reaches its writer through here, so an operator lowering
    /// `tx:worker_threads` narrows all ten of them at once. zenoh names the same
    /// subsystem at the same seam — `ZRuntime::TX.spawn` around the unicast
    /// `tx_task` (`io/zenoh-transport/src/unicast/universal/link.rs`
    /// @ `ZRuntime::TX.spawn(async move {`) and around the multicast one
    /// (`io/zenoh-transport/src/multicast/link.rs`
    /// @ `ZRuntime::TX.spawn(async move {`).
    pub fn spawn<F, Fut>(rx: OutboundRx, task: F) -> Self
    where
        F: FnOnce(OutboundQueue) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self::spawn_on(WzRuntime::Tx.handle().clone(), rx, task)
    }

    /// [`Self::spawn`] onto a NAMED tokio runtime rather than the TX subsystem.
    ///
    /// The general form, and the escape a caller needs when the writer must
    /// share a runtime with whoever is observing it. That is not a niche:
    /// tokio's paused clock is per-runtime, so a test that advances time and a
    /// writer on another runtime are measuring two different clocks — the
    /// [`WRITER_STALL_MS`] bound would then be spent in real seconds while the
    /// test believes it moved instantly. A host embedding wz inside its own
    /// reactor has the same need for the same reason.
    pub fn spawn_on<F, Fut>(handle: tokio::runtime::Handle, rx: OutboundRx, task: F) -> Self
    where
        F: FnOnce(OutboundQueue) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (seal, seal_rx) = watch::channel(false);
        let queue = OutboundQueue {
            rx,
            seal: Some(seal_rx),
            sealed: false,
        };
        WriterHandle {
            join: TokioJoinHandle::from_tokio(handle.spawn(task(queue))),
            seal,
        }
    }

    /// Terminal drain: seal the queue, then await the writer to COMPLETION.
    ///
    /// The await is unbounded on purpose and is safe to be: the seal makes the
    /// queue finite and [`OutboundQueue::guarded`] bounds the one write a wedged
    /// peer can stall on, so the task terminates in bounded time without a
    /// wall-clock budget that would cut a writer still making progress.
    pub async fn drain(self) {
        let _ = self.seal.send(true);
        let _ = self.join.await;
    }

    /// Abort the writer where it stands, dropping whatever it still holds. The
    /// deliberate opposite of [`Self::drain`] — for callers tearing down a
    /// session whose link is already gone.
    pub fn abort(&self) {
        self.join.abort();
    }

    /// Release the join handle alone, dropping the seal — which, since R2367,
    /// seals the queue. For callers that have already released every sender and
    /// want the raw join: there the queue is finite either way, so this stays
    /// the await-the-tail form of [`Self::drain`] rather than a weaker one.
    pub fn into_join(self) -> TokioJoinHandle<()> {
        self.join
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A buffer of exactly `capacity` bytes, its address recorded by the caller.
    fn buffer_of(capacity: usize) -> Vec<u8> {
        let mut b = Vec::with_capacity(capacity);
        b.extend_from_slice(b"stale frame bytes");
        b
    }

    /// ARCHITECTURE section 9.1 — a buffer the writer is done with is the next
    /// one lent, emptied, so a link in steady state builds its frames in memory it
    /// already has.
    #[test]
    fn a_recycled_buffer_is_lent_again_emptied() {
        let (tx, rx) = outbound_channel();
        let mut b = tx.take_buffer(100);
        b.extend_from_slice(b"the previous frame");
        let at = b.as_ptr();
        rx.recycle(b);
        let again = tx.take_buffer(100);
        assert_eq!(again.as_ptr(), at, "the buffer comes back, not a new one");
        assert!(
            again.is_empty(),
            "and the old bytes are not the next frame's"
        );
        assert!(again.capacity() >= 100);
    }

    /// The pool is bounded in count, so a burst cannot make a link hoard buffers.
    #[test]
    fn the_spare_pool_keeps_no_more_than_its_bound() {
        let (tx, rx) = outbound_channel();
        // Measured on the pool itself: comparing addresses would be fooled by the
        // allocator handing a freed buffer's address to the next allocation.
        let held: Vec<Vec<u8>> = (0..SPARE_MAX + 3).map(|_| tx.take_buffer(64)).collect();
        assert_eq!(tx.spare_count(), 0, "CONTROL: nothing kept yet");
        for (i, b) in held.into_iter().enumerate() {
            rx.recycle(b);
            assert_eq!(
                tx.spare_count(),
                (i + 1).min(SPARE_MAX),
                "after {} given",
                i + 1
            );
        }
    }

    /// A buffer past the size bound is freed, not kept: a rare large frame must not
    /// pin its memory for the life of the link.
    #[test]
    fn a_buffer_past_the_size_bound_is_not_kept() {
        let (tx, rx) = outbound_channel();
        rx.recycle(buffer_of(SPARE_CAPACITY_MAX + 1));
        assert_eq!(tx.shared.state.lock().expect("lanes").spare.len(), 0);
        rx.recycle(buffer_of(SPARE_CAPACITY_MAX));
        assert_eq!(
            tx.shared.state.lock().expect("lanes").spare.len(),
            1,
            "CONTROL: one at the bound is kept"
        );
    }

    /// The smallest buffer that fits is the one lent, so a small frame does not
    /// take the large buffer a large frame needs.
    #[test]
    fn the_smallest_buffer_that_fits_is_lent() {
        let (tx, rx) = outbound_channel();
        let (small, large) = (buffer_of(1000), buffer_of(4000));
        let (small_at, large_at) = (small.as_ptr(), large.as_ptr());
        rx.recycle(large);
        rx.recycle(small);
        // Each taken buffer is HELD, so the next take cannot be handed the same
        // address back by the allocator and pass for a recycled one.
        let first = tx.take_buffer(500);
        assert_eq!(first.as_ptr(), small_at, "the smaller one that fits");
        let second = tx.take_buffer(500);
        assert_eq!(second.as_ptr(), large_at, "the other, next");
        let third = tx.take_buffer(500);
        assert!(third.capacity() >= 500, "and a fresh one when none is kept");
        assert!(third.as_ptr() != small_at && third.as_ptr() != large_at);
    }

    /// R2952 (open-debt item 835) — the block-first slot: one per priority;
    /// a second ask at the same priority waits its full `wait_us` and is
    /// refused, another priority is free, and a release wakes a waiter.
    #[test]
    fn the_block_first_slot_is_one_per_priority_and_a_release_wakes_a_waiter() {
        let (tx, _rx) = outbound_channel();
        assert!(tx.block_first_acquire(Priority::Data, 0));
        let started = Instant::now();
        assert!(
            !tx.block_first_acquire(Priority::Data, 20_000),
            "the slot is taken, so the ask runs out"
        );
        assert!(
            started.elapsed() >= Duration::from_millis(20),
            "and it waited"
        );
        assert!(
            tx.block_first_acquire(Priority::RealTime, 0),
            "another priority has its own slot"
        );

        let waiter = tx.clone();
        let handle =
            std::thread::spawn(move || waiter.block_first_acquire(Priority::Data, 2_000_000));
        std::thread::sleep(Duration::from_millis(20));
        tx.block_first_release(Priority::Data);
        assert!(
            handle.join().expect("waiter"),
            "the release woke it and it took the slot"
        );
    }

    /// R3052 -- THE ORDER A HANDSHAKE MESSAGE'S LANE IS CHOSEN FOR. The `Control`
    /// lane leaves before any other lane however late its frame was queued, and a
    /// lane is FIFO. So an OpenAck queued on `Control` leaves before a Declare
    /// queued on `Control` after it, and before everything else; the same OpenAck on
    /// `Data` leaves AFTER a Declare queued on `Control` behind it, which is the
    /// overtaking a C subscriber replaying its declarations lost one connection in
    /// twenty to. The second half is the control: it shows the lanes DO reorder, so
    /// the first half is the lane choice doing its work and not a queue that never
    /// reorders anything.
    #[test]
    fn the_control_lane_leaves_first_and_a_lane_is_fifo() {
        let drain = |lane_of_the_ack: Priority| {
            let (tx, mut rx) = outbound_channel();
            tx.send(lane_of_the_ack, b"OpenAck".to_vec())
                .expect("queue the OpenAck");
            tx.send(Priority::Control, b"Declare".to_vec())
                .expect("queue the Declare");
            let mut order = Vec::new();
            while let Some(frame) = rx.try_recv() {
                order.push(String::from_utf8(frame).expect("ascii"));
            }
            order
        };
        assert_eq!(
            drain(Priority::Control),
            ["OpenAck", "Declare"],
            "one lane is FIFO, and the OpenAck was queued first"
        );
        assert_eq!(
            drain(Priority::Data),
            ["Declare", "OpenAck"],
            "a lower lane leaves after a Control frame queued behind it"
        );
    }

    /// The seal ends the writer even though a sender clone is still ALIVE.
    ///
    /// This is the accept-path shape in miniature: the routing registry holds a
    /// `TokioSession`, hence a clone of the outbound sender, past the drain. Under
    /// the pre-R311y519 close signal (sender liveness) the drain could only ever
    /// end on its wall clock; here it ends because the queue was sealed, and the
    /// surviving sender is held to the end of the test to prove it.
    #[tokio::test]
    async fn a_seal_ends_the_writer_while_a_sender_clone_survives() {
        let (tx, rx) = outbound_channel();
        let seen = Arc::new(AtomicUsize::new(0));
        let seen_task = seen.clone();
        let handle = WriterHandle::spawn(rx, move |mut queue| async move {
            while let Some(frame) = queue.next().await {
                seen_task.fetch_add(frame.len(), Ordering::SeqCst);
            }
        });

        tx.send(Priority::DEFAULT, vec![0u8; 3]).expect("enqueue");
        tx.send(Priority::DEFAULT, vec![0u8; 4]).expect("enqueue");

        // The clone that the drain cannot make go away.
        let survivor = tx.clone();
        handle.drain().await;

        assert_eq!(
            seen.load(Ordering::SeqCst),
            7,
            "the sealed writer must hand over every frame that was already queued"
        );
        assert!(
            survivor.send(Priority::DEFAULT, vec![0u8; 5]).is_err(),
            "the seal must CLOSE the channel, so a surviving sender cannot enqueue \
             behind the drain"
        );
        drop(tx);
    }

    /// R2367 — DROPPING the handle ends the writer while a sender clone
    /// survives, exactly as [`WriterHandle::drain`] does.
    ///
    /// The sibling above proves the EXPLICIT seal; this proves the implicit one,
    /// and the surviving sender is what makes them the same claim. Without it
    /// the writer would wait on sender liveness, and since R2366 put every
    /// writer on the process-wide TX subsystem that wait no longer has a
    /// runtime-shaped floor under it — the task would hold the link's write half
    /// for the life of the PROCESS, so the socket never closes and the peer
    /// never learns the session is gone.
    ///
    /// The assertion is the task's own exit, observed through the join handle:
    /// `into_join` releases the seal (which is the drop under test) and hands
    /// back the tail to await.
    ///
    /// That await is BOUNDED, and the bound is the reason this reads as a test
    /// rather than as a hang. Measured with the pre-R2367 detach restored, the
    /// unbounded form did not fail — it stopped, because "the writer never ends"
    /// has no timeout of its own, and a control probe whose red is a job-level
    /// timeout costs the run its budget instead of naming the defect. The bound
    /// is orders of magnitude over a drain of two queued frames, so it can only
    /// expire on the property this test is about.
    #[tokio::test]
    async fn dropping_the_handle_ends_the_writer_while_a_sender_clone_survives() {
        let (tx, rx) = outbound_channel();
        let seen = Arc::new(AtomicUsize::new(0));
        let seen_task = seen.clone();
        let handle = WriterHandle::spawn(rx, move |mut queue| async move {
            while let Some(frame) = queue.next().await {
                seen_task.fetch_add(frame.len(), Ordering::SeqCst);
            }
        });

        tx.send(Priority::DEFAULT, vec![0u8; 3]).expect("enqueue");
        tx.send(Priority::DEFAULT, vec![0u8; 4]).expect("enqueue");

        // Held to the END of the test: it is the whole point that the writer
        // ends anyway. A `drop(tx)` before the await would prove nothing.
        let survivor = tx.clone();

        // The drop under test, and then the tail.
        let join = handle.into_join();
        timeout(Duration::from_millis(WRITER_STALL_MS), join)
            .await
            .expect(
                "a dropped handle must END the writer; without the seal it waits on the \
                 surviving sender forever, holding the link's write half open for the \
                 life of the process",
            )
            .expect("the writer task itself must not panic");

        assert_eq!(
            seen.load(Ordering::SeqCst),
            7,
            "a dropped handle must SEAL — finish the queue — not discard it"
        );
        assert!(
            survivor.send(Priority::DEFAULT, vec![0u8; 5]).is_err(),
            "the dropped handle must close the channel, so a surviving sender \
             cannot enqueue behind a writer that has already exited"
        );
        drop(tx);
    }

    /// A write that is already blocked when the seal lands is bounded, not left
    /// to hang — the wedged-peer case the wall-clock budget used to cover.
    ///
    /// The bound is exercised through a pending-forever future, so the test
    /// measures the arming of the bound rather than a real socket.
    ///
    /// [`WriterHandle::spawn_on`] with THIS runtime's handle, not
    /// [`WriterHandle::spawn`]: the paused clock belongs to the test's runtime,
    /// and a writer on the TX subsystem would spend the bound in two real
    /// seconds of wall clock while `start_paused` reported instants.
    #[tokio::test(start_paused = true)]
    async fn a_write_in_flight_when_the_seal_lands_is_bounded() {
        let (tx, rx) = outbound_channel();
        let bailed = Arc::new(AtomicUsize::new(0));
        let bailed_task = bailed.clone();
        let handle = WriterHandle::spawn_on(
            tokio::runtime::Handle::current(),
            rx,
            move |mut queue| async move {
                while let Some(_frame) = queue.next().await {
                    if queue.guarded(std::future::pending::<()>()).await.is_none() {
                        bailed_task.fetch_add(1, Ordering::SeqCst);
                        return;
                    }
                }
            },
        );

        tx.send(Priority::DEFAULT, vec![0u8; 1]).expect("enqueue");
        // Let the writer reach the wedged write before teardown lands.
        tokio::task::yield_now().await;
        handle.drain().await;

        assert_eq!(
            bailed.load(Ordering::SeqCst),
            1,
            "a write still in flight at seal time must inherit the {WRITER_STALL_MS} ms \
             bound; without it the drain's unbounded await never returns"
        );
    }

    /// [`WriterHandle::into_join`] under its DOCUMENTED precondition — every
    /// sender released — hands over what was already queued and joins.
    ///
    /// R2367 rewrote this test twice over. It used to assert that releasing the
    /// handle "leaves sender liveness as the close signal", which is the
    /// contract that same round removed; the outcome it checks is unchanged
    /// because with no sender left the two signals agree, but the claim in the
    /// name was no longer one this file makes.
    ///
    /// The enqueue also had to move ABOVE the release. It sat below, which was
    /// safe only while `spawn` used the ambient current-thread test runtime and
    /// the writer therefore could not run until the test awaited. R2366 put the
    /// writer on the multi-threaded TX subsystem, so it can now reach the seal's
    /// `rx.close()` before the test's next line — and the send would then fail
    /// its `expect`. That race was latent from R2366 and armed by this round's
    /// seal-on-drop; ordering the two removes it rather than widening a window.
    #[tokio::test]
    async fn a_released_handle_hands_over_what_was_already_queued() {
        let (tx, rx) = outbound_channel();
        let seen = Arc::new(AtomicUsize::new(0));
        let seen_task = seen.clone();
        let handle = WriterHandle::spawn(rx, move |mut queue| async move {
            while let Some(frame) = queue.next().await {
                seen_task.fetch_add(frame.len(), Ordering::SeqCst);
            }
        });

        tx.send(Priority::DEFAULT, vec![0u8; 2]).expect("enqueue");
        drop(tx);
        let join = handle.into_join();
        join.await
            .expect("the writer joins once the handle is released");

        assert_eq!(seen.load(Ordering::SeqCst), 2);
    }

    /// R2919 — frames already queued leave in strict ascending priority, not
    /// in arrival order: a RealTime frame enqueued behind a Background backlog
    /// overtakes it, and Control overtakes both (zenoh's consumer pulls the
    /// lowest non-empty priority queue first).
    #[tokio::test]
    async fn queued_frames_leave_highest_priority_first() {
        let (tx, mut rx) = outbound_channel();
        tx.send(Priority::Background, b"bg-1".to_vec())
            .expect("enqueue");
        tx.send(Priority::Background, b"bg-2".to_vec())
            .expect("enqueue");
        tx.send(Priority::Data, b"data".to_vec()).expect("enqueue");
        tx.send(Priority::RealTime, b"rt".to_vec())
            .expect("enqueue");
        tx.send(Priority::Control, b"ctl".to_vec())
            .expect("enqueue");
        drop(tx);

        let mut order = Vec::new();
        while let Some(frame) = rx.recv().await {
            order.push(String::from_utf8(frame).expect("ascii"));
        }
        assert_eq!(order, ["ctl", "rt", "data", "bg-1", "bg-2"]);
    }

    /// R2921 — a lane is bounded, the bound is its own, and a frame keeps its
    /// place in the bound until the writer asks for the next one (zenoh returns
    /// a batch to the pool only after writing it).
    /// A blocking message's request, waiting up to `wait`.
    fn block(wait: Duration) -> RoomWait {
        RoomWait::Block {
            wait_us: wait.as_micros() as u64,
        }
    }

    /// A droppable message's request, waiting up to `wait`.
    fn droppable(wait: Duration) -> RoomWait {
        RoomWait::Drop {
            wait_us: wait.as_micros() as u64,
        }
    }

    #[test]
    fn a_full_lane_has_room_again_only_once_its_frame_is_written() {
        let (tx, mut rx) = outbound_channel_with_capacity([1; Priority::NUM], 10);
        assert_eq!(
            tx.wait_for_room(Priority::Data, block(Duration::ZERO)),
            Room::Free
        );
        tx.send(Priority::Data, vec![0u8; 10]).expect("enqueue");
        assert_eq!(
            tx.wait_for_room(Priority::Data, block(Duration::ZERO)),
            Room::Congested,
            "the lane holds its whole bound"
        );
        assert_eq!(
            tx.wait_for_room(Priority::RealTime, block(Duration::ZERO)),
            Room::Free,
            "another lane's bound is its own"
        );
        assert!(rx.try_recv().is_some(), "the writer takes the frame");
        assert_eq!(
            tx.wait_for_room(Priority::Data, block(Duration::ZERO)),
            Room::Congested,
            "a frame being written still counts"
        );
        assert!(rx.try_recv().is_none(), "the writer asks for the next");
        assert_eq!(
            tx.wait_for_room(Priority::Data, block(Duration::ZERO)),
            Room::Free
        );
    }

    /// R2923 — once a wait on a lane runs out the lane is marked congested,
    /// and while the mark stands a DROPPABLE message is answered at once
    /// instead of spending its wait; a blocking one still waits. The writer
    /// freeing the lane lowers the mark (zenoh's `set_congested` / `refill`).
    #[test]
    fn a_congested_lane_answers_a_droppable_message_at_once_until_the_writer_frees_it() {
        let (tx, mut rx) = outbound_channel_with_capacity([1; Priority::NUM], 4);
        tx.send(Priority::Data, vec![1u8; 4]).expect("enqueue");
        assert_eq!(
            tx.wait_for_room(Priority::Data, droppable(Duration::from_millis(20))),
            Room::Congested,
            "the first droppable message waits its deadline out and finds none"
        );

        let started = Instant::now();
        assert_eq!(
            tx.wait_for_room(Priority::Data, droppable(Duration::from_secs(10))),
            Room::Congested
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a droppable message on a marked lane must not wait: it waited {:?}",
            started.elapsed()
        );
        assert_eq!(
            tx.wait_for_room(Priority::RealTime, droppable(Duration::ZERO)),
            Room::Free,
            "the mark is the lane's own"
        );

        let started = Instant::now();
        assert_eq!(
            tx.wait_for_room(Priority::Data, block(Duration::from_millis(30))),
            Room::Congested
        );
        assert!(
            started.elapsed() >= Duration::from_millis(30),
            "a blocking message waits whatever the mark says"
        );

        assert!(rx.try_recv().is_some(), "the writer takes the frame");
        assert!(
            rx.try_recv().is_none(),
            "and asks for the next: it is written"
        );
        assert_eq!(
            tx.wait_for_room(Priority::Data, droppable(Duration::ZERO)),
            Room::Free,
            "the freed lane is no longer marked"
        );
    }

    /// A sender waiting for room is woken by the writer freeing it, well inside
    /// its wait; one whose wait runs out is told the lane is congested; and
    /// one waiting when the queue closes is told so.
    #[test]
    fn a_waiting_sender_is_woken_by_room_and_released_by_its_deadline() {
        let (tx, mut rx) = outbound_channel_with_capacity([1; Priority::NUM], 4);
        tx.send(Priority::Data, vec![1u8; 4]).expect("enqueue");

        let started = Instant::now();
        assert_eq!(
            tx.wait_for_room(Priority::Data, block(Duration::from_millis(30))),
            Room::Congested
        );
        assert!(started.elapsed() >= Duration::from_millis(30), "it waited");

        let waiter = {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let started = Instant::now();
                let room = tx.wait_for_room(Priority::Data, block(Duration::from_secs(10)));
                (room, started.elapsed())
            })
        };
        std::thread::sleep(Duration::from_millis(20));
        assert!(rx.try_recv().is_some());
        assert!(
            rx.try_recv().is_none(),
            "the written frame leaves the bound"
        );
        let (room, waited) = waiter.join().expect("waiter");
        assert_eq!(room, Room::Free);
        assert!(waited < Duration::from_secs(5), "woken, not timed out");

        tx.send(Priority::Data, vec![1u8; 4]).expect("enqueue");
        let waiter = {
            let tx = tx.clone();
            std::thread::spawn(move || {
                tx.wait_for_room(Priority::Data, block(Duration::from_secs(10)))
            })
        };
        std::thread::sleep(Duration::from_millis(20));
        rx.close();
        assert_eq!(waiter.join().expect("waiter"), Room::Closed);
    }

    /// R2924 — a session that negotiated no QoS has ONE queue, as zenoh's
    /// non-QoS transport does: a keepalive at `Priority::Control` queued behind
    /// data leaves behind it, and every priority draws on the one bound, sized
    /// by the `Priority::DEFAULT` entry.
    #[test]
    fn a_non_qos_shape_is_one_fifo_queue_sized_by_the_default_priority() {
        use wz_session_core::link::TxQueueShape;
        let (tx, mut rx) = outbound_channel_with_capacity([4; Priority::NUM], 4);
        let mut sizes = [16; Priority::NUM];
        sizes[Priority::DEFAULT.wire_byte() as usize] = 1;
        tx.reshape(TxQueueShape {
            sizes,
            qos: false,
            batch_bytes: 4,
        });

        tx.send(Priority::DEFAULT, b"data".to_vec())
            .expect("enqueue");
        assert_eq!(
            tx.wait_for_room(Priority::Control, block(Duration::ZERO)),
            Room::Congested,
            "a Control frame draws on the one queue, which one batch fills"
        );
        tx.send(Priority::Control, b"ka".to_vec()).expect("enqueue");
        assert_eq!(rx.try_recv(), Some(b"data".to_vec()), "arrival order holds");
        assert_eq!(rx.try_recv(), Some(b"ka".to_vec()));
    }

    /// R2924 — a QoS shape bounds each priority by its own size. R2925 — in
    /// batches of the SHAPE's size, the link's negotiated MTU, not the size
    /// the channel was built with.
    #[test]
    fn a_qos_shape_bounds_each_priority_by_its_own_size() {
        use wz_session_core::link::TxQueueShape;
        let (tx, mut rx) = outbound_channel_with_capacity([1; Priority::NUM], 1_000);
        let mut sizes = [1; Priority::NUM];
        sizes[Priority::Data.wire_byte() as usize] = 3;
        tx.reshape(TxQueueShape {
            sizes,
            qos: true,
            batch_bytes: 4,
        });

        tx.send(Priority::RealTime, vec![0u8; 4]).expect("enqueue");
        tx.send(Priority::Data, vec![0u8; 4]).expect("enqueue");
        assert_eq!(
            tx.wait_for_room(Priority::RealTime, block(Duration::ZERO)),
            Room::Congested,
            "one batch fills a size-1 queue"
        );
        assert_eq!(
            tx.wait_for_room(Priority::Data, block(Duration::ZERO)),
            Room::Free,
            "a size-3 queue still has two"
        );
        assert_eq!(rx.try_recv(), Some(vec![0u8; 4]), "RealTime still first");
    }

    /// Within one priority the lane is FIFO: two conduits' frames minted in SN
    /// order at one priority must reach the wire in that order, or the peer's
    /// per-conduit SN gate drops the later-minted one as stale.
    #[tokio::test]
    async fn one_priority_lane_keeps_arrival_order() {
        let (tx, mut rx) = outbound_channel();
        for i in 0u8..5 {
            tx.send(Priority::Data, vec![i]).expect("enqueue");
        }
        assert_eq!(rx.try_recv(), Some(vec![0]));
        drop(tx);
        let mut rest = Vec::new();
        while let Some(frame) = rx.recv().await {
            rest.push(frame[0]);
        }
        assert_eq!(rest, [1, 2, 3, 4]);
    }
}
