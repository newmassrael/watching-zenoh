// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, LockResult, Mutex, MutexGuard, WaitTimeoutResult};
use std::time::{Duration, Instant};

use tokio::sync::{watch, Notify};
use tokio::time::timeout;
use wz_session_core::link::RoomWait;
use wz_session_core::qos::Priority;

use crate::runtime_impl::TokioJoinHandle;
use crate::runtime_pool::WzRuntime;

// R3239 — every pooled item below is gated on `runtime-zero-copy` alone: this
// module exists only where some link has a writer queue, and every such link
// owns a pool under the feature (a stream, the serial link, or a datagram link).
#[cfg(feature = "runtime-zero-copy")]
use crate::link_tx_pool::{TxPoolStats, TxPools, TxSlotState};

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
            urgent: VecDeque::new(),
            lanes: std::array::from_fn(|_| VecDeque::new()),
            capacity: queue_size.map(|n| n * batch_bytes),
            batch_bytes,
            single_lane: false,
            occupied: [0; Priority::NUM],
            reserved: [0; Priority::NUM],
            congested: [false; Priority::NUM],
            block_first: [false; Priority::NUM],
            in_flight: [None; Priority::NUM],
            closed: false,
            senders: 1,
            spare: Vec::new(),
            spare_keep_max: SPARE_CAPACITY_MAX,
            carry: None,
            #[cfg(feature = "runtime-zero-copy")]
            pool: None,
            #[cfg(feature = "runtime-zero-copy")]
            next_batch: 0,
            #[cfg(feature = "runtime-zero-copy")]
            receiver_gone: false,
        }),
        ready: Notify::new(),
        frame_ready: Notify::new(),
        room: RoomSignal::new(),
        idle_hook: Mutex::new(None),
        flush_wanted: AtomicBool::new(false),
        staged: AtomicU64::new(0),
        staged_at_flush: AtomicU64::new(0),
        epoch: Instant::now(),
        last_flush_ns: AtomicU64::new(NEVER_FLUSHED),
        last_write_ns: AtomicU64::new(NEVER_FLUSHED),
        inline: std::sync::OnceLock::new(),
        role: AtomicBool::new(false),
    });
    (
        OutboundTx {
            shared: shared.clone(),
        },
        OutboundRx { shared },
    )
}

/// R3239 — [`outbound_channel`] over the link's own TRANSMIT POOL
/// (`sources/network/session_tx_pool_ap.scxml`), ARCHITECTURE section 9.1, for a
/// BYTE-STREAM link (and the serial link): every frame a sender hands this
/// queue, lent or copied, lies in a slot of the pool until the writer has
/// written it, packed behind the frames before it, so the transmit path
/// allocates nothing per frame, in a burst, or for a frame of any size a stream
/// link can carry.
///
/// The lanes, their byte bounds, their priority order and their congestion
/// marks are [`outbound_channel`]'s, unchanged; the pool adds one condition to
/// "room" (a free slot) and is back-pressure when it is dry. The pool is
/// allocated once here, zeroed, about 1 MiB of address space per link.
#[cfg(feature = "runtime-zero-copy")]
pub fn outbound_channel_pooled() -> (OutboundTx, OutboundRx) {
    outbound_channel_pooled_with_capacity([DEFAULT_QUEUE_SIZE; Priority::NUM], BATCH_BYTES)
}

/// R3239 — [`outbound_channel_pooled`] with each lane's bound, as
/// [`outbound_channel_with_capacity`].
#[cfg(feature = "runtime-zero-copy")]
pub fn outbound_channel_pooled_with_capacity(
    queue_size: [usize; Priority::NUM],
    batch_bytes: usize,
) -> (OutboundTx, OutboundRx) {
    with_pools(
        outbound_channel_with_capacity(queue_size, batch_bytes),
        TxPools::stream(),
    )
}

/// R3240 — [`outbound_channel_pooled`] for a DATAGRAM link (UDP, QUIC
/// datagram, websocket, multicast): a datagram is its own boundary, so a slot
/// carries ONE frame and nothing is packed, and the pool has two size classes
/// (`session_tx_pool_ap_small` for the datagrams the sessions send,
/// `session_tx_pool_ap` for the rest). Each class's per-link slot BUDGET follows
/// the queue's shape, which follows the configuration
/// (`link_tx_pool::TxPools::size_budgets`), so it is re-derived whenever the
/// session shapes the queue ([`OutboundTx::reshape`]).
#[cfg(feature = "runtime-zero-copy")]
pub fn outbound_channel_datagram() -> (OutboundTx, OutboundRx) {
    outbound_channel_datagram_with_capacity([DEFAULT_QUEUE_SIZE; Priority::NUM], BATCH_BYTES)
}

/// R3240 — the queue every DATAGRAM write half builds: [`outbound_channel_datagram`]
/// under `runtime-zero-copy`, the heap [`outbound_channel`] otherwise. One
/// constructor, so a datagram pipeline cannot pick the wrong one.
pub fn datagram_outbound_channel() -> (OutboundTx, OutboundRx) {
    #[cfg(feature = "runtime-zero-copy")]
    {
        outbound_channel_datagram()
    }
    #[cfg(not(feature = "runtime-zero-copy"))]
    {
        outbound_channel()
    }
}

/// R3240 — [`outbound_channel_datagram`] with each lane's bound.
#[cfg(feature = "runtime-zero-copy")]
pub fn outbound_channel_datagram_with_capacity(
    queue_size: [usize; Priority::NUM],
    batch_bytes: usize,
) -> (OutboundTx, OutboundRx) {
    with_pools(
        outbound_channel_with_capacity(queue_size, batch_bytes),
        TxPools::datagram(),
    )
}

/// Give a fresh queue its pool, budgets sized from its lanes.
#[cfg(feature = "runtime-zero-copy")]
fn with_pools(channel: (OutboundTx, OutboundRx), pools: TxPools) -> (OutboundTx, OutboundRx) {
    {
        let mut st = channel
            .0
            .shared
            .state
            .lock()
            .expect("outbound lanes poisoned");
        st.pool = Some(pools);
        st.size_budgets();
    }
    channel
}

struct Lanes {
    state: Mutex<LaneState>,
    /// Wakes the (single) writer when a frame lands or the last sender goes.
    ready: Notify,
    /// Wakes the writer ONLY for a frame that landed, which is what it waits for while it
    /// lets producers finish (see `let_producers_finish`): `ready` also carries the request
    /// to flush what is staged, which is the very thing that wait is for putting off.
    frame_ready: Notify,
    /// Wakes senders waiting for room when the writer frees some, or the
    /// queue closes.
    room: RoomSignal,
    /// What the writer runs when it has nothing to write and is about to wait: the
    /// session's flush of the batch frames it has staged
    /// ([`OutboundTx::set_idle_hook`]).
    idle_hook: Mutex<Option<IdleHook>>,
    /// A sender staged something the hook would flush and has said so
    /// ([`OutboundTx::wake_for_flush`]); the writer clears it just before it runs the
    /// hook. It is what keeps the wake to one per idle spell and not one per message.
    flush_wanted: AtomicBool,
    /// How many messages senders have staged for the hook to flush, ever
    /// ([`OutboundTx::wake_for_flush`] counts each). The writer reads it twice a few
    /// microseconds apart to tell producers that are still adding from producers that
    /// have stopped, which is zenoh's batching backoff
    /// (`io/zenoh-transport/src/common/pipeline.rs` @ `fn try_pull_deep(`: pull once
    /// "no new bytes have been written on the batch").
    staged: AtomicU64,
    /// What [`Self::staged`] stood at when the writer last came to flush: the writer's alone.
    /// The difference at the next flush is how many messages the producers staged in between,
    /// which is what tells a stream from a lone message.
    staged_at_flush: AtomicU64,
    /// The instant this queue was made, which `last_flush_ns` counts from.
    epoch: Instant,
    /// When the last flush ran, in nanoseconds from `epoch`: the writer's or a sender's own.
    /// A sender flushes its own message only when the link has been quiet for a while, which is
    /// what a request and its reply are and a stream is not: a stream's messages come faster
    /// than a flush can be written, and a flush per message would turn them into a system
    /// call each, where the writer coalesces them.
    last_flush_ns: AtomicU64,
    /// When a write of this queue's frames last finished, in nanoseconds from `epoch`:
    /// the writer's or an inline sender's, [`NEVER_FLUSHED`] before the first. The keepalive
    /// emitter reads it, because the line has spoken when bytes left and not when a frame was
    /// queued ([`OutboundTx::ms_since_wire_write`]).
    last_write_ns: AtomicU64,
    /// How a thread other than the writer puts bytes on the link, when the link has a way
    /// ([`OutboundTx::set_inline_write`]). Set once, before the first frame.
    inline: std::sync::OnceLock<Arc<dyn InlineWrite>>,
    /// The right to take frames off the lanes and write them to the link. One thread holds
    /// it from the take to the end of the write, so what one thread takes is written before
    /// what another takes after it: the writer, and (on a link with an
    /// `inline`) a sender that flushes its own message. Held across no wait for
    /// work: the writer lets it go before it parks.
    role: AtomicBool,
}

impl Lanes {
    /// Nanoseconds since the queue was made.
    fn now_ns(&self) -> u64 {
        self.epoch.elapsed().as_nanos() as u64
    }

    /// A write of this queue's frames has finished: the line has spoken now.
    fn note_wire_write(&self) {
        self.last_write_ns.store(self.now_ns(), Ordering::Relaxed);
    }

    /// Milliseconds since [`Self::note_wire_write`] last ran, `None` before the first.
    fn ms_since_wire_write(&self) -> Option<u64> {
        let last = self.last_write_ns.load(Ordering::Relaxed);
        (last != NEVER_FLUSHED).then(|| self.now_ns().saturating_sub(last) / 1_000_000)
    }

    /// A frame landed in a lane: wake the writer, and tell a writer that is letting producers
    /// finish that one did.
    ///
    /// Not when the thread that did it is the one that writes it: a sender flushing its own
    /// message (`flush_inline`) takes what lands before it lets go of the role,
    /// and waking the writer for it is the thread hop that flush exists to save.
    fn frame_landed(&self) {
        if INLINE_STEP.with(std::cell::Cell::get) {
            return;
        }
        self.ready.notify_one();
        self.frame_ready.notify_one();
    }

    /// Take the role, waiting for the thread that holds it. It is held for the length of a
    /// non-blocking write, so the wait is a few microseconds, spun and then yielded.
    fn acquire_role(self: &Arc<Self>) -> RoleGuard {
        let mut spins = 0u32;
        while self
            .role
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spins += 1;
            if spins < 64 {
                std::hint::spin_loop();
            } else {
                std::thread::yield_now();
            }
        }
        RoleGuard(Arc::clone(self))
    }

    /// Take the role if it is free.
    fn try_acquire_role(self: &Arc<Self>) -> Option<RoleGuard> {
        self.role
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| RoleGuard(Arc::clone(self)))
    }

    /// The handle on what `take_next` took.
    fn make_wire(self: &Arc<Self>, out: Out) -> WireFrame {
        match out {
            Out::Heap(bytes) => WireFrame(Wire::Heap(bytes), None),
            #[cfg(feature = "runtime-zero-copy")]
            Out::Slot {
                class,
                idx,
                base,
                len,
            } => WireFrame(
                Wire::Slot(SlotWire {
                    home: Arc::clone(self),
                    class,
                    idx,
                    base,
                    len,
                    started: false,
                    written: false,
                }),
                None,
            ),
        }
    }

    /// Take what is queued, in the writer's order and the writer's packing, and write it
    /// through `sink` until the queue is empty or the link takes no more. The caller holds the
    /// role. Answers whether the rest of a frame was left in the carry.
    fn write_inline(self: &Arc<Self>, sink: &dyn InlineWrite) -> bool {
        self.write_inline_scope(sink, InlineScope::All)
    }

    /// [`Self::write_inline`] over `scope`: everything queued, or the urgent frames alone.
    fn write_inline_scope(self: &Arc<Self>, sink: &dyn InlineWrite, scope: InlineScope) -> bool {
        loop {
            let (carried, taken, freed) = {
                let mut st = self.state.lock().expect("outbound lanes poisoned");
                match st.carry.take() {
                    Some(carried) => (Some(carried), Taken::Empty, false),
                    None => match scope {
                        InlineScope::All => {
                            let budget = st.batch_bytes.max(1);
                            let (taken, freed) = st.take_next_packed(budget);
                            (None, taken, freed)
                        }
                        InlineScope::Urgent => {
                            let (taken, freed) = st.take_urgent_only();
                            (None, taken, freed)
                        }
                    },
                }
            };
            if freed {
                self.room.notify_all();
            }
            let (priority, mut wire) = match (carried, taken) {
                (Some(carried), _) => carried,
                (None, Taken::Frame(priority, out)) => (priority, self.make_wire(out)),
                _ => return false,
            };
            wire.begin_write();
            let total = wire.len();
            let mut at = 0usize;
            while at < total {
                match sink.try_write(&wire[at..]) {
                    Ok(n) if n > 0 => at += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    // The link took none of it now (or failed: the writer will meet the
                    // same failure and end the link as it does for any write).
                    _ => {
                        wire.advance(at);
                        self.keep_carry(priority, wire);
                        return true;
                    }
                }
            }
            self.recycle_wire(wire);
        }
    }

    /// Keep the rest of a frame for the next thread that holds the role. Dropped when the
    /// queue is closed, outside the lock.
    fn keep_carry(&self, priority: Priority, wire: WireFrame) {
        let refused = {
            let mut st = self.state.lock().expect("outbound lanes poisoned");
            if st.closed {
                Some(wire)
            } else {
                st.carry = Some((priority, wire));
                None
            }
        };
        drop(refused);
    }

    /// Whether anything is waiting for a thread that holds the role: a frame on a lane, or the
    /// rest of one.
    fn has_queued(&self) -> bool {
        let st = self.state.lock().expect("outbound lanes poisoned");
        st.carry.is_some() || !st.urgent.is_empty() || st.lanes.iter().any(|lane| !lane.is_empty())
    }

    /// The thread that wrote `wire` out is done with it: what [`OutboundRx::recycle_wire`] does.
    fn recycle_wire(&self, wire: WireFrame) {
        self.note_wire_write();
        match wire.0 {
            Wire::Heap(bytes) => self
                .state
                .lock()
                .expect("outbound lanes poisoned")
                .give_spare(bytes),
            #[cfg(feature = "runtime-zero-copy")]
            Wire::Slot(mut slot) => slot.written = true,
        }
    }
}

/// What an inline write takes off the lanes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum InlineScope {
    /// Whatever is queued, in the writer's order and packing.
    All,
    /// The urgent frames alone.
    Urgent,
}

thread_local! {
    /// Whether this thread is in the middle of flushing its own message
    /// (`flush_inline`).
    static INLINE_STEP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A way to put bytes on a link from any thread, without waiting: what a sender that
/// flushes its own message writes with.
pub trait InlineWrite: Send + Sync {
    /// Write as much of `buf` as the link takes now. `WouldBlock` is "none of it now", and any
    /// other error is the writer's to find: the bytes are left for it.
    fn try_write(&self, buf: &[u8]) -> std::io::Result<usize>;
}

/// This thread is flushing its own message (`flush_inline`) from `enter` to drop.
struct InlineStep;

impl InlineStep {
    fn enter() -> Self {
        INLINE_STEP.with(|step| step.set(true));
        Self
    }
}

impl Drop for InlineStep {
    fn drop(&mut self) {
        INLINE_STEP.with(|step| step.set(false));
    }
}

/// The role (`Lanes::role`) held; let go on drop.
struct RoleGuard(Arc<Lanes>);

impl Drop for RoleGuard {
    fn drop(&mut self) {
        self.0.role.store(false, Ordering::Release);
    }
}

/// The writer's idle hook.
type IdleHook = Arc<dyn Fn() + Send + Sync>;

/// How long the writer lets producers keep adding to the open frames before it flushes
/// them, at most. Zenoh's `batching/time_limit` is a millisecond; the writer waits for
/// the producers to stop and only this long if they do not.
const COALESCE_LIMIT: Duration = Duration::from_micros(200);

/// How far apart the writer's two reads of the staged count are: long enough that a
/// producer that stages a message every microsecond or two shows up in it.
const COALESCE_PROBE: Duration = Duration::from_micros(3);

/// How many probes the writer spins through before it decides the producers are a stream and
/// stops spinning: a producer that is still adding after this many reads, microseconds of
/// them, is not about to stop, and the wait that remains is better spent asleep than on the
/// core.
const COALESCE_SPIN_PROBES: u32 = 3;

/// How many messages the producers staged between two flushes for the writer to call it a
/// stream and give up the CPU once before it flushes (`let_producers_finish`).
/// A request and its reply are one message per flush, a burst of a few are a few; a producer
/// that fills the writer's time is hundreds.
const STREAM_STAGED_MIN: u64 = 32;

/// How many messages staged since the last flush still make a lone message or a pair: the
/// writer flushes at once, without the probes of `let_producers_finish`.
const LONE_STAGED_MAX: u64 = 2;

/// How long no flush may have run for a sender to flush its own message (`flush_inline`): a
/// request and its reply are a round trip apart, tens of microseconds, and a stream's messages
/// are well inside this.
const INLINE_MIN_QUIET_NS: u64 = 8_000;

/// `last_flush_ns` of a queue that has not flushed yet: it has been quiet for as long as it has
/// lived.
const NEVER_FLUSHED: u64 = u64::MAX;

/// The senders' wait for room: a `Condvar` that is notified only while
/// someone waits on it.
///
/// `std`'s futex condvar makes a system call on EVERY notify, waiter or not, and
/// the writer notifies after every frame it takes. A sender that never waits
/// (the usual case: the lane has room) paid for that call per message, in a
/// process whose only job is to move messages.
///
/// A waiter counts itself in while it holds the lanes' lock and before the wait
/// gives the lock up; a notifier changed the state under that same lock before
/// it asks. So either the waiter's check saw the change, or the count the
/// notifier reads includes the waiter: a wake-up cannot be lost.
///
/// A sender that does not wait on a thread but HOLDS its messages for a full lane and goes on
/// when there is room (the router's credit stage) leaves a `watcher`, which is called on the
/// notifying thread. It is read behind its own flag, so a queue nobody watches pays one atomic
/// read per notice, which is what the waiter count costs.
struct RoomSignal {
    cv: Condvar,
    waiters: AtomicUsize,
    /// Whether a watcher is set. Read before the watcher's lock is taken.
    watched: AtomicBool,
    watcher: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// The tasks waiting for room by waker ([`OutboundTx::poll_reserve`]): each is woken once,
    /// by the next notice, and asks again. Whether any is set is read before the lock is taken.
    waiting: AtomicBool,
    wakers: Mutex<Vec<std::task::Waker>>,
}

impl RoomSignal {
    fn new() -> Self {
        Self {
            cv: Condvar::new(),
            waiters: AtomicUsize::new(0),
            watched: AtomicBool::new(false),
            watcher: Mutex::new(None),
            waiting: AtomicBool::new(false),
            wakers: Mutex::new(Vec::new()),
        }
    }

    /// Have `waker` woken by the next notice, replacing one the same task registered before.
    /// Call it holding the lanes' lock, after the room was found missing: a notice changes the
    /// state under that lock before it asks, so either the check saw the change or the waker
    /// is in the list when the notice reads it, and a wake-up cannot be lost.
    fn register(&self, waker: &std::task::Waker) {
        let mut wakers = self.wakers.lock().unwrap_or_else(|e| e.into_inner());
        if !wakers.iter().any(|known| known.will_wake(waker)) {
            wakers.push(waker.clone());
        }
        self.waiting.store(true, Ordering::SeqCst);
    }

    /// Call `watcher` at every notice from now on, or stop calling the one there is. One
    /// watcher at a time: a second replaces the first.
    fn watch(&self, watcher: Option<Arc<dyn Fn() + Send + Sync>>) {
        let on = watcher.is_some();
        *self.watcher.lock().unwrap_or_else(|e| e.into_inner()) = watcher;
        self.watched.store(on, Ordering::SeqCst);
    }

    /// Only the pooled queue waits without a bound (for a free slot).
    #[cfg(feature = "runtime-zero-copy")]
    fn wait<'a>(&self, guard: MutexGuard<'a, LaneState>) -> LockResult<MutexGuard<'a, LaneState>> {
        self.waiters.fetch_add(1, Ordering::SeqCst);
        let woken = self.cv.wait(guard);
        self.waiters.fetch_sub(1, Ordering::SeqCst);
        woken
    }

    fn wait_timeout<'a>(
        &self,
        guard: MutexGuard<'a, LaneState>,
        limit: Duration,
    ) -> LockResult<(MutexGuard<'a, LaneState>, WaitTimeoutResult)> {
        self.waiters.fetch_add(1, Ordering::SeqCst);
        let woken = self.cv.wait_timeout(guard, limit);
        self.waiters.fetch_sub(1, Ordering::SeqCst);
        woken
    }

    /// Wake the waiters, if there are any. Call after the state they wait on
    /// changed under the lanes' lock.
    fn notify_all(&self) {
        if self.waiters.load(Ordering::SeqCst) > 0 {
            self.cv.notify_all();
        }
        if self.waiting.load(Ordering::SeqCst) {
            // Taken out of the lock before any is woken: a waker may run its task at once.
            let woken = {
                let mut wakers = self.wakers.lock().unwrap_or_else(|e| e.into_inner());
                self.waiting.store(false, Ordering::SeqCst);
                std::mem::take(&mut *wakers)
            };
            for waker in woken {
                waker.wake();
            }
        }
        if self.watched.load(Ordering::SeqCst) {
            // Cloned out of the lock, so that the call is made holding nothing of this queue's.
            let watcher = self
                .watcher
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            if let Some(watcher) = watcher {
                watcher();
            }
        }
    }
}

struct LaneState {
    /// Transport messages that carry no sequence number and may pass whatever the lanes hold:
    /// the keepalive ([`OutboundTx::send_urgent`]). Each is a whole wire frame, taken before
    /// any lane's at the next frame boundary. Not counted against a lane's bound: a keepalive
    /// is a few bytes, and refusing one on a full lane is how a peer's lease is lost.
    urgent: VecDeque<Vec<u8>>,
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
    /// Each lane's bytes PROMISED to a sender that holds a [`Permit`] and has not yet sent its
    /// frame: room that is spoken for and not yet used. A lane has room for another permit
    /// while `occupied + reserved` is under its bound ([`LaneState::has_room`]), which is what
    /// lets a sender that waits for room and a sender that already has it never be given the
    /// same room twice.
    reserved: [usize; Priority::NUM],
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
    /// The bytes the writer holds in each lane, `None` where it holds none:
    /// still occupying the lane until the writer asks for the next item.
    ///
    /// R3366 — one entry per lane and not one frame, because a stream writer
    /// takes everything that is queued as one buffer ([`LaneState::take_next_packed`]),
    /// and that buffer holds frames of several lanes.
    in_flight: [Option<usize>; Priority::NUM],
    /// No further enqueue lands — set by the receiver's `close` (the seal).
    closed: bool,
    /// Live `OutboundTx` clones; the queue is finished once this reaches 0
    /// and the lanes are empty.
    senders: usize,
    /// ARCHITECTURE section 9.1 — frame buffers the writer is done with, kept to
    /// be lent again so a link in steady state allocates none. Bounded in count
    /// and in size ([`SPARE_MAX`], `spare_keep_max`) so a burst of large
    /// frames cannot make a link hoard memory.
    spare: Vec<Vec<u8>>,
    /// The largest buffer kept spare: [`SPARE_CAPACITY_MAX`] until a sender asks for a buffer
    /// of the size the session builds its frames in (a batch), then that size up to
    /// [`SPARE_CAPACITY_CEIL`]. A buffer the link itself asked for is the one it will ask for
    /// again, and freeing it on the way back made every frame a fresh allocation of a batch.
    spare_keep_max: usize,
    /// The rest of a frame that a sender flushing its own message could not write all of
    /// (the link took part and would take no more), with its priority: the next thread
    /// that holds the role writes it before it takes anything else, so the bytes of the
    /// stream stay in order. Always `None` on a link with no inline write.
    carry: Option<(Priority, WireFrame)>,
    /// R3239 — ARCHITECTURE section 9.1 under `runtime-zero-copy`: the link's
    /// transmit pool, on a queue built by [`outbound_channel_pooled`] or
    /// [`outbound_channel_datagram`]. While it is here every frame a sender
    /// hands this queue lies in one of its slots ([`Entry::Batch`]), and a dry
    /// pool is back-pressure.
    #[cfg(feature = "runtime-zero-copy")]
    pool: Option<TxPools>,
    /// The id the next batch is given, so a lend can find its batch again.
    #[cfg(feature = "runtime-zero-copy")]
    next_batch: u64,
    /// The receiving half has been DROPPED (not merely sealed): nothing will
    /// ever write what is queued, so a batch a lend gives back goes home
    /// whatever it holds.
    #[cfg(feature = "runtime-zero-copy")]
    receiver_gone: bool,
}

/// One queued item of a lane.
enum Entry {
    /// A frame in a vector of its own, with the priority it was sent at.
    Heap(Priority, Vec<u8>),
    /// R3239 — a slot of the link's transmit pool: frames back to back on a
    /// stream link, one datagram on a datagram link.
    #[cfg(feature = "runtime-zero-copy")]
    Batch(Batch),
}

/// R3239 — a slot of a pooled queue while it is on its lane: the frames
/// written into it so far, and whether a lend is writing the next one.
///
/// On a stream link a sender appends to its lane's NEWEST batch while it has
/// room and no lend is in it, so frames pack into few slots and a slot is written
/// by one write; on a byte stream the concatenation is the wire. On a datagram
/// link a batch is one datagram. The slot is cpu-mut for as long as it is here,
/// which is the state the generated lifecycle gives a slot the CPU is still
/// writing.
#[cfg(feature = "runtime-zero-copy")]
struct Batch {
    /// The priority of the first frame in it (all of them, on a QoS lane).
    priority: Priority,
    id: u64,
    /// The size class and the slot's index in it.
    class: usize,
    idx: usize,
    /// The slot's bytes.
    cap: usize,
    /// First byte of the slot, from the pool.
    base: usize,
    /// R3264 — where the first frame starts in the slot: 0, except for a frame
    /// a link framed around its message in place ([`OutboundTx::commit_from`]),
    /// which starts where its header begins. Only a non-packing batch has any.
    offset: usize,
    /// Bytes of whole frames written into it, from `offset`.
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
    #[cfg(feature = "runtime-zero-copy")]
    Blocked,
    /// Nothing is queued.
    Empty,
}

/// The parts of a taken item; [`OutboundRx`] makes the [`WireFrame`].
enum Out {
    Heap(Vec<u8>),
    #[cfg(feature = "runtime-zero-copy")]
    Slot {
        class: usize,
        idx: usize,
        base: usize,
        len: usize,
    },
}

/// How many spare frame buffers a lane set keeps.
const SPARE_MAX: usize = 4;

/// The largest buffer worth keeping spare before the link has said what size it works in. A
/// frame buffer past it is freed instead, so the pool's worst case is
/// `SPARE_MAX * SPARE_CAPACITY_MAX` bytes per link, until [`OutboundTx::take_buffer`] is
/// asked for more (below).
const SPARE_CAPACITY_MAX: usize = 16 * 1024;

/// The most a link's own buffer size can raise the bound to: the largest frame the byte door
/// accepts (`u16::MAX`) and its length prefix. A request past it is not a size a frame has.
const SPARE_CAPACITY_CEIL: usize = u16::MAX as usize + 8;

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
            || buf.capacity() > self.spare_keep_max
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
        // A lane is bounded in the configured unit, not in the batch the link
        // sends (`TxQueueShape::queue_unit_bytes` says why).
        self.capacity = shape.sizes.map(|n| n * shape.queue_unit_bytes);
        if self.single_lane {
            // zenoh sizes a non-QoS transport's one queue by the DEFAULT
            // priority's size.
            let default = Priority::DEFAULT.wire_byte() as usize;
            self.capacity = [self.capacity[default]; Priority::NUM];
        }
        #[cfg(feature = "runtime-zero-copy")]
        self.size_budgets();
    }

    /// R3239 — size the pool's per-link slot budgets from the lanes this queue
    /// has now: one lane's bound when the session runs no QoS, every lane's
    /// otherwise (`link_tx_pool::TxPools::size_budgets` has the rule).
    #[cfg(feature = "runtime-zero-copy")]
    fn size_budgets(&mut self) {
        let lanes = if self.single_lane { 1 } else { Priority::NUM };
        let default = Priority::DEFAULT.wire_byte() as usize;
        let mut bounds = [0usize; Priority::NUM];
        for (i, bound) in bounds.iter_mut().take(lanes).enumerate() {
            *bound = if self.single_lane {
                self.capacity[default]
            } else {
                self.capacity[i]
            };
        }
        if let Some(pool) = self.pool.as_mut() {
            pool.size_budgets(&bounds[..lanes]);
        }
        self.reserve_lanes_for_the_pool();
    }

    /// R3247 — give every lane a frame can be queued on room for as many
    /// entries as the pool lets this link hold slots (`TxPools::budget`), so
    /// queueing a slot never grows a lane. A pooled lane's entries are its
    /// slots, one each, and any one lane may hold every slot the link may take,
    /// so that budget is the most entries a lane can have: reserved here, the
    /// lend and the byte door push onto a lane that never reallocates. Left to
    /// grow, a lane reallocated the first time a slower writer let it reach a
    /// depth it had not reached before, which is an allocation on the transmit
    /// path at the moment of a burst (measured: one in a burst past the slot
    /// budget, at the lane's first push past four entries).
    ///
    /// Run whenever the budgets are sized (at the pool's arrival and at every
    /// reshape), so the room follows the budget. A lane no frame can reach any
    /// more (the others, once the session runs one lane) keeps only what it
    /// still holds. A heap frame on a pooled queue (`send`, the websocket byte
    /// door) is outside this bound: it is an allocation of its own already.
    #[cfg(feature = "runtime-zero-copy")]
    fn reserve_lanes_for_the_pool(&mut self) {
        let Some(budget) = self.pool.as_ref().map(TxPools::budget) else {
            return;
        };
        let single_lane = self.single_lane;
        let default = Priority::DEFAULT.wire_byte() as usize;
        for (i, lane) in self.lanes.iter_mut().enumerate() {
            let reachable = !single_lane || i == default;
            let room = if reachable { budget } else { 0 };
            let want = room.max(lane.len());
            if lane.capacity() < want {
                lane.reserve_exact(want - lane.len());
            } else {
                lane.shrink_to(want);
            }
        }
    }

    /// Each lane's room for entries, for a test to see that queueing up to the
    /// pool's budget does not grow it.
    #[cfg(all(test, feature = "runtime-zero-copy"))]
    fn lane_capacities(&self) -> [usize; Priority::NUM] {
        std::array::from_fn(|i| self.lanes[i].capacity())
    }

    /// Take the next frame, highest priority first, after releasing the one
    /// the writer held. Returns whether room was freed, so the caller wakes
    /// senders waiting for it.
    ///
    /// R2929 — the frame comes with the priority it was sent at, which is not
    /// its lane's when the lanes are one.
    fn take_next(&mut self) -> (Taken, bool) {
        let freed = self.release_in_flight();
        // A keepalive passes every lane, at this frame boundary: zenoh's tx task writes it
        // between batches, and a lane it queued behind would hold it as long as the data.
        if let Some(urgent) = self.take_urgent() {
            return (urgent, freed);
        }
        for lane in 0..Priority::NUM {
            match self.take_from(lane) {
                Taken::Empty => continue,
                taken => return (taken, freed),
            }
        }
        (Taken::Empty, freed)
    }

    /// The next urgent frame, if one is waiting: the keepalive that passes the lanes.
    fn take_urgent(&mut self) -> Option<Taken> {
        self.urgent
            .pop_front()
            .map(|frame| Taken::Frame(Priority::Control, Out::Heap(frame)))
    }

    /// The urgent frames alone, made the taker's: what a thread that carries only the
    /// session's liveness takes ([`OutboundTx::send_urgent`]), so that it writes a keepalive
    /// and never someone's data.
    fn take_urgent_only(&mut self) -> (Taken, bool) {
        let freed = self.release_in_flight();
        (self.take_urgent().unwrap_or(Taken::Empty), freed)
    }

    /// The next item of `lane`, made the writer's.
    ///
    /// R3239 — on a pooled queue a batch a lend is writing into is not the
    /// writer's yet. One with nothing committed holds no frame, so the items
    /// behind it are taken past it (they are other conduits' frames: the lend's
    /// own conduit cannot have a later frame while its lend is open). One that
    /// already holds frames is waited for, because a later item of the lane may
    /// be a later frame of a conduit whose earlier one is in it.
    fn take_from(&mut self, lane: usize) -> Taken {
        #[cfg(feature = "runtime-zero-copy")]
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
        #[cfg(not(feature = "runtime-zero-copy"))]
        let at = 0;
        let Some(entry) = self.lanes[lane].remove(at) else {
            return Taken::Empty;
        };
        match entry {
            Entry::Heap(priority, frame) => {
                self.in_flight[lane] = Some(frame.len());
                Taken::Frame(priority, Out::Heap(frame))
            }
            #[cfg(feature = "runtime-zero-copy")]
            Entry::Batch(batch) => {
                let pool = self
                    .pool
                    .as_mut()
                    .expect("a batch is queued only on a pooled queue");
                // Off its lane: no sender may write it again. Cpu-mut to
                // dma-armed-tx, and its address is the pool's own answer for an
                // armed slot.
                let base = pool
                    .class(batch.class)
                    .arm(batch.idx)
                    .expect("a queued batch is the CPU's, so it arms");
                self.in_flight[lane] = Some(batch.fill);
                Taken::Frame(
                    batch.priority,
                    Out::Slot {
                        class: batch.class,
                        idx: batch.idx,
                        base: base as usize + batch.offset,
                        len: batch.fill,
                    },
                )
            }
        }
    }

    /// R3239 — whether a frame could be given a slot: always on a heap queue;
    /// on a pooled one, while some class of the pool has a slot this link may
    /// take (free, and under its budget). Conservative by design: a frame that
    /// would have fit behind the newest batch is told "no room" too when the
    /// pool is out, because the answer is given before the frame's size is known.
    fn slot_room(&self) -> bool {
        #[cfg(feature = "runtime-zero-copy")]
        if let Some(pool) = self.pool.as_ref() {
            return pool.has_room();
        }
        true
    }

    /// R3264 — [`Self::slot_room`] once the frame's size is known: a slot of a
    /// class that holds `need` bytes, which is what a sender that is already
    /// waiting for a slot of its own must see before it goes on. Asking the
    /// question for ANY class here let a sender that needs the large class
    /// stop waiting because the small one had a slot, find none large, and go
    /// round again at full speed.
    #[cfg(feature = "runtime-zero-copy")]
    fn slot_room_for(&self, need: usize) -> bool {
        match self.pool.as_ref() {
            Some(pool) => pool.has_room_for(need),
            None => true,
        }
    }

    /// R2923 — the answer to `wait` on `lane` if it needs no waiting: the
    /// queue is closed, a droppable message meets the congested mark, the
    /// lane has room, or the request may not wait at all. `None` means the
    /// caller has to wait for the writer.
    /// Whether `lane` has room for one more frame: what it holds, and what is promised to a
    /// sender that has not sent yet, is under its bound, and a pooled queue has a slot. The one
    /// definition of room, asked by a sender that waits on a thread and by one that waits on a
    /// waker alike.
    fn has_room(&self, lane: usize) -> bool {
        self.occupied[lane] + self.reserved[lane] < self.capacity[lane] && self.slot_room()
    }

    fn room_at_once(&mut self, lane: usize, wait: RoomWait) -> Option<Room> {
        if self.closed {
            return Some(Room::Closed);
        }
        if wait.is_droppable() && self.congested[lane] {
            return Some(Room::Congested);
        }
        if self.has_room(lane) {
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
        let mut freed = false;
        for lane in 0..Priority::NUM {
            if let Some(bytes) = self.in_flight[lane].take() {
                self.occupied[lane] = self.occupied[lane].saturating_sub(bytes);
                // zenoh lowers the mark when a written batch returns to its
                // priority's pool (`fn refill(`), room or not.
                self.congested[lane] = false;
                freed = true;
            }
        }
        freed
    }

    /// R3366 — [`Self::take_next`] for a BYTE-STREAM writer: everything queued, up
    /// to `budget` bytes, as ONE buffer, in exactly the order `take_next` would
    /// have handed the frames out one by one.
    ///
    /// # Why this exists
    ///
    /// A writer that takes a frame, writes it and asks for the next pays one
    /// system call, one lock round and one wake-up per frame. Measured against
    /// the reference library on a small-message stream (8-byte payloads, a
    /// loopback link), that was one write of 30 bytes per message where the
    /// reference writes 8 KiB, and a publish rate fifty times lower. zenoh's
    /// transmission pipeline coalesces a burst of messages into a batch; this is
    /// that, at the queue.
    ///
    /// # Why it is correct on a byte stream
    ///
    /// Each frame is already the bytes the peer reads (its length prefix
    /// included), and a stream carries them back to back, so the concatenation of
    /// frames IS the wire the frames written one by one would have made. Nothing
    /// is added, reordered or split: a lane stays FIFO (a conduit's sequence
    /// numbers keep their order), the lanes are drained in the priority order
    /// `take_next` uses, and a frame that does not fit the budget stays queued for
    /// the next take whole. A DATAGRAM link must not use this (one frame is one
    /// datagram there), which is why it is a separate door and not a change to
    /// `take_next`.
    ///
    /// # No added latency
    ///
    /// It never waits for more to arrive: it takes what is queued when the writer
    /// asks, so a lone frame leaves at once and, being alone, is handed over
    /// as it is, without a copy. Frames pile up behind a write that is under
    /// way, and that backlog is what the next take packs.
    ///
    /// The bound's accounting is `take_next`'s: every packed frame stays in its
    /// lane's occupancy until the writer asks again.
    ///
    /// A pooled queue packs frames into its own batches already, so it is taken
    /// as `take_next` takes it.
    fn take_next_packed(&mut self, budget: usize) -> (Taken, bool) {
        #[cfg(feature = "runtime-zero-copy")]
        if self.pool.is_some() {
            return self.take_next();
        }
        let freed = self.release_in_flight();
        // The keepalive leaves alone, ahead of the lanes (see `take_next`).
        if let Some(urgent) = self.take_urgent() {
            return (urgent, freed);
        }
        // What is queued now: the occupancy minus nothing, the previous take
        // having just been released above.
        let queued: usize = self.occupied.iter().sum();
        let mut first: Option<(Priority, Vec<u8>)> = None;
        let mut joined: Option<Vec<u8>> = None;
        'lanes: for lane in 0..Priority::NUM {
            while let Some(Entry::Heap(_, frame)) = self.lanes[lane].front() {
                if let Some((_, head)) = first.as_ref() {
                    let so_far = joined.as_ref().map_or(head.len(), Vec::len);
                    if so_far.saturating_add(frame.len()) > budget {
                        break 'lanes;
                    }
                }
                let Some(Entry::Heap(priority, frame)) = self.lanes[lane].pop_front() else {
                    break;
                };
                self.in_flight[lane] = Some(self.in_flight[lane].unwrap_or(0) + frame.len());
                if first.is_none() {
                    // The first frame of the take: held as it is, in case it is
                    // the only one.
                    first = Some((priority, frame));
                    continue;
                }
                if let Some(buffer) = joined.as_mut() {
                    buffer.extend_from_slice(&frame);
                    self.give_spare(frame);
                    continue;
                }
                // The second frame: only now is there something to join.
                let (_, head) = first.as_mut().expect("the first frame was held above");
                let mut buffer =
                    Vec::with_capacity(queued.min(budget).max(head.len() + frame.len()));
                buffer.extend_from_slice(head);
                buffer.extend_from_slice(&frame);
                self.give_spare(std::mem::take(head));
                self.give_spare(frame);
                joined = Some(buffer);
            }
        }
        match (first, joined) {
            (None, _) => (Taken::Empty, freed),
            (Some((priority, _)), Some(buffer)) => {
                (Taken::Frame(priority, Out::Heap(buffer)), freed)
            }
            (Some((priority, frame)), None) => (Taken::Frame(priority, Out::Heap(frame)), freed),
        }
    }
}

/// How many senders may be parked waiting for room at once, each on a thread the runtime handed
/// over for it (`block_in_place`): the bulkhead between a stopped reader and everyone else.
///
/// A parked sender's wait releases its worker, and the release is paid out of the runtime's
/// `max_blocking_threads` (50 in the wz pool, upstream's default; 512 in a plain tokio runtime).
/// Past that number the surplus holds workers again and starves the faces that share them
/// (measured: 24 parked senders on a cap of 8 cost an unrelated timer 1.18 s). A node therefore
/// does not let more park than it can release: a sender that finds the budget spent is answered
/// as congested at once, which for a message that may not be dropped is upstream's own verdict
/// for a lane that stays full (the session whose lane it is closes as unresponsive), reached
/// earlier and without a thread. The count of those refusals is [`ParkStats::refused`].
///
/// 32 is below both caps with room for the blocking tasks the runtime has besides: a host that
/// runs the faces on a runtime capped lower sets it lower ([`set_park_budget`]).
pub const DEFAULT_PARK_BUDGET: usize = 32;

/// The bulkhead's counts. One per node ([`NODE_PARK_BUDGET`]); a value of its own for a test.
pub struct ParkBudget {
    limit: AtomicUsize,
    parked: AtomicUsize,
    refused: AtomicU64,
}

/// What a [`ParkBudget`] holds now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParkStats {
    /// Senders that may park at once.
    pub limit: usize,
    /// Senders parked now.
    pub parked: usize,
    /// Senders turned away because the budget was spent, since the process started.
    pub refused: u64,
}

/// A parked sender's place in the budget; released when it stops waiting.
struct ParkPermit<'a>(&'a ParkBudget);

impl Drop for ParkPermit<'_> {
    fn drop(&mut self) {
        self.0.parked.fetch_sub(1, Ordering::AcqRel);
    }
}

impl ParkBudget {
    /// A budget of `limit` parked senders.
    pub const fn new(limit: usize) -> Self {
        Self {
            limit: AtomicUsize::new(limit),
            parked: AtomicUsize::new(0),
            refused: AtomicU64::new(0),
        }
    }

    /// Take a place, or count the refusal and say there is none.
    fn try_park(&self) -> Option<ParkPermit<'_>> {
        let limit = self.limit.load(Ordering::Acquire);
        let took = self
            .parked
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |parked| {
                (parked < limit).then_some(parked + 1)
            })
            .is_ok();
        if took {
            Some(ParkPermit(self))
        } else {
            self.refused.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// The budget's counts now.
    pub fn stats(&self) -> ParkStats {
        ParkStats {
            limit: self.limit.load(Ordering::Acquire),
            parked: self.parked.load(Ordering::Acquire),
            refused: self.refused.load(Ordering::Relaxed),
        }
    }
}

/// The node's bulkhead, read by every [`OutboundTx::link_room`] of the process.
pub static NODE_PARK_BUDGET: ParkBudget = ParkBudget::new(DEFAULT_PARK_BUDGET);

/// How many senders may park at once on this node. Zero turns every wait that would park into an
/// immediate congested answer.
pub fn set_park_budget(limit: usize) {
    NODE_PARK_BUDGET.limit.store(limit, Ordering::Release);
}

/// The node's bulkhead now: what the capacity report says about parked senders.
pub fn park_stats() -> ParkStats {
    NODE_PARK_BUDGET.stats()
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

/// Why a reservation was not given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveError {
    /// The lane has no room now. [`OutboundTx::try_reserve`] answers it at once;
    /// [`OutboundTx::poll_reserve`] waits for the room instead.
    Full,
    /// The queue is closed: nothing more will be written on this link.
    Closed,
}

/// Room on a lane, promised to one sender: the right to enqueue one frame without asking again.
///
/// This is the reservation of a bounded channel (Tokio's `mpsc::Sender::reserve`, a `Sink`'s
/// `poll_ready` before `start_send`). Asking for room and using it are two steps so that a
/// sender can wait for the first WITHOUT holding what the second needs: a session takes its
/// conduit's lock, mints a sequence number and emits under it, and cannot wait for room under
/// that lock on a thread that has to go on, so it gets its [`Permit`] first and sends under
/// the lock with nothing left to wait for.
///
/// The lane counts what a permit promises as occupied until it is used or dropped
/// (`LaneState::has_room`), by the unit the lane was shaped in when the permit was given, so
/// that what is given back is what was taken whatever the queue is reshaped to meanwhile.
/// Dropping an unused permit returns the room and wakes whoever waits for it.
#[must_use = "a permit that is dropped at once promises nothing: send with it, or do not ask"]
pub struct Permit {
    shared: Arc<Lanes>,
    lane: usize,
    unit: usize,
}

impl Drop for Permit {
    fn drop(&mut self) {
        // A destructor that panics while a test unwinds aborts the process: no `expect`.
        if let Ok(mut st) = self.shared.state.lock() {
            st.reserved[self.lane] = st.reserved[self.lane].saturating_sub(self.unit);
        }
        self.shared.room.notify_all();
    }
}

impl OutboundTx {
    /// Promise one frame of room on `priority`'s lane if there is some now, without waiting.
    pub fn try_reserve(&self, priority: Priority) -> Result<Permit, ReserveError> {
        let mut st = self.shared.state.lock().expect("outbound lanes poisoned");
        self.reserve_in(&mut st, priority)
    }

    /// [`Self::try_reserve`], and when there is no room, the waker of `cx` is woken when there
    /// may be, which is when the writer takes a frame, a permit is dropped, or the queue closes.
    /// The task then asks again: a wake-up is a reason to ask and not a grant, since another
    /// sender may have taken the room first.
    ///
    /// The deadline is the caller's. A link that decided how long a message may wait would have
    /// to know whether the message may be dropped and whether it is the first of a chain; the
    /// caller knows both and wraps this in the timeout it has (`tokio::time::timeout`, or a
    /// blocking adapter's own).
    pub fn poll_reserve(
        &self,
        cx: &mut std::task::Context<'_>,
        priority: Priority,
    ) -> std::task::Poll<Result<Permit, ReserveError>> {
        let mut st = self.shared.state.lock().expect("outbound lanes poisoned");
        match self.reserve_in(&mut st, priority) {
            Err(ReserveError::Full) => {
                // Registered under the lock the room was found missing under, which is what
                // keeps a notice from slipping between the check and the registration.
                self.shared.room.register(cx.waker());
                std::task::Poll::Pending
            }
            other => std::task::Poll::Ready(other),
        }
    }

    fn reserve_in(&self, st: &mut LaneState, priority: Priority) -> Result<Permit, ReserveError> {
        if st.closed {
            return Err(ReserveError::Closed);
        }
        let lane = st.lane_of(priority);
        if !st.has_room(lane) {
            return Err(ReserveError::Full);
        }
        // One batch is what a frame may carry; it is what the lane's bound is counted in.
        let unit = st.batch_bytes.max(1);
        st.reserved[lane] += unit;
        // As a wait that finds room lowers the mark (zenoh's `refill`).
        st.congested[lane] = false;
        Ok(Permit {
            shared: Arc::clone(&self.shared),
            lane,
            unit,
        })
    }

    /// Enqueue `frame` on `priority`'s lane with the room `permit` promised, which turns from
    /// promised into occupied. A closed queue gives the frame back, and the permit is returned
    /// with it dropped.
    pub fn send_reserved(
        &self,
        mut permit: Permit,
        priority: Priority,
        frame: Vec<u8>,
    ) -> Result<(), OutboundClosed> {
        debug_assert!(
            Arc::ptr_eq(&permit.shared, &self.shared),
            "a permit is for the queue that gave it"
        );
        let mut st = self.shared.state.lock().expect("outbound lanes poisoned");
        // What was promised is given back in the same step as what is used is counted, under
        // one lock, so that no one sees the room twice or not at all. The permit then holds
        // nothing, and its `Drop`, which runs when this function ends and the lock is let go,
        // gives back nothing.
        let unit = std::mem::take(&mut permit.unit);
        st.reserved[permit.lane] = st.reserved[permit.lane].saturating_sub(unit);
        if st.closed {
            return Err(OutboundClosed(frame));
        }
        let lane = st.lane_of(priority);
        st.occupied[lane] += frame.len();
        st.lanes[lane].push_back(Entry::Heap(priority, frame));
        drop(st);
        self.shared.frame_landed();
        Ok(())
    }

    /// Whether `priority`'s lane is marked congested (R2923): a wait for room on it ran out and
    /// the writer has not freed any since. A sender that owns its deadline asks, for a message
    /// that may be dropped, before it waits at all, as zenoh does.
    pub fn is_congested(&self, priority: Priority) -> bool {
        let st = self.shared.state.lock().expect("outbound lanes poisoned");
        st.congested[st.lane_of(priority)]
    }

    /// Mark `priority`'s lane congested: a wait the caller owns ran out. The writer freeing room,
    /// or a later reservation, lowers it.
    pub fn mark_congested(&self, priority: Priority) {
        let mut st = self.shared.state.lock().expect("outbound lanes poisoned");
        let lane = st.lane_of(priority);
        st.congested[lane] = true;
    }

    /// An empty buffer with room for at least `min_capacity` bytes, to build a
    /// frame in: one the writer has finished with when the lane set keeps one that
    /// fits, a fresh allocation otherwise.
    pub fn take_buffer(&self, min_capacity: usize) -> Vec<u8> {
        let spare = {
            let mut st = self.shared.state.lock().expect("outbound lanes poisoned");
            // The size asked for is the size the session builds its frames in, and the
            // buffer comes back to the pool at that size: keep what is asked for.
            st.spare_keep_max = st.spare_keep_max.max(min_capacity.min(SPARE_CAPACITY_CEIL));
            st.take_spare(min_capacity)
        };
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

    /// Have the writer run `hook` whenever it is about to wait with nothing queued: the
    /// session's flush of the batch frames it holds, which hands them to this queue.
    ///
    /// The writer holds nothing of the queue's while it runs the hook, so the hook may send
    /// into the queue. A second call replaces the first (a link that is swapped under a live
    /// session installs the new session's hook).
    pub fn set_idle_hook(&self, hook: IdleHook) {
        *self.shared.idle_hook.lock().expect("idle hook poisoned") = Some(hook);
    }

    /// Tell the writer that the hook has something to flush, once per spell in which it is
    /// asleep or busy: while the flag stands, a sender that stages another message finds it
    /// set and costs one load. The writer clears it just before it runs the hook, so a
    /// message staged after that wakes it again.
    ///
    /// On a link with an inline write ([`Self::set_inline_write`]), a lone message is not left
    /// to the writer: see `flush_inline`.
    pub fn wake_for_flush(&self) {
        let staged = self
            .shared
            .staged
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        if !self.shared.flush_wanted.load(Ordering::Relaxed)
            && !self.shared.flush_wanted.swap(true, Ordering::SeqCst)
            && !self.flush_inline(staged)
        {
            self.shared.ready.notify_one();
        }
    }

    /// Give the queue a way to put bytes on the link from the thread of a sender
    /// ([`InlineWrite`]). Once, before the first frame; a second call is ignored.
    pub fn set_inline_write(&self, sink: Arc<dyn InlineWrite>) {
        let _ = self.shared.inline.set(sink);
    }

    /// Flush the message this sender has just staged, and write it, on the sender's own
    /// thread: the writer is a thread asleep in the runtime, and waking it, running its task
    /// and handing the frame over cost two thread hops and a system call per message in
    /// the round trip of a request and its reply. Answers whether it did; when it did not, the
    /// caller wakes the writer as it always did, and nothing has been taken.
    ///
    /// Only for a message that is alone: `staged` is the count with this message in it, and
    /// when more than a couple were staged since the last flush the traffic is a stream, which
    /// the writer coalesces into large writes and a flush per message would turn into a system
    /// call per message. Only when the role is free (`Lanes::role`): a writer that is mid-write
    /// finds the flush request this sender raised when it looks for work. Only on a link that
    /// has an inline write, which writes without waiting; a write the link takes part of
    /// leaves the rest in the queue's carry for the writer, who is woken.
    fn flush_inline(&self, staged: u64) -> bool {
        let shared = &self.shared;
        let Some(sink) = shared.inline.get() else {
            return false;
        };
        let since = staged.wrapping_sub(shared.staged_at_flush.load(Ordering::Relaxed));
        if since > LONE_STAGED_MAX {
            return false;
        }
        // A flush ran a moment ago: messages come faster than a flush is written, which is a
        // stream, and the writer coalesces them. Counting what was staged is not enough to tell:
        // one sender of a stream always finds just its own message staged since the last flush.
        let last = shared.last_flush_ns.load(Ordering::Relaxed);
        if last != NEVER_FLUSHED && shared.now_ns().saturating_sub(last) < INLINE_MIN_QUIET_NS {
            return false;
        }
        let Some(role) = shared.try_acquire_role() else {
            return false;
        };
        if shared.state.lock().expect("outbound lanes poisoned").closed {
            return false;
        }
        shared.staged_at_flush.store(staged, Ordering::Relaxed);
        // This flush answers the request that brought us here, and a message staged while it
        // runs raises the flag again for the writer.
        shared.flush_wanted.store(false, Ordering::SeqCst);
        let step = InlineStep::enter();
        let hook = shared.idle_hook.lock().expect("idle hook poisoned").clone();
        if let Some(hook) = hook {
            hook();
        }
        let left = shared.write_inline(sink.as_ref());
        drop(step);
        drop(role);
        shared
            .last_flush_ns
            .store(shared.now_ns(), Ordering::Relaxed);
        // Work the writer must see: the rest of a frame, a frame a lend completed behind our
        // take, a request raised while we held the role.
        if left || shared.has_queued() || shared.flush_wanted.load(Ordering::SeqCst) {
            shared.ready.notify_one();
        }
        true
    }

    /// Queue `frame` as an URGENT frame: a whole wire frame that carries no sequence number (the
    /// keepalive), which the writer takes ahead of every lane at its next frame boundary, as
    /// zenoh's tx task writes a keepalive between batches. It is not counted against a lane's
    /// bound and is never refused for room.
    ///
    /// The writer of a link whose runtime is short of CPU may not run for seconds, and a
    /// keepalive that waits for it is a peer's lease spent for nothing; so on a link that can be
    /// written from another thread ([`InlineWrite`]) it is written from the calling thread now,
    /// when the writer does not hold the role mid-write. When it cannot be, it stays queued
    /// and the writer, woken here, takes it first.
    pub fn send_urgent(&self, frame: Vec<u8>) -> Result<(), OutboundClosed> {
        {
            let mut st = self.shared.state.lock().expect("outbound lanes poisoned");
            if st.closed {
                return Err(OutboundClosed(frame));
            }
            st.urgent.push_back(frame);
        }
        self.shared.frame_landed();
        self.flush_urgent_inline();
        Ok(())
    }

    /// Write the urgent frames on THIS thread, and only them: the thread that does it carries
    /// session liveness and never takes on data. A write the link takes part of leaves the
    /// rest in the carry, which the writer finishes first and is woken to.
    fn flush_urgent_inline(&self) {
        let shared = &self.shared;
        let Some(sink) = shared.inline.get() else {
            return;
        };
        let Some(role) = shared.try_acquire_role() else {
            return;
        };
        if shared.state.lock().expect("outbound lanes poisoned").closed {
            return;
        }
        let left = shared.write_inline_scope(sink.as_ref(), InlineScope::Urgent);
        drop(role);
        // The writer is owed a wake for what this left (the rest of a frame, an urgent frame the
        // link would not take), not for the data it was woken for when that was queued.
        let urgent_left = !shared
            .state
            .lock()
            .expect("outbound lanes poisoned")
            .urgent
            .is_empty();
        if left || urgent_left {
            shared.ready.notify_one();
        }
    }

    /// How long ago, in milliseconds, a write of this queue's frames last finished, or `None`
    /// when none has. A frame still queued has not been written: this is when the LINE last
    /// spoke, which is what a keepalive must measure and the time a frame was enqueued is not
    /// ([`wz_session_core::link::BoxedLinkDriver::ms_since_wire_write`]).
    pub fn ms_since_wire_write(&self) -> Option<u64> {
        self.shared.ms_since_wire_write()
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
        self.shared.frame_landed();
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
            if st.has_room(lane) {
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
        self.link_room_in(&NODE_PARK_BUDGET, priority, wait)
    }

    /// [`Self::link_room`] with the bulkhead `budget` instead of the node's.
    pub fn link_room_in(
        &self,
        budget: &ParkBudget,
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
                        // The release is paid from the runtime's blocking threads, so it is
                        // rationed: a sender that finds none left is answered congested now.
                        match budget.try_park() {
                            Some(_place) => tokio::task::block_in_place(wait),
                            None => Room::Congested,
                        }
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

    /// Have `waker` called whenever room is made on this queue (the writer took a frame, or the
    /// queue was reshaped or closed), or stop calling the one there is when given `None`
    /// (`BoxedLinkDriver::watch_room`, which every write driver over this queue answers with).
    /// The call is made on the thread that made the room, holding nothing of the queue's.
    pub fn watch_room(&self, waker: Option<Arc<dyn Fn() + Send + Sync>>) {
        self.shared.room.watch(waker);
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

/// R3239 — why a pooled queue refused a frame.
#[cfg(feature = "runtime-zero-copy")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PooledSendError {
    /// The queue is closed (sealed or its receiver gone): nothing more is
    /// written.
    Closed,
    /// The frame is larger than the pool's largest slot. A stream frame never
    /// is (that slot holds the largest one, `link_tx_pool::MAX_STREAM_FRAME`),
    /// nor is a datagram, so this is a caller that bypassed the write half's own
    /// length guard.
    TooLarge,
    /// The link's encoder could not write the frame (`OutboundTx::send_encoded`);
    /// nothing was queued.
    Unencodable,
}

#[cfg(feature = "runtime-zero-copy")]
impl std::fmt::Display for PooledSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "outbound queue closed"),
            Self::TooLarge => write!(f, "frame larger than a transmit slot"),
            Self::Unencodable => write!(f, "frame could not be encoded"),
        }
    }
}

/// R3239 — the part of a pooled lane's slot a sender has been lent to encode
/// one frame into. Consumed by [`OutboundTx::commit`] or
/// [`OutboundTx::abort_lend`]; until one of them runs, nothing else writes those
/// bytes and the writer does not take the slot.
#[cfg(feature = "runtime-zero-copy")]
#[derive(Debug)]
pub struct TxLend {
    lane: usize,
    batch: u64,
    base: usize,
    cap: usize,
}

#[cfg(feature = "runtime-zero-copy")]
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

/// R3239 — the pooled queue's sender side. Every method here is for a queue
/// built by [`outbound_channel_pooled`]; on a heap queue they answer as a link
/// that lends nothing.
#[cfg(feature = "runtime-zero-copy")]
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
    /// pool's own count, over every class. `None` on a heap queue.
    pub fn tx_pool_stats(&self) -> Option<(TxPoolStats, usize)> {
        let st = self.shared.state.lock().expect("outbound lanes poisoned");
        st.pool
            .as_ref()
            .map(|pool| (pool.stats(), pool.free_count()))
    }

    /// Each lane's room for entries, read under the lock (a test's view of
    /// `LaneState::reserve_lanes_for_the_pool`).
    #[cfg(test)]
    pub(crate) fn lane_capacities(&self) -> [usize; Priority::NUM] {
        self.shared
            .state
            .lock()
            .expect("outbound lanes poisoned")
            .lane_capacities()
    }

    /// Slots in the pool, over every class. `None` on a heap queue.
    pub fn tx_pool_capacity(&self) -> Option<usize> {
        let st = self.shared.state.lock().expect("outbound lanes poisoned");
        st.pool.as_ref().map(TxPools::capacity)
    }

    /// Class `class`'s counters, free slots and budget. `None` on a heap queue
    /// or past the classes.
    pub fn tx_class_stats(&self, class: usize) -> Option<(TxPoolStats, usize, usize)> {
        let st = self.shared.state.lock().expect("outbound lanes poisoned");
        let pool = st.pool.as_ref()?;
        (class < pool.classes()).then(|| {
            let c = pool.class_ref(class);
            (c.stats(), c.free_count(), c.budget())
        })
    }

    /// The lifecycle state the pool's emit records for slot `idx` of class
    /// `class`.
    pub fn tx_slot_state(&self, class: usize, idx: usize) -> Option<TxSlotState> {
        let st = self.shared.state.lock().expect("outbound lanes poisoned");
        let pool = st.pool.as_ref()?;
        (class < pool.classes())
            .then(|| pool.class_ref(class).slot_state(idx))
            .flatten()
    }

    /// Enqueue the frame `prefix` + `payload` on `priority`'s lane by COPYING it
    /// into a slot: on a stream pool behind the frames of the lane's newest batch
    /// when it has room and no lend is in it, else (and always on a datagram
    /// pool) into a fresh slot of the smallest class that holds it. This is the byte door
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
        self.send_encoded(priority, need, |dst| {
            dst[..prefix.len()].copy_from_slice(prefix);
            dst[prefix.len()..need].copy_from_slice(payload);
            Some(need)
        })
    }

    /// R3239 — [`Self::send_framed`] for a frame the LINK encodes: `encode` is
    /// handed `room` bytes of a slot (behind the lane's newest batch when they
    /// are free, else a fresh slot) and answers how many it wrote, or `None` when
    /// the frame cannot be encoded, which queues nothing and gives back a slot
    /// taken for it. The serial link's COBS framing is the case: the stuffed
    /// length is known only once it is written, and is at most `room`.
    ///
    /// On a heap queue the frame is encoded into a vector of its own.
    pub fn send_encoded(
        &self,
        priority: Priority,
        room: usize,
        encode: impl FnOnce(&mut [u8]) -> Option<usize>,
    ) -> Result<(), PooledSendError> {
        if self.max_frame().is_some_and(|max| room > max) {
            return Err(PooledSendError::TooLarge);
        }
        let mut encode = Some(encode);
        loop {
            {
                let mut guard = self.shared.state.lock().expect("outbound lanes poisoned");
                if guard.closed {
                    return Err(PooledSendError::Closed);
                }
                let lane = guard.lane_of(priority);
                let st = &mut *guard;
                let Some(pool) = st.pool.as_mut() else {
                    drop(guard);
                    let encode = encode.take().expect("encoded once");
                    let mut frame = vec![0u8; room];
                    let written = encode(&mut frame).ok_or(PooledSendError::Unencodable)?;
                    frame.truncate(written.min(room));
                    return self
                        .send(priority, frame)
                        .map_err(|_| PooledSendError::Closed);
                };
                let behind = pool.packs()
                    && matches!(
                        st.lanes[lane].back(),
                        Some(Entry::Batch(batch)) if !batch.lent && batch.cap - batch.fill >= room
                    );
                let written = if behind {
                    let Some(Entry::Batch(batch)) = st.lanes[lane].back_mut() else {
                        unreachable!("checked directly above");
                    };
                    // SAFETY: `[fill, fill + room)` lies in this batch's slot
                    // (checked), and the batch is cpu-mut on its lane with no lend
                    // in it, so nothing else reads or writes those bytes while the
                    // lanes are locked here.
                    let dst = unsafe {
                        std::slice::from_raw_parts_mut((batch.base + batch.fill) as *mut u8, room)
                    };
                    let encode = encode.take().expect("encoded once");
                    let written = encode(dst).ok_or(PooledSendError::Unencodable)?.min(room);
                    batch.fill += written;
                    pool.class(batch.class).note_copied();
                    written
                } else {
                    let Some((class, idx, base)) = pool.acquire(room) else {
                        drop(guard);
                        if !self.wait_for_slot(room) {
                            return Err(PooledSendError::Closed);
                        }
                        continue;
                    };
                    let cap = pool.slot_size(class);
                    let base = base as usize;
                    // SAFETY: a fresh slot of `cap >= room` bytes (the class was
                    // chosen to hold it), held by this call alone until it is on
                    // the lane.
                    let dst = unsafe { std::slice::from_raw_parts_mut(base as *mut u8, room) };
                    let encode = encode.take().expect("encoded once");
                    let Some(written) = encode(dst) else {
                        pool.class(class).give_back(idx);
                        drop(guard);
                        self.shared.room.notify_all();
                        return Err(PooledSendError::Unencodable);
                    };
                    let written = written.min(room);
                    pool.class(class).note_copied();
                    let id = st.next_batch;
                    st.next_batch += 1;
                    st.lanes[lane].push_back(Entry::Batch(Batch {
                        priority,
                        id,
                        class,
                        idx,
                        cap,
                        base,
                        offset: 0,
                        fill: written,
                        lent: false,
                    }));
                    written
                };
                st.occupied[lane] += written;
            }
            self.shared.frame_landed();
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
        if need > self.max_frame()? {
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
                if pool.packs() {
                    if let Some(Entry::Batch(batch)) = st.lanes[lane].back_mut() {
                        if !batch.lent && batch.cap - batch.fill >= need {
                            batch.lent = true;
                            return Some(TxLend {
                                lane,
                                batch: batch.id,
                                base: batch.base + batch.fill,
                                cap: batch.cap - batch.fill,
                            });
                        }
                    }
                }
                if let Some((class, idx, base)) = pool.acquire(need) {
                    let cap = pool.slot_size(class);
                    let base = base as usize;
                    let id = st.next_batch;
                    st.next_batch += 1;
                    // On the lane at once, so its place in the lane's order is
                    // the order the frame was lent in.
                    st.lanes[lane].push_back(Entry::Batch(Batch {
                        priority,
                        id,
                        class,
                        idx,
                        cap,
                        base,
                        offset: 0,
                        fill: 0,
                        lent: true,
                    }));
                    return Some(TxLend {
                        lane,
                        batch: id,
                        base,
                        cap,
                    });
                }
            }
            if !self.wait_for_slot(need) {
                return None;
            }
        }
    }

    /// The sender wrote a frame of `len` bytes (its prefix included) at the
    /// start of `lend`: it is queued behind the batch's earlier frames. Refused
    /// when the queue has closed since the lend, as [`Self::send`] refuses; the
    /// slot then goes home if nothing else is in it.
    pub fn commit(&self, lend: TxLend, len: usize) -> Result<(), PooledSendError> {
        self.commit_at(lend, 0, len)
    }

    /// R3264 — [`Self::commit`] for a frame that starts `start` bytes into the
    /// lend instead of at its first byte: a link that frames a message around
    /// its payload in place (the WebSocket link writes the RFC 6455 header just
    /// before the payload the session encoded, so the slot IS the wire frame)
    /// queues what lies in `[start, start + len)`. Datagram pools only, where a
    /// slot holds one frame; a packing pool's frames follow one another from
    /// the batch's start.
    pub fn commit_from(
        &self,
        lend: TxLend,
        start: usize,
        len: usize,
    ) -> Result<(), PooledSendError> {
        self.commit_at(lend, start, len)
    }

    fn commit_at(&self, lend: TxLend, start: usize, len: usize) -> Result<(), PooledSendError> {
        debug_assert!(
            start + len <= lend.cap,
            "a lent frame stays inside its lend"
        );
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
                if start > 0 {
                    debug_assert!(
                        batch.fill == 0 && lend.base == batch.base,
                        "only a slot's one frame starts past the slot's first byte"
                    );
                    batch.offset = start;
                }
                batch.fill += len;
                let class = batch.class;
                st.occupied[lend.lane] += len;
                if let Some(pool) = st.pool.as_mut() {
                    pool.class(class).note_lent();
                }
                (Ok(()), false)
            }
        };
        self.shared.frame_landed();
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
        self.shared.frame_landed();
        if freed {
            self.shared.room.notify_all();
        }
    }

    /// Wait until the pool has a free slot for a frame of `need` bytes (`true`)
    /// or the queue closes (`false`). On a multi-thread runtime the wait
    /// releases the worker, as [`Self::link_room`]'s does and for the same
    /// reason: the writer that frees the slot may be queued behind the waiter.
    fn wait_for_slot(&self, need: usize) -> bool {
        let wait = || {
            let mut st = self.shared.state.lock().expect("outbound lanes poisoned");
            loop {
                if st.closed {
                    return false;
                }
                if st.slot_room_for(need) {
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

    /// The largest frame a slot of this queue's pool holds; `None` on a heap
    /// queue.
    pub fn max_frame(&self) -> Option<usize> {
        let st = self.shared.state.lock().expect("outbound lanes poisoned");
        st.pool.as_ref().map(TxPools::max_frame)
    }
}

/// R3240 — the slots a write half has LENT the session and not yet taken back
/// (`BoxedLinkDriver::tx_slot_acquire`), by slot number: an occupied entry is a
/// lend the session is encoding into, and a free number is reused. Shared by the
/// datagram write halves, which lend with no headroom (a datagram has no
/// framing prefix), so each is the same four lines over this.
#[cfg(feature = "runtime-zero-copy")]
#[derive(Default)]
pub struct LendTable {
    lent: Mutex<(Vec<Option<TxLend>>, Vec<u32>)>,
}

#[cfg(feature = "runtime-zero-copy")]
impl LendTable {
    /// Lend the session a slot of `tx`'s pool for a frame of up to `want`
    /// bytes, capped at `max` (the link's own limit on a frame). `None` on a
    /// heap queue, a closed one, or a frame no class holds.
    pub fn acquire(
        &self,
        tx: &OutboundTx,
        want: usize,
        max: usize,
        priority: Priority,
    ) -> Option<wz_session_core::link::TxSlotGrant> {
        self.acquire_with_headroom(tx, want, max, 0, priority)
    }

    /// R3264 — [`Self::acquire`] for a link that frames each message in place:
    /// the lend is `headroom` bytes longer, and the grant says the message
    /// starts that far into the slot, so the link can write its header in front
    /// of it ([`OutboundTx::commit_from`]). `max` is the most the MESSAGE may be.
    pub fn acquire_with_headroom(
        &self,
        tx: &OutboundTx,
        want: usize,
        max: usize,
        headroom: usize,
        priority: Priority,
    ) -> Option<wz_session_core::link::TxSlotGrant> {
        let lend = tx.lend(priority, headroom + want.min(max))?;
        let mut table = self.lent.lock().expect("lent slots poisoned");
        let (slots, free) = &mut *table;
        let number = match free.pop() {
            Some(number) => number,
            None => {
                slots.push(None);
                (slots.len() - 1) as u32
            }
        };
        slots[number as usize] = Some(lend);
        Some(wz_session_core::link::TxSlotGrant {
            slot: wz_session_core::link::TxSlot(number),
            headroom,
        })
    }

    /// Where lent slot `slot` is, and how many bytes it holds.
    pub fn storage(&self, slot: wz_session_core::link::TxSlot) -> (*mut u8, usize) {
        let table = self.lent.lock().expect("lent slots poisoned");
        let lend = table.0[slot.0 as usize]
            .as_ref()
            .expect("a slot the session names is a slot this link lent");
        (lend.base(), lend.capacity())
    }

    /// Take lent slot `slot` back out of the table.
    pub fn take(&self, slot: wz_session_core::link::TxSlot) -> TxLend {
        let mut table = self.lent.lock().expect("lent slots poisoned");
        let (slots, free) = &mut *table;
        let lend = slots[slot.0 as usize]
            .take()
            .expect("a slot the session names is a slot this link lent");
        free.push(slot.0);
        lend
    }

    /// The session wrote a datagram of `len` bytes at the start of lent slot
    /// `slot`: queue it. `len` past `max` is refused as oversize and the slot
    /// goes home.
    pub fn send(
        &self,
        tx: &OutboundTx,
        slot: wz_session_core::link::TxSlot,
        start: usize,
        len: usize,
        max: usize,
    ) -> wz_session_core::link::LinkSendOutcome {
        use wz_session_core::link::{LinkDropCause, LinkSendOutcome};
        let lend = self.take(slot);
        debug_assert_eq!(start, 0, "a datagram lend has no headroom");
        if len > max || start != 0 {
            tx.abort_lend(lend);
            return LinkSendOutcome::Dropped(LinkDropCause::Oversize);
        }
        match tx.commit(lend, len) {
            Ok(()) => LinkSendOutcome::Sent,
            Err(_) => LinkSendOutcome::Dropped(LinkDropCause::WriterGone),
        }
    }

    /// The session is not sending what it was lent.
    pub fn abort(&self, tx: &OutboundTx, slot: wz_session_core::link::TxSlot) {
        tx.abort_lend(self.take(slot));
    }
}

#[cfg(feature = "runtime-zero-copy")]
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
                pool.class(batch.class).give_back(batch.idx);
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
                    Entry::Batch(batch) => {
                        pool.class(batch.class).give_back(batch.idx);
                    }
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

    /// R3264 — the pool's counters, its free slots and its capacity, by the
    /// pool's own count, read from the receiving half; `None` on a heap queue.
    #[cfg(feature = "runtime-zero-copy")]
    pub fn tx_pool_stats(&self) -> Option<(TxPoolStats, usize, usize)> {
        let st = self.shared.state.lock().expect("outbound lanes poisoned");
        st.pool
            .as_ref()
            .map(|pool| (pool.stats(), pool.free_count(), pool.capacity()))
    }

    /// R3264 — the writer has written `wire` out: a heap frame's buffer is kept
    /// to be lent again ([`Self::recycle`]); a pooled frame's slot goes home
    /// through the completion edge, counted as written. For a writer that holds
    /// the receiving half itself (the multicast transmit task) as well as for
    /// [`OutboundQueue::recycle_wire`].
    pub fn recycle_wire(&self, wire: WireFrame) {
        self.shared.note_wire_write();
        match wire.0 {
            Wire::Heap(bytes) => self.recycle(bytes),
            #[cfg(feature = "runtime-zero-copy")]
            Wire::Slot(mut slot) => slot.written = true,
        }
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

    /// R3239 — [`Self::recv`] as the [`WireFrame`] the queue holds: on a pooled
    /// queue, a slot of the link's transmit pool armed for the write, which the
    /// writer starts, writes and hands back ([`OutboundQueue::recycle_wire`]).
    pub async fn recv_wire(&mut self) -> Option<WireFrame> {
        self.recv_wire_tagged().await.map(|(_, wire)| wire)
    }

    /// R3239 — [`Self::recv_wire`], with the priority the frame was sent at (a
    /// batch's: the priority of the first frame in it).
    pub async fn recv_wire_tagged(&mut self) -> Option<(Priority, WireFrame)> {
        self.recv_wire_tagged_with(false).await
    }

    /// R3366 — [`Self::recv_wire`] for a BYTE-STREAM writer: all that is queued, up
    /// to the queue's batch size, as one buffer in the order the frames would
    /// have been taken one by one. See `LaneState::take_next_packed` for why
    /// that is the same wire, and why a datagram writer must not use it.
    pub async fn recv_wire_packed(&mut self) -> Option<WireFrame> {
        self.recv_wire_mode(true).await
    }

    /// [`Self::recv_wire`] or [`Self::recv_wire_packed`], by `packed`: the one
    /// call the seal-aware queue wrapper makes either way.
    pub(crate) async fn recv_wire_mode(&mut self, packed: bool) -> Option<WireFrame> {
        self.recv_wire_tagged_with(packed)
            .await
            .map(|(_, wire)| wire)
    }

    /// Before the idle hook flushes, let producers that are still staging finish: while the
    /// staged count moves between two reads a few microseconds apart, wait, for at most
    /// [`COALESCE_LIMIT`]. A producer that stops (a lone message, the end of a burst) is
    /// seen to have stopped by the second read, so the flush it is owed leaves within
    /// microseconds; a producer that does not stop is flushed by the limit, and by its own
    /// frame filling up before that. Without the wait the writer, which is faster than a
    /// producer that has to build each message, flushes after nearly every one and sends a
    /// few hundred bytes a write where zenoh sends kilobytes.
    ///
    /// The first reads are a spin and not a sleep, because a sleep cannot be as short as the
    /// few microseconds a lone message may wait: the runtime's timer has a millisecond
    /// granularity. The spin is [`COALESCE_SPIN_PROBES`] reads, microseconds in all, so it
    /// holds the thread for no longer than a write does. A producer that is still adding
    /// after them is a stream, and from there the writer WAITS on the runtime, giving the
    /// thread back: the `tx` runtime has one worker for every link writer of the process, so
    /// a writer that held it (spinning, or asleep on the thread) for the length of a stream
    /// would starve every other link's writer for as long. It wakes when a frame lands
    /// (answered `true`: the producers are filling frames, and a frame is the work to do now,
    /// not the partial frames that are still open) or when [`COALESCE_LIMIT`] passes
    /// (`false`: flush what is open).
    async fn let_producers_finish(&self) -> bool {
        // A stream: the producers staged many messages since the last flush, so the writer is
        // being woken to write a few hundred bytes at a time. When the producer shares the
        // writer's CPU the wake preempted it, and the flush now would take the CPU back from
        // it again and again; give the CPU up once, so that the producer fills what it can
        // first. With a CPU of its own the producer is not waiting for this, and the call
        // returns at once.
        let staged = self.shared.staged.load(Ordering::Relaxed);
        let since_flush = staged.wrapping_sub(self.shared.staged_at_flush.load(Ordering::Relaxed));
        if since_flush >= STREAM_STAGED_MIN {
            std::thread::yield_now();
        }
        self.shared.staged_at_flush.store(
            self.shared.staged.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.shared
            .last_flush_ns
            .store(self.shared.now_ns(), Ordering::Relaxed);
        // A lone message (a request, a reply): the producers staged one or two since the last
        // flush, so there is no stream to wait out and nothing for the probes below to find,
        // and the message would wait for them for nothing. A burst that starts here is
        // flushed in its first message and then coalesced from the second flush on, when
        // what was staged since is more than a few.
        if since_flush <= LONE_STAGED_MAX {
            return false;
        }
        let mut seen = self.shared.staged.load(Ordering::Relaxed);
        for _ in 0..COALESCE_SPIN_PROBES {
            let probe = Instant::now();
            while probe.elapsed() < COALESCE_PROBE {
                std::hint::spin_loop();
            }
            let now = self.shared.staged.load(Ordering::Relaxed);
            if now == seen {
                return false;
            }
            seen = now;
        }
        tokio::select! {
            _ = self.shared.frame_ready.notified() => true,
            _ = tokio::time::sleep(COALESCE_LIMIT) => false,
        }
    }

    async fn recv_wire_tagged_with(&mut self, packed: bool) -> Option<(Priority, WireFrame)> {
        // The idle hook runs once per call: if it flushed something the next take finds it,
        // and if it did not there is nothing more to ask before waiting.
        let mut idle_hook_ran = false;
        // On a link whose senders may write their own messages ([`InlineWrite`]) the writer
        // takes frames only while it holds the role, which it keeps until the frame it
        // takes is written (it travels with the frame) and lets go of before it waits.
        let inline = self.shared.inline.get().is_some();
        loop {
            let notified = self.shared.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let role = if inline {
                Some(self.shared.acquire_role())
            } else {
                None
            };
            {
                // The lock is held in a block of its own, so that the guard is plainly gone
                // before the wait below (a `drop` is not enough for the compiler to see that
                // the future holds no guard across an await, and the writer's future must be
                // `Send`).
                let (carried, taken, freed, finished) = {
                    let mut st = self.shared.state.lock().expect("outbound lanes poisoned");
                    if let Some(carried) = st.carry.take() {
                        // What a sender left half written goes first: the bytes of the
                        // stream stay in order.
                        (Some(carried), Taken::Empty, false, false)
                    } else {
                        let (taken, freed) = if packed {
                            let budget = st.batch_bytes.max(1);
                            st.take_next_packed(budget)
                        } else {
                            st.take_next()
                        };
                        let finished =
                            matches!(taken, Taken::Empty) && (st.closed || st.senders == 0);
                        (None, taken, freed, finished)
                    }
                };
                if freed {
                    self.shared.room.notify_all();
                }
                if let Some((priority, wire)) = carried {
                    return Some((priority, wire.holding(role)));
                }
                match taken {
                    Taken::Frame(priority, out) => {
                        return Some((priority, self.wire(out).holding(role)))
                    }
                    Taken::Empty if finished => return None,
                    // Nothing queued and the writer is about to wait: this is the moment
                    // the session's staged batch frames are owed a write. Cleared BEFORE
                    // the hook runs, so a message staged while it runs raises the flag
                    // again and wakes the next wait.
                    Taken::Empty if !idle_hook_ran => {
                        let hook = self
                            .shared
                            .idle_hook
                            .lock()
                            .expect("idle hook poisoned")
                            .clone();
                        if let Some(hook) = hook {
                            idle_hook_ran = true;
                            // Cleared before the hook runs, and only a flag that stood means
                            // something was staged since the last flush: no wait for a
                            // writer that is merely going to sleep.
                            if self.shared.flush_wanted.swap(false, Ordering::SeqCst)
                                && self.let_producers_finish().await
                            {
                                // A frame landed while the producers were still staging: take
                                // it. The open frames stay open for the next idle, which the
                                // request raised again will coalesce and then flush.
                                idle_hook_ran = false;
                                self.shared.flush_wanted.store(true, Ordering::SeqCst);
                                continue;
                            }
                            hook();
                            continue;
                        }
                    }
                    // Empty and not finished, or a lend in progress at the head
                    // of the highest lane: a send, a commit, an abort or the
                    // last sender's drop notifies.
                    _ => {}
                }
            }
            // About to wait for work: the role is not held across the wait, so a sender
            // that stages a lone message can flush it itself.
            drop(role);
            notified.await;
            // Woken: something was sent, staged or closed, and the hook is owed a run
            // before the writer waits again. Left set, it would let a message staged
            // after the first idle spell sit unflushed until the next unrelated wake.
            idle_hook_ran = false;
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

    /// R3239 — [`Self::try_recv_tagged`] as the [`WireFrame`] the queue holds.
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

    /// R3366 — [`Self::recv_wire_packed`] when something is queued right now. For
    /// a test that must ask without waiting.
    #[cfg(test)]
    pub(crate) fn try_recv_wire_packed(&mut self) -> Option<WireFrame> {
        let (taken, freed) = {
            let mut st = self.shared.state.lock().expect("outbound lanes poisoned");
            let budget = st.batch_bytes.max(1);
            st.take_next_packed(budget)
        };
        if freed {
            self.shared.room.notify_all();
        }
        match taken {
            Taken::Frame(_, out) => Some(self.wire(out)),
            _ => None,
        }
    }

    /// The writer's handle on what [`LaneState::take_next`] took.
    fn wire(&self, out: Out) -> WireFrame {
        self.shared.make_wire(out)
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
        // R3239 — nothing will write what is still queued, so a pooled queue's
        // slots go home now rather than when the last sender lets go: a closing
        // connection returns its slots.
        #[cfg(feature = "runtime-zero-copy")]
        {
            if let Ok(mut st) = self.shared.state.lock() {
                st.release_unwritten();
            }
            self.shared.room.notify_all();
        }
        // What a sender left half written: dropped outside the lock, because a pooled frame's
        // drop takes it, and a frame that holds its queue must not be kept by it.
        let carried = self
            .shared
            .state
            .lock()
            .ok()
            .and_then(|mut st| st.carry.take());
        drop(carried);
    }
}

/// R3239 — what the writer is handed: a frame (or, on a pooled queue, a run of
/// frames packed into one slot), readable as bytes.
///
/// A heap queue hands over the vector the sender enqueued, as it always did. A
/// pooled queue hands over a SLOT of the link's transmit pool, armed for the
/// write: [`Self::begin_write`] starts it, and the slot goes home through the
/// generated pool's completion edge when the frame is handed back with
/// [`OutboundQueue::recycle_wire`] or dropped, so no path out of a writer can
/// keep it.
///
/// The second field is the role (`Lanes::role`) the thread that took it holds until it has
/// written it: dropped with the frame, so no way out of a writer keeps it.
pub struct WireFrame(Wire, Option<RoleGuard>);

enum Wire {
    Heap(Vec<u8>),
    #[cfg(feature = "runtime-zero-copy")]
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
            #[cfg(feature = "runtime-zero-copy")]
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
            #[cfg(feature = "runtime-zero-copy")]
            Wire::Slot(slot) => Some(slot.idx),
        }
    }

    /// The size class of that slot (0 the smallest), if the bytes lie in one.
    pub fn slot_class(&self) -> Option<usize> {
        match &self.0 {
            Wire::Heap(_) => None,
            #[cfg(feature = "runtime-zero-copy")]
            Wire::Slot(slot) => Some(slot.class),
        }
    }

    /// R3240 — the frame as `bytes::Bytes` for a library that takes
    /// ownership of the buffer it sends (quinn's `send_datagram`). A heap
    /// frame's vector moves in; a pooled frame's SLOT moves in as the `Bytes`' owner
    /// (`Bytes::from_owner`), so the library reads the slot in place and the
    /// slot goes home through the completion edge when the library drops the
    /// last clone: the write ended when the library has done with the bytes,
    /// which for quinn is after it has packetised them. The write is started
    /// here and counted as written, since the library has accepted the bytes.
    ///
    /// The one allocation this costs is the library's, not a copy: `from_owner`
    /// boxes its owner (bytes 1.11 `Bytes::from_owner`), one small allocation
    /// per frame and no copy of the frame's bytes.
    #[cfg(feature = "transport-link-quic-datagram")]
    pub fn into_bytes(mut self) -> bytes::Bytes {
        self.begin_write();
        match self.0 {
            Wire::Heap(bytes) => bytes::Bytes::from(bytes),
            #[cfg(feature = "runtime-zero-copy")]
            Wire::Slot(mut slot) => {
                slot.written = true;
                bytes::Bytes::from_owner(SlotBytes(slot))
            }
        }
    }
}

/// R3240 — a writer's slot as the owner of a `bytes::Bytes`.
#[cfg(all(
    feature = "runtime-zero-copy",
    feature = "transport-link-quic-datagram"
))]
struct SlotBytes(SlotWire);

#[cfg(all(
    feature = "runtime-zero-copy",
    feature = "transport-link-quic-datagram"
))]
impl AsRef<[u8]> for SlotBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl WireFrame {
    /// The writer is about to write this frame: a pooled slot moves from armed
    /// to busy. Idempotent, and a no-op for a heap frame.
    pub fn begin_write(&mut self) {
        #[cfg(feature = "runtime-zero-copy")]
        if let Wire::Slot(slot) = &mut self.0 {
            slot.begin();
        }
    }

    /// The first `n` bytes are written: what is left is the frame. A heap frame moves its tail
    /// down; a pooled one moves where its bytes start, and goes home whole as it always does.
    fn advance(&mut self, n: usize) {
        match &mut self.0 {
            Wire::Heap(bytes) => {
                bytes.drain(..n);
            }
            #[cfg(feature = "runtime-zero-copy")]
            Wire::Slot(slot) => {
                slot.base += n;
                slot.len -= n;
            }
        }
    }

    /// The same frame, with the role its taker holds (`Lanes::role`) kept until it drops.
    fn holding(mut self, role: Option<RoleGuard>) -> Self {
        self.1 = role;
        self
    }
}

impl std::ops::Deref for WireFrame {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match &self.0 {
            Wire::Heap(bytes) => bytes,
            #[cfg(feature = "runtime-zero-copy")]
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
        Self(Wire::Heap(bytes), None)
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

/// R3239 — one slot of a pooled queue, in the writer's hands.
///
/// Armed when the writer took it off its lane; busy once [`Self::begin`] ran.
/// Its `Drop` is the way home in every case, by the edge the state names: a
/// busy slot's write has ended (written, failed, or the writer was stopped in
/// it), so it takes the completion edge; an armed one was never started, so it
/// is un-armed and returned. Holding the queue's shared state is what keeps the
/// pool, and so the slot's bytes, alive while the writer reads them.
#[cfg(feature = "runtime-zero-copy")]
struct SlotWire {
    home: Arc<Lanes>,
    /// The size class and the slot's index in it.
    class: usize,
    idx: usize,
    /// First byte of the slot, by the pool's own answer for an armed slot.
    base: usize,
    len: usize,
    started: bool,
    /// The write ended with every byte written (`recycle_wire`), as opposed to
    /// a failed or abandoned one; only the counters read it.
    written: bool,
}

#[cfg(feature = "runtime-zero-copy")]
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
            st.pool
                .as_mut()
                .map(|pool| pool.class(self.class).start(self.idx))
        };
        self.started = started == Some(true);
        // With the lock released, for the reason `Drop` gives.
        debug_assert!(started != Some(false), "the slot the writer took is armed");
    }
}

#[cfg(feature = "runtime-zero-copy")]
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
                Some(pool) if self.started => {
                    pool.class(self.class).complete(self.idx, self.written)
                }
                Some(pool) => pool.class(self.class).unarm(self.idx),
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

    /// R3239 — the writer has written `wire` out: a heap frame's buffer is kept
    /// to be lent again ([`Self::recycle`]); a pooled frame's slot goes home
    /// through the completion edge, counted as written.
    pub fn recycle_wire(&self, wire: WireFrame) {
        self.rx.recycle_wire(wire);
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

    /// R3239 — [`Self::next`] as the [`WireFrame`] the queue holds, which is
    /// what a writer of a pooled queue takes: it starts the frame
    /// ([`WireFrame::begin_write`]), writes it, and hands it back
    /// ([`Self::recycle_wire`]) or drops it.
    pub async fn next_wire(&mut self) -> Option<WireFrame> {
        self.next_wire_with(false).await
    }

    /// R3366 — [`Self::next_wire`] for a BYTE-STREAM writer: what is queued, up
    /// to a batch, as one buffer ([`OutboundRx::recv_wire_packed`]). The seal
    /// behaves exactly as it does there.
    pub async fn next_wire_packed(&mut self) -> Option<WireFrame> {
        self.next_wire_with(true).await
    }

    async fn next_wire_with(&mut self, packed: bool) -> Option<WireFrame> {
        loop {
            if self.sealed || self.seal.is_none() {
                return self.rx.recv_wire_mode(packed).await;
            }
            let seal = self.seal.as_mut().expect("checked directly above");
            let mut sealed_now = false;
            let frame = tokio::select! {
                biased;
                frame = self.rx.recv_wire_mode(packed) => Some(frame),
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

    /// A link a test writes through ([`InlineWrite`]): it takes at most `chunk` bytes of a
    /// write, answers `WouldBlock` to every `block_every`th call (never when that is 0), and
    /// keeps what it took, in the order it took it.
    struct FakeLink {
        taken: Mutex<Vec<u8>>,
        calls: AtomicUsize,
        chunk: usize,
        block_every: usize,
    }

    impl FakeLink {
        fn new(chunk: usize, block_every: usize) -> Arc<Self> {
            Arc::new(Self {
                taken: Mutex::new(Vec::new()),
                calls: AtomicUsize::new(0),
                chunk,
                block_every,
            })
        }

        fn bytes(&self) -> Vec<u8> {
            self.taken.lock().expect("fake link").clone()
        }
    }

    impl InlineWrite for FakeLink {
        fn try_write(&self, buf: &[u8]) -> std::io::Result<usize> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.block_every != 0 && call % self.block_every == 0 {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            let take = buf.len().min(self.chunk);
            self.taken
                .lock()
                .expect("fake link")
                .extend_from_slice(&buf[..take]);
            Ok(take)
        }
    }

    /// The line has spoken when a write FINISHES, not when a frame is queued: a queue that has
    /// had frames handed to it and written none reports no write, and one the writer has
    /// finished with reports the time since.
    #[tokio::test]
    async fn the_write_report_moves_when_the_writer_finishes_and_not_when_a_frame_is_queued() {
        let (tx, mut rx) = outbound_channel();
        assert_eq!(tx.ms_since_wire_write(), None, "nothing written yet");

        tx.send(Priority::Data, b"frame".to_vec()).expect("open");
        assert_eq!(
            tx.ms_since_wire_write(),
            None,
            "a queued frame has not been written"
        );

        let wire = rx.recv_wire().await.expect("the frame");
        assert_eq!(
            tx.ms_since_wire_write(),
            None,
            "a frame the writer has taken but not finished has not been written"
        );
        rx.recycle_wire(wire);
        let ago = tx
            .ms_since_wire_write()
            .expect("the writer finished a write");
        assert!(ago < 1_000, "the report is the time since: {ago} ms");
    }

    /// The thread that carries session liveness writes a keepalive without the writer, and takes
    /// nothing but it: the data queued beside it stays for the writer. The queue puts every
    /// frame in one lane (no QoS), which is the case that has no control lane to take from.
    #[tokio::test]
    async fn an_urgent_frame_is_written_inline_ahead_of_the_data() {
        let (tx, rx) = outbound_channel();
        rx.shared.state.lock().expect("lanes").single_lane = true;
        let link = FakeLink::new(usize::MAX, 0);
        tx.set_inline_write(link.clone());
        tx.send(Priority::Control, b"data".to_vec()).expect("open");

        tx.send_urgent(b"keepalive".to_vec()).expect("open");

        assert_eq!(link.bytes(), b"keepalive", "only the urgent frame left");
        assert!(rx.shared.has_queued(), "the data is still the writer's");
        assert!(
            tx.ms_since_wire_write().is_some(),
            "a finished urgent write is the line speaking"
        );
    }

    /// Without a way to write from another thread an urgent frame waits for the writer, which
    /// takes it before every lane at its next frame boundary, whatever the lanes hold.
    #[tokio::test]
    async fn an_urgent_frame_is_the_writers_next_frame_whatever_the_lanes_hold() {
        let (tx, mut rx) = outbound_channel();
        tx.send(Priority::Data, b"first".to_vec()).expect("open");
        tx.send(Priority::Data, b"second".to_vec()).expect("open");
        tx.send_urgent(b"keepalive".to_vec()).expect("open");

        assert_eq!(rx.recv().await.expect("a frame"), b"keepalive");
        assert_eq!(rx.recv().await.expect("a frame"), b"first");
        assert_eq!(rx.recv().await.expect("a frame"), b"second");
    }

    /// An urgent frame is never refused for room: a full lane is where a keepalive is most
    /// needed, and the lane's bound does not count it.
    #[tokio::test]
    async fn an_urgent_frame_is_not_counted_against_a_lane() {
        let (tx, rx) = outbound_channel_with_capacity([1; Priority::NUM], 1);
        tx.send(Priority::Data, vec![0u8; 64]).expect("open");
        let occupied = rx.shared.state.lock().expect("lanes").occupied;

        tx.send_urgent(b"keepalive".to_vec()).expect("open");

        assert_eq!(
            rx.shared.state.lock().expect("lanes").occupied,
            occupied,
            "no lane's bytes moved"
        );
    }

    /// An urgent frame does not start past the rest of a partly written one: the carry goes
    /// first, so the bytes of two frames never interleave.
    #[tokio::test]
    async fn an_urgent_frame_waits_for_the_carried_rest_of_a_frame() {
        let (tx, rx) = outbound_channel();
        // Takes three bytes a call, and blocks on every second call.
        let link = FakeLink::new(3, 2);
        tx.set_inline_write(link.clone());
        tx.send(Priority::Data, b"abcdef".to_vec()).expect("open");
        // The writer's own inline write takes "abc" and leaves "def" in the carry.
        assert!(rx.shared.write_inline(link.as_ref()), "the rest is carried");
        assert_eq!(link.bytes(), b"abc", "the link took part of the frame");

        tx.send_urgent(b"KA".to_vec()).expect("open");

        assert_eq!(
            link.bytes(),
            b"abcdef",
            "the carried rest is written first; the keepalive after it, not inside it"
        );
        assert!(rx.shared.has_queued(), "the keepalive waits in the carry");
    }

    /// A lone message staged on a link that can be written from a sender's thread is flushed,
    /// written and finished by that thread, and the writer is not woken for it: nothing is
    /// queued and no wake-up is waiting.
    #[tokio::test]
    async fn a_lone_message_is_flushed_by_its_sender_and_the_writer_is_not_woken() {
        let (tx, rx) = outbound_channel();
        let link = FakeLink::new(usize::MAX, 0);
        tx.set_inline_write(link.clone());
        let hook_tx = tx.clone();
        tx.set_idle_hook(Arc::new(move || {
            let _ = hook_tx.send(Priority::DEFAULT, b"frame".to_vec());
        }));

        tx.wake_for_flush();

        assert_eq!(link.bytes(), b"frame", "the sender wrote its own message");
        assert!(
            !rx.shared.has_queued(),
            "and nothing is left for the writer"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(30), rx.shared.ready.notified())
                .await
                .is_err(),
            "the writer was not woken: the flush did not hand it a frame"
        );
    }

    /// A write the link takes part of leaves the rest in the carry for the writer, who writes
    /// it before anything staged after it, and is woken to.
    #[tokio::test]
    async fn the_rest_of_a_partly_written_frame_goes_to_the_writer_first() {
        let (tx, mut rx) = outbound_channel();
        // Three bytes, then the link blocks.
        let link = FakeLink::new(3, 2);
        tx.set_inline_write(link.clone());
        let hook_tx = tx.clone();
        tx.set_idle_hook(Arc::new(move || {
            let _ = hook_tx.send(Priority::DEFAULT, b"abcdefgh".to_vec());
        }));

        tx.wake_for_flush();

        assert_eq!(link.bytes(), b"abc", "the link took three bytes of it");
        assert!(
            tokio::time::timeout(Duration::from_secs(5), rx.shared.ready.notified())
                .await
                .is_ok(),
            "the writer is woken for the rest"
        );
        // Staged after the part write, so it must come after the rest.
        tx.send(Priority::DEFAULT, b"next".to_vec()).expect("send");
        let rest = rx.recv_wire_packed().await.expect("the carried rest");
        assert_eq!(
            &*rest, b"defgh",
            "the rest comes first, from where the link stopped"
        );
        rx.recycle_wire(rest);
        let next = rx.recv_wire_packed().await.expect("the frame behind it");
        assert_eq!(&*next, b"next");
        rx.recycle_wire(next);
    }

    /// A stream is not flushed message by message by its senders: when many messages were
    /// staged since the last flush the writer coalesces them, and a sender that wrote its own
    /// would make a system call of each.
    #[tokio::test]
    async fn a_stream_is_left_to_the_writer() {
        let (tx, rx) = outbound_channel();
        let link = FakeLink::new(usize::MAX, 0);
        tx.set_inline_write(link.clone());
        tx.shared.staged.fetch_add(10, Ordering::Relaxed);

        tx.wake_for_flush();

        assert!(link.bytes().is_empty(), "no sender wrote anything");
        assert!(
            tokio::time::timeout(Duration::from_secs(5), rx.shared.ready.notified())
                .await
                .is_ok(),
            "the writer is woken to flush, as it always was"
        );
    }

    /// A sender that finds a flush has just run does not flush its own message, however few
    /// were staged since: one sender of a stream always finds only its own, and a flush per
    /// message would turn the stream into a system call each. The last flush is put in the
    /// future so that no clock can make this pass by chance.
    #[tokio::test]
    async fn a_message_right_after_a_flush_is_left_to_the_writer() {
        let (tx, rx) = outbound_channel();
        let link = FakeLink::new(usize::MAX, 0);
        tx.set_inline_write(link.clone());
        let hook_tx = tx.clone();
        tx.set_idle_hook(Arc::new(move || {
            let _ = hook_tx.send(Priority::DEFAULT, b"frame".to_vec());
        }));
        let in_a_minute = tx.shared.now_ns() + 60_000_000_000;
        tx.shared
            .last_flush_ns
            .store(in_a_minute, Ordering::Relaxed);

        tx.wake_for_flush();

        assert!(link.bytes().is_empty(), "no sender wrote anything");
        assert!(
            tokio::time::timeout(Duration::from_secs(5), rx.shared.ready.notified())
                .await
                .is_ok(),
            "the writer is woken to flush, as it always was"
        );

        // And the same queue, quiet again, is flushed by its sender.
        tx.shared
            .last_flush_ns
            .store(NEVER_FLUSHED, Ordering::Relaxed);
        tx.shared.flush_wanted.store(false, Ordering::SeqCst);
        tx.wake_for_flush();
        assert_eq!(
            link.bytes(),
            b"frame",
            "a quiet link's message is flushed inline"
        );
    }

    /// A queue nothing will read is not written through: its senders flush nothing.
    #[tokio::test]
    async fn a_closed_queue_is_not_written_through() {
        let (tx, rx) = outbound_channel();
        let link = FakeLink::new(usize::MAX, 0);
        tx.set_inline_write(link.clone());
        let hook_tx = tx.clone();
        tx.set_idle_hook(Arc::new(move || {
            let _ = hook_tx.send(Priority::DEFAULT, b"late".to_vec());
        }));
        drop(rx);

        tx.wake_for_flush();

        assert!(link.bytes().is_empty(), "a closed queue wrote nothing");
    }

    /// Several senders flushing their own messages, and a writer, over a link that takes a
    /// few bytes at a time and sometimes none: whichever thread takes a frame writes it before
    /// another thread takes the next, and what a sender could not finish the writer does first.
    /// The bytes that reach the link are every frame, once, in each sender's order, and no
    /// frame is cut by another's. Run 25 times over fresh queues, since what it looks for
    /// is a race that one run may not meet.
    #[test]
    fn senders_that_write_their_own_messages_and_the_writer_keep_the_stream_in_order() {
        let mut inline_flushes = 0;
        for _round in 0..25 {
            inline_flushes += one_race_of_senders_and_the_writer();
        }
        // Most attempts find the role held (four senders and a writer contend for it); a few
        // hundred that get it are each a flush whose rest the writer must finish.
        assert!(
            inline_flushes > 100,
            "the race must reach the senders' own flush ({inline_flushes} of 150000 tries)"
        );
    }

    /// One run of the race described above; how many messages a sender flushed itself.
    fn one_race_of_senders_and_the_writer() -> usize {
        const SENDERS: u8 = 4;
        const EACH: u32 = 3000;
        const FRAME: usize = 6;
        let (tx, mut rx) = outbound_channel();
        // Five bytes at a time, against six-byte frames, with every third write refused.
        let link = FakeLink::new(5, 3);
        tx.set_inline_write(link.clone());

        let writer_link = link.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async move {
                while let Some(mut wire) = rx.recv_wire_packed().await {
                    wire.begin_write();
                    let mut at = 0;
                    while at < wire.len() {
                        match writer_link.try_write(&wire[at..]) {
                            Ok(n) if n > 0 => at += n,
                            _ => tokio::task::yield_now().await,
                        }
                    }
                    rx.recycle_wire(wire);
                }
            });
            let _ = done_tx.send(());
        });

        let hits = Arc::new(AtomicUsize::new(0));
        let senders: Vec<_> = (0..SENDERS)
            .map(|sender| {
                let tx = tx.clone();
                let hits = hits.clone();
                std::thread::spawn(move || {
                    for seq in 0..EACH {
                        let s = seq.to_le_bytes();
                        let frame = vec![sender, s[0], s[1], s[2], s[3], sender ^ s[0] ^ s[3]];
                        tx.send(Priority::DEFAULT, frame).expect("send");
                        if seq % 2 == 0 {
                            // As a sender of a lone message finds the queue: nothing staged
                            // since the last flush. Asked directly, so that the race does not
                            // depend on the flush-wanted flag the writer clears.
                            let staged = tx.shared.staged.fetch_add(1, Ordering::Relaxed) + 1;
                            tx.shared
                                .staged_at_flush
                                .store(staged - 1, Ordering::Relaxed);
                            tx.shared
                                .last_flush_ns
                                .store(NEVER_FLUSHED, Ordering::Relaxed);
                            if tx.flush_inline(staged) {
                                hits.fetch_add(1, Ordering::Relaxed);
                            } else {
                                tx.shared.ready.notify_one();
                            }
                        } else {
                            tx.wake_for_flush();
                        }
                    }
                })
            })
            .collect();
        for sender in senders {
            sender.join().expect("a sender thread");
        }
        drop(tx);
        done_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("the writer never finished: a wake-up was lost");
        writer.join().expect("the writer thread");

        let bytes = link.bytes();
        assert_eq!(
            bytes.len(),
            SENDERS as usize * EACH as usize * FRAME,
            "every frame arrived once"
        );
        let mut next = [0u32; SENDERS as usize];
        for frame in bytes.chunks_exact(FRAME) {
            let sender = frame[0] as usize;
            assert!(
                sender < SENDERS as usize,
                "a frame cut by another's: {frame:?}"
            );
            assert_eq!(
                frame[5],
                frame[0] ^ frame[1] ^ frame[4],
                "a frame cut by another's: {frame:?}"
            );
            let seq = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]);
            assert_eq!(seq, next[sender], "sender {sender}'s frames out of order");
            next[sender] += 1;
        }
        assert!(next.iter().all(|n| *n == EACH));
        hits.load(Ordering::Relaxed)
    }

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

    /// A link that asks for a batch-sized buffer gets that buffer back: the session builds
    /// every frame in one of a batch's size, so freeing it on the way back (it is past the
    /// default bound) made each frame a fresh allocation of a batch.
    #[test]
    fn a_buffer_of_the_size_the_link_asked_for_is_kept_and_lent_again() {
        let batch = 49_154;
        let (tx, rx) = outbound_channel();
        // CONTROL: before the link has asked for that size, a buffer of it is freed.
        rx.recycle(buffer_of(batch));
        assert_eq!(tx.spare_count(), 0, "CONTROL: past the default bound");
        let first = tx.take_buffer(batch);
        let at = first.as_ptr();
        rx.recycle(first);
        assert_eq!(tx.spare_count(), 1, "the buffer the link asked for is kept");
        let again = tx.take_buffer(batch);
        assert_eq!(again.as_ptr(), at, "and it is the one lent again");
        assert!(again.is_empty());
    }

    /// What a link asks for raises the bound only to the largest frame there is.
    #[test]
    fn a_request_past_the_largest_frame_does_not_raise_the_bound_past_it() {
        let (tx, rx) = outbound_channel();
        let huge = tx.take_buffer(SPARE_CAPACITY_CEIL * 4);
        rx.recycle(huge);
        assert_eq!(tx.spare_count(), 0, "a buffer past the ceiling is freed");
        rx.recycle(buffer_of(SPARE_CAPACITY_CEIL));
        assert_eq!(tx.spare_count(), 1, "CONTROL: one at the ceiling is kept");
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

    /// R3366 — a byte-stream writer takes everything that is queued as ONE buffer,
    /// and that buffer is the frames in exactly the order they would have left one
    /// by one (the test above), so the wire it makes is the same wire.
    #[tokio::test]
    async fn a_stream_writer_takes_what_is_queued_as_one_buffer_in_the_one_by_one_order() {
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

        let wire = rx.recv_wire_packed().await.expect("a buffer").into_vec();
        assert_eq!(wire, b"ctlrtdatabg-1bg-2");
        assert!(
            rx.recv_wire_packed().await.is_none(),
            "all of it left in the one take"
        );
    }

    /// R3366 — a frame that is alone is handed over as it is: no copy, and so no
    /// cost for the link that is never busy. Packing only ever starts at the second
    /// frame.
    #[tokio::test]
    async fn a_lone_queued_frame_is_taken_whole_and_uncopied() {
        let (tx, mut rx) = outbound_channel();
        let frame = b"only".to_vec();
        let at = frame.as_ptr();
        tx.send(Priority::Data, frame).expect("enqueue");

        let wire = rx.recv_wire_packed().await.expect("a frame").into_vec();
        assert_eq!(wire, b"only");
        assert_eq!(wire.as_ptr(), at, "the buffer itself, not a copy of it");
    }

    /// R3366 — the take stops at the batch size and splits no frame: what does not
    /// fit stays queued, whole, for the next take; and a frame larger than the
    /// budget is still taken (alone), because a frame is the unit and a budget
    /// cannot make it smaller.
    #[tokio::test]
    async fn the_packed_take_stops_at_the_budget_and_splits_no_frame() {
        let (tx, mut rx) = outbound_channel_with_capacity([8; Priority::NUM], 10);
        for frame in [b"aaaa", b"bbbb", b"cccc"] {
            tx.send(Priority::Data, frame.to_vec()).expect("enqueue");
        }
        let first = rx.recv_wire_packed().await.expect("a buffer").into_vec();
        assert_eq!(
            first, b"aaaabbbb",
            "8 of the 10, the next frame would be 12"
        );
        let second = rx.recv_wire_packed().await.expect("a buffer").into_vec();
        assert_eq!(second, b"cccc", "the frame that did not fit, whole");

        tx.send(Priority::Data, vec![7u8; 25]).expect("enqueue");
        tx.send(Priority::Data, b"after".to_vec()).expect("enqueue");
        let big = rx.recv_wire_packed().await.expect("a frame").into_vec();
        assert_eq!(big, vec![7u8; 25], "past the budget, taken alone");
        let after = rx.recv_wire_packed().await.expect("a frame").into_vec();
        assert_eq!(after, b"after");
    }

    /// R3366 — every frame of a packed take stays in its lane's occupancy until the
    /// writer asks for the next item, as one frame being written always has: the
    /// bound a sender waits on is not lowered by the take, only by the write that
    /// the next ask says is over. Two lanes are packed here, so the release has to
    /// reach both.
    #[test]
    fn a_packed_take_holds_each_lanes_bytes_until_the_next_ask() {
        let (tx, mut rx) = outbound_channel_with_capacity([2; Priority::NUM], 6);
        tx.send(Priority::Control, b"abc".to_vec())
            .expect("enqueue");
        tx.send(Priority::RealTime, b"def".to_vec())
            .expect("enqueue");
        let occupied = |rx: &OutboundRx| {
            let st = rx.shared.state.lock().expect("lanes");
            (
                st.occupied[Priority::Control.wire_byte() as usize],
                st.occupied[Priority::RealTime.wire_byte() as usize],
            )
        };
        assert_eq!(occupied(&rx), (3, 3), "queued");

        let wire = rx.try_recv_wire_packed().expect("a buffer").into_vec();
        assert_eq!(wire, b"abcdef", "both lanes in one buffer");
        assert_eq!(occupied(&rx), (3, 3), "still held while it is written");

        assert!(rx.try_recv_wire_packed().is_none(), "nothing more queued");
        assert_eq!(occupied(&rx), (0, 0), "released by the next ask, in both");
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

    /// A sender that holds its messages for a full lane, in place of waiting on a thread, is told
    /// when room is made: the watcher is called when the writer takes a frame and again when it
    /// asks for the next (which is when the lane is free), not before and not after it was
    /// cleared. A queue nobody watches calls nothing.
    #[test]
    fn a_watcher_is_called_when_room_is_made_and_only_while_it_is_set() {
        let (tx, mut rx) = outbound_channel_with_capacity([1; Priority::NUM], 4);
        let called = Arc::new(AtomicUsize::new(0));
        let waker: Arc<dyn Fn() + Send + Sync> = {
            let called = Arc::clone(&called);
            Arc::new(move || {
                called.fetch_add(1, Ordering::SeqCst);
            })
        };
        tx.send(Priority::Data, vec![1u8; 4]).expect("enqueue");
        tx.send(Priority::Data, vec![2u8; 4]).expect("enqueue");

        // Not set yet: the writer taking a frame calls nobody.
        assert!(rx.try_recv().is_some());
        assert_eq!(called.load(Ordering::SeqCst), 0, "nothing was watching");

        tx.watch_room(Some(Arc::clone(&waker)));
        assert!(
            rx.try_recv().is_some(),
            "the writer asks for the next frame"
        );
        assert!(
            called.load(Ordering::SeqCst) >= 1,
            "the lane's first frame was written, which is room, and the watcher was told"
        );

        let before = called.load(Ordering::SeqCst);
        tx.watch_room(None);
        tx.send(Priority::Data, vec![3u8; 4]).expect("enqueue");
        assert!(rx.try_recv().is_some());
        assert!(rx.try_recv().is_none());
        assert_eq!(
            called.load(Ordering::SeqCst),
            before,
            "a cleared watcher is not called"
        );
    }

    /// A waker that counts how many times it was woken, for a test that polls by hand.
    struct CountingWake(AtomicUsize);

    impl std::task::Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counting_waker() -> (Arc<CountingWake>, std::task::Waker) {
        let counter = Arc::new(CountingWake(AtomicUsize::new(0)));
        let waker = std::task::Waker::from(Arc::clone(&counter));
        (counter, waker)
    }

    fn polled(
        tx: &OutboundTx,
        waker: &std::task::Waker,
    ) -> std::task::Poll<Result<Permit, ReserveError>> {
        let mut cx = std::task::Context::from_waker(waker);
        tx.poll_reserve(&mut cx, Priority::Data)
    }

    /// A lane of two batches of four bytes: two permits fit and a third does not. The promise
    /// counts against room as a frame does, and the other way: a wait that asks the old way
    /// finds a lane full of promises full, so that the two kinds of sender are never given the
    /// same room.
    #[test]
    fn a_permit_takes_room_that_a_waiting_sender_would_have_been_given() {
        let (tx, _rx) = outbound_channel_with_capacity([2; Priority::NUM], 4);
        let first = tx.try_reserve(Priority::Data).expect("the first fits");
        let second = tx.try_reserve(Priority::Data).expect("the second fits");
        assert_eq!(
            tx.try_reserve(Priority::Data).err(),
            Some(ReserveError::Full),
            "two batches are promised"
        );
        assert_eq!(
            tx.wait_for_room(Priority::Data, block(Duration::ZERO)),
            Room::Congested,
            "and a sender that asks for room the other way is told so"
        );
        assert!(
            tx.try_reserve(Priority::RealTime).is_ok(),
            "another lane's room is its own"
        );
        drop(second);
        assert_eq!(
            tx.wait_for_room(Priority::Data, block(Duration::ZERO)),
            Room::Free,
            "a permit that is dropped unused gives its room back"
        );
        drop(first);
    }

    /// Sending with a permit turns the promise into a frame, exactly once: the lane holds one
    /// frame and no promise, so the room is neither counted twice nor lost, and the frame is
    /// the writer's.
    #[test]
    fn sending_with_a_permit_turns_the_promise_into_the_frame_and_nothing_stays_promised() {
        let (tx, mut rx) = outbound_channel_with_capacity([2; Priority::NUM], 4);
        let permit = tx.try_reserve(Priority::Data).expect("room");
        tx.send_reserved(permit, Priority::Data, vec![7u8; 4])
            .expect("the queue is open");
        let second = tx
            .try_reserve(Priority::Data)
            .expect("one batch is held, one is free");
        assert_eq!(
            tx.try_reserve(Priority::Data).err(),
            Some(ReserveError::Full),
            "one frame and one promise fill two batches, and the sent permit promises nothing more"
        );
        drop(second);
        assert_eq!(
            rx.try_recv(),
            Some(vec![7u8; 4]),
            "the frame is the writer's"
        );
        assert!(rx.try_recv().is_none(), "and the writer asks for the next");
        assert!(
            tx.try_reserve(Priority::Data).is_ok() && tx.try_reserve(Priority::Data).is_ok(),
            "the lane is empty and promised nothing: both batches are free again"
        );
    }

    /// Sending with one permit gives back that permit's room and no other's: while another sender
    /// still holds its promise, the lane stays as full as the two of them make it. With only one
    /// permit out a double release would be hidden (the count cannot go below zero), so the case
    /// is made with two.
    #[test]
    fn sending_with_a_permit_does_not_give_back_the_room_another_still_holds() {
        let (tx, _rx) = outbound_channel_with_capacity([2; Priority::NUM], 4);
        let other = tx.try_reserve(Priority::Data).expect("room");
        let mine = tx.try_reserve(Priority::Data).expect("room");
        tx.send_reserved(mine, Priority::Data, vec![1u8; 4])
            .expect("open");
        assert_eq!(
            tx.try_reserve(Priority::Data).err(),
            Some(ReserveError::Full),
            "one promise and one frame fill two batches, whatever was given back for the frame"
        );
        drop(other);
        assert!(
            tx.try_reserve(Priority::Data).is_ok(),
            "and the promise that is dropped is the room that comes back"
        );
    }

    /// A sender that finds no room is woken when there is some, once, and has to ask again: the
    /// writer taking a frame is room, a permit being dropped is room, and the queue closing is an
    /// answer. Each is a separate case because each is a different notice.
    #[test]
    fn a_task_waiting_for_a_permit_is_woken_by_each_way_room_is_made() {
        // The writer takes a frame.
        let (tx, mut rx) = outbound_channel_with_capacity([1; Priority::NUM], 4);
        tx.send(Priority::Data, vec![1u8; 4])
            .expect("fills the lane");
        let (woken, waker) = counting_waker();
        assert!(polled(&tx, &waker).is_pending(), "no room");
        assert_eq!(woken.0.load(Ordering::SeqCst), 0, "and not woken yet");
        assert!(rx.try_recv().is_some());
        assert!(
            rx.try_recv().is_none(),
            "the writer asks for the next: that frees the lane"
        );
        assert_eq!(
            woken.0.load(Ordering::SeqCst),
            1,
            "woken by the writer, once"
        );
        assert!(matches!(polled(&tx, &waker), std::task::Poll::Ready(Ok(_))));

        // A permit is dropped.
        let (tx, _rx) = outbound_channel_with_capacity([1; Priority::NUM], 4);
        let held = tx.try_reserve(Priority::Data).expect("room");
        let (woken, waker) = counting_waker();
        assert!(polled(&tx, &waker).is_pending());
        drop(held);
        assert_eq!(
            woken.0.load(Ordering::SeqCst),
            1,
            "woken by the room a permit gave back"
        );
        assert!(matches!(polled(&tx, &waker), std::task::Poll::Ready(Ok(_))));

        // The queue closes.
        let (tx, mut rx) = outbound_channel_with_capacity([1; Priority::NUM], 4);
        tx.send(Priority::Data, vec![1u8; 4])
            .expect("fills the lane");
        let (woken, waker) = counting_waker();
        assert!(polled(&tx, &waker).is_pending());
        rx.close();
        assert_eq!(woken.0.load(Ordering::SeqCst), 1, "woken by the close");
        assert!(matches!(
            polled(&tx, &waker),
            std::task::Poll::Ready(Err(ReserveError::Closed))
        ));
    }

    /// The same task polled twice while it waits is registered once, and a task that was woken and
    /// asked again by someone else first waits again: a wake-up is a reason to ask and not a grant.
    #[test]
    fn a_waiting_task_is_registered_once_and_waits_again_when_the_room_was_taken() {
        let (tx, _rx) = outbound_channel_with_capacity([1; Priority::NUM], 4);
        let held = tx.try_reserve(Priority::Data).expect("room");
        let (woken, waker) = counting_waker();
        assert!(polled(&tx, &waker).is_pending());
        assert!(polled(&tx, &waker).is_pending());
        assert!(polled(&tx, &waker).is_pending());
        drop(held);
        assert_eq!(
            woken.0.load(Ordering::SeqCst),
            1,
            "three polls of one task, one wake-up"
        );
        // Another sender takes the room before the woken task asks again.
        let thief = tx
            .try_reserve(Priority::Data)
            .expect("the room is free for anyone");
        assert!(
            polled(&tx, &waker).is_pending(),
            "the woken task finds it taken and waits again"
        );
        drop(thief);
        assert_eq!(woken.0.load(Ordering::SeqCst), 2, "and is woken again");
    }

    /// The mark of R2923 is the caller's to read and raise, because the deadline is the caller's:
    /// a sender that waited its own time out marks the lane, a droppable sender asks before it
    /// waits, and a later reservation lowers it.
    #[test]
    fn the_congested_mark_is_the_callers_to_raise_and_a_reservation_lowers_it() {
        let (tx, _rx) = outbound_channel_with_capacity([1; Priority::NUM], 4);
        assert!(!tx.is_congested(Priority::Data));
        tx.mark_congested(Priority::Data);
        assert!(tx.is_congested(Priority::Data));
        assert!(
            !tx.is_congested(Priority::RealTime),
            "the mark is the lane's own"
        );
        let permit = tx.try_reserve(Priority::Data).expect("there is room");
        assert!(
            !tx.is_congested(Priority::Data),
            "a reservation that found room lowers the mark, as a wait that finds room does"
        );
        drop(permit);
    }

    /// Many tasks on a multi-thread runtime reserve and send through a lane of two batches while one
    /// thread writes: every frame arrives, nothing is promised at the end, and no task is left
    /// waiting for a wake-up that was lost. The bound on time is the test's: a lost wake-up would
    /// hang it, and a leaked promise would leave the lane full.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn many_tasks_reserving_and_sending_lose_no_frame_no_wakeup_and_no_room() {
        const TASKS: usize = 32;
        const PER_TASK: usize = 200;
        let (tx, mut rx) = outbound_channel_with_capacity([2; Priority::NUM], 4);
        let received = Arc::new(AtomicUsize::new(0));
        let writer = {
            let received = Arc::clone(&received);
            std::thread::spawn(move || {
                while received.load(Ordering::SeqCst) < TASKS * PER_TASK {
                    match rx.try_recv() {
                        Some(_) => {
                            received.fetch_add(1, Ordering::SeqCst);
                        }
                        None => std::thread::yield_now(),
                    }
                }
                rx
            })
        };
        let mut tasks = Vec::new();
        for _ in 0..TASKS {
            let tx = tx.clone();
            tasks.push(tokio::spawn(async move {
                for _ in 0..PER_TASK {
                    let permit = std::future::poll_fn(|cx| tx.poll_reserve(cx, Priority::Data))
                        .await
                        .expect("the queue stays open");
                    tx.send_reserved(permit, Priority::Data, vec![1u8; 4])
                        .expect("open");
                }
            }));
        }
        let all = async {
            for task in tasks {
                task.await.expect("a sending task");
            }
        };
        tokio::time::timeout(Duration::from_secs(60), all)
            .await
            .expect("every task finished: no wake-up was lost");
        let mut rx = writer.join().expect("the writer thread");
        assert_eq!(received.load(Ordering::SeqCst), TASKS * PER_TASK);
        assert!(rx.try_recv().is_none(), "nothing is left queued");
        assert_eq!(
            tx.wait_for_room(Priority::Data, block(Duration::ZERO)),
            Room::Free,
            "and nothing is promised: the lane is empty"
        );
        let first = tx
            .try_reserve(Priority::Data)
            .expect("both batches are free");
        let second = tx
            .try_reserve(Priority::Data)
            .expect("both batches are free");
        drop((first, second));
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

    /// How a test sender asks for room.
    type Through = Arc<dyn Fn(&OutboundTx, RoomWait) -> Room + Send + Sync>;

    /// The session's seam, [`OutboundTx::link_room_in`], under `budget`, its answer mapped back
    /// to [`Room`] for the comparison.
    fn through_link_room(budget: Arc<ParkBudget>) -> Through {
        Arc::new(
            move |tx, w| match tx.link_room_in(&budget, Priority::Data, w).room {
                wz_session_core::link::LinkRoom::Free => Room::Free,
                wz_session_core::link::LinkRoom::Congested => Room::Congested,
                wz_session_core::link::LinkRoom::Gone => Room::Closed,
            },
        )
    }

    /// The longest an unrelated 20 ms timer on a two-worker runtime was served late while
    /// `waiters` tasks each waited `wait` for room on a lane that never frees, `through` being
    /// how a task waits. A face whose peer stopped reading, with publishers that may not drop,
    /// is exactly this: many senders parked on a full lane. The question is whether the other
    /// faces' tasks, which share the workers, feel it.
    ///
    /// `blocking_cap` is the runtime's `max_blocking_threads`, which is what bounds how many
    /// waits can release a worker at once: the pool's own default is 50 (upstream's).
    fn timer_lateness_under_waiters(
        waiters: usize,
        blocking_cap: usize,
        wait: Duration,
        through: Through,
    ) -> (Duration, Vec<Room>) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(blocking_cap)
            .enable_time()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let (tx, _rx) = outbound_channel_with_capacity([1; Priority::NUM], 10);
            tx.send(Priority::Data, vec![0u8; 10]).expect("fill");
            let handles: Vec<_> = (0..waiters)
                .map(|_| {
                    let tx = tx.clone();
                    let through = Arc::clone(&through);
                    tokio::spawn(async move { through(&tx, block(wait)) })
                })
                .collect();
            // The timer starts once the waiters are queued, and runs for the whole wait.
            let mut worst = Duration::ZERO;
            let ends = Instant::now() + wait;
            while Instant::now() < ends {
                let planned = Duration::from_millis(20);
                let before = Instant::now();
                tokio::time::sleep(planned).await;
                worst = worst.max(before.elapsed().saturating_sub(planned));
            }
            let mut rooms = Vec::new();
            for h in handles {
                rooms.push(h.await.expect("waiter"));
            }
            (worst, rooms)
        })
    }

    /// A stopped reader with many blocking senders does not cost the node's other tasks the
    /// runtime: the wait releases its worker (`link_room`'s `block_in_place`), so an unrelated
    /// timer is served on time while eight senders are parked on a lane that will not free.
    /// And the measure is sensitive: the same eight senders waiting WITHOUT releasing the
    /// worker (`wait_for_room` called directly, on a two-worker runtime) starve the timer for
    /// about the whole wait.
    #[test]
    fn senders_parked_on_a_full_lane_do_not_starve_the_runtime_that_releases_its_worker() {
        let wait = Duration::from_millis(600);
        let (worst, rooms) = timer_lateness_under_waiters(
            8,
            64,
            wait,
            through_link_room(Arc::new(ParkBudget::new(DEFAULT_PARK_BUDGET))),
        );
        assert!(
            rooms.iter().all(|r| *r == Room::Congested),
            "every sender waited out its deadline: {rooms:?}"
        );
        eprintln!("timer lateness with 8 senders parked, worker released: {worst:?}");
        assert!(
            worst < Duration::from_millis(250),
            "an unrelated timer was served {worst:?} late while senders were parked"
        );

        // The control: the same wait that keeps its worker.
        let (starved, rooms) = timer_lateness_under_waiters(
            8,
            64,
            wait,
            Arc::new(|tx, w| tx.wait_for_room(Priority::Data, w)),
        );
        assert!(rooms.iter().all(|r| *r == Room::Congested));
        eprintln!("timer lateness with 8 senders parked, worker kept: {starved:?}");
        assert!(
            starved >= Duration::from_millis(300),
            "without the release the timer should be starved for most of the wait, saw {starved:?}"
        );
    }

    /// The release has a limit, the runtime's `max_blocking_threads`: with more senders parked than
    /// that, the surplus holds workers and starves the unrelated timer. The bulkhead keeps the
    /// node inside it. On a runtime capped at 8, 24 senders with no bulkhead starve the timer
    /// (1.18 s measured); the same 24 under a budget of 6 leave it on time, the 6 that parked wait
    /// out their deadline, and the 18 that found the budget spent are answered congested at
    /// once, counted, and the budget is empty again afterwards.
    #[test]
    fn the_bulkhead_keeps_parked_senders_inside_the_blocking_thread_cap() {
        let wait = Duration::from_millis(600);
        // No bulkhead (a budget no smaller than the senders): the surplus over the cap starves.
        let (over, _) = timer_lateness_under_waiters(
            24,
            8,
            wait,
            through_link_room(Arc::new(ParkBudget::new(1_000))),
        );
        // The bulkhead, inside the cap.
        let budget = Arc::new(ParkBudget::new(6));
        let (held, rooms) =
            timer_lateness_under_waiters(24, 8, wait, through_link_room(Arc::clone(&budget)));
        eprintln!("timer lateness, 24 senders on a cap of 8: {over:?} without a bulkhead, {held:?} with a budget of 6");
        assert!(
            over >= Duration::from_millis(300),
            "without it the surplus holds workers: {over:?}"
        );
        assert!(
            held < Duration::from_millis(250),
            "with it the timer is on time: {held:?}"
        );
        assert!(rooms.iter().all(|r| *r == Room::Congested));
        let stats = budget.stats();
        assert_eq!(stats.refused, 18, "24 senders, 6 places");
        assert_eq!(stats.parked, 0, "every place was given back");
    }

    /// A place is taken and given back, and a budget of zero parks nobody.
    #[test]
    fn a_park_budget_counts_its_places_and_gives_them_back() {
        let budget = ParkBudget::new(2);
        let first = budget.try_park().expect("first place");
        let _second = budget.try_park().expect("second place");
        assert!(budget.try_park().is_none(), "no third place");
        assert_eq!(
            budget.stats(),
            ParkStats {
                limit: 2,
                parked: 2,
                refused: 1
            }
        );
        drop(first);
        assert!(budget.try_park().is_some(), "a returned place is reusable");
        assert!(ParkBudget::new(0).try_park().is_none());
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
            queue_unit_bytes: 4,
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
            queue_unit_bytes: 4,
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

    /// The lane's bound is counted in the shape's `queue_unit_bytes`, not in
    /// the batch the link sends. A datagram link sends 1450 bytes; with the
    /// default size of two, counting in that batch bounds the lane at 2,900
    /// bytes, three replies of 1 KiB fill it, and the fourth, a droppable
    /// message that waits `wait_before_drop`, is dropped. Counted in the
    /// configured 65,535 it finds room. The control is the same four frames
    /// under the datagram unit, which refuse the fourth.
    #[test]
    fn a_datagram_link_does_not_shrink_a_lane_to_two_datagrams() {
        use wz_session_core::link::TxQueueShape;
        const REPLY: usize = 1066;
        let four_replies = |unit: usize| {
            let (tx, _rx) = outbound_channel_with_capacity([2; Priority::NUM], 65_535);
            tx.reshape(TxQueueShape {
                sizes: [2; Priority::NUM],
                qos: false,
                batch_bytes: 1450,
                queue_unit_bytes: unit,
            });
            for _ in 0..3 {
                tx.send(Priority::DEFAULT, vec![0u8; REPLY])
                    .expect("enqueue");
            }
            tx.wait_for_room(Priority::DEFAULT, droppable(Duration::ZERO))
        };
        assert_eq!(
            four_replies(65_535),
            Room::Free,
            "a lane counted in the configured batch has room for a fourth reply"
        );
        assert_eq!(
            four_replies(1450),
            Room::Congested,
            "counted in the datagram, the same lane is full after three"
        );
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

    /// The CPU time a thread of this process has used, in clock ticks, read off
    /// its own `/proc` entry.
    #[cfg(all(feature = "runtime-zero-copy", target_os = "linux"))]
    fn thread_cpu_ticks(tid: u32) -> u64 {
        let stat = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat"))
            .expect("the thread's stat");
        // The command name is parenthesised and may hold spaces; the fields
        // after it start at the state, which is field 3, so utime and stime
        // (fields 14 and 15) are the 12th and 13th after the closing bracket.
        let after = &stat[stat.rfind(')').expect("the comm field ends") + 2..];
        let field = |n: usize| -> u64 {
            after
                .split_whitespace()
                .nth(n)
                .and_then(|f| f.parse().ok())
                .expect("a numeric stat field")
        };
        field(11) + field(12)
    }

    /// A sender that needs a slot of a class whose budget is spent WAITS for the
    /// writer, as it waits when the whole pool is spent: it does not poll.
    ///
    /// The wait used to ask "does ANY class have a slot to take", and the small
    /// class always did, so a frame that only the large class holds found the
    /// wait over at once, found no large slot, and went round again: a thread
    /// spinning at full CPU until the writer happened to free a large slot.
    /// Measured here as the waiter's own CPU time while it waits, which is
    /// near nothing parked and most of the interval spinning.
    #[cfg(all(feature = "runtime-zero-copy", target_os = "linux"))]
    #[test]
    fn a_lend_for_a_spent_class_parks_instead_of_spinning() {
        use std::sync::mpsc;
        use std::time::Duration;

        let (tx, mut rx) = outbound_channel_datagram_with_capacity([2; Priority::NUM], 1450);
        let past_small = TxPools::datagram().slot_size(0) + 1;
        let mut held = 0;
        while tx
            .tx_class_stats(1)
            .is_some_and(|(_, free, budget)| free > 0 && held < budget)
        {
            let lend = tx
                .lend(Priority::DEFAULT, past_small)
                .expect("a large slot");
            tx.commit(lend, 1).expect("queued");
            held += 1;
        }
        assert!(held > 0, "CONTROL: the large class was spent by lends");
        assert!(
            tx.tx_class_stats(0).is_some_and(|(_, free, _)| free > 0),
            "CONTROL: the small class still has a slot, which is what fooled the wait"
        );

        let waiter_tx = tx.clone();
        let (tid_tx, tid_rx) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let tid = std::fs::read_link("/proc/thread-self")
                .expect("this thread's proc entry")
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.parse::<u32>().ok())
                .expect("a tid");
            tid_tx.send(tid).expect("main is listening");
            let lend = waiter_tx.lend(Priority::DEFAULT, past_small);
            let got = lend.is_some();
            if let Some(lend) = lend {
                waiter_tx.abort_lend(lend);
            }
            got
        });
        let tid = tid_rx.recv_timeout(Duration::from_secs(10)).expect("a tid");
        let start = thread_cpu_ticks(tid);
        std::thread::sleep(Duration::from_millis(400));
        let spent = thread_cpu_ticks(tid) - start;
        assert!(!waiter.is_finished(), "the lend waits for a large slot");
        // At 100 ticks a second a spinning thread uses about 40 of these.
        assert!(
            spent <= 4,
            "the waiting lend used {spent} ticks of CPU in 400 ms"
        );

        // The writer takes one large frame and is done with it: the waiter lends.
        drop(rx.try_recv_wire_tagged().expect("a queued frame").1);
        assert!(
            waiter.join().expect("the waiter ends"),
            "it was lent a slot"
        );
    }
}
