// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2748 — THE TASK THAT DRIVES THE FIXED-BUFFER READ, and the ring that is a
//! node's rather than a call's.
//!
//! ## What was missing, stated as a structure and not as a call site
//!
//! `runtime-tokio-uring`'s first residual has read "nothing selects this path
//! for a production link" since R311y589. R2746 aimed it at the right table and
//! R2747 built [`RxWindow`], the frame
//! boundaries a reader that does not size its reads needs. What was still
//! missing was not a call site: `crate::uring::FixedSlotRing::read_framed`
//! SUBMITS ITS READ AND THEN BLOCKS FOR ITS OWN COMPLETION, and nothing in a
//! `tokio` runtime may do that. So the residual's remaining half is two things
//! that are one: a TASK where the blocking belongs, and — because that task
//! owns the ring — a place for the ring to LIVE that is not a single call's
//! stack.
//!
//! ## Upstream's shape, read rather than invented
//!
//! The pinned zenoh holds its ring at MANAGER scope
//! (`io/zenoh-transport/src/unicast/universal/link.rs` @
//! `if transport.manager.state.uring.is_some() && link.link.get_fd().is_ok() {`)
//! and drives it from ONE blocking worker:
//! `commons/zenoh-uring/src/linux/api/reader/mod.rs` @ `ZRuntime::RX.spawn_blocking(move || {`
//! runs a loop whose tail is `ring.submit_and_wait(1)?` and whose head
//! demultiplexes each completion to the per-fd context that submitted it. A
//! waker entry is what lets a command reach a worker already parked in that
//! wait — the same file's `IndexGeneration::INVALID_MAX` arm reads the waker fd
//! and re-arms it.
//!
//! [`UringReactor`] is that worker with wz's nouns. The blocking wait is
//! upstream's own answer, not a workaround: a `spawn_blocking` thread is where
//! a `submit_and_wait` is allowed to sit.
//!
//! ## What is DELIBERATELY not upstream's
//!
//! * **A LINK PULLS; upstream's PUSHES.** Upstream's callback IS the consumer —
//!   `ring_cb` calls `transport.read_messages(..)` on the worker thread — so it
//!   keeps a read armed at all times and answers a full pool with `ENOBUFS`.
//!   wz's consumer is [`LinkDriver::poll_event`](crate::LinkDriver::poll_event),
//!   which is PULLED once per frame by the session loop. So a read is armed
//!   when a link asks for one and not before, which is exactly the
//!   back-pressure `crate::poll_framed` has (it does not touch the socket until
//!   it is polled) and removes the unbounded queue a push model would need
//!   between the worker and a slow session.
//! * **ONE READ IN FLIGHT PER LINK.** It follows from the above rather than
//!   being chosen: a link asks again only after it has consumed what the last
//!   completion carried. It is also what lets a completion be keyed by the
//!   `buf_index` it wrote into — see
//!   [`FixedSlotRing::FIRST_FREE_KEY`](crate::uring::FixedSlotRing::FIRST_FREE_KEY).
//! * **THE PAYLOAD IS COPIED AT THE SAME BOUNDARY `poll_framed` COPIES IT.**
//!   `RxFrame` carries an owned `Vec<u8>` (`wz-session-core`'s own note: "R51
//!   baseline: owned `Vec<u8>`. Future rounds ... will switch this to a
//!   pool-slot borrow") and `crate::poll_framed` ends with
//!   `RxFrame::new(payload.to_vec())`. This body does the same, in the
//!   callback. ⚠ So the zero-copy claim of this path is UNCHANGED and is not
//!   weakened here: the kernel still writes into the pool slot and nothing
//!   intermediate exists before the `LinkEvent`. Retiring that last copy is
//!   `RxFrame`'s own residual and belongs to `runtime-zero-copy`, not to this
//!   module — written down so a later round grades against the right thing.
//!
//! ## What this module does NOT do
//!
//! Nothing here SELECTS this body for a production link. A link reaches it by
//! being [`attach`](UringReactor::attach)ed, and no `wire_*` constructor calls
//! that yet — the read half would have to answer "do my bytes have a raw fd"
//! the way upstream makes every link answer `get_fd`, which is a trait across
//! seven reader types and its own round. The atom's residual therefore keeps
//! its first half and loses the rest.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as cmd_chan;
use std::sync::Arc;

use tokio::sync::mpsc as frame_chan;

use wz_session_core::link::{LinkEvent, LostCause, RxFrame};

use crate::link_rx_arena::{LinkRxArena, LinkRxFrame};
use crate::link_rx_window::RxWindow;
use crate::session_rx_pool_ap::SLOT_SIZE;
use crate::uring::{Completion, FixedSlotRing};

/// `user_data` for the waker read. Above every other key by construction:
/// slots occupy `0..SLOT_COUNT`, a spilled read's ticket counts up from
/// [`FixedSlotRing::FIRST_FREE_KEY`], and a cancellation carries
/// [`FixedSlotRing::CANCEL_KEY`].
const WAKE_KEY: u64 = u64::MAX;

/// How many submission entries the reactor's ring carries.
///
/// One per link that may have a read in flight, plus the waker, plus room for
/// the cancellations shutdown pushes at once. `SLOT_COUNT` is 64 and a link
/// holds at most one slot at a time, so the table is the ceiling on concurrent
/// reads and this is the next power of two above it.
const RING_ENTRIES: u32 = 256;

/// What the worker hands a link for one of its completions.
enum Delivery {
    /// The frames that ENDED inside one completion, in wire order. May be
    /// EMPTY: a completion carrying only part of a frame ends none.
    Frames(Vec<Vec<u8>>),
    /// The link ended, and why.
    Lost(LostCause),
}

/// What a link asks the worker to do.
enum Cmd {
    /// Take this link on: remember its fd and its prefix-width SOURCE, and
    /// where to deliver.
    Attach {
        id: u64,
        fd: RawFd,
        lowlatency: Arc<AtomicBool>,
        deliver: frame_chan::UnboundedSender<Delivery>,
    },
    /// Arm ONE read for this link.
    Read { id: u64 },
    /// This link is gone.
    ///
    /// ⚠ A read of its own may still be IN FLIGHT, and its frame stays in the
    /// worker's in-flight table until the completion arrives. The kernel holds
    /// a pointer into that frame's slot; dropping it here would free a slot the
    /// kernel is still writing into.
    Detach { id: u64 },
    /// Stop: cancel what is outstanding, drain it, and end the worker.
    Stop,
}

/// An `eventfd` a parked worker can be woken through, closed when the last
/// holder drops it.
struct WakeFd(RawFd);

impl WakeFd {
    fn new() -> io::Result<Self> {
        // SAFETY: an FFI call taking two scalars and returning a fd or -1.
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(fd))
    }

    /// Raise the counter, which completes the worker's armed waker read.
    ///
    /// A failure here is REPORTED rather than ignored: it means a command has
    /// been queued that the worker will not look at until something else wakes
    /// it, and the caller turns that into a lost link rather than a hang.
    fn wake(&self) -> io::Result<()> {
        let one: u64 = 1;
        // SAFETY: an 8-byte write from a live local into an eventfd, which is
        // the only width an eventfd accepts.
        let n = unsafe {
            libc::write(
                self.0,
                std::ptr::addr_of!(one).cast::<libc::c_void>(),
                std::mem::size_of::<u64>(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for WakeFd {
    fn drop(&mut self) {
        // SAFETY: this type owns the fd for its whole life and closes it once.
        unsafe { libc::close(self.0) };
    }
}

/// The node's `io_uring` reader: one ring, one blocking worker, many links.
///
/// Upstream's `manager.state.uring`. Cloneable-by-reference through
/// [`Self::node`], which is the shape
/// [`LinkRxArena::node`](crate::link_rx_arena::LinkRxArena::node) already
/// established for the table this registers — and for the same reason: there
/// is no node object in this crate to hang either off yet, and both say so in
/// one place rather than inventing one.
pub struct UringReactor {
    cmds: cmd_chan::Sender<Cmd>,
    wake: Arc<WakeFd>,
    next_id: std::sync::atomic::AtomicU64,
    worker: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl UringReactor {
    /// THE NODE's reader, built on first use, or `None` when this host cannot
    /// have one.
    ///
    /// `None` and not an error, because that is the question the selection
    /// point asks — upstream's is literally `uring.is_some()`. A kernel without
    /// `io_uring`, a `RLIMIT_MEMLOCK` below
    /// [`FixedSlotRing::required_locked_bytes`], a seccomp filter: every one of
    /// them means "this node reads the ordinary way", and none of them is a
    /// defect in the link that asked.
    ///
    /// Built LAZILY for the same reason the table is: a process that never
    /// opens a byte-stream link pins nothing and spawns nothing.
    pub fn node() -> Option<&'static UringReactor> {
        static REACTOR: std::sync::OnceLock<Option<UringReactor>> = std::sync::OnceLock::new();
        REACTOR
            .get_or_init(|| UringReactor::start(LinkRxArena::node()).ok())
            .as_ref()
    }

    /// A reader over `arena`, for a caller that owns its own node.
    ///
    /// The seam a node object plugs into once one exists, and what lets a test
    /// observe a reactor without touching whatever else the process is
    /// receiving. Same pair, same argument, as
    /// [`LinkRxArena::new`](crate::link_rx_arena::LinkRxArena::new) beside
    /// [`LinkRxArena::node`](crate::link_rx_arena::LinkRxArena::node).
    pub fn start(mut arena: LinkRxArena) -> io::Result<Self> {
        let ring = FixedSlotRing::register(&mut arena, RING_ENTRIES)?;
        let wake = Arc::new(WakeFd::new()?);
        let (tx, rx) = cmd_chan::channel();
        let worker_wake = Arc::clone(&wake);
        // A plain OS thread and not `tokio::task::spawn_blocking`: the worker
        // runs for the node's whole life, and a blocking-pool slot held forever
        // is one the runtime cannot give back. Upstream reaches for its own
        // `ZRuntime::RX` pool for the same job, which is the same choice made
        // where a dedicated pool exists to make it in.
        let handle = std::thread::Builder::new()
            .name("wz-uring-rx".to_owned())
            .spawn(move || run_worker(ring, worker_wake, rx))?;
        Ok(Self {
            cmds: tx,
            wake,
            next_id: std::sync::atomic::AtomicU64::new(0),
            worker: std::sync::Mutex::new(Some(handle)),
        })
    }

    /// Take `fd` on and hand back the read body for it.
    ///
    /// Upstream's `setup_read(link.link.get_fd()?, ring_cb)`. `lowlatency` is
    /// the link's own negotiated-transport flag; the prefix width follows from
    /// it — 2 on the universal path and 4 under `transport-lowlatency`.
    ///
    /// ⚠ R2755 — IT IS THE FLAG AND NOT A WIDTH, and the previous signature
    /// (`attach(fd, width: usize)`) is what this round is repairing. Freezing
    /// the width at attach was justified as `crate::poll_framed`'s own rule,
    /// which it is not: that rule fixes the width AT FRAME START, once per
    /// frame, and this froze it once per LINK. Both statements behind the
    /// generalisation are true — the flag flips at Established, and a link's
    /// first read happens before that — and the conclusion drawn from them was
    /// false, because a link's first read is its HANDSHAKE and the flip comes
    /// after it. So a TCP link that negotiated lowlatency kept a 2-byte prefix
    /// on a 4-byte wire and every frame after Established was cut in the wrong
    /// place.
    ///
    /// MEASURED: `wz-runtime-tokio`'s `lowlatency_e2e` over real TCP, with the
    /// wide feature leg's 80 features, fails at
    /// "subscriber did not fire within the ~3s budget"; the same leg with
    /// `runtime-tokio-uring` removed — the only difference being whether this
    /// reactor is selected at all — passes. It reached origin unseen because
    /// hosted Layer C1bn stops at the `--lib` target and that target was red
    /// for an unrelated reason.
    ///
    /// The width is now re-derived where [`crate::link_rx_window::RxWindow`]
    /// already admits one, at a frame boundary, which is `poll_framed`'s rule
    /// stated for a reader whose reads the kernel sizes.
    ///
    /// The fd is BORROWED, not owned: the caller's reader half keeps it open,
    /// and the returned [`UringRx`] must not outlive it. That is the same
    /// contract `crate::uring::FixedSlotRing::read_framed` has and it is
    /// upheld the same way — by the driver owning both.
    pub fn attach(&self, fd: RawFd, lowlatency: Arc<AtomicBool>) -> io::Result<UringRx> {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (deliver, frames) = frame_chan::unbounded_channel();
        self.send(Cmd::Attach {
            id,
            fd,
            lowlatency,
            deliver,
        })?;
        Ok(UringRx {
            id,
            cmds: self.cmds.clone(),
            wake: Arc::clone(&self.wake),
            frames,
            pending: VecDeque::new(),
            armed: false,
            lost: None,
        })
    }

    fn send(&self, cmd: Cmd) -> io::Result<()> {
        self.cmds
            .send(cmd)
            .map_err(|_| io::Error::other("the uring reactor's worker has stopped"))?;
        self.wake.wake()
    }
}

impl Drop for UringReactor {
    fn drop(&mut self) {
        // Best effort in both directions: a worker that has already died
        // answers `Err` on the send, and a `wake` that fails leaves it parked
        // — which the join below would then wait on forever, so the join is
        // only attempted when the stop was delivered.
        if self.send(Cmd::Stop).is_err() {
            return;
        }
        let Ok(mut slot) = self.worker.lock() else {
            return;
        };
        if let Some(handle) = slot.take() {
            let _ = handle.join();
        }
    }
}

/// ONE link's fixed-buffer read body: the counterpart to `crate::poll_framed`,
/// with the same contract and a different way of getting its bytes.
///
/// [`Self::poll_event`] answers exactly what `poll_framed` answers, which is
/// what makes these TWO BODIES rather than two behaviours — a link means the
/// same thing whichever read it was given.
pub struct UringRx {
    id: u64,
    cmds: cmd_chan::Sender<Cmd>,
    wake: Arc<WakeFd>,
    frames: frame_chan::UnboundedReceiver<Delivery>,
    /// Frames one completion carried that the session has not asked for yet.
    ///
    /// Bounded BY THE PROTOCOL rather than by a capacity: one read is armed at
    /// a time and the next is armed only once this is empty, so it holds at
    /// most what a single `SLOT_SIZE` completion can.
    pending: VecDeque<Vec<u8>>,
    /// Whether a read is already asked for. Kept across a cancelled
    /// [`Self::poll_event`] so a lost race does not arm a second one.
    armed: bool,
    /// STICKY: a link that has ended stays ended.
    ///
    /// `crate::poll_framed` resets to `Idle` after a `Lost` because its next
    /// read would fail the same way and cost nothing. Here the next read costs
    /// a submission on a dead fd, and the worker would answer every one of them
    /// — so the cause is remembered and re-reported instead.
    lost: Option<LostCause>,
}

impl UringRx {
    /// One [`LinkEvent`], read through the ring.
    ///
    /// CANCEL-SAFE, which is not incidental: the session loop awaits this
    /// inside a `tokio::select!` and R265 is the round that paid for a framing
    /// read that was not. Nothing is lost when the future is dropped — the
    /// delivery stays in the channel, `armed` stays true so the next call does
    /// not ask twice, and `pending` is only drained by a return.
    pub async fn poll_event(&mut self) -> LinkEvent {
        loop {
            if let Some(bytes) = self.pending.pop_front() {
                return LinkEvent::Rx(RxFrame::new(bytes));
            }
            if let Some(cause) = self.lost {
                return LinkEvent::Lost { cause };
            }
            if !self.armed {
                if self.ask().is_err() {
                    // The worker is gone, which is not something a link can
                    // report as a wire fact; `OsError` is what `poll_framed`
                    // answers when the read itself failed.
                    self.lost = Some(LostCause::OsError);
                    continue;
                }
                self.armed = true;
            }
            match self.frames.recv().await {
                Some(Delivery::Frames(frames)) => {
                    self.armed = false;
                    self.pending.extend(frames);
                }
                Some(Delivery::Lost(cause)) => {
                    self.armed = false;
                    self.lost = Some(cause);
                }
                None => self.lost = Some(LostCause::OsError),
            }
        }
    }

    fn ask(&self) -> io::Result<()> {
        self.cmds
            .send(Cmd::Read { id: self.id })
            .map_err(|_| io::Error::other("the uring reactor's worker has stopped"))?;
        self.wake.wake()
    }
}

impl Drop for UringRx {
    fn drop(&mut self) {
        if self.cmds.send(Cmd::Detach { id: self.id }).is_ok() {
            let _ = self.wake.wake();
        }
    }
}

/// One attached link, as the worker sees it.
struct LinkCtx {
    fd: RawFd,
    /// R2755 — the prefix width's SOURCE, not the width. See
    /// [`UringReactor::attach`] for what freezing it cost.
    lowlatency: Arc<AtomicBool>,
    /// The width in force for the frame currently being assembled.
    ///
    /// Carried rather than recomputed per push because a prefix that is
    /// already half-read must not widen underneath the window:
    /// [`Self::frame_width`] re-derives this only when the window says it is
    /// between frames.
    width: usize,
    /// The frame boundaries ACROSS completions. This is the state that makes a
    /// reader which does not size its reads possible at all, and it lives here
    /// because the worker is what sees every completion for this link.
    window: RxWindow,
    deliver: frame_chan::UnboundedSender<Delivery>,
}

/// One read the kernel has been given and has not answered yet.
struct InFlight {
    /// Which link asked. `None` once that link has detached — the entry stays
    /// because the KERNEL still holds a pointer into `frame`.
    link: Option<u64>,
    /// The destination. Alive for exactly as long as the kernel may write to
    /// it, which is what this table is for.
    frame: LinkRxFrame,
}

/// The worker: one ring, one thread, and every completion routed by its key.
///
/// R2750 — NO ARENA PARAMETER. The ring carries the table it registered, so
/// there is no second handle to pass down and none to get wrong; `start`'s own
/// `arena` argument is free to be dropped the moment registration is done, and
/// the pinned storage still outlives the ring because the ring holds a refcount
/// on it. That is the residual "the lifetime contract is upheld by scoping"
/// closing, visible here as an argument that no longer needs to exist.
fn run_worker(mut ring: FixedSlotRing, wake: Arc<WakeFd>, cmds: cmd_chan::Receiver<Cmd>) {
    // The waker's destination. Declared before the loop and never moved, which
    // is what makes the always-armed read into it sound.
    let mut wake_buf = [0u8; 8];
    let mut links: HashMap<u64, LinkCtx> = HashMap::new();
    let mut inflight: HashMap<u64, InFlight> = HashMap::new();
    let mut next_ticket = FixedSlotRing::FIRST_FREE_KEY;
    let mut reaped: Vec<Completion> = Vec::new();
    let mut stopping = false;

    if arm_wake(&mut ring, &wake, &mut wake_buf).is_err() {
        return;
    }
    // Whether the waker's OWN read is outstanding. Tracked because shutdown has
    // to cancel that one too: `wake_buf` is this function's local and returning
    // drops it, so a waker read the kernel still holds would name a dead stack
    // frame. Same hazard as an outstanding link read, in the one place it is
    // easy to miss because the waker is not a link.
    let mut wake_outstanding = true;

    loop {
        // Commands first: a wakeup exists to let them in, and arming a read
        // before parking is what keeps the wait from being unbounded.
        while let Ok(cmd) = cmds.try_recv() {
            match cmd {
                Cmd::Attach {
                    id,
                    fd,
                    lowlatency,
                    deliver,
                } => {
                    let width = crate::prefix_width(lowlatency.load(Ordering::Acquire));
                    links.insert(
                        id,
                        LinkCtx {
                            fd,
                            lowlatency,
                            width,
                            window: RxWindow::new(),
                            deliver,
                        },
                    );
                }
                Cmd::Read { id } => {
                    if let Some(ctx) = links.get(&id) {
                        if let Err(cause) =
                            arm_read(&mut ring, &mut inflight, &mut next_ticket, id, ctx.fd)
                        {
                            let _ = ctx.deliver.send(Delivery::Lost(cause));
                        }
                    }
                }
                Cmd::Detach { id } => {
                    links.remove(&id);
                    // The frames those reads name stay where they are; only the
                    // routing is dropped.
                    for entry in inflight.values_mut() {
                        if entry.link == Some(id) {
                            entry.link = None;
                        }
                    }
                }
                Cmd::Stop => stopping = true,
            }
        }

        if stopping {
            // Nothing outstanding: every buffer the kernel was given is back,
            // so the ring and this frame may go.
            if inflight.is_empty() && !wake_outstanding {
                return;
            }
            // Cancel what IS outstanding rather than hoping it lands: a read on
            // a quiet socket never completes on its own, and neither a frame's
            // slot nor `wake_buf` may be released while the kernel may still
            // write to it. Re-issued every pass rather than once — a cancel
            // that could not be pushed would otherwise leave this loop with
            // nothing to wait for, and a cancel for a request that has already
            // gone comes back `ENOENT`, which costs one completion and no
            // correctness.
            for key in inflight.keys().copied().collect::<Vec<_>>() {
                let _ = ring.submit_cancel(key);
            }
            if wake_outstanding {
                let _ = ring.submit_cancel(WAKE_KEY);
            }
        }

        reaped.clear();
        if ring.submit_and_reap(&mut reaped).is_err() {
            // The ring itself failed, so no link can be served any more. Tell
            // every attached one rather than leaving them parked on a channel
            // nothing will write to again.
            for ctx in links.values() {
                let _ = ctx.deliver.send(Delivery::Lost(LostCause::OsError));
            }
            // LEAKED, deliberately, and this is the one place this module
            // prefers a leak. The ring cannot be asked to cancel what it is
            // still holding, so every outstanding read names a buffer the
            // kernel may yet write into; returning their slots to the table
            // would hand that memory to another link. A forfeited slot costs
            // one of `SLOT_COUNT` for the process's life, which is what
            // `LinkRxFrame`'s own poisoned-lock arm already trades for the same
            // reason.
            for entry in inflight.into_values() {
                std::mem::forget(entry.frame);
            }
            return;
        }

        for completion in reaped.drain(..) {
            match completion.key {
                WAKE_KEY => {
                    wake_outstanding = false;
                    // Not re-armed while stopping: the loop above is waiting
                    // for exactly this to come back before it may drop the
                    // buffer the read names.
                    if !stopping {
                        if arm_wake(&mut ring, &wake, &mut wake_buf).is_err() {
                            // A worker that cannot be woken again can still be
                            // wound down, and MUST be rather than returned from
                            // here: link reads may be outstanding and their
                            // frames are not this frame's to drop.
                            stopping = true;
                        } else {
                            wake_outstanding = true;
                        }
                    }
                }
                // A cancellation's own completion says nothing about a link:
                // the read it named reports itself, with `-ECANCELED`.
                FixedSlotRing::CANCEL_KEY => {}
                key => deliver_completion(&mut inflight, &mut links, key, completion.result),
            }
        }
    }
}

/// Re-arm the always-pending read on the waker fd.
fn arm_wake(ring: &mut FixedSlotRing, wake: &WakeFd, buf: &mut [u8; 8]) -> io::Result<()> {
    // SAFETY: `buf` belongs to the worker's own frame, outlives every wait, and
    // nothing else reads it; `WAKE_KEY` is above every key any other submission
    // can carry.
    unsafe { ring.submit_read(wake.0, buf.as_mut_ptr(), buf.len() as u32, WAKE_KEY) }
}

/// Take a destination and give the kernel one read for `link`.
fn arm_read(
    ring: &mut FixedSlotRing,
    inflight: &mut HashMap<u64, InFlight>,
    next_ticket: &mut u64,
    link: u64,
    fd: RawFd,
) -> Result<(), LostCause> {
    // R2750 — from the RING's table, because it is the one the ring registered.
    // This used to take an `arena` argument the caller had to keep in step with
    // the registration; there is no second table to get wrong now.
    let mut frame = ring.take_slot();
    // MOVING the frame after the submission is sound, and that is why the
    // insert below may follow the push rather than having to precede it: the
    // kernel was given the address of a SLOT (storage the table owns, behind an
    // `Arc` the frame only points at) or of a `Vec`'s heap buffer. Neither
    // moves when the `LinkRxFrame` header does.
    let key = if frame.is_pooled() {
        match ring.submit_read_fixed(fd, &mut frame, SLOT_SIZE) {
            // A frame with no room is a contradiction here — `take(SLOT_SIZE)`
            // asked for a whole slot — so it is the ring refusing, not an EOF.
            Ok((0, _)) | Err(_) => return Err(LostCause::OsError),
            Ok((_, key)) => key,
        }
    } else {
        // A SPILLED frame is read the ORDINARY way rather than refused. The
        // table ran dry, which `crate::link_rx_arena`'s own dry arm answers
        // with an allocation — refusing would turn a transient shortage into a
        // lost link. What is lost is the pinning, not the frame.
        let ticket = *next_ticket;
        *next_ticket += 1;
        debug_assert!(ticket < FixedSlotRing::CANCEL_KEY);
        let len = frame.as_ref().len() as u32;
        let dst = frame.as_mut().as_mut_ptr();
        // SAFETY: `dst` names the frame's own allocation, the frame is moved
        // into `inflight` below and stays there until this key's completion is
        // reaped, and nothing else touches those bytes meanwhile. `ticket` is
        // above `FIRST_FREE_KEY` — so above every slot key — and asserted below
        // `CANCEL_KEY`.
        if unsafe { ring.submit_read(fd, dst, len, ticket) }.is_err() {
            return Err(LostCause::OsError);
        }
        ticket
    };
    inflight.insert(
        key,
        InFlight {
            link: Some(link),
            frame,
        },
    );
    Ok(())
}

/// Route one read completion to the link that asked for it.
fn deliver_completion(
    inflight: &mut HashMap<u64, InFlight>,
    links: &mut HashMap<u64, LinkCtx>,
    key: u64,
    result: i32,
) {
    let Some(entry) = inflight.remove(&key) else {
        // A key nothing is waiting for. Not reachable through this worker's own
        // submissions, and dropped rather than asserted on: a completion the
        // kernel invented is not something a link can be told about.
        return;
    };
    let mut frame = entry.frame;
    // The frame drops at the end of this function either way, which is what
    // sends its slot home.
    let Some(link) = entry.link else {
        return; // detached while its read was in flight
    };
    let Some(ctx) = links.get_mut(&link) else {
        return;
    };
    if result < 0 {
        let _ = ctx.deliver.send(Delivery::Lost(LostCause::OsError));
        return;
    }
    let n = result as usize;
    if n == 0 {
        // EOF. Between frames it is a clean close; anywhere else the peer cut a
        // frame in half — and both lose the link, which is what
        // `crate::poll_framed` answers for the same two cases.
        let _ = ctx.deliver.send(Delivery::Lost(LostCause::PeerClosed));
        return;
    }
    frame.truncate(n);
    let mut frames: Vec<Vec<u8>> = Vec::new();
    // The copy `RxFrame` still asks for, at the same boundary `poll_framed`
    // makes it. See the module header: this is not where the zero-copy claim
    // lives or dies.
    let mut collect = |payload: &[u8]| frames.push(payload.to_vec());
    // R2755 — RE-DERIVE THE WIDTH AT A FRAME BOUNDARY, and only there. This is
    // `crate::poll_framed`'s rule ("the width is fixed HERE, at frame start, so
    // a flag flip cannot widen a prefix that is already half-read") stated for
    // a reader whose reads the kernel sizes: `between_frames` is the window's
    // own answer to "could the stream end here without truncating a frame",
    // which is the same instant.
    //
    // ⚠ A completion can carry the LAST universal frame and the FIRST lean one
    // together, and this reads the flag once for the whole push. That window is
    // the handshake's final frame and the session's first data frame arriving
    // in one read, which needs the peer to have written both before either was
    // reaped; upstream avoids it by dispatching to the ring only after the
    // transport is established. Recorded rather than claimed closed.
    if ctx.window.between_frames() {
        ctx.width = crate::prefix_width(ctx.lowlatency.load(Ordering::Acquire));
    }
    match ctx.window.push(frame.as_ref(), ctx.width, &mut collect) {
        Ok(()) => {
            let _ = ctx.deliver.send(Delivery::Frames(frames));
        }
        Err(_) => {
            // An oversize length prefix. `crate::poll_framed` answers a prefix
            // naming more than a frame may hold with `Lost { PeerClosed }`, and
            // the two bodies must agree about what a link means.
            let _ = ctx.deliver.send(Delivery::Lost(LostCause::PeerClosed));
        }
    }
}

/// R2748 — ⚠ these tests each REGISTER THE WHOLE POOL, like `crate::uring`'s
/// own.
///
/// Two of them running concurrently ask the kernel for twice
/// [`FixedSlotRing::required_locked_bytes`] and the second is refused with
/// `ENOMEM`. Layer C1br serializes this crate's uring tests for exactly that
/// reason; a bare parallel run on a tightly-limited box can fail here with
/// nothing wrong with the reactor.
#[cfg(test)]
mod tests {
    use super::*;
    // R2750 — the worker no longer takes slots itself (the ring does), so this
    // trait is a TEST import now: the dry-table witness drains the table by
    // hand. At module scope it would be an unused import under `-D warnings`.
    use crate::frame_arena::FrameArena;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    /// A link flag that never flips: the universal 2-byte prefix.
    ///
    /// R2755 — [`UringReactor::attach`] takes the link's own `lowlatency` flag
    /// rather than a width, so a test that wants a width states it as the flag
    /// that produces it. Every witness below reads a universal wire except
    /// [`a_lowlatency_link_reads_the_four_byte_prefix`], which passes `true`,
    /// and [`a_width_flip_at_a_frame_boundary_is_honoured`], which flips one.
    fn universal() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    /// The universal streamed envelope: a 2-byte LE length, then the payload.
    ///
    /// Built here rather than through `wz_codecs::stream_envelope` so a test of
    /// the READ body does not take its input from the encoder it is supposed to
    /// be independent of. `crate::stream_link`'s
    /// `the_writers_codec_frames_what_this_reader_unframes` is where the two
    /// halves are pinned together.
    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut wire = (payload.len() as u16).to_le_bytes().to_vec();
        wire.extend_from_slice(payload);
        wire
    }

    fn payload_of(event: LinkEvent) -> Vec<u8> {
        match event {
            LinkEvent::Rx(frame) => frame.bytes,
            other => panic!("expected a frame, got {other:?}"),
        }
    }

    /// Bounded so a defect reds instead of hanging a lane. Generous, because
    /// the witness is never "it was fast".
    async fn within<F: std::future::Future>(f: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(10), f)
            .await
            .expect("the reactor must answer")
    }

    /// Every frame a completion carried comes out, in wire order.
    ///
    /// Both frames are written BEFORE the link is polled, so one completion
    /// carries both — the case `crate::poll_framed` cannot produce (it sizes
    /// each read to one frame) and the whole reason
    /// [`RxWindow`](crate::link_rx_window::RxWindow) exists.
    #[tokio::test]
    async fn one_completion_carrying_two_frames_yields_two_events() {
        let arena = LinkRxArena::new();
        let reactor = UringReactor::start(arena.clone()).expect("a reactor");

        let (rd, mut wr) = std::io::pipe().expect("pipe");
        wr.write_all(&framed(b"alpha")).expect("write");
        wr.write_all(&framed(b"beta")).expect("write");

        let mut rx = reactor.attach(rd.as_raw_fd(), universal()).expect("attach");
        assert_eq!(payload_of(within(rx.poll_event()).await), b"alpha");
        assert_eq!(payload_of(within(rx.poll_event()).await), b"beta");

        drop(rx);
        drop((wr, rd));
    }

    /// THE REACTOR'S OWN CLAIM: two links on ONE ring each get their own bytes.
    ///
    /// This is what a per-link ring would not need and what
    /// `crate::uring::FixedSlotRing::read_framed` cannot do — it takes whatever
    /// completion comes back, which is only correct while one read exists. The
    /// witness is that each link's payload is the one written to ITS pipe; the
    /// control is to route by arrival instead of by key, and delivering each
    /// completion to the first attached link reds this and nothing else.
    #[tokio::test]
    async fn two_links_on_one_ring_each_get_their_own_bytes() {
        let arena = LinkRxArena::new();
        let reactor = UringReactor::start(arena.clone()).expect("a reactor");

        let (rd_a, mut wr_a) = std::io::pipe().expect("pipe");
        let (rd_b, mut wr_b) = std::io::pipe().expect("pipe");
        let mut a = reactor
            .attach(rd_a.as_raw_fd(), universal())
            .expect("attach a");
        let mut b = reactor
            .attach(rd_b.as_raw_fd(), universal())
            .expect("attach b");

        // B is written FIRST, so a body answering in attach order rather than
        // by key would hand A's poll B's bytes.
        wr_b.write_all(&framed(b"for-b")).expect("write b");
        wr_a.write_all(&framed(b"for-a")).expect("write a");

        assert_eq!(payload_of(within(a.poll_event()).await), b"for-a");
        assert_eq!(payload_of(within(b.poll_event()).await), b"for-b");

        drop((a, b));
        drop((wr_a, wr_b, rd_a, rd_b));
    }

    /// A LINK IS SERVED WHILE ANOTHER LINK'S READ IS STILL OUTSTANDING.
    ///
    /// The task claim, and the one a blocking `read_framed` cannot make: link A
    /// is armed on a pipe nobody ever writes to, so its read never completes,
    /// and link B must still be answered. The structure that makes that
    /// possible is the WAKER — B's `Cmd::Read` has to reach a worker already
    /// parked in `submit_and_wait` — and the control is deleting the waker
    /// arming: with no way into a parked wait, B's command sits in the channel
    /// and this times out.
    #[tokio::test]
    async fn a_second_link_is_served_while_the_first_read_never_completes() {
        let arena = LinkRxArena::new();
        let reactor = UringReactor::start(arena.clone()).expect("a reactor");

        let (rd_quiet, wr_quiet) = std::io::pipe().expect("pipe");
        let mut quiet = reactor
            .attach(rd_quiet.as_raw_fd(), universal())
            .expect("attach");
        // Parks the quiet link INSIDE the ring: its command is delivered, a
        // read is armed, and nothing will ever complete it.
        let parked = tokio::spawn(async move { quiet.poll_event().await });
        // The worker must have reached its wait before the second link asks, or
        // this would witness an empty queue rather than a parked one.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let (rd, mut wr) = std::io::pipe().expect("pipe");
        wr.write_all(&framed(b"served anyway")).expect("write");
        let mut live = reactor.attach(rd.as_raw_fd(), universal()).expect("attach");
        assert_eq!(
            payload_of(within(live.poll_event()).await),
            b"served anyway"
        );

        drop(live);
        parked.abort();
        drop((wr_quiet, rd_quiet, wr, rd));
    }

    /// A frame SPLIT ACROSS TWO COMPLETIONS arrives on the second.
    ///
    /// The window lives in the worker and survives a completion, which is what
    /// makes a reader that does not size its reads possible at all. The control
    /// is a window rebuilt per completion: the second half is then read as a
    /// fresh length prefix and the payload never arrives.
    #[tokio::test]
    async fn a_frame_split_across_two_completions_arrives_on_the_second() {
        let arena = LinkRxArena::new();
        let reactor = UringReactor::start(arena.clone()).expect("a reactor");

        let (rd, mut wr) = std::io::pipe().expect("pipe");
        let wire = framed(b"halves");
        let (head, tail) = wire.split_at(4);
        wr.write_all(head).expect("write head");

        let mut rx = reactor.attach(rd.as_raw_fd(), universal()).expect("attach");
        let waiting = tokio::spawn(async move {
            let event = rx.poll_event().await;
            (rx, event)
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        wr.write_all(tail).expect("write tail");

        let (rx, event) = tokio::time::timeout(Duration::from_secs(10), waiting)
            .await
            .expect("the reactor must answer")
            .expect("the poll task must not panic");
        assert_eq!(payload_of(event), b"halves");

        drop(rx);
        drop((wr, rd));
    }

    /// A CANCELLED POLL LOSES NOTHING.
    ///
    /// The session loop awaits `poll_event` inside a `tokio::select!`, so its
    /// future is dropped whenever another arm wins — R265 is the round that
    /// paid for a framing read which was not cancel-safe. Here the first poll
    /// is dropped with a read already armed; the frame arrives afterwards and
    /// the NEXT poll must still see it.
    #[tokio::test]
    async fn a_cancelled_poll_does_not_lose_its_frame() {
        let arena = LinkRxArena::new();
        let reactor = UringReactor::start(arena.clone()).expect("a reactor");

        let (rd, mut wr) = std::io::pipe().expect("pipe");
        let mut rx = reactor.attach(rd.as_raw_fd(), universal()).expect("attach");

        // Nothing is written yet, so this cannot resolve; dropping the future
        // is exactly what a lost `select!` race does.
        assert!(
            tokio::time::timeout(Duration::from_millis(300), rx.poll_event())
                .await
                .is_err(),
            "a poll with nothing to read must not resolve"
        );

        wr.write_all(&framed(b"after the cancel")).expect("write");
        // ⚠ THE SLEEP IS THE TEST, not politeness. Without it the next poll
        // starts within microseconds of the write and may well be waiting
        // before the worker routes the completion — which passes even if a
        // delivery only survives while someone is parked on it. The property
        // is that the frame keeps until it is ASKED FOR, so the window where
        // nobody is asking has to actually exist. Measured: the control for
        // this test came back GREEN without it.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            payload_of(within(rx.poll_event()).await),
            b"after the cancel"
        );

        drop(rx);
        drop((wr, rd));
    }

    /// A WIDTH FLIP AT A FRAME BOUNDARY IS HONOURED.
    ///
    /// R2755 — the witness for the defect [`UringReactor::attach`] records.
    /// This is a link's real shape: it reads its handshake on the universal
    /// 2-byte prefix, negotiates lowlatency, its open helper flips the shared
    /// flag at Established, and every frame after that is on the 4-byte one.
    /// The reactor used to take a WIDTH at attach, which froze whatever the
    /// flag said during the handshake, so the second frame here was cut at the
    /// wrong offset and no payload ever arrived.
    ///
    /// ⚠ THE TWO FRAMES ARE IN SEPARATE COMPLETIONS BY CONSTRUCTION — the
    /// first is read before the second is written — because the flip is only
    /// honoured at a frame boundary and a single completion carrying both
    /// would be read at one width. That is the residual `attach`'s doc states;
    /// this test is deliberately NOT written to hide it.
    ///
    /// CONTROL: take the width at attach again (or drop the `between_frames`
    /// re-read in the worker) and the second `poll_event` never yields
    /// `b"lean"` — the 2-byte prefix reads the lean frame's low half as a
    /// length.
    #[tokio::test]
    async fn a_width_flip_at_a_frame_boundary_is_honoured() {
        let arena = LinkRxArena::new();
        let reactor = UringReactor::start(arena.clone()).expect("a reactor");

        // The flag the link and its open helper share. False for the
        // handshake, flipped at Established — exactly as `stream_link` passes
        // it.
        let lowlatency = universal();

        let (rd, mut wr) = std::io::pipe().expect("pipe");
        wr.write_all(&framed(b"handshake")).expect("write");
        let mut rx = reactor
            .attach(rd.as_raw_fd(), Arc::clone(&lowlatency))
            .expect("attach");
        assert_eq!(payload_of(within(rx.poll_event()).await), b"handshake");

        // Established: the session is lean from the next frame on.
        lowlatency.store(true, Ordering::Release);

        let lean = b"lean";
        let mut wire = (lean.len() as u32).to_le_bytes().to_vec();
        wire.extend_from_slice(lean);
        wr.write_all(&wire).expect("write");
        assert_eq!(
            payload_of(within(rx.poll_event()).await),
            lean,
            "the width must follow the flag at a frame boundary"
        );

        drop(rx);
        drop((wr, rd));
    }

    /// EOF loses the link, and it STAYS lost.
    ///
    /// `crate::poll_framed` answers a stream that ends with
    /// `Lost { PeerClosed }` and resets, because its next read fails the same
    /// way for free. This body remembers instead — its next read would cost a
    /// submission on a dead fd — so the second poll must answer the same cause
    /// without going back to the ring.
    #[tokio::test]
    async fn an_ended_stream_loses_the_link_and_keeps_it_lost() {
        let arena = LinkRxArena::new();
        let reactor = UringReactor::start(arena.clone()).expect("a reactor");

        let (rd, wr) = std::io::pipe().expect("pipe");
        drop(wr);
        let mut rx = reactor.attach(rd.as_raw_fd(), universal()).expect("attach");

        for _ in 0..2 {
            match within(rx.poll_event()).await {
                LinkEvent::Lost {
                    cause: LostCause::PeerClosed,
                } => {}
                other => panic!("expected PeerClosed, got {other:?}"),
            }
        }

        drop(rx);
        drop(rd);
    }

    /// An oversize 4-byte prefix loses the link, in the same vocabulary the
    /// other body uses.
    ///
    /// `crate::poll_framed` refuses a `u32` prefix above `u16::MAX` with
    /// `Lost { PeerClosed }` before it allocates; the window refuses it with
    /// `WindowError::OversizeBatch`, and the worker is where that becomes the
    /// same `LinkEvent`. Two bodies that disagreed here would make a link mean
    /// different things depending on which one read it.
    #[tokio::test]
    async fn an_oversize_lowlatency_prefix_loses_the_link() {
        let arena = LinkRxArena::new();
        let reactor = UringReactor::start(arena.clone()).expect("a reactor");

        let (rd, mut wr) = std::io::pipe().expect("pipe");
        wr.write_all(&(u16::MAX as u32 + 1).to_le_bytes())
            .expect("write");

        let mut rx = reactor
            .attach(rd.as_raw_fd(), Arc::new(AtomicBool::new(true)))
            .expect("attach");
        match within(rx.poll_event()).await {
            LinkEvent::Lost {
                cause: LostCause::PeerClosed,
            } => {}
            other => panic!("expected PeerClosed, got {other:?}"),
        }

        drop(rx);
        drop((wr, rd));
    }

    /// A DRY TABLE STILL DELIVERS FRAMES.
    ///
    /// Every slot is held elsewhere, so the frame this read lands in is an
    /// allocation rather than a registered slot and `READ_FIXED` cannot be used
    /// for it. `crate::link_rx_arena`'s dry arm answers a shortage with an
    /// allocation, and refusing the read instead would turn one into a lost
    /// link. The control is that refusal: making the spilled arm return an
    /// error reds this and nothing else.
    #[tokio::test]
    async fn a_dry_table_still_delivers_frames_the_ordinary_way() {
        let arena = LinkRxArena::new();
        let reactor = UringReactor::start(arena.clone()).expect("a reactor");

        // Drained AFTER the registration, which needs the table whole.
        let mut held = arena.clone();
        let hostages: Vec<_> = (0..arena.free_slots())
            .map(|_| held.take(SLOT_SIZE))
            .collect();
        assert_eq!(arena.free_slots(), 0, "the table must be dry");
        assert!(
            hostages.iter().all(|f| f.is_pooled()),
            "the hostages must be the table's own slots"
        );

        let (rd, mut wr) = std::io::pipe().expect("pipe");
        wr.write_all(&framed(b"spilled but delivered"))
            .expect("write");
        let mut rx = reactor.attach(rd.as_raw_fd(), universal()).expect("attach");
        assert_eq!(
            payload_of(within(rx.poll_event()).await),
            b"spilled but delivered"
        );

        drop(rx);
        drop(hostages);
        drop((wr, rd));
    }

    /// DROPPING THE REACTOR ENDS ITS WORKER even with a read outstanding.
    ///
    /// A read on a quiet socket never completes on its own, so a worker that
    /// merely set a flag and waited would park forever and the join in
    /// [`UringReactor::drop`] would never return. The witness is that the drop
    /// COMPLETES; the control is deleting the cancellation, which leaves this
    /// waiting out its timeout.
    #[tokio::test]
    async fn dropping_the_reactor_ends_a_worker_with_a_read_outstanding() {
        let arena = LinkRxArena::new();
        let reactor = UringReactor::start(arena.clone()).expect("a reactor");

        let (rd, wr) = std::io::pipe().expect("pipe");
        let mut rx = reactor.attach(rd.as_raw_fd(), universal()).expect("attach");
        let parked = tokio::spawn(async move { rx.poll_event().await });
        // Long enough for the read to be ARMED rather than merely queued.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let (done, waited) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            drop(reactor);
            let _ = done.send(());
        });
        assert!(
            waited.recv_timeout(Duration::from_secs(10)).is_ok(),
            "dropping the reactor must cancel what is outstanding and join"
        );

        parked.abort();
        drop((wr, rd));
    }

    /// Every slot goes home once the links that borrowed them are gone.
    ///
    /// The accounting seam
    /// [`LinkRxArena::free_slots`](crate::link_rx_arena::LinkRxArena::free_slots)
    /// exists for: a frame the worker forgot to release shows up here and
    /// nowhere else until the table runs dry somewhere unrelated. Both arms are
    /// covered — a completion that delivered frames, and one that lost the
    /// link.
    #[tokio::test]
    async fn every_slot_goes_home_when_the_links_do() {
        let arena = LinkRxArena::new();
        let reactor = UringReactor::start(arena.clone()).expect("a reactor");
        let whole = arena.free_slots();

        let (rd_ok, mut wr_ok) = std::io::pipe().expect("pipe");
        wr_ok.write_all(&framed(b"delivered")).expect("write");
        let mut ok = reactor
            .attach(rd_ok.as_raw_fd(), universal())
            .expect("attach");
        assert_eq!(payload_of(within(ok.poll_event()).await), b"delivered");

        let (rd_eof, wr_eof) = std::io::pipe().expect("pipe");
        drop(wr_eof);
        let mut eof = reactor
            .attach(rd_eof.as_raw_fd(), universal())
            .expect("attach");
        assert!(matches!(
            within(eof.poll_event()).await,
            LinkEvent::Lost { .. }
        ));

        drop((ok, eof));
        drop(reactor);
        assert_eq!(
            arena.free_slots(),
            whole,
            "a slot the reactor borrowed must be back on the table"
        );
        drop((wr_ok, rd_ok, rd_eof));
    }
}
