// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
//! * **THE FRAMES ARE THE SLOT.** Until R2971 the payload was copied at the
//!   boundary `crate::poll_framed` copied it, because `RxFrame` could only
//!   carry an owned `Vec<u8>`; this header said that retiring the copy was
//!   `RxFrame`'s residual and `runtime-zero-copy`'s. R2971 retired it in both
//!   bodies at once: `RxFrame` carries `RxBytes`, and each frame that lies
//!   whole inside one completion is a range of that completion's slot, the slot
//!   going home when the last of them drops. A frame the window assembled
//!   across completions is still copied — out of the window's carry, since it
//!   lies in no one slot.
//!
//! ## Two framings: a byte stream and a datagram
//!
//! A link is attached with the rule its completions are cut by, and the rule is
//! fixed for the link's life, as upstream fixes it at task start on
//! `is_streamed` (`io/zenoh-transport/src/unicast/universal/link.rs` @
//! `match link.link.is_streamed() {`):
//!
//! | link | attached by | one completion is | upstream's body |
//! |---|---|---|---|
//! | TCP, unix-domain stream, unixpipe, vsock | [`UringReactor::attach`] | any run of bytes; frames are length-prefixed and [`RxWindow`] finds them, across completions | `setup_fragmented_read` |
//! | connected UDP | `UringReactor::attach_datagram` | exactly one datagram, which is one frame | `setup_read` |
//!
//! A datagram has no length prefix: the kernel keeps its boundary, and a read
//! of a datagram socket returns one datagram whatever room it was given, so
//! the completion's length IS the frame's. Putting it through the window would
//! read its first two bytes as a length and cut it wrong. So the datagram rule
//! is the window's absence, not a second window: the completion is handed up
//! as one frame, tagged with the peer the socket is connected to (the read
//! reports no source, and a connected socket has one).
//!
//! The slot a datagram is read into is the node's DATAGRAM RECEIVE POOL's, the
//! one the socket read of `crate::link_rx_datagram` fills, and the frame is
//! handed up by that pool's size rule: a datagram the rule calls small ends in
//! a slot of the small class whichever reader received it. That pool's large
//! class is the table this reactor's ring registered, so the read is still a
//! fixed one. Every case is answered as that socket read answers it:
//!
//! * a read of 0 bytes is an EMPTY DATAGRAM, which is a frame and not an end
//!   of stream (a datagram socket has none);
//! * a read that fills the whole slot is a TRUNCATION, because a slot is wider
//!   than any UDP datagram (65600 against 65527 over IPv6), so the last byte is
//!   the witness: the datagram is refused and counted, and the link reads on;
//! * a datagram no class had a slot for is consumed and counted refused, and
//!   the link reads on;
//! * the width flag does not exist: there is no prefix.
//!
//! ## Why not upstream's multishot receive over provided buffers
//!
//! Upstream reads every link, streamed or not, with one multishot receive over
//! a group of buffers it provides to the kernel
//! (`commons/zenoh-uring/src/linux/api/reader/mod.rs` @
//! `let recv = opcode::RecvMulti::new(types::Fd(fd), group_id)`, with the
//! buffers given in `commons/zenoh-uring/src/linux/reader/buffer_group.rs` @
//! `let entry = opcode::ProvideBuffers::new(`). That shape answers upstream's
//! PUSH model: a read is armed at all times and the kernel must find a buffer
//! when a datagram ARRIVES, so the buffer is chosen then, from the group. This
//! reactor's links PULL (one read armed when the link asks, see below), so the
//! destination is known when the read is ARMED and a fixed read into a
//! registered slot is the same receive with the buffer chosen one step
//! earlier. What a datagram needs is the framing rule above; the multishot
//! shape is the push model's, and the datagram is not what asks for it.
//!
//! What comes with it: the size of a datagram is not known when its read is
//! armed, so every datagram lands in a slot wide enough for the largest.
//! Upstream keeps the datagram there, in buffers of one and a half batches
//! (`commons/zenoh-uring/src/linux/api/reader/mod.rs` @
//! `let batch_size = batch_size + batch_size / 2;`), so a sample kept from a
//! small datagram holds a whole buffer. Here a datagram the size rule calls
//! small is copied out into a small slot and the wide one goes home at once,
//! a receive copy-break (`crate::link_rx_datagram` gives the argument), so
//! what a kept sample holds is the slot the socket read would have given it.
//!
//! ## Neither direction between a link and the worker allocates per read
//!
//! A link asks once per read and is answered once per read, so carrying the
//! ask and the answer may not cost an allocation. The ask is the link's id
//! pushed onto a list the worker drains when its waker fires; each attached
//! link reserves its one entry of that list when it attaches, since a link
//! asks again only once it has been answered. The answer is the link's own
//! one-place mailbox, for the same reason. A datagram's frame in it is a
//! counted range of a pool slot, so a datagram costs no allocation at all; a
//! stream completion is still handed up behind one `Arc`, which the frames cut
//! from it share. Only attaching and detaching, once per link, go through a
//! channel.
//!
//! ## What selects this body, and what does not
//!
//! ⚠ THIS PARAGRAPH SAID, FROM R2748, THAT NO LINK SELECTS THIS BODY, AND IT
//! WENT STALE: `StreamReadDriver::choose_ring` (`stream_link.rs`) attaches a
//! link whose reader can name a raw descriptor
//! (`crate::link_ring_fd::RingReadable`), which is upstream's dispatch on
//! `get_fd`, and a TCP stream link on Linux with `runtime-tokio-uring` on is
//! one, as are a unix-domain stream, a unixpipe and a vsock link. A reader that
//! cannot name one (a TLS stream, QUIC, an in-memory duplex that is not a
//! witness) stays on the framed body. The fifth link the pinned upstream hands
//! its ring, connected UDP, is attached by `UdpReadDriver` (`udp_pipeline.rs`)
//! with the datagram framing; an accepted UDP face reads the listener's shared
//! socket through the accept demux and stays off the ring, as upstream's
//! unconnected UDP does (`crate::link_ring_fd` holds the table). This module
//! is compiled with the stream framing it shares its table and window with
//! (`transport-link-tcp`), so a build that carries UDP and not TCP reads its
//! UDP links through tokio. What follows is what the paragraph said when it
//! was written, kept because the argument in it still holds:
//!
//! Nothing here SELECTS this body for a production link. A link reaches it by
//! being [`attach`](UringReactor::attach)ed, and no `wire_*` constructor calls
//! that yet — the read half would have to answer "do my bytes have a raw fd"
//! the way upstream makes every link answer `get_fd`, which is a trait across
//! seven reader types and its own round. The atom's residual therefore keeps
//! its first half and loses the rest.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as cmd_chan;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::Notify;

use wz_session_core::link::{LinkEvent, LostCause, RxBytes, RxFrame, RxStorage};

use crate::link_rx_arena::{LinkRxArena, LinkRxFrame};
#[cfg(feature = "transport-link-udp")]
use crate::link_rx_datagram::{DatagramRxPool, UnsizedRead};
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

/// What the worker hands a link for one of its reads.
enum Delivery {
    /// A stream completion's bytes, uncut. The link cuts them ([`StreamCut`])
    /// one frame per [`UringRx::poll_event`], because the prefix width of a
    /// frame is known only once the session has handled the frame before it.
    Bytes(Arc<LinkRxFrame>),
    /// A datagram completion's frame, as a range of the pool slot the size
    /// rule picked; `None` when the datagram was consumed and refused, which
    /// the pool counts.
    #[cfg(feature = "transport-link-udp")]
    Datagram(Option<RxBytes>),
    /// The link ended, and why.
    Lost(LostCause),
}

/// How a link's reads are armed and its completions cut into frames, fixed at
/// attach (see the module's "Two framings").
enum ReadKind {
    /// Into a slot of the ring's table; length-prefixed frames over a byte
    /// stream, cut by the link ([`StreamCut`]), not by the worker.
    Stream,
    /// Into a slot of this datagram receive pool; one datagram per completion,
    /// one frame per datagram.
    #[cfg(feature = "transport-link-udp")]
    Datagram(Arc<DatagramRxPool>),
}

/// What a link, or the reactor, asks the worker to do, other than a read.
enum Cmd {
    /// Take this link on.
    Attach { id: u64, ctx: LinkCtx },
    /// This link is gone.
    ///
    /// ⚠ A read of its own may still be IN FLIGHT, and its frame stays in the
    /// worker's in-flight table until the completion arrives. The kernel holds
    /// a pointer into that frame's slot; dropping it here would free a slot the
    /// kernel is still writing into. The worker cancels that read, because on
    /// a quiet socket nothing else ever completes it: the slot would stay out
    /// and the kernel's reference would keep the socket open after its owner
    /// closed it.
    Detach { id: u64 },
    /// Run this on the worker's thread ([`UringReactor::run_on_worker`]).
    Run(Box<dyn FnOnce() + Send>),
    /// Stop: cancel what is outstanding, drain it, and end the worker.
    Stop,
}

/// The links that asked for a read since the worker last looked: the request
/// direction, taken once per read, so it must not allocate.
///
/// A link asks again only once its last ask has been answered, so the list
/// holds at most one entry per attached link, and a link reserves that entry
/// when it attaches. `links` counts the links attached and not yet detached by
/// the worker, which is the room the list must have.
#[derive(Default)]
struct Asks {
    ids: Vec<u64>,
    links: usize,
}

/// A lock whose holders cannot leave its data half-written: the ask list and a
/// mailbox are each changed by one push, take or replace, so a holder that
/// panicked elsewhere left them whole and the next holder goes on.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A newly attached link's entry of the ask list, so its asks never grow it.
fn reserve_ask(asks: &Mutex<Asks>) {
    let mut asks = lock(asks);
    asks.links += 1;
    let room = asks.links.saturating_sub(asks.ids.len());
    asks.ids.reserve(room);
}

/// A detached link's entry of the ask list, given back with any ask of its
/// still waiting there. Called by the worker once the link's detach is in, so
/// nothing of that link is pushed after it.
fn release_ask(asks: &Mutex<Asks>, id: u64) {
    let mut asks = lock(asks);
    asks.ids.retain(|&asked| asked != id);
    asks.links = asks.links.saturating_sub(1);
}

/// Move every waiting ask into `into`, which the worker keeps empty between
/// calls, with room for one ask per attached link so the move never grows it
/// past what it has had.
fn take_asks(asks: &Mutex<Asks>, into: &mut Vec<u64>) {
    let mut asks = lock(asks);
    into.reserve(asks.links);
    into.append(&mut asks.ids);
}

/// The answer direction, from the worker to ONE link: a link has one read
/// asked for at a time, so at most one answer waits, in one place.
struct Mailbox {
    delivery: Mutex<Option<Delivery>>,
    /// The worker has let go of the link and will put nothing here again.
    closed: AtomicBool,
    ready: Notify,
}

impl Mailbox {
    fn new() -> Self {
        Self {
            delivery: Mutex::new(None),
            closed: AtomicBool::new(false),
            ready: Notify::new(),
        }
    }

    fn put(&self, delivery: Delivery) {
        let displaced = lock(&self.delivery).replace(delivery);
        debug_assert!(
            displaced.is_none(),
            "a link has one read asked for at a time, so one answer waits at most"
        );
        // Dropped outside the lock: a displaced frame's slot goes home under
        // the pool's own lock.
        drop(displaced);
        self.ready.notify_one();
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.ready.notify_one();
    }

    /// The next answer, or the link's loss once the worker has let go of it.
    ///
    /// Cancel-safe: an answer stays in its place until a call returns it, and
    /// a permit `notify_one` left behind only costs one more look.
    async fn next(&self) -> Delivery {
        loop {
            let waiting = lock(&self.delivery).take();
            if let Some(delivery) = waiting {
                return delivery;
            }
            if self.closed.load(Ordering::Acquire) {
                // An answer put before the close is visible once the close is.
                let last = lock(&self.delivery).take();
                return last.unwrap_or(Delivery::Lost(LostCause::OsError));
            }
            self.ready.notified().await;
        }
    }
}

/// Where a reactor's reads land: the link-RX table its ring registers, and the
/// datagram receive pool whose large class is that same table.
struct Destinations {
    arena: LinkRxArena,
    #[cfg(feature = "transport-link-udp")]
    datagrams: Arc<DatagramRxPool>,
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
    asks: Arc<Mutex<Asks>>,
    wake: Arc<WakeFd>,
    next_id: std::sync::atomic::AtomicU64,
    worker: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    /// Where a datagram link's reads land.
    #[cfg(feature = "transport-link-udp")]
    datagrams: Arc<DatagramRxPool>,
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
    ///
    /// A datagram link it reads lands in the node's datagram receive pool,
    /// the one the socket read of a UDP link fills, so the node has one pool
    /// of datagram slots whichever body reads a link.
    pub fn node() -> Option<&'static UringReactor> {
        static REACTOR: std::sync::OnceLock<Option<UringReactor>> = std::sync::OnceLock::new();
        REACTOR
            .get_or_init(|| {
                UringReactor::start_over(Destinations {
                    arena: LinkRxArena::node(),
                    #[cfg(feature = "transport-link-udp")]
                    datagrams: Arc::clone(DatagramRxPool::node_shared()),
                })
                .ok()
            })
            .as_ref()
    }

    /// A reader over `arena`, for a caller that owns its own node.
    ///
    /// The seam a node object plugs into once one exists, and what lets a test
    /// observe a reactor without touching whatever else the process is
    /// receiving. Same pair, same argument, as
    /// [`LinkRxArena::new`](crate::link_rx_arena::LinkRxArena::new) beside
    /// [`LinkRxArena::node`](crate::link_rx_arena::LinkRxArena::node). Its
    /// datagram links land in a datagram receive pool of its own, whose large
    /// class is `arena`'s table.
    pub fn start(arena: LinkRxArena) -> io::Result<Self> {
        Self::start_over(Destinations {
            #[cfg(feature = "transport-link-udp")]
            datagrams: Arc::new(DatagramRxPool::over_table(arena.table())),
            arena,
        })
    }

    fn start_over(mut to: Destinations) -> io::Result<Self> {
        let ring = FixedSlotRing::register(&mut to.arena, RING_ENTRIES)?;
        let wake = Arc::new(WakeFd::new()?);
        let asks = Arc::new(Mutex::new(Asks::default()));
        let (tx, rx) = cmd_chan::channel();
        let worker_wake = Arc::clone(&wake);
        let worker_asks = Arc::clone(&asks);
        // A plain OS thread and not `tokio::task::spawn_blocking`: the worker
        // runs for the node's whole life, and a blocking-pool slot held forever
        // is one the runtime cannot give back. Upstream reaches for its own
        // `ZRuntime::RX` pool for the same job, which is the same choice made
        // where a dedicated pool exists to make it in.
        let handle = std::thread::Builder::new()
            .name("wz-uring-rx".to_owned())
            .spawn(move || run_worker(ring, worker_wake, rx, worker_asks))?;
        Ok(Self {
            cmds: tx,
            asks,
            wake,
            next_id: std::sync::atomic::AtomicU64::new(0),
            worker: std::sync::Mutex::new(Some(handle)),
            #[cfg(feature = "transport-link-udp")]
            datagrams: to.datagrams,
        })
    }

    /// Run `f` on this reactor's worker thread, the next time the worker looks
    /// at its commands.
    ///
    /// The worker is a thread of the reactor's own, which no runtime a caller
    /// builds owns, so per-thread state a caller attributes to work done for
    /// it (an allocation count, a thread-local) is set up through this, as a
    /// runtime builder's `on_thread_start` sets it up on its workers. `f` runs
    /// between two waits of the ring, so it must not block for long.
    pub fn run_on_worker(&self, f: Box<dyn FnOnce() + Send>) -> io::Result<()> {
        self.send(Cmd::Run(f))
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
    /// The width is read when a frame starts, and a frame starts when the
    /// session asks for it: the worker hands the link a completion uncut and
    /// [`UringRx::poll_event`] cuts one frame per call (`StreamCut`). That is
    /// `poll_framed`'s rule exactly, and it holds when one completion carries
    /// the handshake's last frame and the first lean one: the flag flips while
    /// the session handles the first, before the second is cut. A worker that
    /// cut a whole completion at one width read both frames on the 2-byte
    /// prefix.
    ///
    /// The fd is BORROWED, not owned: the caller's reader half keeps it open,
    /// and the returned [`UringRx`] must not outlive it. That is the same
    /// contract `crate::uring::FixedSlotRing::read_framed` has and it is
    /// upheld the same way — by the driver owning both.
    pub fn attach(&self, fd: RawFd, lowlatency: Arc<AtomicBool>) -> io::Result<UringRx> {
        self.attach_framed(fd, ReadKind::Stream, None, Some(StreamCut::new(lowlatency)))
    }

    /// Take a CONNECTED datagram socket's `fd` on, and hand back the read body
    /// for it: each completion is one datagram and is delivered as one frame
    /// from `peer`.
    ///
    /// Upstream's `setup_read(link.link.get_fd()?, ring_cb)` for a link whose
    /// `is_streamed` is false. Only a connected socket may be attached: an
    /// unconnected one receives from any peer, and a read through the ring
    /// would bypass the demultiplexing by source that decides which link a
    /// datagram belongs to (upstream refuses its fd for the same reason,
    /// `io/zenoh-links/zenoh-link-udp/src/unicast.rs` @
    /// `bail!("FD unavailable for unconnected UDP")`). `peer` is the address
    /// the socket is connected to, which is the source of every datagram it
    /// can receive.
    ///
    /// The fd is BORROWED, under the contract [`Self::attach`] states.
    #[cfg(feature = "transport-link-udp")]
    pub fn attach_datagram(&self, fd: RawFd, peer: SocketAddr) -> io::Result<UringRx> {
        self.attach_framed(
            fd,
            ReadKind::Datagram(Arc::clone(&self.datagrams)),
            Some(peer),
            None,
        )
    }

    fn attach_framed(
        &self,
        fd: RawFd,
        read: ReadKind,
        src: Option<SocketAddr>,
        stream: Option<StreamCut>,
    ) -> io::Result<UringRx> {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mailbox = Arc::new(Mailbox::new());
        self.send(Cmd::Attach {
            id,
            ctx: LinkCtx {
                fd,
                read,
                mailbox: Arc::clone(&mailbox),
            },
        })?;
        // After the attach is sent and before the link exists, so the link's
        // first ask finds its room.
        reserve_ask(&self.asks);
        Ok(UringRx {
            id,
            cmds: self.cmds.clone(),
            asks: Arc::clone(&self.asks),
            wake: Arc::clone(&self.wake),
            mailbox,
            src,
            stream,
            #[cfg(feature = "transport-link-udp")]
            datagram: None,
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
    asks: Arc<Mutex<Asks>>,
    wake: Arc<WakeFd>,
    mailbox: Arc<Mailbox>,
    /// The source every frame of this link is tagged with: the peer a
    /// datagram socket is connected to, `None` for a stream link, whose frames
    /// carry no source as `crate::poll_framed`'s do not.
    src: Option<SocketAddr>,
    /// A stream link's cut: its window, its width flag and the completion it
    /// is cutting. `None` for a datagram link, whose completions arrive cut.
    stream: Option<StreamCut>,
    /// The frame a datagram completion carried that the session has not asked
    /// for yet: one at most, since a completion is one datagram and the next
    /// read is asked for only once this is empty.
    #[cfg(feature = "transport-link-udp")]
    datagram: Option<RxBytes>,
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
    /// delivery stays in the mailbox, `armed` stays true so the next call does
    /// not ask twice, and a waiting datagram is only taken by a return.
    pub async fn poll_event(&mut self) -> LinkEvent {
        loop {
            #[cfg(feature = "transport-link-udp")]
            {
                if let Some(bytes) = self.datagram.take() {
                    return self.event(bytes);
                }
            }
            if let Some(cut) = self.stream.as_mut() {
                match cut.next_frame() {
                    Ok(Some(bytes)) => return self.event(bytes),
                    Ok(None) => {}
                    Err(cause) => self.lost = Some(cause),
                }
            }
            if let Some(cause) = self.lost {
                return LinkEvent::Lost { cause };
            }
            if !self.armed {
                if self.ask().is_err() {
                    // The worker cannot be woken to see the ask, which is not
                    // something a link can report as a wire fact; `OsError` is
                    // what `poll_framed` answers when the read itself failed.
                    self.lost = Some(LostCause::OsError);
                    continue;
                }
                self.armed = true;
            }
            // A worker that let go of the link answers its loss here, so a
            // link whose worker stopped is not left parked.
            let delivery = self.mailbox.next().await;
            self.armed = false;
            match delivery {
                Delivery::Bytes(slot) => {
                    // Only a stream link is attached with the framing the
                    // worker answers with uncut bytes.
                    if let Some(cut) = self.stream.as_mut() {
                        cut.hold(slot);
                    }
                }
                #[cfg(feature = "transport-link-udp")]
                Delivery::Datagram(bytes) => self.datagram = bytes,
                Delivery::Lost(cause) => self.lost = Some(cause),
            }
        }
    }

    fn event(&self, bytes: RxBytes) -> LinkEvent {
        LinkEvent::Rx(match self.src {
            Some(src) => RxFrame::with_src(bytes, src),
            None => RxFrame::new(bytes),
        })
    }

    /// Ask the worker for ONE read: an entry of the ask list this link
    /// reserved when it attached, so the ask allocates nothing.
    fn ask(&self) -> io::Result<()> {
        lock(&self.asks).ids.push(self.id);
        self.wake.wake()
    }
}

/// What cutting a byte stream into frames carries from one frame to the next,
/// on the link's side of the mailbox.
///
/// The cut is here and not in the worker because the worker sees a completion
/// once, while the width of each frame in it is a fact only the session can
/// settle, by handling the frame before. Cutting one frame per
/// [`UringRx::poll_event`] reads the width at the instant `crate::poll_framed`
/// reads it.
struct StreamCut {
    /// The link's negotiated-transport flag, read when each frame starts.
    lowlatency: Arc<AtomicBool>,
    /// The frame boundaries ACROSS completions.
    window: RxWindow,
    /// The completion being cut, and how many of its bytes the window has
    /// consumed. Dropped the moment it is consumed, so the slot goes home when
    /// the last frame cut from it drops, and a read is armed only once it is
    /// gone.
    held: Option<(Arc<LinkRxFrame>, usize)>,
}

impl StreamCut {
    fn new(lowlatency: Arc<AtomicBool>) -> Self {
        Self {
            lowlatency,
            window: RxWindow::new(),
            held: None,
        }
    }

    fn hold(&mut self, slot: Arc<LinkRxFrame>) {
        self.held = Some((slot, 0));
    }

    /// The next frame of the held completion, cut at the width the flag names
    /// now; `None` when the completion ends without completing one (what is
    /// left of a frame is in the window's carry).
    ///
    /// A frame lying whole in the completion is a range of its slot; one the
    /// window assembled across completions is copied out of the carry, since
    /// it lies in no one slot. An oversize length prefix loses the link with
    /// the cause `crate::poll_framed` gives it.
    fn next_frame(&mut self) -> Result<Option<RxBytes>, LostCause> {
        let Some((slot, mut at)) = self.held.take() else {
            return Ok(None);
        };
        let whole: &[u8] = AsRef::<[u8]>::as_ref(&*slot);
        let (base, len) = (whole.as_ptr() as usize, whole.len());
        let mut cut: Option<RxBytes> = None;
        while cut.is_none() && at < len {
            let width = crate::prefix_width(self.lowlatency.load(Ordering::Acquire));
            let mut collect = |payload: &[u8]| {
                let start = (payload.as_ptr() as usize).wrapping_sub(base);
                let lent = start < len && payload.len() <= len - start;
                cut = Some(if lent {
                    let storage: Arc<dyn RxStorage> = slot.clone();
                    RxBytes::shared(storage, start..start + payload.len())
                        .expect("a payload inside the slot is a range of it")
                } else {
                    RxBytes::from(payload.to_vec())
                });
            };
            at += self
                .window
                .push_frame(&whole[at..], width, &mut collect)
                .map_err(|_| LostCause::PeerClosed)?;
        }
        if at < len {
            self.held = Some((slot, at));
        }
        Ok(cut)
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
    /// How this link's reads are armed and its completions handed up.
    read: ReadKind,
    mailbox: Arc<Mailbox>,
}

impl Drop for LinkCtx {
    /// The worker lets go of a link only by dropping this: on its detach, when
    /// the link is gone already, and when the worker ends, when the link must
    /// be told it is lost rather than left waiting for an answer.
    fn drop(&mut self) {
        self.mailbox.close();
    }
}

/// One read the kernel has been given and has not answered yet.
struct InFlight {
    /// Which link asked. `None` once that link has detached — the entry stays
    /// because the KERNEL still holds a pointer into `dest`.
    link: Option<u64>,
    /// The destination. Alive for exactly as long as the kernel may write to
    /// it, which is what this table is for.
    dest: Dest,
}

/// What a read in flight writes into.
enum Dest {
    /// A stream read's frame: a slot of the ring's table, or a spilled
    /// allocation.
    Frame(LinkRxFrame),
    /// A datagram read's slot of the receive pool, or no slot when no class
    /// had one and the read consumes the datagram into nothing.
    #[cfg(feature = "transport-link-udp")]
    Datagram(UnsizedRead),
}

/// The worker: one ring, one thread, and every completion routed by its key.
///
/// R2750 — NO ARENA PARAMETER. The ring carries the table it registered, so
/// there is no second handle to pass down and none to get wrong; `start`'s own
/// `arena` argument is free to be dropped the moment registration is done, and
/// the pinned storage still outlives the ring because the ring holds a refcount
/// on it. That is the residual "the lifetime contract is upheld by scoping"
/// closing, visible here as an argument that no longer needs to exist.
fn run_worker(
    mut ring: FixedSlotRing,
    wake: Arc<WakeFd>,
    cmds: cmd_chan::Receiver<Cmd>,
    asks: Arc<Mutex<Asks>>,
) {
    // The waker's destination. Declared before the loop and never moved, which
    // is what makes the always-armed read into it sound.
    let mut wake_buf = [0u8; 8];
    let mut links: HashMap<u64, LinkCtx> = HashMap::new();
    // Sized for every read the ring carries, so taking one entry and giving it
    // back per read never grows the table.
    let mut inflight: HashMap<u64, InFlight> = HashMap::with_capacity(RING_ENTRIES as usize);
    // The asks taken off the shared list, empty between passes.
    let mut asked: Vec<u64> = Vec::new();
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
        // Asks and commands first: a wakeup exists to let them in, and arming
        // a read before parking is what keeps the wait from being unbounded.
        //
        // The asks are taken BEFORE the commands are read. A link sends its
        // attach before it can ask, so every link an ask taken here names is
        // attached once the commands below are in; and a link whose detach is
        // among them is skipped rather than read for.
        take_asks(&asks, &mut asked);
        while let Ok(cmd) = cmds.try_recv() {
            match cmd {
                Cmd::Attach { id, ctx } => {
                    links.insert(id, ctx);
                }
                Cmd::Detach { id } => {
                    links.remove(&id);
                    release_ask(&asks, id);
                    // The frames those reads name stay where they are; only the
                    // routing is dropped, and the read is cancelled so that its
                    // completion, `-ECANCELED` or the bytes that beat the
                    // cancel, brings the slot home. A cancel that could not be
                    // pushed leaves the read to complete on its own, which is
                    // what every read did before the cancel existed.
                    for (key, entry) in inflight.iter_mut() {
                        if entry.link == Some(id) {
                            entry.link = None;
                            let _ = ring.submit_cancel(*key);
                        }
                    }
                }
                Cmd::Run(f) => f(),
                Cmd::Stop => stopping = true,
            }
        }
        // A stopping worker arms nothing new: the links are told they are lost
        // when it ends.
        if stopping {
            asked.clear();
        }
        for id in asked.drain(..) {
            let Some(ctx) = links.get(&id) else {
                continue;
            };
            if let Err(cause) = arm_read(&mut ring, &mut inflight, &mut next_ticket, id, ctx) {
                ctx.mailbox.put(Delivery::Lost(cause));
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
            // The ring itself failed, so no link can be served any more. The
            // return below drops every link's context, which tells each one it
            // is lost rather than leaving it parked on a mailbox nothing will
            // answer again.
            //
            // LEAKED, deliberately, and this is the one place this module
            // prefers a leak. The ring cannot be asked to cancel what it is
            // still holding, so every outstanding read names a buffer the
            // kernel may yet write into; returning their slots to the table
            // would hand that memory to another link. A forfeited slot costs
            // one of `SLOT_COUNT` for the process's life, which is what
            // `LinkRxFrame`'s own poisoned-lock arm already trades for the same
            // reason.
            for entry in inflight.into_values() {
                std::mem::forget(entry.dest);
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
                key => deliver_completion(&mut inflight, &links, key, completion.result),
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
    ctx: &LinkCtx,
) -> Result<(), LostCause> {
    let (key, dest) = match &ctx.read {
        ReadKind::Stream => arm_stream(ring, next_ticket, ctx.fd)?,
        #[cfg(feature = "transport-link-udp")]
        ReadKind::Datagram(pool) => arm_datagram(ring, next_ticket, ctx.fd, pool)?,
    };
    inflight.insert(
        key,
        InFlight {
            link: Some(link),
            dest,
        },
    );
    Ok(())
}

/// A key for a read into memory no registered slot names: above every slot
/// key and asserted below the cancellation's.
fn take_ticket(next_ticket: &mut u64) -> u64 {
    let ticket = *next_ticket;
    *next_ticket += 1;
    debug_assert!(ticket < FixedSlotRing::CANCEL_KEY);
    ticket
}

/// A stream read: into a slot of the ring's own table, or a spilled frame.
fn arm_stream(
    ring: &mut FixedSlotRing,
    next_ticket: &mut u64,
    fd: RawFd,
) -> Result<(u64, Dest), LostCause> {
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
        let ticket = take_ticket(next_ticket);
        let len = frame.as_ref().len() as u32;
        let dst = frame.as_mut().as_mut_ptr();
        // SAFETY: `dst` names the frame's own allocation, the frame is moved
        // into `inflight` by the caller and stays there until this key's
        // completion is reaped, and nothing else touches those bytes meanwhile.
        // `ticket` is above `FIRST_FREE_KEY` — so above every slot key — and
        // asserted below `CANCEL_KEY`.
        if unsafe { ring.submit_read(fd, dst, len, ticket) }.is_err() {
            return Err(LostCause::OsError);
        }
        ticket
    };
    Ok((key, Dest::Frame(frame)))
}

/// A datagram read: into the slot `pool` arms for a read whose length is not
/// known yet, a fixed read when that slot is one the ring registered, or a
/// receive of no bytes when the pool had no slot.
///
/// A read that could not be pushed drops its slot here, before any read
/// names it, which sends it home.
#[cfg(feature = "transport-link-udp")]
fn arm_datagram(
    ring: &mut FixedSlotRing,
    next_ticket: &mut u64,
    fd: RawFd,
    pool: &Arc<DatagramRxPool>,
) -> Result<(u64, Dest), LostCause> {
    let read = pool.arm_unsized();
    let pushed = match read.destination() {
        Some((dst, len)) => match ring.registered_slot(dst) {
            // SAFETY: `dst` is the first byte of registered slot `buf_index`
            // and `len` is that slot's width; the slot is armed for this read
            // alone, and `read`, which holds it, is moved into `inflight` by
            // the caller and stays there until this key's completion is reaped.
            Some(buf_index) => unsafe { ring.submit_read_fixed_at(fd, dst, len, buf_index) },
            None => {
                let ticket = take_ticket(next_ticket);
                // SAFETY: as above, for a slot no registration names (the small
                // class), read the ordinary way under a ticket above every slot
                // key and below the cancellation's.
                unsafe { ring.submit_read(fd, dst, len as u32, ticket) }.map(|()| ticket)
            }
        },
        None => {
            let ticket = take_ticket(next_ticket);
            // SAFETY: the ticket is above every slot key and below the
            // cancellation's; the receive names no memory.
            unsafe { ring.submit_discard(fd, ticket) }.map(|()| ticket)
        }
    };
    let key = pushed.map_err(|_| LostCause::OsError)?;
    Ok((key, Dest::Datagram(read)))
}

/// Route one read completion to the link that asked for it.
fn deliver_completion(
    inflight: &mut HashMap<u64, InFlight>,
    links: &HashMap<u64, LinkCtx>,
    key: u64,
    result: i32,
) {
    let Some(entry) = inflight.remove(&key) else {
        // A key nothing is waiting for. Not reachable through this worker's own
        // submissions, and dropped rather than asserted on: a completion the
        // kernel invented is not something a link can be told about.
        return;
    };
    // A detached link, or one already gone, has nothing to be told: the frame
    // drops here, which is what sends its slot home.
    let Some(link) = entry.link else {
        return; // detached while its read was in flight
    };
    let Some(ctx) = links.get(&link) else {
        return;
    };
    // The delivery is built to completion BEFORE it is sent, and the function
    // that builds it takes the frame by value. That order is the contract, and
    // the signature is what keeps it: when the link can see the delivery, this
    // worker holds no handle on the slot, so the slot is home the instant the
    // last range of it drops. Sending from inside the function that holds the
    // slot made "the slot is home" depend on whether the worker thread had been
    // scheduled again since the send.
    let delivery = completion_delivery(entry.dest, result);
    ctx.mailbox.put(delivery);
}

/// What one read completion means for the link that asked for it.
///
/// Takes `dest` BY VALUE and returns only a [`Delivery`], so everything this
/// function holds on the completion's slot -- the frame, the `Arc` the ranges
/// are cut from, the large slot a small datagram was copied out of -- is
/// released before its caller can send anything. The only handles left on a
/// slot are the ranges inside the returned delivery (none at all for a lost
/// link or a refused datagram, whose slot is home on return).
fn completion_delivery(dest: Dest, result: i32) -> Delivery {
    if result < 0 {
        return Delivery::Lost(LostCause::OsError);
    }
    let n = result as usize;
    match dest {
        Dest::Frame(frame) => stream_delivery(frame, n),
        // One datagram read: the whole completion is one frame, landed by the
        // pool's size rule (the module's "Two framings" gives every case).
        #[cfg(feature = "transport-link-udp")]
        Dest::Datagram(read) => Delivery::Datagram(read.land(n)),
    }
}

/// One byte-stream read: its bytes, uncut, for the link to cut as it is asked
/// for frames ([`StreamCut`]).
fn stream_delivery(mut frame: LinkRxFrame, n: usize) -> Delivery {
    if n == 0 {
        // EOF. Between frames it is a clean close; anywhere else the peer cut a
        // frame in half — and both lose the link, which is what
        // `crate::poll_framed` answers for the same two cases.
        return Delivery::Lost(LostCause::PeerClosed);
    }
    frame.truncate(n);
    // R3037 -- THE COMPLETION EDGE, on the row where the bus master is real: the
    // kernel's completion for this read was reaped above, so it has finished
    // writing the slot, and everything handed up from here only reads it.
    // The frames cut from it are ranges of this slot, and the slot goes home
    // when the last of them drops.
    Delivery::Bytes(Arc::new(frame.complete()))
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
            LinkEvent::Rx(frame) => frame.bytes.into_vec(),
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

    /// R2971 — THE FRAMES OF ONE COMPLETION ARE RANGES OF ITS SLOT, and the
    /// slot goes home only when the last of them drops.
    ///
    /// The population is the witness: a completion holds ONE slot, and a link
    /// arms its next read only once it has consumed what the last completion
    /// carried, so with both frames of one completion alive exactly one slot is
    /// out. Under the copy this replaced the slot was home as soon as the
    /// worker had split it, so the count would already be full here.
    #[tokio::test]
    async fn two_frames_of_one_completion_are_ranges_of_its_slot() {
        use crate::session_rx_pool_ap::{SlotState, SLOT_COUNT};

        let arena = LinkRxArena::new();
        let reactor = UringReactor::start(arena.clone()).expect("a reactor");

        let (rd, mut wr) = std::io::pipe().expect("pipe");
        let mut wire = framed(b"alpha");
        wire.extend_from_slice(&framed(b"beta"));
        wr.write_all(&wire)
            .expect("one write, so one read can carry both");

        let mut rx = reactor.attach(rd.as_raw_fd(), universal()).expect("attach");
        let LinkEvent::Rx(alpha) = within(rx.poll_event()).await else {
            panic!("the first frame");
        };
        let LinkEvent::Rx(beta) = within(rx.poll_event()).await else {
            panic!("the second frame");
        };
        assert_eq!(alpha.bytes, b"alpha");
        assert_eq!(beta.bytes, b"beta");
        assert!(alpha.bytes.is_shared() && beta.bytes.is_shared());
        let slot_start = alpha
            .bytes
            .as_ptr()
            .wrapping_sub(crate::prefix_width(false));
        let slot = arena
            .slot_of(slot_start)
            .expect("the first frame starts a slot of this table, by the pool's own answer");
        assert_eq!(
            arena.free_slots(),
            SLOT_COUNT - 1,
            "both frames are ranges of the one slot their completion filled"
        );
        // R3037 -- the kernel's completion was reaped, so the pool records the
        // slot as shared read-only, not as still owned by the read that filled
        // it. This is the edge on the row where the bus master is real.
        assert_eq!(
            arena.slot_state(slot),
            Some(SlotState::CpuRef),
            "a delivered completion's slot is shared read-only while any frame of it lives"
        );

        drop(alpha);
        assert_eq!(
            arena.free_slots(),
            SLOT_COUNT - 1,
            "the second frame still holds the slot"
        );
        assert_eq!(arena.slot_state(slot), Some(SlotState::CpuRef));
        drop(beta);
        // Exact, not eventual: the worker thread has been releasing its own
        // handle on the slot since before it sent the delivery these frames
        // came in (`completion_delivery` takes the frame by value), so no
        // scheduling of that thread can leave the slot out here.
        assert_eq!(
            arena.free_slots(),
            SLOT_COUNT,
            "the last range is gone, so the slot is home"
        );
        assert_eq!(arena.slot_state(slot), Some(SlotState::Free));

        drop(rx);
        drop((wr, rd));
    }

    /// WHEN A DELIVERY EXISTS, THE WORKER HOLDS NOTHING ON ITS SLOT.
    ///
    /// The witness for the ordering the test above depends on and cannot
    /// observe: the worker is another thread, and between sending a delivery
    /// and returning it used to keep its own handle on the slot, so "the last
    /// range dropped" and "the slot is home" were two instants whose gap was
    /// the scheduler's. Here the building function runs on this thread, so the
    /// instant after it returns is the instant a link may see the delivery, and
    /// the arena is read at exactly that point: the completion inside the
    /// delivery is the only holder (one slot out), a lost link's slot is
    /// already home, and the frames the link cuts from the completion are then
    /// the slot's only holders, the last of them bringing it back.
    ///
    /// The control is a handle that outlives the function (a leaked clone of
    /// the slot's `Arc`, or a frame held past its return), or a cut that keeps
    /// a consumed completion: the count stays one short and this reds on the
    /// line naming which holder it was.
    #[test]
    fn a_built_delivery_leaves_the_worker_holding_nothing_on_its_slot() {
        use crate::session_rx_pool_ap::SLOT_COUNT;

        let arena = LinkRxArena::new();
        let mut taker = arena.clone();
        let mut filled = |wire: &[u8]| {
            let mut frame = taker.take(SLOT_SIZE);
            assert!(frame.is_pooled(), "a fresh table lends a slot");
            frame.as_mut()[..wire.len()].copy_from_slice(wire);
            frame
        };

        let mut wire = framed(b"alpha");
        wire.extend_from_slice(&framed(b"beta"));
        let Delivery::Bytes(slot) =
            completion_delivery(Dest::Frame(filled(&wire)), wire.len() as i32)
        else {
            panic!("a stream completion is delivered as its bytes");
        };
        assert_eq!(
            arena.free_slots(),
            SLOT_COUNT - 1,
            "the delivered completion is the slot's only holder"
        );

        let mut cut = StreamCut::new(universal());
        cut.hold(slot);
        let alpha = cut.next_frame().expect("no oversize prefix");
        let beta = cut.next_frame().expect("no oversize prefix");
        assert_eq!(alpha.as_ref().map(|b| b.as_slice()), Some(&b"alpha"[..]));
        assert_eq!(beta.as_ref().map(|b| b.as_slice()), Some(&b"beta"[..]));
        assert!(
            cut.held.is_none(),
            "a consumed completion is let go with the frame that consumed it"
        );
        assert!(matches!(cut.next_frame(), Ok(None)));
        drop(alpha);
        assert_eq!(
            arena.free_slots(),
            SLOT_COUNT - 1,
            "the second frame still holds the slot"
        );
        drop(beta);
        assert_eq!(
            arena.free_slots(),
            SLOT_COUNT,
            "the last range is gone, so the slot is home"
        );

        // The two arms that lose the link in the worker hand up no slot.
        for (what, result) in [("a read error", -5), ("an end of stream", 0)] {
            let delivery = completion_delivery(Dest::Frame(filled(&[])), result);
            assert!(
                matches!(delivery, Delivery::Lost(_)),
                "{what} loses the link"
            );
            assert_eq!(
                arena.free_slots(),
                SLOT_COUNT,
                "{what}: the slot is home before the delivery is sent"
            );
        }

        // The arm that loses the link in the cut lets its completion go too.
        let oversize = (u16::MAX as u32 + 1).to_le_bytes();
        let Delivery::Bytes(slot) = completion_delivery(Dest::Frame(filled(&oversize)), 4) else {
            panic!("a stream completion is delivered as its bytes");
        };
        let mut cut = StreamCut::new(Arc::new(AtomicBool::new(true)));
        cut.hold(slot);
        assert!(matches!(cut.next_frame(), Err(LostCause::PeerClosed)));
        assert_eq!(
            arena.free_slots(),
            SLOT_COUNT,
            "an oversize prefix: the slot is home once the link is lost"
        );
    }

    /// ONE COMPLETION CARRYING THE HANDSHAKE'S LAST FRAME AND THE FIRST LEAN
    /// ONE is cut at each frame's own width.
    ///
    /// The flag flips while the session handles the first frame, which is
    /// after the completion arrived and before the second frame is asked for.
    /// A cut of the whole completion at the width in force when it arrived
    /// reads the lean frame's 4-byte prefix as a 2-byte length.
    ///
    /// CONTROL: read the width once per held completion (in `hold`) rather
    /// than per `next_frame`, and the second frame is not `lean`.
    #[test]
    fn one_completion_holding_a_universal_and_a_lean_frame_cuts_each_at_its_width() {
        let arena = LinkRxArena::new();
        let mut taker = arena.clone();
        let mut frame = taker.take(SLOT_SIZE);
        assert!(frame.is_pooled(), "a fresh table lends a slot");
        let mut wire = framed(b"handshake");
        wire.extend_from_slice(&4u32.to_le_bytes());
        wire.extend_from_slice(b"lean");
        frame.as_mut()[..wire.len()].copy_from_slice(&wire);
        let Delivery::Bytes(slot) = completion_delivery(Dest::Frame(frame), wire.len() as i32)
        else {
            panic!("a stream completion is delivered as its bytes");
        };

        let lowlatency = universal();
        let mut cut = StreamCut::new(Arc::clone(&lowlatency));
        cut.hold(slot);
        let first = cut.next_frame().expect("no oversize prefix");
        assert_eq!(
            first.as_ref().map(|b| b.as_slice()),
            Some(&b"handshake"[..])
        );

        // Established: the session is lean from the next frame on.
        lowlatency.store(true, Ordering::Release);
        let second = cut.next_frame().expect("no oversize prefix");
        assert_eq!(
            second.as_ref().map(|b| b.as_slice()),
            Some(&b"lean"[..]),
            "the second frame of the completion is cut at the width in force when it starts"
        );
        assert!(
            second.is_some_and(|b| b.is_shared()),
            "a frame whole in the completion is a range of its slot"
        );
    }

    /// A DATAGRAM COMPLETION IS ONE FRAME, whatever its first bytes would say
    /// as a length prefix, in the class its size picks, and each of the
    /// datagram rule's own cases leaves the slots accounted for when the
    /// delivery exists.
    ///
    /// The datagram begins `02 00`, which the stream rule reads as a two-byte
    /// frame followed by the start of another; the datagram rule hands up all
    /// five bytes as one frame. It is small, so it is a slot of the small class
    /// and the large slot the read landed in is home by the time the delivery
    /// exists. A datagram past the small class is a range of the large slot it
    /// landed in. A read that fills the whole slot is a truncated datagram: no
    /// frame, slot home. A failed read loses the link.
    ///
    /// CONTROL: hand a small datagram up where it landed (skip the copy-break
    /// in `UnsizedRead::land`) and the first class assertion reds, with the
    /// table one slot short.
    #[cfg(feature = "transport-link-udp")]
    #[test]
    fn a_built_datagram_delivery_is_one_frame_in_the_class_its_size_picks() {
        use crate::link_rx_datagram::RxClassId;
        use crate::session_rx_pool_ap::SLOT_COUNT;

        let arena = LinkRxArena::new();
        let pool = Arc::new(DatagramRxPool::over_table(arena.table()));
        let filled = |wire: &[u8]| {
            let read = pool.arm_unsized();
            let (dst, room) = read.destination().expect("a fresh pool lends a slot");
            assert_eq!(room, SLOT_SIZE, "the read lands in a slot of the table");
            // SAFETY: `dst` is the first byte of the slot armed for this read
            // alone, valid for `room` bytes, more than any wire here.
            unsafe { std::slice::from_raw_parts_mut(dst, wire.len()) }.copy_from_slice(wire);
            read
        };

        let datagram = [0x02u8, 0x00, b'x', b'y', b'z'];
        let Delivery::Datagram(Some(small)) =
            completion_delivery(Dest::Datagram(filled(&datagram)), datagram.len() as i32)
        else {
            panic!("a datagram is delivered as its frame");
        };
        assert_eq!(small, datagram, "the frame is the whole datagram");
        assert_eq!(
            pool.slot_of(small.as_ptr()).map(|s| s.0),
            Some(RxClassId::Small),
            "a small datagram is a slot of the small class"
        );
        assert_eq!(
            arena.free_slots(),
            SLOT_COUNT,
            "the large slot it landed in is home when the delivery exists"
        );
        drop(small);

        let wide = vec![0xA5u8; 2000];
        let Delivery::Datagram(Some(large)) =
            completion_delivery(Dest::Datagram(filled(&wide)), wide.len() as i32)
        else {
            panic!("a datagram is delivered as its frame");
        };
        assert_eq!(large, wide);
        assert_eq!(
            pool.slot_of(large.as_ptr()).map(|s| s.0),
            Some(RxClassId::Large)
        );
        assert_eq!(
            arena.free_slots(),
            SLOT_COUNT - 1,
            "a datagram past the small class is the slot it landed in"
        );
        drop(large);
        assert_eq!(arena.free_slots(), SLOT_COUNT, "the slot is home");

        let Delivery::Datagram(Some(empty)) = completion_delivery(Dest::Datagram(filled(&[])), 0)
        else {
            panic!("an empty datagram is not the end of a datagram socket");
        };
        assert!(empty.is_empty(), "an empty datagram is one empty frame");
        assert_eq!(arena.free_slots(), SLOT_COUNT);
        drop(empty);

        assert!(
            matches!(
                completion_delivery(Dest::Datagram(filled(&[])), SLOT_SIZE as i32),
                Delivery::Datagram(None)
            ),
            "a datagram that filled its slot is refused, not a lost link"
        );
        assert_eq!(pool.truncated(), 1);
        assert_eq!(arena.free_slots(), SLOT_COUNT, "the refused slot is home");

        assert!(matches!(
            completion_delivery(Dest::Datagram(filled(&[])), -111),
            Delivery::Lost(LostCause::OsError)
        ));
        assert_eq!(arena.free_slots(), SLOT_COUNT);
        assert_eq!(
            pool.free_slots(RxClassId::Small),
            pool.capacity(RxClassId::Small)
        );
    }

    /// DATAGRAMS ON A CONNECTED SOCKET ARRIVE ONE FRAME EACH, through the ring,
    /// tagged with the peer.
    ///
    /// All three are sent before the link is polled, so the reads that carry
    /// them are not paced by the sender: what separates them is the socket's
    /// datagram boundary, which a stream link would not keep. The first begins
    /// with what a stream link reads as a length prefix, and the second is
    /// empty, which a stream link reads as the end.
    #[cfg(feature = "transport-link-udp")]
    #[tokio::test]
    async fn datagrams_on_a_connected_socket_arrive_one_frame_each() {
        let arena = LinkRxArena::new();
        let reactor = UringReactor::start(arena.clone()).expect("a reactor");

        let local = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let peer_addr = peer.local_addr().expect("peer address");
        local.connect(peer_addr).expect("connect");
        peer.connect(local.local_addr().expect("local address"))
            .expect("connect");

        let first = [0x02u8, 0x00, b'x', b'y', b'z'];
        peer.send(&first).expect("send");
        peer.send(&[]).expect("send");
        peer.send(b"tail").expect("send");

        let mut rx = reactor
            .attach_datagram(local.as_raw_fd(), peer_addr)
            .expect("attach");
        for want in [&first[..], &[][..], &b"tail"[..]] {
            match within(rx.poll_event()).await {
                LinkEvent::Rx(frame) => {
                    assert_eq!(frame.bytes, want, "one datagram, one frame");
                    assert_eq!(frame.src, Some(peer_addr), "tagged with the peer");
                }
                other => panic!("expected a frame, got {other:?}"),
            }
        }

        drop(rx);
        drop((local, peer));
    }

    /// A DETACHED LINK'S OUTSTANDING READ IS CANCELLED, so its slot comes home
    /// while the reactor lives.
    ///
    /// The link is armed on a socket nobody sends to, so its read never
    /// completes on its own; dropping the link must still bring the slot back.
    /// CONTROL: drop the cancel from the `Detach` arm and the count stays one
    /// short until the reactor itself is dropped.
    #[cfg(feature = "transport-link-udp")]
    #[tokio::test]
    async fn a_detached_links_read_is_cancelled_and_its_slot_comes_home() {
        let arena = LinkRxArena::new();
        let reactor = UringReactor::start(arena.clone()).expect("a reactor");
        let whole = arena.free_slots();

        let quiet = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let silent_addr = silent.local_addr().expect("address");
        quiet.connect(silent_addr).expect("connect");

        let mut rx = reactor
            .attach_datagram(quiet.as_raw_fd(), silent_addr)
            .expect("attach");
        let parked = tokio::spawn(async move {
            let _ = rx.poll_event().await;
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while arena.free_slots() == whole {
            assert!(
                std::time::Instant::now() < deadline,
                "the read was never armed"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        parked.abort();
        let _ = parked.await;
        while arena.free_slots() != whole {
            assert!(
                std::time::Instant::now() < deadline,
                "the detached link's slot did not come home while the reactor lives"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        drop(reactor);
        drop((quiet, silent));
    }

    /// A DATAGRAM READ THROUGH THE RING TAKES THE CLASS ITS SIZE PICKS, as the
    /// socket read gives it: a small one is a small slot and holds no slot of
    /// the table, a wide one is the table slot it landed in.
    ///
    /// The link asks for its next read only when polled, so after each poll
    /// the table's count is exactly what the frames held so far keep out.
    /// CONTROL: skip the copy-break in `UnsizedRead::land` and the first count
    /// is one short, the small frame holding a table slot.
    #[cfg(feature = "transport-link-udp")]
    #[tokio::test]
    async fn a_datagram_read_through_the_ring_takes_the_class_its_size_picks() {
        use crate::link_rx_datagram::RxClassId;
        use crate::session_rx_pool_ap::SLOT_COUNT;

        let arena = LinkRxArena::new();
        let reactor = UringReactor::start(arena.clone()).expect("a reactor");
        let local = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let peer_addr = peer.local_addr().expect("peer address");
        local.connect(peer_addr).expect("connect");
        peer.connect(local.local_addr().expect("local address"))
            .expect("connect");
        let mut rx = reactor
            .attach_datagram(local.as_raw_fd(), peer_addr)
            .expect("attach");

        let narrow = [0x5Au8; 64];
        let wide = vec![0xC3u8; 20 * 1024];
        peer.send(&narrow).expect("send");
        peer.send(&wide).expect("send");

        let LinkEvent::Rx(small) = within(rx.poll_event()).await else {
            panic!("the first datagram");
        };
        assert_eq!(small.bytes, narrow);
        assert_eq!(
            reactor.datagrams.slot_of(small.bytes.as_ptr()).map(|s| s.0),
            Some(RxClassId::Small)
        );
        assert_eq!(
            arena.free_slots(),
            SLOT_COUNT,
            "a small datagram holds no slot of the table"
        );

        let LinkEvent::Rx(large) = within(rx.poll_event()).await else {
            panic!("the second datagram");
        };
        assert_eq!(large.bytes, wide);
        assert_eq!(
            reactor.datagrams.slot_of(large.bytes.as_ptr()).map(|s| s.0),
            Some(RxClassId::Large)
        );
        assert_eq!(
            arena.free_slots(),
            SLOT_COUNT - 1,
            "a wide datagram is the table slot it landed in"
        );

        drop((small, large));
        assert_eq!(arena.free_slots(), SLOT_COUNT);
        assert_eq!(
            reactor.datagrams.free_slots(RxClassId::Small),
            reactor.datagrams.capacity(RxClassId::Small)
        );
        drop(rx);
        drop((local, peer));
    }

    /// WITH EVERY SLOT OUT, A DATAGRAM IS CONSUMED, COUNTED, AND THE LINK READS
    /// ON, as the socket read refuses one when neither class has a slot.
    ///
    /// The read is a receive of no bytes. The count is read again after a
    /// pause because a receive that did not take the datagram off the queue
    /// would complete again at once, every time the link asks, and the count
    /// would climb: CONTROL, submit a `READ` of no bytes in
    /// `FixedSlotRing::submit_discard`, which returns without receiving.
    #[cfg(feature = "transport-link-udp")]
    #[tokio::test]
    async fn with_every_slot_out_a_datagram_is_consumed_counted_and_the_link_reads_on() {
        let arena = LinkRxArena::new();
        let reactor = UringReactor::start(arena.clone()).expect("a reactor");
        // Drained AFTER the registration, which needs the table whole.
        let mut taker = arena.clone();
        let table: Vec<_> = (0..arena.free_slots())
            .map(|_| taker.take(SLOT_SIZE))
            .collect();
        assert_eq!(arena.free_slots(), 0, "the table must be dry");
        let small: Vec<UnsizedRead> = (0..reactor
            .datagrams
            .capacity(crate::link_rx_datagram::RxClassId::Small))
            .map(|_| reactor.datagrams.arm_unsized())
            .collect();
        assert!(
            small.iter().all(|read| read.destination().is_some()),
            "each of these holds a small slot"
        );
        assert!(
            reactor.datagrams.arm_unsized().destination().is_none(),
            "no class has a slot left"
        );

        let local = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let peer_addr = peer.local_addr().expect("peer address");
        local.connect(peer_addr).expect("connect");
        peer.connect(local.local_addr().expect("local address"))
            .expect("connect");
        let mut rx = reactor
            .attach_datagram(local.as_raw_fd(), peer_addr)
            .expect("attach");
        let reading = tokio::spawn(async move {
            let event = rx.poll_event().await;
            (rx, event)
        });

        peer.send(b"refused").expect("send");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while reactor.datagrams.refused() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the datagram was never consumed"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            reactor.datagrams.refused(),
            1,
            "one datagram, consumed once"
        );
        assert!(
            !reading.is_finished(),
            "a refused datagram is no frame and no loss: the link reads on"
        );

        reading.abort();
        let _ = reading.await;
        drop((small, table));
        assert_eq!(
            arena.free_slots(),
            crate::session_rx_pool_ap::SLOT_COUNT,
            "every slot held for the test is home"
        );
        drop(reactor);
        drop((local, peer));
    }

    /// AN ATTACHED LINK HOLDS ROOM FOR ITS ASK, so no ask grows the list, and
    /// gives it back when the worker has taken its detach.
    ///
    /// CONTROL: drop the `reserve_ask` call from `attach_framed` and the
    /// capacity assertion reds.
    #[tokio::test]
    async fn an_attached_link_holds_room_for_its_ask_until_it_detaches() {
        let reactor = UringReactor::start(LinkRxArena::new()).expect("a reactor");
        let pipes: Vec<_> = (0..3).map(|_| std::io::pipe().expect("pipe")).collect();
        let mut links: Vec<UringRx> = pipes
            .iter()
            .map(|(rd, _)| reactor.attach(rd.as_raw_fd(), universal()).expect("attach"))
            .collect();
        {
            let asks = lock(&reactor.asks);
            assert_eq!(asks.links, 3);
            assert!(
                asks.ids.capacity() >= 3,
                "room for one ask of each attached link"
            );
        }

        drop(links.pop());
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while lock(&reactor.asks).links != 2 {
            assert!(
                std::time::Instant::now() < deadline,
                "the worker never took the detach"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        drop(links);
        drop(pipes);
    }

    /// AN ANSWER PUT BEFORE THE WORKER LETS GO IS TAKEN BEFORE THE LOSS, and a
    /// wait that was cancelled loses nothing.
    #[tokio::test]
    async fn a_mailbox_answers_what_was_put_before_it_closed_then_the_loss() {
        let mailbox = Mailbox::new();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), mailbox.next())
                .await
                .is_err(),
            "an empty mailbox waits"
        );
        mailbox.put(Delivery::Lost(LostCause::PeerClosed));
        mailbox.close();
        assert!(matches!(
            within(mailbox.next()).await,
            Delivery::Lost(LostCause::PeerClosed)
        ));
        assert!(matches!(
            within(mailbox.next()).await,
            Delivery::Lost(LostCause::OsError)
        ));
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
    /// possible is the WAKER — B's ask has to reach a worker already parked in
    /// `submit_and_wait` — and the control is deleting the waker arming: with
    /// no way into a parked wait, B's ask sits in the list and this times out.
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
    /// The window lives in the link and survives a completion, which is what
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
    /// The two frames are in separate completions here (the first is read
    /// before the second is written);
    /// [`a_width_flip_between_two_frames_of_one_completion_is_honoured`] is the
    /// same flip inside one completion.
    ///
    /// CONTROL: take the width at attach again and the second `poll_event`
    /// never yields `b"lean"` — the 2-byte prefix reads the lean frame's low
    /// half as a length.
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

    /// A WIDTH FLIP BETWEEN TWO FRAMES OF ONE COMPLETION IS HONOURED.
    ///
    /// The handshake's last frame and the first lean frame are written in one
    /// write before the link is polled, so one completion carries both, which
    /// is the peer having written both before this side reaped either. The
    /// flag flips after the first frame is handed up, as the open helper flips
    /// it after the handshake returns.
    ///
    /// CONTROL: cut the whole completion when it arrives (in the worker, or in
    /// `StreamCut::hold`) and the second `poll_event` is not `b"lean"`.
    #[tokio::test]
    async fn a_width_flip_between_two_frames_of_one_completion_is_honoured() {
        let arena = LinkRxArena::new();
        let reactor = UringReactor::start(arena.clone()).expect("a reactor");
        let lowlatency = universal();

        let (rd, mut wr) = std::io::pipe().expect("pipe");
        let lean = b"lean";
        let mut wire = framed(b"handshake");
        wire.extend_from_slice(&(lean.len() as u32).to_le_bytes());
        wire.extend_from_slice(lean);
        wr.write_all(&wire)
            .expect("one write, so one read can carry both");

        let mut rx = reactor
            .attach(rd.as_raw_fd(), Arc::clone(&lowlatency))
            .expect("attach");
        assert_eq!(payload_of(within(rx.poll_event()).await), b"handshake");
        lowlatency.store(true, Ordering::Release);
        assert_eq!(
            payload_of(within(rx.poll_event()).await),
            lean,
            "the second frame of one completion is cut at the width in force when it starts"
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
