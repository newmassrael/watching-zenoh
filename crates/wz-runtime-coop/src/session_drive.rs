// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The cooperative unicast session drive loop, over any datagram link.
//!
//! The MCU analog of `wz_runtime_tokio::session_glue::drive_session_until_terminal`,
//! minus the `tokio::select!`: a cooperative single-task polling loop. Every
//! decision PRIMITIVE is the shared `wz_session_core` SSOT — this module is
//! only the loop STRUCTURE that sequences them:
//!
//! - inbound: what [`SessionDatagramLink::try_recv`] read, or under `rx-in-place` what
//!   [`SessionDatagramLink::recv_with`] lends, is handed with the time to the session's
//!   receive ([`UnicastRx`]), which dispatches it, stages its fragments and reports each
//!   outcome. The pump keeps no state of the receive between two datagrams.
//! - deadlines: the session's own timers
//!   ([`TransportTimers`](wz_session_core::transport_timers::TransportTimers))
//!   say how long the link may wait and judge the handshake, lease and
//!   keep-alive deadlines when the loop hands them the time; the loop keeps
//!   none of its own.
//! - outbound is transparent: the FSM action methods call
//!   `link_driver().send_blocking` on the link's own `BoxedLinkDriver`.
//!
//! R2915 — the loop used to live in `wz-session-lwip`, typed on lwIP's link
//! and UDP driver, so no MCU profile could run a session over any other
//! network stack. zenoh-pico's Zephyr port runs its session over Zephyr's
//! own BSD sockets, which a wz Zephyr profile could not do without writing a
//! second copy of this loop. The loop now names only what it needs from a
//! link — [`SessionDatagramLink`] — and each network stack implements that
//! seam (`wz_session_lwip::LwipSessionLink` over lwIP).

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::boxed::Box;
#[cfg(not(feature = "session-slot"))]
use alloc::rc::Rc;
#[cfg(all(
    feature = "alloc",
    not(feature = "session-slot"),
    target_has_atomic = "ptr"
))]
use alloc::sync::Arc;
#[cfg(feature = "session-slot")]
use core::cell::{Cell, UnsafeCell};
#[cfg(all(feature = "reassembly", not(feature = "session-slot")))]
use core::mem::ManuallyDrop;
use core::mem::MaybeUninit;
use core::net::SocketAddr;
#[cfg(feature = "session-slot")]
use core::ops::{Deref, DerefMut};
#[cfg(all(
    feature = "alloc",
    not(feature = "session-slot"),
    target_has_atomic = "ptr"
))]
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "session-slot")]
use critical_section::Mutex;
use wz_runtime_core::TimeSource;
use wz_session_core::caps;
use wz_session_core::drive::new_session_engine_in;
use wz_session_core::drive::SessionEngine;
use wz_session_core::driver_loop::{DriverOutcome, EventSink, IterationEvent};
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::link::LostCause;
#[cfg(feature = "alloc")]
use wz_session_core::link::RxFrame;
use wz_session_core::session_fsm_unicast::SessionFsmUnicastEvent;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::text_out::{FixedText, TextOut};
use wz_session_core::transport_timers::TransportTimers;
use wz_session_core::unicast_rx::{RxReassembly, UnicastRx};

// The units a pump dispatched in place, by the path they took: the session receive's count.
#[cfg(feature = "rx-in-place")]
pub use wz_session_core::unicast_rx::RxPathCounts;

#[cfg(all(feature = "reassembly", feature = "rx-in-place"))]
use crate::reassembly_rx::{in_place_reassembly, InPlaceReassembly, PoolStorage, ReassemblyArena};
#[cfg(all(feature = "reassembly", not(feature = "rx-in-place")))]
use crate::reassembly_rx::{mcu_reassembly, CoopReassembly};

#[cfg(not(feature = "session-slot"))]
use crate::link_storage::LinkTables;
use crate::session_runtime::{SessionEntropy, SessionHandle};
use crate::{yield_now, ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopRuntime, CoopTime};

/// What the drive loop needs from a network stack: advance its input path,
/// and hand over the next inbound datagram.
///
/// The OUTBOUND half is not here. It is the link's
/// [`wz_session_core::link::BoxedLinkDriver`], which lives inside the
/// session's action bundle and is reached by the FSM action methods, not by
/// the loop. One object usually implements both.
pub trait SessionDatagramLink {
    /// Advance the stack's input path by one pass. A stack the loop must
    /// pump (lwIP `NO_SYS`, polled from this thread) does its work here; one
    /// whose input runs on its own thread or ISR does nothing.
    fn service(&self);

    /// [`Self::service`], told how long the loop can do without it: `max_wait_ms` is the time
    /// until anything the session or its runtime has to do falls due (a handshake, lease or
    /// keep-alive deadline, a registered timer), and `u64::MAX` when nothing does. A link that
    /// can sleep until then (a socket that blocks) may wait up to that long for a datagram
    /// instead of for one tick, and the loop wakes for no more than what is due.
    ///
    /// The provided form ignores it, which is right for a link that is pumped from here (lwIP
    /// polls its stack on every pass) and for every link that has not said it can do better.
    /// A link that waits longer than a tick is only right when it is the only thing the loop
    /// waits on: another session's socket is not looked at while this one blocks, so a link
    /// takes the permission to wait from its image (the stack's idle wait) and not from this
    /// number alone.
    fn service_within(&self, max_wait_ms: u64) {
        let _ = max_wait_ms;
        self.service();
    }

    /// Whether this link makes use of the time until something falls due
    /// ([`Self::service_within`]). The loop works that time out only for a link that does: it is a
    /// clock read and the session's deadlines every pass, which a link that waits the tick
    /// regardless would spend for nothing. A link answers `false` until it has been given leave to
    /// wait longer, so an image that has not asked runs the code it always ran.
    fn uses_wake_budget(&self) -> bool {
        false
    }

    /// The next inbound datagram from the link's peer as a frame, or `None`
    /// when none is queued. A link has one peer, fixed once known
    /// (`wz_session_core::datagram_peer`): an initiator's from its dial, an
    /// acceptor's from the first `InitSyn` it takes. A datagram from anyone
    /// else never reaches the session and moves none of its replies. The
    /// copying receive is the heap profile's (the frame is an owned
    /// [`RxFrame`]), so a build with no allocator has no such method and a
    /// link answers [`Self::recv_with`] alone.
    #[cfg(feature = "alloc")]
    fn try_recv(&self) -> Option<RxFrame>;

    /// Lend the next inbound datagram's bytes to `f` WHERE THE LINK HOLDS
    /// THEM, and let it go once `f` returns; `false` when nothing is queued.
    /// Only the peer's, as [`Self::try_recv`] takes, and the `InitSyn` that
    /// binds an acceptor is bound before `f` runs, so what `f` sends goes to
    /// the peer.
    ///
    /// The receive the `rx-in-place` loop makes. The bytes are valid for the
    /// call only, which is what lets a link hand over its own buffer instead
    /// of a copy of it. `f` may send on the session (the link's outbound half
    /// must stay usable while it runs) but must not receive.
    ///
    /// The provided form takes the datagram through [`Self::try_recv`], so it
    /// costs that frame's copy: right for a link with no buffer of its own to
    /// lend, and what every link answered before this existed. A link that
    /// holds its datagrams overrides it. With no allocator there is no copying
    /// receive to fall back to, so every link states this one.
    #[cfg(feature = "alloc")]
    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        match self.try_recv() {
            Some(frame) => {
                f(&frame.bytes);
                true
            }
            None => false,
        }
    }

    /// Lend the next inbound datagram's bytes to `f` where the link holds them
    /// (see the form above); with no allocator a link states it.
    #[cfg(not(feature = "alloc"))]
    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool;

    /// Whether the link under the session is gone, and how: a stream whose peer
    /// closed it or whose socket failed. Asked once a step finds nothing to
    /// receive, so what was queued before the end is read first; the loop then
    /// tells the session, which closes. The provided form answers `None`: a
    /// datagram link has no connection to lose, and its peer's silence is the
    /// lease's to judge.
    fn lost(&self) -> Option<LostCause> {
        None
    }

    /// Whether the link holds input it has already taken from its stack: a whole batch read
    /// together with the one before it, a datagram read while the loop waited. The next step
    /// reads it, and a wait on the stack would not see it (`input_wait`, the heap profile's).
    fn holds_input(&self) -> bool {
        false
    }

    /// Whether the link has input waiting in its stack that it cannot read: it receives into a
    /// pool of buffers its session's links share, holds none, and every one is held by another
    /// link for something of its own. A wait on its input would end at once and the step
    /// that follows would read nothing, so its owner leaves it out of the wait; the step that
    /// gives a buffer back is woken by the holder's own input, and the link is waited on again
    /// once a buffer is free. The provided form answers `false`: a link that receives into a
    /// buffer of its own always can. Only a build that accepts links has pools.
    #[cfg(feature = "session-unicast-accept")]
    fn waits_for_buffer(&self) -> bool {
        false
    }

    /// Whether the link owes its stack bytes of a frame it was already handed, which its next
    /// step writes as far as the stack takes them ([`Self::service`]). While it does, a wait its
    /// owner makes for the link's input must end on room as well (`LinkWait::input_or_room`),
    /// or the rest waits for the next input; while it owes nothing that wait is for input alone,
    /// so a link with room does not wake it. The provided form owes nothing: a link that writes
    /// each frame whole.
    fn owes_write(&self) -> bool {
        false
    }

    /// Write what the link owes its stack, as far as the stack takes it now, without waiting: what
    /// [`Self::service`] writes before it waits. A publish that finds every slot of its session's
    /// pool held asks it of every link, so a link whose stack has room by now gives its slot back
    /// without a step of its own. The provided form owes nothing. Only a build that accepts links
    /// has pools.
    #[cfg(feature = "session-unicast-accept")]
    fn write_owed_now(&self) {}

    /// Whether the session may be handed input now. A link whose owner holds its input back (the
    /// delivery lane of a session that cannot take another message) answers `false`, and the loop
    /// then dispatches nothing this step: no datagram, and not the rest of one already read, so
    /// what one step delivers is never more than one message. The provided form answers `true`.
    fn takes_input(&self) -> bool {
        true
    }

    /// Whether the link can keep the datagram it is lending ([`Self::keep`]) and lend the same
    /// bytes again: a link that receives into a buffer of its own, which nothing writes until it
    /// reads the next datagram. A session whose delivery cannot take all of a datagram then stops
    /// part-way and goes on from there on a later step, and nothing is copied to wait. The
    /// provided form answers `false`, and the session reads on or parks a copy of the rest.
    fn keeps_input(&self) -> bool {
        false
    }

    /// Keep the datagram being lent: called from inside the `f` of [`Self::recv_with`], it has
    /// the next `recv_with` lend the same bytes again, before any other datagram. Does nothing on
    /// a link that does not keep ([`Self::keeps_input`]).
    fn keep(&self) {}

    /// Whether the bytes [`Self::recv_with`] lends stay where they lie, unwritten, after `f`
    /// returns, until the link is next asked to receive or to be serviced: what lets the link's
    /// owner hand what it read to a callback where the datagram lies, holding the link back from
    /// receiving and from being serviced until the callback returns. The provided form answers
    /// `false`, which a link whose buffer its stack may write at any time answers too.
    fn lends_until_next_receive(&self) -> bool {
        false
    }

    /// What the link's OWNER waits on for its next input ([`LinkWaits::wait`]), from any thread
    /// and with nothing of the session held, for a link opened to be waited on that way: its
    /// [`Self::service`] then does not wait, so the loop that drives it never sleeps under its
    /// owner's lock. `None` for a link whose loop waits, which is every link that was not opened
    /// otherwise. The heap profile's: a slot image's loop is the only thing that drives its links.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn input_wait(&self) -> Option<WaitOn> {
        None
    }

    /// What a thread that does not drive the link waits on for room on its outbound side
    /// ([`LinkWaits::wait_room`]), with nothing of the session held: a sender that finds the
    /// session held by another, which may be waiting for room on this link up to
    /// `wait_before_close`, asks this instead of waiting for the session, so that a message it may
    /// drop is not held behind one it may not. `None` for a link that cannot tell. The heap
    /// profile's, as [`Self::input_wait`] is.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn room_wait(&self) -> Option<WaitOn> {
        None
    }

    /// Lend the owner the free part of this link's receive buffer for one read it makes with
    /// nothing of the session held, waiting in the read itself ([`RxLease`]), where a wait on the
    /// link's input ([`Self::input_wait`]) is followed by the step's read. `None` for a link
    /// that gives no such read, holds input already, has a lease out, or has ended; its owner then
    /// waits on its input. While the lease is out the link's receive reads nothing and leaves
    /// the buffer alone, and what the read brought is the link's once the lease is landed
    /// ([`Self::land_rx`]).
    ///
    /// Asked only where the link could be asked to receive: what is left of a batch is moved to
    /// the front of the buffer here, as a receive moves it, so nothing a receive lent may be read
    /// any more ([`Self::lends_until_next_receive`]). The heap profile's, as [`Self::input_wait`]
    /// is.
    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    fn lend_rx(&self) -> Option<RxLease> {
        None
    }

    /// Take back a lease [`Self::lend_rx`] gave, with what its read brought: the bytes it read
    /// are the link's from here, and a stream it found ended or failed ends the link, after what
    /// came before is handed over. A lease another link gave is let go of and changes nothing.
    #[cfg(all(
        feature = "alloc",
        not(feature = "session-slot"),
        target_has_atomic = "ptr"
    ))]
    fn land_rx(&self, lease: RxLease) {
        drop(lease);
    }
}

/// A wait that a thread which drives no link makes beside the links' (`LinkWaits`): the program's
/// word that a clock it moves has moved on, which no stack names to its platform. A wait over
/// links with one of these beside them is a look at the links, and the step that follows reads
/// every link.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub trait LinkReadiness: Send + Sync {
    /// Block until what this waits for has come, or `timeout_ms` has passed; return at once
    /// when it already has.
    fn wait_readable(&self, timeout_ms: u32);
}

/// What a wait on a link names: the link's handle in the stack that made it, a value copied into
/// a wait set that holds nothing of the link. A handle whose link has gone may name another by
/// the time it is waited on (a descriptor number a close freed for a new socket), so what a wait
/// on it answers is a hint, as every wake is: the step that follows looks again under the
/// session's lock.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOn {
    /// A socket of the platform's: a POSIX or Zephyr descriptor, a Windows `SOCKET`.
    Socket(usize),
    /// A link of the program's transport by its handle (`wz_session_core::app_link_table`'s
    /// `LinkHandle`), which is never reused: a wait on one whose link has gone answers at once.
    AppLink(u64),
    /// A wake the stack made for a session ([`LinkWaits::wake`]): ready once its waker is woken
    /// from any thread, and made quiet again by the wait that finds it so.
    Wake(usize),
}

/// A wake a stack makes once for a session ([`LinkWaits::wake`]): what a wait names it by, and
/// the waker that makes it ready from any thread. Whoever holds the waker ends the session's next
/// wait over its links by waking it, as the program's word that its clock moved on does.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub struct StackWake {
    /// What a wait names the wake by.
    pub on: WaitOn,
    /// What makes the wake ready.
    pub waker: core::task::Waker,
}

/// One entry of a wait over several links ([`LinkWaits::wait`]): the link, and whether the wait
/// ends on its room as well as on its input. A link that owes its stack the rest of a frame
/// ([`SessionDatagramLink::owes_write`]) is waited on for both, so the rest is written as soon as
/// the stack takes it; one that owes nothing for its input alone, so a link with room does not
/// wake its owner.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkWait {
    /// The link waited on.
    pub on: WaitOn,
    /// Whether room on the link ends the wait as well.
    pub room: bool,
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl LinkWait {
    /// A wait for the input of `on`.
    pub const fn input(on: WaitOn) -> Self {
        Self { on, room: false }
    }

    /// A wait for the input of `on` or for room on it.
    pub const fn input_or_room(on: WaitOn) -> Self {
        Self { on, room: true }
    }
}

/// The waits of one stack's links, made by a thread that does not drive them and with nothing of
/// the session held: one value for the stack, taken once when the session opens
/// ([`SessionLinks::waits`]), that waits on the handles its links name ([`WaitOn`]) and holds
/// nothing of any link.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub trait LinkWaits: Send + Sync {
    /// Block until one of `on` has input, or room for an entry that asks for it, or `timeout_ms`
    /// has passed; at once when one already has, and when `on` is empty. A failed wait is a
    /// quiet link: the step that follows reads and reports the failure. An entry the stack cannot
    /// name to its platform bounds the wait at a look of a millisecond, so it is not starved
    /// behind a wait on the others.
    fn wait(&self, on: &[LinkWait], timeout_ms: u32);

    /// Wait up to `timeout_us` microseconds for `on` to take more bytes: `true` once it will
    /// (or once it has failed or gone, which the send that follows reports), `false` when it
    /// still would not when the time is up.
    fn wait_room(&self, on: WaitOn, timeout_us: u64) -> bool;

    /// A wake of this stack's, made once for a session at its open: a handle a wait over the
    /// session's links names beside them ([`WaitOn::Wake`]), and the waker any thread makes it
    /// ready with. `None` for a stack that has none, whose waits a wake beside them bounds at a
    /// look instead. The provided form has none.
    fn wake(&self) -> Option<StackWake> {
        None
    }
}

/// The waits of a stack whose links name nothing to wait on: each of them waits in its own loop,
/// so no wait is asked of this. One asked anyway ends at once, and a wait for room finds it.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
#[derive(Debug, Clone, Copy, Default)]
pub struct NoWaits;

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl LinkWaits for NoWaits {
    fn wait(&self, on: &[LinkWait], timeout_ms: u32) {
        let _ = (on, timeout_ms);
    }

    fn wait_room(&self, on: WaitOn, timeout_us: u64) -> bool {
        let _ = (on, timeout_us);
        true
    }
}

/// What a read its owner made of a link's input came to ([`LinkRead::read_waiting`]).
#[cfg(all(
    feature = "alloc",
    not(feature = "session-slot"),
    target_has_atomic = "ptr"
))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadWaited {
    /// This many bytes were taken into the buffer, at least one.
    Read(usize),
    /// Nothing came within the wait, or the wait was interrupted: the link is as it was.
    Quiet,
    /// The other end closed the stream: nothing more comes.
    Ended,
    /// The read failed, with the platform's code for why.
    Failed(i32),
}

/// A read of a link's input that its owner makes with nothing of the session held and that waits
/// in the read itself, as zenoh-pico's read task waits in its socket's `recv`
/// (`vendor/zenoh-pico/src/transport/unicast/read.c` @ `_z_unicast_client_read`): one call where a
/// wait for the link to be readable and the read after it are two
/// ([`SessionDatagramLink::lend_rx`]).
#[cfg(all(
    feature = "alloc",
    not(feature = "session-slot"),
    target_has_atomic = "ptr"
))]
pub trait LinkRead: Send + Sync {
    /// Wait up to `timeout_ms` milliseconds (at least one) for the link's stack to have bytes,
    /// and take what it has, at most `buf.len()`, into `buf`; at once when some are queued.
    fn read_waiting(&self, buf: &mut [u8], timeout_ms: u32) -> ReadWaited;
}

/// A link's [`LinkRead`], shared between the link and the leases it gives ([`RxLease`]), with
/// whether a read of a lease is under way: what the link waits out before it lets its buffer go
/// ([`Self::wait_out`]).
#[cfg(all(
    feature = "alloc",
    not(feature = "session-slot"),
    target_has_atomic = "ptr"
))]
pub struct OwnerRead {
    read: Box<dyn LinkRead>,
    reading: AtomicBool,
}

#[cfg(all(
    feature = "alloc",
    not(feature = "session-slot"),
    target_has_atomic = "ptr"
))]
impl OwnerRead {
    /// The owner's read `read`, with no lease out.
    pub fn new(read: Box<dyn LinkRead>) -> Arc<Self> {
        Arc::new(Self {
            read,
            reading: AtomicBool::new(false),
        })
    }

    /// Lend the `len` bytes at `at` to one read of the owner's.
    ///
    /// # Safety
    /// The bytes are writable, and nothing reads, writes or frees them until the lease's read has
    /// ended or the lease is let go of unread, which [`Self::wait_out`] waits for.
    pub unsafe fn lend(self: &Arc<Self>, at: *mut u8, len: usize) -> RxLease {
        self.reading.store(true, Ordering::Release);
        RxLease {
            owner: Arc::clone(self),
            at,
            len,
            waited: None,
        }
    }

    /// Return once no read of a lease of this is under way. A link that lets go of its buffer
    /// while a lease is out first ends the read (its stream shut, which a read waiting on it
    /// answers at once) and then waits here, so the buffer is not freed under the read.
    pub fn wait_out(&self) {
        while self.reading.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
    }

    /// Whether `lease` was lent by this, and not by another link's read.
    pub fn lent(self: &Arc<Self>, lease: &RxLease) -> bool {
        Arc::ptr_eq(self, &lease.owner)
    }
}

/// The free part of a link's receive buffer, lent to one read its owner makes with nothing of the
/// session held ([`SessionDatagramLink::lend_rx`]), and what that read brought. Made, read and
/// landed by the owner's thread; the session takes it back under its lock
/// ([`SessionDatagramLink::land_rx`]).
#[cfg(all(
    feature = "alloc",
    not(feature = "session-slot"),
    target_has_atomic = "ptr"
))]
pub struct RxLease {
    owner: Arc<OwnerRead>,
    at: *mut u8,
    len: usize,
    waited: Option<ReadWaited>,
}

#[cfg(all(
    feature = "alloc",
    not(feature = "session-slot"),
    target_has_atomic = "ptr"
))]
impl RxLease {
    /// Make the read, waiting up to `timeout_ms` milliseconds in it. A lease is read once; a
    /// second call reads nothing.
    pub fn read(&mut self, timeout_ms: u32) {
        if self.waited.is_some() {
            return;
        }
        // SAFETY: the bytes were lent by `OwnerRead::lend`, whose caller leaves them to this read
        // alone until it ends, which the store below says.
        let buf = unsafe { core::slice::from_raw_parts_mut(self.at, self.len) };
        let waited = self.owner.read.read_waiting(buf, timeout_ms.max(1));
        self.owner.reading.store(false, Ordering::Release);
        self.waited = Some(waited);
    }

    /// What the read brought: [`ReadWaited::Quiet`] for a lease not read.
    pub fn waited(&self) -> ReadWaited {
        self.waited.unwrap_or(ReadWaited::Quiet)
    }
}

#[cfg(all(
    feature = "alloc",
    not(feature = "session-slot"),
    target_has_atomic = "ptr"
))]
impl Drop for RxLease {
    fn drop(&mut self) {
        // A lease let go of unread lets the link have its buffer back; one that was read said so
        // when its read ended, and a later lease of the same link may be reading now.
        if self.waited.is_none() {
            self.owner.reading.store(false, Ordering::Release);
        }
    }
}

/// The loop's sink as the dispatch of a datagram sees it: what is handed goes to `sink`, and
/// whether the session takes another record, and whether the datagram stays where the link holds
/// it when the dispatch stops, are the link's to say.
#[cfg(feature = "rx-in-place")]
struct LinkSink<'a, L: ?Sized, F: ?Sized> {
    link: &'a L,
    sink: &'a mut F,
}

#[cfg(feature = "rx-in-place")]
impl<L: SessionDatagramLink + ?Sized, F: EventSink + ?Sized> EventSink for LinkSink<'_, L, F> {
    fn event(&mut self, event: IterationEvent<'_, '_>) {
        self.sink.event(event)
    }

    fn record(&mut self, record: wz_session_core::driver_loop::InPlaceRecord<'_, '_>) {
        self.sink.record(record)
    }

    fn takes_another(&mut self) -> bool {
        self.link.takes_input()
    }

    fn holds_datagram(&self) -> bool {
        self.link.keeps_input()
    }

    fn lend_rejoined(&mut self, message: Option<&[u8]>) {
        self.sink.lend_rejoined(message)
    }
}

/// A shared link is a link: the same object is usually the session's
/// `Rc<dyn BoxedLinkDriver>` sink too, so the loop takes a clone of that `Rc`.
///
/// Absent under `session-slot`, where nothing is shared by a pointer: the driver
/// is a value in the session's slot and the pump reads it through a handle to that
/// slot (fixed-memory step S9c).
#[cfg(not(feature = "session-slot"))]
impl<T: SessionDatagramLink + ?Sized> SessionDatagramLink for Rc<T> {
    fn service(&self) {
        (**self).service()
    }

    fn service_within(&self, max_wait_ms: u64) {
        (**self).service_within(max_wait_ms)
    }

    fn uses_wake_budget(&self) -> bool {
        (**self).uses_wake_budget()
    }

    fn try_recv(&self) -> Option<RxFrame> {
        (**self).try_recv()
    }

    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        (**self).recv_with(f)
    }

    fn lost(&self) -> Option<LostCause> {
        (**self).lost()
    }

    fn holds_input(&self) -> bool {
        (**self).holds_input()
    }

    #[cfg(feature = "session-unicast-accept")]
    fn waits_for_buffer(&self) -> bool {
        (**self).waits_for_buffer()
    }

    fn owes_write(&self) -> bool {
        (**self).owes_write()
    }

    #[cfg(feature = "session-unicast-accept")]
    fn write_owed_now(&self) {
        (**self).write_owed_now()
    }

    fn takes_input(&self) -> bool {
        (**self).takes_input()
    }

    fn keeps_input(&self) -> bool {
        (**self).keeps_input()
    }

    fn keep(&self) {
        (**self).keep()
    }

    fn lends_until_next_receive(&self) -> bool {
        (**self).lends_until_next_receive()
    }

    #[cfg(feature = "alloc")]
    fn input_wait(&self) -> Option<WaitOn> {
        (**self).input_wait()
    }

    #[cfg(feature = "alloc")]
    fn room_wait(&self) -> Option<WaitOn> {
        (**self).room_wait()
    }

    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    fn lend_rx(&self) -> Option<RxLease> {
        (**self).lend_rx()
    }

    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    fn land_rx(&self, lease: RxLease) {
        (**self).land_rx(lease)
    }
}

/// A link in a cell is a link: the handle the drive loop pumps names the same driver the
/// session's actions send through (`crate::link_cells`).
#[cfg(not(feature = "session-slot"))]
impl<T: SessionDatagramLink + ?Sized> SessionDatagramLink for crate::link_cells::CellRc<T> {
    fn service(&self) {
        (**self).service()
    }

    fn service_within(&self, max_wait_ms: u64) {
        (**self).service_within(max_wait_ms)
    }

    fn uses_wake_budget(&self) -> bool {
        (**self).uses_wake_budget()
    }

    fn try_recv(&self) -> Option<RxFrame> {
        (**self).try_recv()
    }

    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        (**self).recv_with(f)
    }

    fn lost(&self) -> Option<LostCause> {
        (**self).lost()
    }

    fn holds_input(&self) -> bool {
        (**self).holds_input()
    }

    #[cfg(feature = "session-unicast-accept")]
    fn waits_for_buffer(&self) -> bool {
        (**self).waits_for_buffer()
    }

    fn owes_write(&self) -> bool {
        (**self).owes_write()
    }

    #[cfg(feature = "session-unicast-accept")]
    fn write_owed_now(&self) {
        (**self).write_owed_now()
    }

    fn takes_input(&self) -> bool {
        (**self).takes_input()
    }

    fn keeps_input(&self) -> bool {
        (**self).keeps_input()
    }

    fn keep(&self) {
        (**self).keep()
    }

    fn lends_until_next_receive(&self) -> bool {
        (**self).lends_until_next_receive()
    }

    #[cfg(feature = "alloc")]
    fn input_wait(&self) -> Option<WaitOn> {
        (**self).input_wait()
    }

    #[cfg(feature = "alloc")]
    fn room_wait(&self) -> Option<WaitOn> {
        (**self).room_wait()
    }

    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    fn lend_rx(&self) -> Option<RxLease> {
        (**self).lend_rx()
    }

    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    fn land_rx(&self, lease: RxLease) {
        (**self).land_rx(lease)
    }
}

/// The protocol of a link, as a locator's scheme names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkProto {
    /// `udp/`: datagrams.
    Udp,
    /// `tcp/`: a byte stream.
    Tcp,
    /// `tls/`: a byte stream inside a TLS 1.3 channel, each end proving its key
    /// (decision D9 of `docs/session-lifecycle-intent.md`).
    Tls,
}

impl LinkProto {
    /// The locator scheme that names the protocol: `udp`, `tcp` or `tls`.
    pub const fn scheme(self) -> &'static str {
        match self {
            LinkProto::Udp => "udp",
            LinkProto::Tcp => "tcp",
            LinkProto::Tls => "tls",
        }
    }

    /// What a link of the protocol reports of itself to a connectivity plane
    /// (`BoxedLinkDriver::link_subject`): its kind, which says whether it is streamed and how
    /// reliable. The NICs its address sits on are not resolved, so they read as undetermined and
    /// not as none: an answer a link that does not ask the platform cannot give.
    #[cfg(feature = "alloc")]
    pub fn subject(self) -> &'static wz_session_core::link::LinkSubject {
        use wz_session_core::link::{LinkKind, LinkSubject};
        static UDP: LinkSubject = LinkSubject {
            kind: Some(LinkKind::Udp),
            ..LinkSubject::UNKNOWN
        };
        static TCP: LinkSubject = LinkSubject {
            kind: Some(LinkKind::Tcp),
            ..LinkSubject::UNKNOWN
        };
        static TLS: LinkSubject = LinkSubject {
            kind: Some(LinkKind::Tls),
            ..LinkSubject::UNKNOWN
        };
        match self {
            LinkProto::Udp => &UDP,
            LinkProto::Tcp => &TCP,
            LinkProto::Tls => &TLS,
        }
    }
}

/// What a dial names: a protocol and the end it reaches, an IPv4 or an IPv6 address and a port:
/// `udp/a.b.c.d:port`, `tcp/[x:y::z]:port`, `tls/...`. The address is `core::net`'s, which every
/// stack's socket seam takes, so one locator type reaches datagram and stream links alike and a
/// stack refuses a family it does not carry when it opens the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Locator {
    /// The protocol the link speaks.
    pub proto: LinkProto,
    /// The end the link reaches.
    pub at: SocketAddr,
}

impl Locator {
    /// A UDP locator.
    pub const fn udp(at: SocketAddr) -> Self {
        Self {
            proto: LinkProto::Udp,
            at,
        }
    }

    /// A TCP locator.
    pub const fn tcp(at: SocketAddr) -> Self {
        Self {
            proto: LinkProto::Tcp,
            at,
        }
    }

    /// A TLS locator.
    pub const fn tls(at: SocketAddr) -> Self {
        Self {
            proto: LinkProto::Tls,
            at,
        }
    }

    /// zenoh's text of the locator, the [`Display`](core::fmt::Display) text, written without
    /// `core::fmt` into text of [`MAX_LOCATOR_LEN`](caps::MAX_LOCATOR_LEN) bytes.
    ///
    /// Every IPv4 locator fits: the bound is held at compile time to at least
    /// [`LONGEST_IPV4_LOCATOR_LEN`]. An IPv6 locator is up to [`LONGEST_IP_LOCATOR_LEN`] bytes,
    /// inside the default bound; in a build whose bound is shorter, the text of a longer one is
    /// refused, which [`FixedText::finish`] reports, never a locator cut short.
    pub fn text(&self) -> FixedText<{ caps::MAX_LOCATOR_LEN }> {
        let mut text = FixedText::new();
        text.push_str(self.proto.scheme());
        text.push('/');
        text.push_socket_addr(self.at);
        text
    }
}

/// The longest IPv4 locator text, 25 bytes: every scheme is three letters, and the widest end is
/// `255.255.255.255:65535`. It is the least [`MAX_LOCATOR_LEN`](caps::MAX_LOCATOR_LEN) may
/// be, because every link of this engine is an IP link and every stack it runs over carries
/// IPv4: a build whose bound could not name an IPv4 end could name no end at all.
pub const LONGEST_IPV4_LOCATOR_LEN: usize = "tcp/255.255.255.255:65535".len();

/// The longest IP locator text, 62 bytes: an IPv6 end with every group written out and the widest
/// scope, `tcp/[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535`. A bound below it still
/// builds; the text of an end longer than the bound is refused (see [`Locator::text`]).
pub const LONGEST_IP_LOCATOR_LEN: usize =
    "tcp/[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535".len();

const _: () = assert!(
    caps::MAX_LOCATOR_LEN >= LONGEST_IPV4_LOCATOR_LEN,
    "MAX_LOCATOR_LEN cannot hold an IPv4 locator such as udp/255.255.255.255:65535 (25 bytes)"
);

/// zenoh's text of the locator, `<scheme>/a.b.c.d:port` or `<scheme>/[ipv6]:port`.
impl core::fmt::Display for Locator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}/{}", self.proto.scheme(), self.at)
    }
}

/// Why a stack could not open a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkOpenError {
    /// The stack has no socket, port or buffer left to give. Worth trying
    /// again later, which is why a dial that meets it is retried.
    Exhausted,
    /// The stack cannot open a link of the locator's protocol at all (an lwIP
    /// image asked for `tcp/`). Permanent for the locator: a retry would meet
    /// the same answer.
    Unsupported,
    /// The stack tried and the other end did not take the link (a TCP
    /// connection refused or unreachable). Worth trying again later.
    Refused,
}

/// The two halves of one session link, as a stack opens them: the outbound half
/// the session's action bundle sends through and the inbound half the drive loop
/// pumps. One object often is both (Zephyr's socket driver); lwIP's are two
/// (its stack handle, pumped, and its UDP driver, read).
///
/// Absent under `session-slot`: its sink is an `Rc` of a driver, and a link on that
/// profile is a driver moved into a slot of the session table with a pump over a
/// handle to it (fixed-memory step S9c; `wz_session_lwip::session_host::SessionHost`).
#[cfg(not(feature = "session-slot"))]
pub struct OpenedLink<P> {
    /// What the session's actions send through: a counted handle on the cell the link's driver
    /// lives in (`crate::link_cells`).
    pub sink: crate::link_cells::CellRc<dyn BoxedLinkDriver>,
    /// What the drive loop services and takes datagrams from.
    pub pump: P,
}

/// What a network stack gives a session shell that is written once for all of
/// them: the means to open the two ends of a UDP session link.
///
/// This is the seam a node that LISTENS and DIALS needs, where
/// [`SessionDatagramLink`] is the seam a loop that DRIVES one link needs. The
/// admin node is the first user: it accepts one session on a port and dials
/// whatever endpoints a host writes, and neither is any stack's business but the
/// socket under it.
///
/// Absent under `session-slot`, with [`OpenedLink`] (see there).
#[cfg(not(feature = "session-slot"))]
pub trait SessionLinks {
    /// What the drive loop pumps for a link this stack opened.
    type Pump: SessionDatagramLink + 'static;

    /// A dial this stack began ([`Self::begin_initiator`]), held by value where the session holds
    /// its face: one type for each stack, so a dial is neither boxed nor called through a table of
    /// its own. A link made at once is one ([`From`]), which is what [`Dialled`] is for a stack
    /// whose dials do not wait.
    type Dial: PendingDial<Self::Pump> + From<OpenedLink<Self::Pump>> + 'static;

    /// Whether the stack opens links to an IPv6 end. `false` for a stack built without IPv6:
    /// what reads an endpoint for it refuses a bracketed address as one it never dials and reads
    /// IPv4 text alone, so an image of such a stack carries no reader of IPv6 text. A constant,
    /// for that reason, as `Bind::IPV6` is on the slot profile.
    const IPV6: bool = true;

    /// The waits of this stack's links ([`LinkWaits`]): what every handle its links, ports and
    /// groups name ([`WaitOn`]) is waited on with. The heap profile's, as
    /// [`SessionDatagramLink::input_wait`] is.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    type Waits: LinkWaits + Clone + 'static;

    /// The waits of this stack's links, which a session takes once when it opens and makes every
    /// wait of its links' with.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    fn waits(&self) -> Self::Waits;

    /// A UDP link that accepts: bound on `port`, with no peer until the first
    /// `InitSyn` it takes names one.
    fn open_acceptor(&self, port: u16) -> Result<OpenedLink<Self::Pump>, LinkOpenError>;

    /// A link that dials `to`: on a port the stack picks, with every send going
    /// to the end it names. A protocol the stack has no link for is
    /// [`LinkOpenError::Unsupported`].
    fn open_initiator(&self, to: Locator) -> Result<OpenedLink<Self::Pump>, LinkOpenError>;

    /// The buffers of every link the stack opens from now on, for the session the links serve:
    /// tables the session laid out in the memory it reserved when it opened, a receive buffer and
    /// outbound storage for each link it may hold. A stack that takes them opens each link over a
    /// buffer of each, and a link the tables have no buffer left for is
    /// [`LinkOpenError::Exhausted`], never one that allocates; told before the session listens, so
    /// a listener it opens after takes them too. The default ignores them: a stack whose links
    /// bring buffers of their own (an lwIP pool, a test network) keeps them.
    fn lend_buffers(&mut self, tables: LinkTables) {
        let _ = tables;
    }

    /// The bytes of a cell that holds any link the stack opens (`crate::link_cells`): what a
    /// session's arena lays the cells of its link table out with. The default, `0`, is a stack
    /// that places each link on the heap.
    fn link_cell_bytes(&self) -> usize {
        0
    }

    /// The cells every link the stack opens from now on is placed in, for the session the links
    /// serve: a link that finds none free is [`LinkOpenError::Exhausted`], and none is placed on
    /// the heap. The default ignores them, as a stack whose `link_cell_bytes` is `0` does.
    fn lend_cells(&mut self, cells: wz_session_core::byte_cells::LentByteCells) {
        let _ = cells;
    }

    /// [`Self::open_initiator`], begun without waiting for the link's connection to be made: the
    /// dial is asked again ([`PendingDial::poll`]) until its link is made or refused, so a dial that
    /// is slow to be answered or refused (a stream's connect) does not hold whoever holds the
    /// session meanwhile. The default makes the link here, as [`Self::open_initiator`] does, which
    /// is the answer of a stack whose dials do not wait.
    fn begin_initiator(&self, to: Locator) -> Result<Self::Dial, LinkOpenError> {
        self.open_initiator(to).map(Into::into)
    }

    /// A listener on `at`, which yields one link for each connection a peer opens to it. A stack
    /// that does not listen, or not for the locator's protocol, is
    /// [`LinkOpenError::Unsupported`]: the default, so a stack that never accepts a stream
    /// writes nothing here.
    #[cfg(feature = "alloc")]
    fn open_listener(
        &self,
        at: Locator,
    ) -> Result<Box<dyn LinkListener<Self::Pump>>, LinkOpenError> {
        let _ = at;
        Err(LinkOpenError::Unsupported)
    }

    /// The multicast group `endpoint` names, joined: the
    /// [`GroupTransport`](crate::group_transport::GroupTransport) a group session runs over,
    /// opened as the session's link when the session takes it. The endpoint is the text the
    /// config states (a `udp/` locator naming an interface), which each stack reads as it reads
    /// a group. A stack that joins no group, or not the one named, is
    /// [`LinkOpenError::Unsupported`]: the default, so a stack without groups writes nothing here.
    #[cfg(feature = "alloc")]
    fn open_group(
        &self,
        endpoint: &str,
    ) -> Result<Box<dyn crate::group_transport::GroupTransport>, LinkOpenError> {
        let _ = endpoint;
        Err(LinkOpenError::Unsupported)
    }

    /// The link `pump` as one handle that whatever reads it shares: a session's gates over it and
    /// its owner's read of it reach the same link through clones of this. The default puts the
    /// pump behind a pointer of its own; a stack whose pump is already a shared handle hands that
    /// handle back, so its link is behind one pointer and not two.
    fn share_pump(pump: Self::Pump) -> crate::link_cells::CellRc<dyn SessionDatagramLink> {
        crate::link_cells::CellRc::boxed(pump).into_link()
    }
}

/// The accepting end of a stream protocol: a port a node listens on, and the links of the
/// connections that arrive on it. It is a value the node holds and polls from its loop, like the
/// slot profile's `Accept`; what it yields is the link of a connection already made, so a session
/// opened over it takes the acceptor's role at the handshake and nothing else differs from a
/// dial.
///
/// Absent under `session-slot`, with [`OpenedLink`] (see there).
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub trait LinkListener<P> {
    /// The locator the listener is bound to, with the port the stack chose when the one asked
    /// for was 0.
    fn local(&self) -> Locator;

    /// The link of the connection waiting on the port, taken without blocking: `Ok(None)` when
    /// none waits. [`LinkOpenError::Exhausted`] when the stack had no socket or buffer for it
    /// (the connection is closed or stays queued, as the stack's listener says, and a later call
    /// tries again); [`LinkOpenError::Unsupported`] when the listener is broken for good.
    fn accept(&self) -> Result<Option<OpenedLink<P>>, LinkOpenError>;

    /// What a thread other than the one that accepts waits on for a connection
    /// ([`LinkWaits::wait`]); `None` when the stack gives none, and then the node looks for one
    /// at a pace of its own.
    fn input_wait(&self) -> Option<WaitOn> {
        None
    }
}

/// A dial begun and not yet answered ([`SessionLinks::begin_initiator`]), asked without waiting
/// whether its link has been made.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub trait PendingDial<P> {
    /// The link, once its connection is made; the refusal, once the other end or the stack has
    /// refused it; `None` while it is still being made, and after it has answered.
    fn poll(&mut self) -> Option<Result<OpenedLink<P>, LinkOpenError>>;
}

/// A dial whose link was made by the time it was begun: what a stack whose dials do not wait
/// answers [`SessionLinks::begin_initiator`] with.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub struct Dialled<P>(Option<OpenedLink<P>>);

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<P> Dialled<P> {
    /// The dial whose link is `opened`.
    pub fn new(opened: OpenedLink<P>) -> Self {
        Self(Some(opened))
    }
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<P> PendingDial<P> for Dialled<P> {
    fn poll(&mut self) -> Option<Result<OpenedLink<P>, LinkOpenError>> {
        self.0.take().map(Ok)
    }
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl<P> From<OpenedLink<P>> for Dialled<P> {
    fn from(opened: OpenedLink<P>) -> Self {
        Self::new(opened)
    }
}

/// The handshake role to activate the FSM with before the loop starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// Listen for an inbound peer (the InitSyn arrives first). Activates
    /// the FSM via the `inbound.start` event.
    Acceptor,
    /// Dial a configured peer (emit the InitSyn first). Activates the FSM
    /// via the `outbound.start` event.
    Initiator,
}

impl SessionRole {
    /// The events that activate the FSM in this role, in order.
    ///
    /// R2831 — the initiator takes TWO, as the AP's `initiator_open` does:
    /// `OutboundStart` enters LinkOpening and `LinkOpened` moves to
    /// SentInitSyn, whose entry sends the InitSyn. The UDP link is open by
    /// the time a pump exists (the driver's socket is already bound), so
    /// both are raised at once. Raising only the first left an MCU initiator
    /// in LinkOpening forever, silent on the wire; nothing drove one until
    /// the dialer did.
    fn activation(self) -> &'static [SessionFsmUnicastEvent] {
        match self {
            // The core states which events start an acceptor in this build: none in one without
            // `session-unicast-accept`, where the machine has no accepting role.
            SessionRole::Acceptor => wz_session_core::drive::acceptor_activation(),
            SessionRole::Initiator => &[
                SessionFsmUnicastEvent::OutboundStart,
                SessionFsmUnicastEvent::LinkOpened,
            ],
        }
    }
}

/// R311lw — the static parameterization of one `run_session` drive: the
/// handshake-deadline budget, the FSM activation role, and the test-only
/// iteration cap, separated from the loop's live collaborators (the
/// runtime / link / actions / clock handles + the `on_event` observer) via
/// the Introduce-Parameter-Object refactor. The unicast MCU sibling of
/// `wz_session_core::multicast_params::MulticastDriveConfig` (R311ls/R311lt):
/// it brings `run_session` within clippy's argument-count bound. All three
/// fields are `Copy`, so this owns them by value and carries no lifetime.
pub struct SessionDriveConfig {
    /// The handshake deadline budget ([`SessionTimeouts::spec_defaults`]);
    /// seeds the session's timers ([`TransportTimers`]).
    pub timeouts: SessionTimeouts,
    /// The role to activate the FSM with before the loop starts
    /// ([`SessionRole::Acceptor`] listens for an inbound peer;
    /// [`SessionRole::Initiator`] dials the configured peer).
    pub role: SessionRole,
    /// `Some(n)` caps the loop for test determinism; `None` drives unbounded
    /// for production.
    pub max_iters: Option<usize>,
}

/// Drive one logical session over `link` to a terminal FSM state (or the
/// `config.max_iters` cap). Builds the FSM engine from `actions` via the
/// shared [`new_session_engine_in`], activates `config.role`, then polls until
/// `engine.is_in_final_state()`.
///
/// Parameters:
/// - `runtime` — the [`CoopRuntime`] whose `run_until_idle` is pumped each
///   tick (spawned keepalive workers + deadline-keyed timers).
/// - `link` — the [`SessionDatagramLink`]: serviced each tick, and the source
///   of inbound frames. Its outbound twin sits inside `actions`.
/// - `actions` — the session action bundle; its `clock` MUST share an epoch
///   with `clock` (R263) so the lease comparator's `now_ms` and the recorded
///   keepalive / established stamps agree. Build one [`CoopTime`], clone it
///   into `new_generic`, pass the original here.
/// - `config` — the static run parameterization ([`SessionDriveConfig`]).
/// - `on_event` — the per-iteration observer (`Poll` with the decoded
///   `FramePayload` batch the application dispatches, or `Lease`).
///
/// Absent under `session-slot` with `reassembly`, where a pump is not built on
/// the caller's stack with a heap table behind it: see `SessionPump::new`.
#[cfg(not(all(feature = "session-slot", feature = "reassembly")))]
pub fn run_session<C, L, F>(
    runtime: &CoopRuntime<C>,
    link: L,
    actions: &SessionHandle<C>,
    entropy: SessionEntropy,
    clock: &CoopTime<C>,
    config: SessionDriveConfig,
    mut on_event: F,
) -> DriverOutcome
where
    C: ClockSource,
    L: SessionDatagramLink,
    F: FnMut(IterationEvent<'_, '_>),
{
    let mut pump = SessionPump::new(
        runtime.clone(),
        link,
        actions.clone(),
        entropy,
        clock.clone(),
        config,
    );
    loop {
        // The synchronous driver owns the executor pass: nothing else is
        // driving this runtime, so spawned workers and deadline-keyed
        // timers only advance because this loop says so. `step` deliberately
        // does not do it — see its doc.
        pump.runtime().run_until_idle();
        if let Some(outcome) = pump.step(&mut on_event) {
            return outcome;
        }
    }
}

/// The reassembly Router a pump builds for itself when its maker hands it none (`SessionPump::new`):
/// the generated pool's Router of growable chains, or with `rx-in-place` the session's own Router
/// staging into the slots of a `reassembly_pool_mcu` table it owns (`ReassemblyArena`), where a
/// fragment is read where the link holds it and copied once, into its slot.
#[cfg(all(feature = "reassembly", not(feature = "rx-in-place")))]
pub type DefaultRouter = CoopReassembly;

/// See the copying receive's form.
#[cfg(all(feature = "reassembly", feature = "rx-in-place"))]
pub type DefaultRouter = InPlaceReassembly;

/// Without `reassembly` a pump rejoins no fragment and holds no Router.
#[cfg(not(feature = "reassembly"))]
pub type DefaultRouter = ();

/// What a [`SessionPump`] is built of besides the runtime it runs on, its receive and its
/// engine, handed to every builder of a pump together: the session's link, its actions, the
/// source it draws its handshake secrets from, its clock and its drive config.
pub struct PumpFields<
    C: ClockSource,
    L,
    D: BoxedLinkDriver + ?Sized + 'static = dyn BoxedLinkDriver,
> {
    /// The link the session reads and writes.
    pub link: L,
    /// The link's actions.
    pub actions: SessionHandle<C, D>,
    /// The session's entropy source, which the engine's handshake binding holds.
    pub entropy: SessionEntropy,
    /// The session's clock.
    pub clock: CoopTime<C>,
    /// How the session is driven.
    pub config: SessionDriveConfig,
}

/// One MCU session, ready to be advanced one iteration at a time.
///
/// R2364 — extracted from `run_session`, whose body this used to be
/// inline. The extraction exists so that the sequencing of an iteration —
/// link input, parked-unit drain, inbound dispatch, handshake / lease
/// deadline, keepalive deadline — is written ONCE and both drivers share
/// it: the synchronous `run_session` loop, and `session_task`, the
/// `!Send` future that runs the session as a task ON the cooperative
/// executor via [`CoopLocalSet::spawn_local`].
///
/// Generic over the link `L` it OWNS: the synchronous loop may hand it a
/// borrow-backed link, while a spawned task must be `'static` and therefore
/// hands it one that owns its shares.
///
/// `D` is the type of the driver the session sends through: the trait object by default, the
/// driver's own type for the profile whose image names it, which is what makes the calls the
/// engine's actions make through the link direct ones.
///
/// `R` is the reassembly Router the session's receive stages its fragments in ([`RxReassembly`]):
/// the one the pump builds for itself ([`DefaultRouter`]), or one its maker hands it.
pub struct SessionPump<
    C: ClockSource,
    L: SessionDatagramLink,
    D: BoxedLinkDriver + ?Sized + 'static = dyn BoxedLinkDriver,
    R = DefaultRouter,
> {
    runtime: CoopRuntime<C, D>,
    link: L,
    actions: SessionHandle<C, D>,
    clock: CoopTime<C>,
    engine: SessionEngine<CoopRuntime<C, D>, CoopTime<C>>,
    /// The session's own timers: the pump asks them how long its link may wait and hands them
    /// the time, and keeps no deadline of its own.
    timers: TransportTimers,
    /// The session's receive: the reassembly Router its fragments are staged in and, with
    /// `rx-in-place`, the record buffer each inbound record is decoded into and the count of the
    /// paths its units took. Under `session-slot` it lives in the pump, and the pump in a cell of
    /// a `PumpSlots` table, so a datagram costs the heap nothing.
    rx: UnicastRx<R>,
    /// `session-slot` -- the role this pump is to activate the engine with at its
    /// FIRST step, and has not yet. The profile's pump does not speak when it is
    /// built: a dialling pump's activation sends the `InitSyn`, and a pump that
    /// is built (in a cell of its table) before the task that will run it has a
    /// cell would put an `InitSyn` on the wire for a session that then cannot run.
    /// Deferred to the first step, which only a running task makes, the
    /// session's first byte leaves after every table it needs has said yes.
    #[cfg(feature = "session-slot")]
    pending_role: Option<SessionRole>,
    iter: usize,
    max_iters: Option<usize>,
}

impl<C: ClockSource, L: SessionDatagramLink, D: BoxedLinkDriver + ?Sized + 'static>
    SessionPump<C, L, D>
{
    /// Build the engine, activate the configured role, and arm the
    /// handshake deadline tracker — everything `run_session` does before
    /// entering its loop.
    ///
    /// Takes its collaborators BY VALUE. Every one of them is a cheap
    /// shared handle (`CoopRuntime` is `Arc`-backed; the action bundle is
    /// `Rc`; `CoopTime` is a clock handle), so owning them costs a refcount
    /// and buys the `'static` that [`CoopLocalSet::spawn_local`] requires.
    ///
    /// R2965 (open-debt item 847) — never inlined, for the caller's STACK. The
    /// engine is built here as a local and MOVED into the pump; inlined, both
    /// slots (1160 and 1264 bytes on the microbit image) sit in the caller's
    /// frame for the life of the session, because ARMv6-M codegen does not
    /// overlay a dead temporary. Out of line, the temporary is this function's
    /// and is gone when it returns.
    ///
    /// `rx-in-place` with `reassembly`: the session stages its fragments into a
    /// reassembly table of its OWN, allocated here once
    /// ([`PoolStorage::owned`]); [`Self::with_reassembly_arena`] takes one the
    /// image placed instead. Under `session-slot` that table is never the
    /// pump's own heap allocation, so with `reassembly` this constructor is absent
    /// and a pump is made by `PumpSlots::claim` (which places the table in the
    /// pump's cell) or by [`Self::with_reassembly_arena`].
    ///
    /// Under `session-slot` the role is NOT activated here: the first
    /// [`Self::step`] activates it, so a dialling pump's `InitSyn` leaves only
    /// once the task that steps it exists (`pending_role`).
    #[cfg(not(all(feature = "session-slot", feature = "reassembly")))]
    #[inline(never)]
    pub fn new(
        runtime: CoopRuntime<C, D>,
        link: L,
        actions: SessionHandle<C, D>,
        entropy: SessionEntropy,
        clock: CoopTime<C>,
        config: SessionDriveConfig,
    ) -> Self {
        // The reassembly is the session's, so it is built from the session's own snapshot.
        #[cfg(all(feature = "reassembly", not(feature = "rx-in-place")))]
        let reasm = mcu_reassembly(&actions.params.policy);
        #[cfg(all(feature = "reassembly", feature = "rx-in-place"))]
        let reasm = in_place_reassembly(
            ReassemblyArena::new(PoolStorage::owned()),
            &actions.params.policy,
        );
        Self::build(
            runtime,
            link,
            actions,
            entropy,
            clock,
            config,
            #[cfg(feature = "reassembly")]
            reasm,
            #[cfg(not(feature = "reassembly"))]
            (),
        )
    }

    /// `Self::new` over a reassembly arena the caller built: the image hands
    /// the session the table it placed ([`PoolStorage::Static`]), one per
    /// session, so two sessions in one program each stage into their own.
    #[cfg(all(feature = "reassembly", feature = "rx-in-place"))]
    #[inline(never)]
    pub fn with_reassembly_arena(
        runtime: CoopRuntime<C, D>,
        link: L,
        actions: SessionHandle<C, D>,
        entropy: SessionEntropy,
        clock: CoopTime<C>,
        config: SessionDriveConfig,
        arena: ReassemblyArena,
    ) -> Self {
        let reasm = in_place_reassembly(arena, &actions.params.policy);
        Self::build(runtime, link, actions, entropy, clock, config, reasm)
    }

    /// `rx-in-place` with `reassembly` — the session's reassembly Router, and
    /// through it the arena and its table (slot accounting, the address
    /// witness of a delivered payload).
    #[cfg(all(feature = "reassembly", feature = "rx-in-place"))]
    pub fn reassembly(&self) -> &InPlaceReassembly {
        self.rx.router()
    }
}

impl<
        C: ClockSource,
        L: SessionDatagramLink,
        D: BoxedLinkDriver + ?Sized + 'static,
        R: RxReassembly,
    > SessionPump<C, L, D, R>
{
    /// The pump `SessionPump::new` builds, over a reassembly Router its maker built: one whose
    /// chains stage into buffers the session's arena lent, so the session's fragments cost the
    /// heap nothing and are bounded by the buffers' length. Never inlined, for the reason `new`
    /// is not.
    #[cfg(feature = "reassembly")]
    #[inline(never)]
    pub fn with_router(
        runtime: CoopRuntime<C, D>,
        link: L,
        actions: SessionHandle<C, D>,
        entropy: SessionEntropy,
        clock: CoopTime<C>,
        config: SessionDriveConfig,
        reasm: R,
    ) -> Self {
        Self::build(runtime, link, actions, entropy, clock, config, reasm)
    }

    /// [`Self::with_router`] built in `place` and lent back, its Router made in its own field by
    /// `make_router`: neither the pump nor the Router (kilobytes: one slot machine per slot) is a
    /// value on any stack on the way, where `with_router` takes the Router by value and the pump
    /// is returned by value. What a task that keeps its pump in its own future builds it with
    /// (`spawn_session_with_router`).
    ///
    /// `make_router` writes the Router in the place it is handed and lends it back, which safe
    /// code does only by writing it there ([`MaybeUninit::write`]); one that lends back anything
    /// else has written no Router, and the pump is not built: `None`, with what it was to be made
    /// of dropped. `place` is overwritten without dropping what it held.
    #[cfg(feature = "reassembly")]
    pub fn with_router_in(
        place: &mut MaybeUninit<Self>,
        runtime: CoopRuntime<C, D>,
        fields: PumpFields<C, L, D>,
        make_router: impl FnOnce(&mut MaybeUninit<R>) -> &mut R,
    ) -> Option<&mut Self> {
        let at = place.as_mut_ptr();
        // SAFETY: `at` is `place`, valid for writes of a `Self`, and the receive's field is lent as
        // the uninitialised place `MaybeUninit<UnicastRx<R>>` lays out as a `UnicastRx<R>`.
        let rx =
            unsafe { &mut *core::ptr::addr_of_mut!((*at).rx).cast::<MaybeUninit<UnicastRx<R>>>() };
        UnicastRx::init_in(rx, make_router)?;
        // SAFETY: the receive is written, and the rest of the pump is written by `build_in`.
        unsafe {
            Self::build_in(place, runtime, fields, |_| {});
            Some(place.assume_init_mut())
        }
    }

    /// What `Self::new` and [`Self::with_reassembly_arena`] share: the pump as a value, made by
    /// [`Self::build_in`] in a place of its own.
    #[inline(always)]
    fn build(
        runtime: CoopRuntime<C, D>,
        link: L,
        actions: SessionHandle<C, D>,
        entropy: SessionEntropy,
        clock: CoopTime<C>,
        config: SessionDriveConfig,
        reasm: R,
    ) -> Self {
        let mut place = MaybeUninit::<Self>::uninit();
        // SAFETY: the receive is written in the place it is handed: `MaybeUninit::write` lends back
        // the place it wrote, so `init_in` takes it as written. Then `build_in` has written every
        // field of the pump into `place`.
        unsafe {
            Self::build_in(
                &mut place,
                runtime,
                PumpFields {
                    link,
                    actions,
                    entropy,
                    clock,
                    config,
                },
                |rx| {
                    let _ = UnicastRx::init_in(rx, |slot| slot.write(reasm));
                },
            );
            place.assume_init()
        }
    }

    /// Build the pump IN `place`: the engine is made in its field and initialised there, and
    /// every other field is written where it lies, so no copy of the pump or of the engine
    /// is ever on the stack. `place` is fully written on return.
    ///
    /// Never inlined, for the stack: the engine's initial transition runs in here, and what
    /// the machine calls beneath (the transition sets, the actions, the hash of the initial
    /// sequence number) is on the stack for as long as it runs. Inlined into the caller of a
    /// slot, that caller's frame would be under all of it.
    ///
    /// The receive is written first, by `write_rx` in its field (one already written, which
    /// [`Self::with_router_in`] checked, is left as it is), so a receive whose Router could not be
    /// made is refused before any other part is taken.
    ///
    /// # Safety
    /// `write_rx` leaves the receive written in the place it is handed, or finds it written.
    #[inline(never)]
    unsafe fn build_in(
        place: &mut MaybeUninit<Self>,
        runtime: CoopRuntime<C, D>,
        fields: PumpFields<C, L, D>,
        write_rx: impl FnOnce(&mut MaybeUninit<UnicastRx<R>>),
    ) {
        let PumpFields {
            link,
            actions,
            entropy,
            clock,
            config,
        } = fields;
        let SessionDriveConfig {
            timeouts,
            role,
            max_iters,
        } = config;
        let at = place.as_mut_ptr();
        // SAFETY: `at` is valid for writes of a `Self` (it is `place`), each field is written
        // exactly once below through its own address, and the engine is used only after its
        // field is written.
        unsafe {
            write_rx(&mut *core::ptr::addr_of_mut!((*at).rx).cast::<MaybeUninit<UnicastRx<R>>>());
            // The engine is made in its field (`MaybeUninit<T>` has the layout of `T`).
            let engine = new_session_engine_in(
                &mut *core::ptr::addr_of_mut!((*at).engine)
                    .cast::<MaybeUninit<SessionEngine<CoopRuntime<C, D>, CoopTime<C>>>>(),
                &actions,
                entropy,
            );
            // `new_session_engine_in` yields an un-initialized engine (the AP
            // convention — the caller runs the SCXML initial transition into the
            // `Init` state). Without this the `role.activation()` below lands on
            // an engine that never entered `Init`, so `inbound.start` /
            // `outbound.start` does not transition into `AwaitingInitSyn` /
            // `LinkOpening` and the whole handshake stalls.
            engine.initialize().unwrap_or_else(|never| match never {});
            // Under `session-slot` the activation waits for the first step (see
            // `pending_role`); every other profile activates here, as it always did.
            #[cfg(not(feature = "session-slot"))]
            for event in role.activation() {
                engine.process_event(*event);
            }

            core::ptr::addr_of_mut!((*at).runtime).write(runtime);
            core::ptr::addr_of_mut!((*at).link).write(link);
            core::ptr::addr_of_mut!((*at).actions).write(actions);
            core::ptr::addr_of_mut!((*at).clock).write(clock);
            core::ptr::addr_of_mut!((*at).timers).write(TransportTimers::new(timeouts));
            #[cfg(feature = "session-slot")]
            core::ptr::addr_of_mut!((*at).pending_role).write(Some(role));
            core::ptr::addr_of_mut!((*at).iter).write(0);
            core::ptr::addr_of_mut!((*at).max_iters).write(max_iters);
        }
    }

    /// Borrow the runtime this session was built against. The synchronous
    /// driver uses it to take the executor pass that [`Self::step`] does
    /// not.
    pub fn runtime(&self) -> &CoopRuntime<C, D> {
        &self.runtime
    }

    /// `rx-in-place` — the units this session dispatched so far, by the path
    /// they took ([`RxPathCounts`]).
    #[cfg(feature = "rx-in-place")]
    pub fn rx_path_counts(&self) -> RxPathCounts {
        self.rx.path_counts()
    }

    /// How long the loop may wait for a datagram before something of this session's or this
    /// runtime's falls due, in milliseconds, rounded UP so the wait never ends before the
    /// deadline it was computed from: the earliest of the handshake deadline, the lease deadline,
    /// the keep-alive deadline and the next registered timer, less now. A deadline already past
    /// is 0, and `u64::MAX` is nothing due at all.
    ///
    /// The session's deadlines are its timers' ([`TransportTimers::next_due_ms`]), which arm
    /// the handshake deadline of a state they see for the first time from this instant; the
    /// runtime's next timer is the driver's own.
    fn wake_budget_ms(&mut self) -> u64 {
        let now_ms = self.clock.now_monotonic_ms();
        let due_ms = self
            .timers
            .next_due_ms(&self.engine, &self.actions, now_ms)
            .unwrap_or(u64::MAX);
        let mut wait_ms = due_ms.saturating_sub(now_ms);
        if let Some(timer_us) = self.runtime.time_to_next_timer_us() {
            wait_ms = wait_ms.min(timer_us.div_ceil(1000));
        }
        wait_ms
    }

    /// Advance the session by one iteration. `Some(outcome)` means the
    /// session is finished (terminal FSM state, or the test iteration cap);
    /// `None` means call again.
    ///
    /// Deliberately does NOT pump the runtime. Who drives the executor is
    /// the DRIVER's question and the two drivers answer it differently:
    /// `run_session` owns its loop and so takes the pass itself, while
    /// `session_task` runs INSIDE the executor — pumping from there would
    /// have the session drive the pool that is currently polling it, which
    /// is precisely the inversion [`CoopLocalSet`] exists to remove.
    pub fn step<F>(&mut self, on_event: &mut F) -> Option<DriverOutcome>
    where
        F: EventSink,
    {
        // The role's activation, deferred from the pump's making (`session-slot`).
        #[cfg(feature = "session-slot")]
        if let Some(role) = self.pending_role.take() {
            for event in role.activation() {
                self.engine.process_event(*event);
            }
        }
        if self.engine.is_in_final_state() {
            return Some(DriverOutcome::Terminated);
        }
        if let Some(limit) = self.max_iters {
            if self.iter >= limit {
                return Some(DriverOutcome::IterationLimit);
            }
            self.iter += 1;
        }

        // R2922 — raise what the session was asked from OUTSIDE the loop (a
        // rail close) before servicing the link. This loop polls every
        // iteration, so it needs no wake of its own.
        if wz_session_core::drive::check_out_of_band(&self.actions, &mut self.engine) {
            return None;
        }

        if self.link.uses_wake_budget() {
            let wake_budget_ms = self.wake_budget_ms();
            self.link.service_within(wake_budget_ms);
        } else {
            self.link.service();
        }

        let now_ms = self.clock.now_monotonic_ms();
        // The application layer's own deadline (a pending query's, a query left for it), if it
        // has come due: the layer's work is not a datagram or the lease, so no other event says
        // so. Raised before the inbound datagram is read and without ending the step, so a stream
        // of datagrams cannot hold it off and it does not cost one.
        if self.actions.take_app_wake_due(now_ms) {
            on_event.event(IterationEvent::AppWake);
        }
        // Sweep expired reassembly chains and surface the eviction count as
        // an `IterationEvent::ReassemblyTimeout` (the shared SSOT — the AP
        // loop calls the same primitive). A stalled chain whose continuation
        // never arrives is reclaimed here once `now_ms` crosses its deadline.
        self.rx.sweep(now_ms, &mut *on_event);

        // A Router lent to the receive only for its session's step (`RxReassembly::ready`): outside
        // the lend the step takes no input, which the link keeps for a step that can stage it.
        if !self.rx.ready() {
            return None;
        }

        // R311y632 (§17) — the parked remainder of the LAST unit first. A unit
        // is a batch, and `try_recv` below would otherwise hold the second
        // message until the peer sends again.
        // A build with no allocator parks nothing: it reads the rest of a datagram
        // where the link holds it, so there is no remainder to come back to. Nor
        // does a receive in place, but for the rest of a compressed batch, which
        // was inflated into a buffer of its own.
        #[cfg(feature = "alloc")]
        if self.link.takes_input() {
            #[cfg(not(feature = "rx-in-place"))]
            let parked =
                self.rx
                    .dispatch_pending(&self.actions, &mut self.engine, now_ms, &mut *on_event);
            #[cfg(feature = "rx-in-place")]
            let parked = self.rx.dispatch_parked_in_place(
                &self.actions,
                &mut self.engine,
                now_ms,
                &mut *on_event,
            );
            if parked {
                return None;
            }
        }

        // `rx-in-place` — the datagram is read where the link holds it and
        // its records are dispatched one at a time, each outcome reported as
        // it happens. Inside the lend: what the observer does runs on the stack
        // above the receive. A Push record arrives as `IterationEvent::InPlace`,
        // lent where the datagram lies; a Fragment is staged into its slot from
        // where the link holds it. Which path the unit took is counted.
        #[cfg(feature = "rx-in-place")]
        {
            let link = &self.link;
            let actions = &self.actions;
            let engine = &mut self.engine;
            let rx = &mut self.rx;
            let received = link.recv_with(&mut |unit| {
                let mut sink = LinkSink {
                    link,
                    sink: &mut *on_event,
                };
                rx.dispatch_datagram(unit, actions, engine, now_ms, &mut sink);
                // The dispatch stopped where the session had no room: the link keeps the
                // datagram, and a later step reads on from there.
                #[cfg(feature = "alloc")]
                if actions.resumes_datagram() {
                    link.keep();
                }
            });
            if received {
                return None;
            }
        }

        // Inbound datagram? Dispatch it and loop promptly for the next. It is
        // the link's peer's: the link hands over nothing else. Unicast MCU
        // session shell — one peer per link, so no source attribution is
        // needed.
        #[cfg(all(not(feature = "rx-in-place"), feature = "alloc"))]
        if let Some(frame) = self.link.try_recv() {
            self.rx.dispatch_frame(
                frame,
                &self.actions,
                &mut self.engine,
                now_ms,
                &mut *on_event,
            );
            return None;
        }

        // Nothing left to read and the link is gone (a stream whose peer closed
        // it): the session is told, after everything queued before the end has
        // been read. The next step finds the engine final.
        if let Some(cause) = self.link.lost() {
            let outcome = wz_session_core::drive::dispatch_link_lost(&mut self.engine, cause);
            on_event.event(IterationEvent::Poll(&outcome));
            return None;
        }

        // No inbound: the session's timers are handed the time, and raise what has come due.
        self.timers
            .fire_due(&mut self.engine, &self.actions, now_ms, on_event);

        None
    }
}

/// The MCU session AS A TASK — the `!Send` future that
/// [`CoopLocalSet::spawn_local`] hosts.
///
/// R2364. This is the MCU answer to what `TokioRuntime::spawn` gives the AP
/// profile: the MCU action bundle is `Rc`-backed and `!Send` on purpose (that
/// `Rc` is what reaches ARMv6-M, where `alloc::sync::Arc` does not exist), so
/// the session runs IN the local set rather than as a caller-owned loop.
///
/// Awaits [`yield_now`] between iterations rather than spinning, so every
/// other task in the pool — and the local set's own runtime pass — gets a
/// turn each time round. The returned value is the same [`DriverOutcome`]
/// `run_session` returns; reach it through the [`CoopLocalJoinHandle`] the
/// spawn hands back.
#[cfg(not(all(feature = "session-slot", feature = "reassembly")))]
pub async fn session_task<C, L, F>(
    runtime: CoopRuntime<C>,
    link: L,
    actions: SessionHandle<C>,
    entropy: SessionEntropy,
    clock: CoopTime<C>,
    config: SessionDriveConfig,
    mut on_event: F,
) -> DriverOutcome
where
    C: ClockSource,
    L: SessionDatagramLink,
    F: FnMut(IterationEvent<'_, '_>),
{
    let mut pump = SessionPump::new(runtime, link, actions, entropy, clock, config);
    loop {
        if let Some(outcome) = pump.step(&mut on_event) {
            return outcome;
        }
        yield_now().await;
    }
}

/// Spawn one MCU session onto `local` and return its join handle.
///
/// The convenience form of `session_task` + [`CoopLocalSet::spawn_local`],
/// and the call site a deploy `main()` writes. The runtime the session is
/// built against is the local set's own, so a caller cannot accidentally
/// pump one runtime while the session rides another.
///
/// `link` and `on_event` must be `'static` here where `run_session` takes
/// any: a detached task cannot borrow the caller's stack. An observer that
/// needs to publish out of the task should capture an `Rc<RefCell<..>>` —
/// `!Send` is fine, which is the whole point of the local set.
///
/// Absent under `session-slot`: it builds the pump inside the task's future and
/// answers a handle where a spawn can be refused. The slot profile's form is
/// `PumpSlots::claim` and `spawn_pump`.
#[cfg(not(feature = "session-slot"))]
pub fn spawn_session<C, L, F>(
    local: &CoopLocalSet<C>,
    link: L,
    actions: SessionHandle<C>,
    entropy: SessionEntropy,
    clock: CoopTime<C>,
    config: SessionDriveConfig,
    on_event: F,
) -> CoopLocalJoinHandle<DriverOutcome>
where
    C: ClockSource + 'static,
    L: SessionDatagramLink + 'static,
    F: FnMut(IterationEvent<'_, '_>) + 'static,
{
    local.spawn_local(session_task(
        local.runtime().clone(),
        link,
        actions,
        entropy,
        clock,
        config,
        on_event,
    ))
}

/// What writes a session's reassembly Router in its pump's field
/// ([`SessionPump::with_router_in`]): a value of a type that can be named, which is what lets an
/// engine name the task its session runs as ([`RouterSessionTask`]), and so the bytes of the
/// task's cell.
#[cfg(all(feature = "reassembly", not(feature = "session-slot")))]
pub trait MakeRouter<R> {
    /// Write the Router in `place` and lend it back.
    fn make_in(self, place: &mut MaybeUninit<R>) -> &mut R;
}

/// The place a session lends its one Router in is its own maker: the pump holds the place, and
/// the Router stays the session's, lent to the pump for the length of the session's step.
#[cfg(all(
    feature = "reassembly",
    feature = "alloc",
    not(feature = "session-slot")
))]
impl<D> MakeRouter<wz_session_core::unicast_rx::RouterLend<D>>
    for wz_session_core::unicast_rx::RouterLend<D>
{
    fn make_in(
        self,
        place: &mut MaybeUninit<wz_session_core::unicast_rx::RouterLend<D>>,
    ) -> &mut wz_session_core::unicast_rx::RouterLend<D> {
        place.write(self)
    }
}

/// [`spawn_session`] over a reassembly Router its maker builds: a session whose fragment chains
/// stage into buffers its session's arena lent.
///
/// The task is a [`RouterSessionTask`] made in its cell, which builds the pump in its own memory
/// when it first runs, and `make_router` writes the Router in the pump's field, so neither is
/// moved through the stack of the call that opens the session; only the maker, which holds what
/// the Router is made of, is. The pump is dropped with the task, whether the session ended or the
/// task was dropped before. A task the runtime refuses (a table reserved too small for it, or
/// full) is counted by the runtime and answered with why, the maker and what it was to be made of
/// dropped unmade: an engine that reserved its tables at its open tells its program the session
/// has no room, where a handle that reads as a shut runtime would say the session ended.
#[cfg(all(feature = "reassembly", not(feature = "session-slot")))]
pub fn spawn_session_with_router<C, L, R, M, F>(
    local: &CoopLocalSet<C>,
    fields: PumpFields<C, L>,
    make_router: M,
    on_event: F,
) -> Result<CoopLocalJoinHandle<DriverOutcome>, crate::executor::SpawnRefusal>
where
    C: ClockSource + 'static,
    L: SessionDatagramLink + 'static,
    R: RxReassembly + 'static,
    M: MakeRouter<R> + 'static,
    F: EventSink + 'static,
{
    let runtime = local.runtime().clone();
    local.spawn_local_with(move || RouterSessionTask {
        place: Becomes::new(PumpParts {
            runtime,
            fields,
            make_router,
        }),
        on_event,
        _pinned: core::marker::PhantomPinned,
    })
}

/// The task a session runs as on the heap profile ([`spawn_session_with_router`]): a future of a
/// type an engine can name, so the bytes of its cell are a constant of the types it is made of
/// ([`router_session_task_bytes`]) and a runtime can reserve cells of that size before the session
/// opens. It builds the session's pump in its own memory at its first poll, then steps the session
/// once each poll and yields, as a loop of [`SessionPump::step`] and [`yield_now`] does.
#[cfg(all(feature = "reassembly", not(feature = "session-slot")))]
pub struct RouterSessionTask<C, L, R, M, F>
where
    C: ClockSource + 'static,
    L: SessionDatagramLink + 'static,
    R: RxReassembly + 'static,
{
    /// What the pump is made of until the task first runs, and then the pump, in the same bytes.
    place: TaskPlace<C, L, R, M>,
    on_event: F,
    /// The pump is built in `place` and points into itself: the task stays where it is polled.
    _pinned: core::marker::PhantomPinned,
}

/// The place a [`RouterSessionTask`] holds its pump's parts in, and then its pump.
#[cfg(all(feature = "reassembly", not(feature = "session-slot")))]
type TaskPlace<C, L, R, M> = Becomes<PumpParts<C, L, M>, SessionPump<C, L, dyn BoxedLinkDriver, R>>;

/// What a [`RouterSessionTask`] builds its pump of.
#[cfg(all(feature = "reassembly", not(feature = "session-slot")))]
struct PumpParts<C: ClockSource + 'static, L, M> {
    runtime: CoopRuntime<C>,
    fields: PumpFields<C, L>,
    make_router: M,
}

#[cfg(all(feature = "reassembly", not(feature = "session-slot")))]
impl<C, L, R, M, F> core::future::Future for RouterSessionTask<C, L, R, M, F>
where
    C: ClockSource + 'static,
    L: SessionDatagramLink + 'static,
    R: RxReassembly + 'static,
    M: MakeRouter<R>,
    F: EventSink,
{
    type Output = DriverOutcome;

    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<DriverOutcome> {
        // SAFETY: nothing is moved out of the pinned task but the parts, which nothing points
        // into; the pump is built in `place` and stays there, as the task does (`PhantomPinned`).
        let this = unsafe { self.get_unchecked_mut() };
        let built = this.place.build(|parts, slot| {
            let PumpParts {
                runtime,
                fields,
                make_router,
            } = parts;
            SessionPump::with_router_in(slot, runtime, fields, |router| make_router.make_in(router))
        });
        // A pump its maker did not build in its place is no session to drive: the task ends.
        let Some(pump) = built else {
            return core::task::Poll::Ready(DriverOutcome::Terminated);
        };
        match pump.step(&mut this.on_event) {
            Some(outcome) => core::task::Poll::Ready(outcome),
            None => {
                // Yield: the task is ready again at once, after the executor has gone round.
                cx.waker().wake_by_ref();
                core::task::Poll::Pending
            }
        }
    }
}

/// The bytes of the cell that holds the task of a session over these types
/// ([`RouterSessionTask`]) and its outcome: the size a runtime reserved before the session opens
/// gives its cells, so that a layer that grows is a number that follows and not a spawn that is
/// refused ([`crate::executor::SpawnRefusal::TooLarge`]).
#[cfg(all(feature = "reassembly", not(feature = "session-slot")))]
pub const fn router_session_task_bytes<C, L, R, M, F>() -> usize
where
    C: ClockSource + 'static,
    L: SessionDatagramLink + 'static,
    R: RxReassembly + 'static,
    M: MakeRouter<R>,
    F: EventSink,
{
    crate::executor::cell_bytes_for::<RouterSessionTask<C, L, R, M, F>>()
}

/// The bytes a task's pump is built in, which hold what the pump is made of until it is: the parts
/// and the pump share them, so the task's cell is as large as the larger of the two and not their
/// sum. The parts are taken out whole before the pump is written over them, and whichever the place
/// holds is dropped with it.
#[cfg(all(feature = "reassembly", not(feature = "session-slot")))]
struct Becomes<P, T> {
    place: MaybeUninit<Shared<P, T>>,
    stage: Stage,
}

/// The parts or the value, in one place.
#[cfg(all(feature = "reassembly", not(feature = "session-slot")))]
union Shared<P, T> {
    parts: ManuallyDrop<P>,
    value: ManuallyDrop<T>,
}

/// What a [`Becomes`] holds.
#[cfg(all(feature = "reassembly", not(feature = "session-slot")))]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// The parts, not yet taken.
    Parts,
    /// The value, built of them.
    Built,
    /// Nothing: the parts were taken and no value was built.
    Empty,
}

#[cfg(all(feature = "reassembly", not(feature = "session-slot")))]
impl<P, T> Becomes<P, T> {
    /// A place that holds `parts`.
    fn new(parts: P) -> Self {
        Self {
            place: MaybeUninit::new(Shared {
                parts: ManuallyDrop::new(parts),
            }),
            stage: Stage::Parts,
        }
    }

    /// The value built here, built first when the place still holds its parts: they are taken
    /// out and handed to `make`, which writes the value in the place it is handed and lends it
    /// back. A maker that builds nothing answers `None`, and so does this; one that lends back
    /// anything but the place it was handed has not written it there, and is refused the same way.
    /// Either way the place holds nothing after, and `None` is the answer from then on.
    fn build(
        &mut self,
        make: impl FnOnce(P, &mut MaybeUninit<T>) -> Option<&mut T>,
    ) -> Option<&mut T> {
        let at = self.place.as_mut_ptr();
        if self.stage == Stage::Parts {
            // SAFETY: the place holds the parts, untaken; they are read out once, and the stage
            // says the place holds nothing before anything else is done with it.
            let parts = ManuallyDrop::into_inner(unsafe {
                core::ptr::read(core::ptr::addr_of!((*at).parts))
            });
            self.stage = Stage::Empty;
            // SAFETY: the value's field of the place, as the uninitialised place
            // `MaybeUninit<T>` lays out as a `T`, as `ManuallyDrop<T>` does.
            let slot =
                unsafe { &mut *core::ptr::addr_of_mut!((*at).value).cast::<MaybeUninit<T>>() };
            let place: *const T = slot.as_ptr();
            let made: *const T = make(parts, slot)?;
            if !core::ptr::eq(made, place) {
                return None;
            }
            self.stage = Stage::Built;
        }
        if self.stage != Stage::Built {
            return None;
        }
        // SAFETY: the stage says the value is written here, by the maker that lent it back.
        Some(unsafe { &mut *core::ptr::addr_of_mut!((*at).value).cast::<T>() })
    }
}

#[cfg(all(feature = "reassembly", not(feature = "session-slot")))]
impl<P, T> Drop for Becomes<P, T> {
    fn drop(&mut self) {
        let at = self.place.as_mut_ptr();
        // SAFETY: the stage says which of the two the place holds; it is dropped here alone, once.
        unsafe {
            match self.stage {
                Stage::Parts => ManuallyDrop::drop(&mut *core::ptr::addr_of_mut!((*at).parts)),
                Stage::Built => ManuallyDrop::drop(&mut *core::ptr::addr_of_mut!((*at).value)),
                Stage::Empty => {}
            }
        }
    }
}

// ───────────── the pump in a cell of a table the image declares ─────────────
//
// Fixed-memory step S6. A pump is the engine (1160 to 1264 bytes on the microbit
// image), the handles it holds, the record buffer and, with `reassembly`, the
// table its fragments are staged into. Built into a future by `session_task` it
// lives wherever that future is spawned; here it lives in a CELL of a table the
// image declares, one cell per session it can run, and the task that drives it is a
// reference to that cell.

/// Why a pump could not be put in a cell: every cell of the table is taken. The
/// refusal is counted ([`PumpSlots::refused`]) and the session the pump was to run
/// is dropped, which gives its own slot back.
#[cfg(feature = "session-slot")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PumpsFull;

/// A session that could not be run as a task, and why.
#[cfg(feature = "session-slot")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSpawnRefused {
    /// Every cell of the pump table is taken.
    NoPumpCell,
    /// The task table refused the task.
    Task(crate::executor::SpawnRefusal),
}

/// One cell of a [`PumpSlots`] table.
#[cfg(feature = "session-slot")]
struct PumpCell<C: ClockSource, L: SessionDatagramLink, D: BoxedLinkDriver + ?Sized + 'static> {
    taken: Mutex<Cell<bool>>,
    pump: UnsafeCell<MaybeUninit<SessionPump<C, L, D>>>,
    /// With `reassembly`, the table the pump's fragments are staged into: one per
    /// pump, in the pump's own cell.
    #[cfg(feature = "reassembly")]
    pool: UnsafeCell<MaybeUninit<crate::reassembly_pool_mcu::ReassemblyPoolMcu>>,
}

#[cfg(feature = "session-slot")]
impl<C: ClockSource, L: SessionDatagramLink, D: BoxedLinkDriver + ?Sized + 'static>
    PumpCell<C, L, D>
{
    const fn new() -> Self {
        Self {
            taken: Mutex::new(Cell::new(false)),
            pump: UnsafeCell::new(MaybeUninit::uninit()),
            #[cfg(feature = "reassembly")]
            pool: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }
}

/// What a network stack gives the slot profile's session host
/// (`wz_session_mcu::slot_host::SessionHost`): the types of its link, and how the pump of a
/// session is built from them. The host is written once for every stack and a stack states
/// these three types and one function; the trait sits here, beside [`SessionDatagramLink`],
/// so that a stack's own crate names it without taking the host with it.
#[cfg(feature = "session-slot")]
pub trait SlotStack: 'static {
    /// The link driver a session holds in its slot: the outbound half the session's actions
    /// send through, and (usually) the datagram queue the pump reads.
    type Driver: wz_session_core::link::BoxedLinkDriver + 'static;
    /// What the drive loop pumps for a session: it services the stack and takes the next
    /// datagram, reaching the driver through a handle to the slot that holds it.
    type Pump: SessionDatagramLink + 'static;
    /// What an accepted session carries beyond a dialled one, held for as long as it runs and
    /// given back when it ends: the listener's lane. A stack with no listener names `()`.
    type Lane;

    /// The pump for the session whose driver `driver` is the handle to; `lane` is the
    /// listener's lane for an accepted session and `None` for a dialled one.
    fn pump(
        &self,
        driver: wz_session_core::session_slot::SlotDriver<Self::Driver>,
        lane: Option<Self::Lane>,
    ) -> Self::Pump;
}

/// How a stack opens the driver of a dial: a socket on a port it picks, with every send going to
/// the end the locator names. The socket comes out of whatever the stack keeps for it (lwIP's pool
/// the image declared; Zephyr's descriptors), and a stack with none left answers
/// [`LinkOpenError::Exhausted`]. Written beside [`SlotStack`] for the reason that one is.
#[cfg(feature = "session-slot")]
pub trait Bind<D> {
    /// Whether the stack opens links to an IPv6 end. `false` for a stack built without IPv6:
    /// what reads an endpoint for it refuses a bracketed address as one it never dials and reads
    /// IPv4 text alone, so an image of such a stack carries no reader of IPv6 text. A constant,
    /// for that reason, as `DatagramSocket::CAN_SET_RECEIVE_TIMEOUT` is.
    const IPV6: bool = true;

    /// The driver of a link that dials `to`; a protocol the stack has no link for
    /// is [`LinkOpenError::Unsupported`].
    fn bind(&mut self, to: Locator) -> Result<D, LinkOpenError>;

    /// [`Self::bind`], written into `out`, the place the driver is kept (a session's slot):
    /// `out` is written exactly when `Ok` is answered. A stack that builds its driver there
    /// leaves no copy of it in the frames of the claim that asks for it, which a stream link's
    /// handshake runs beneath; this form moves the returned driver in.
    fn bind_in(&mut self, to: Locator, out: &mut MaybeUninit<D>) -> Result<(), LinkOpenError> {
        out.write(self.bind(to)?);
        Ok(())
    }
}

/// How a stack takes the link of a session the other end opened: the listening half of [`Bind`].
/// An acceptor is a value the node holds and polls from its loop; it owns the listening port, and
/// what it yields is the driver of a link whose peer is already connected, so a session opened
/// over it takes the acceptor's role at the handshake and nothing else differs from a dial.
#[cfg(feature = "session-slot")]
pub trait Accept<D> {
    /// The link of the connection waiting on the port, `Ok(None)` when none waits. A stack with
    /// no buffer free for it is [`LinkOpenError::Exhausted`], and the connection is closed, which
    /// is how its peer learns the node is full (a connection left queued would hold the peer in a
    /// handshake that never starts).
    fn accept(&mut self) -> Result<Option<D>, LinkOpenError>;
}

/// The acceptor of a node that listens on nothing: no connection ever waits.
#[cfg(feature = "session-slot")]
#[derive(Debug, Clone, Copy, Default)]
pub struct NoAccept;

#[cfg(feature = "session-slot")]
impl<D> Accept<D> for NoAccept {
    fn accept(&mut self) -> Result<Option<D>, LinkOpenError> {
        Ok(None)
    }
}

/// The pump of a stack whose driver is itself the datagram link: the drive loop's calls go to
/// the driver in the slot, through the handle that keeps the slot for as long as the loop
/// reads. What a stack with no input path of its own to advance (Zephyr's sockets: the kernel's
/// threads run it) uses as [`SlotStack::Pump`]; one that does (lwIP) writes its own.
#[cfg(feature = "session-slot")]
pub struct DriverPump<D: 'static>(pub wz_session_core::session_slot::SlotDriver<D>);

#[cfg(feature = "session-slot")]
impl<D: SessionDatagramLink + 'static> SessionDatagramLink for DriverPump<D> {
    fn service(&self) {
        self.0.service();
    }

    fn service_within(&self, max_wait_ms: u64) {
        self.0.service_within(max_wait_ms);
    }

    fn uses_wake_budget(&self) -> bool {
        self.0.uses_wake_budget()
    }

    #[cfg(feature = "alloc")]
    fn try_recv(&self) -> Option<RxFrame> {
        self.0.try_recv()
    }

    fn recv_with(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        self.0.recv_with(f)
    }

    fn lost(&self) -> Option<LostCause> {
        self.0.lost()
    }

    fn holds_input(&self) -> bool {
        self.0.holds_input()
    }

    fn owes_write(&self) -> bool {
        self.0.owes_write()
    }

    fn takes_input(&self) -> bool {
        self.0.takes_input()
    }

    fn keeps_input(&self) -> bool {
        self.0.keeps_input()
    }

    fn keep(&self) {
        self.0.keep()
    }
}

/// The pump table an image declares: `N` cells, each holding the pump of one
/// session, in a `static`. The pump's counterpart of `wz_session_core`'s
/// `SessionSlots`, and declared the same way:
///
/// ```ignore
/// static PUMPS: PumpSlots<BoardClock, LwipSessionLink<&'static LwipLink>, 3> = PumpSlots::new();
/// let pump = PUMPS.claim(runtime.clone(), link, actions, entropy, clock, config)?;
/// spawn_pump(&local, pump, on_event)?;
/// ```
///
/// [`claim`](PumpSlots::claim) builds the pump IN a free cell, or refuses and
/// counts. The pump is freed (dropped in place, its cell free for the next) when
/// its [`PumpRef`] is dropped, which is when the task that drives it ends or is
/// swept.
///
/// Like the session table, it is `Sync` by the profile's rule and not by any
/// means a compiler can check: a pump is driven by ONE cooperative task on one
/// core, and claiming and freeing are critical sections.
#[cfg(feature = "session-slot")]
pub struct PumpSlots<
    C: ClockSource,
    L: SessionDatagramLink + 'static,
    const N: usize,
    D: BoxedLinkDriver + ?Sized + 'static = dyn BoxedLinkDriver,
> {
    cells: [PumpCell<C, L, D>; N],
    refused: Mutex<Cell<u32>>,
    /// The most cells the table has had taken at once: zero-sized unless the build keeps the mark
    /// (`pool-monitor`), so the table is the size it was.
    high: Mutex<Cell<wz_session_core::pool_gauge::HighWater>>,
}

// SAFETY: the profile's rule, stated on the type. The cell's pump is written by the
// one claimant of the cell (its `taken` flag, set inside a critical section) and
// reached only through that claimant's `PumpRef`.
#[cfg(feature = "session-slot")]
unsafe impl<
        C: ClockSource,
        L: SessionDatagramLink + 'static,
        const N: usize,
        D: BoxedLinkDriver + ?Sized + 'static,
    > Sync for PumpSlots<C, L, N, D>
{
}

#[cfg(feature = "session-slot")]
impl<
        C: ClockSource,
        L: SessionDatagramLink + 'static,
        const N: usize,
        D: BoxedLinkDriver + ?Sized + 'static,
    > PumpSlots<C, L, N, D>
{
    /// A table of free cells.
    pub const fn new() -> Self {
        Self {
            cells: [const { PumpCell::new() }; N],
            refused: Mutex::new(Cell::new(0)),
            high: Mutex::new(Cell::new(wz_session_core::pool_gauge::HighWater::new())),
        }
    }

    /// How many cells the table has.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// How many cells hold a pump.
    pub fn in_use(&self) -> usize {
        self.cells
            .iter()
            .filter(|cell| crate::cs::with(|cs| cell.taken.borrow(cs).get()))
            .count()
    }

    /// How many claims were refused for want of a free cell.
    pub fn refused(&self) -> u32 {
        crate::cs::with(|cs| self.refused.borrow(cs).get())
    }

    /// The bytes this table takes in the image's `.bss`, with each cell's pump (and,
    /// with `reassembly`, its staging table).
    pub const fn size_bytes() -> usize {
        core::mem::size_of::<Self>()
    }

    /// Build the pump of one session in a free cell: the engine, the role's
    /// activation, the handles. `None` of that is built when no cell is free, and
    /// what the caller offered (the link and the handle to the session, which hold
    /// their own slots) is dropped, so a refused pump leaves nothing taken.
    ///
    /// With `reassembly` the pump stages its fragments into a table that lies in the
    /// same cell, handed to the pump as `PoolStorage::Static`.
    pub fn claim(
        &'static self,
        runtime: CoopRuntime<C, D>,
        link: L,
        actions: SessionHandle<C, D>,
        entropy: SessionEntropy,
        clock: CoopTime<C>,
        config: SessionDriveConfig,
    ) -> Result<PumpRef<C, L, D>, PumpsFull> {
        let cell = self.cells.iter().find(|cell| {
            crate::cs::with(|cs| {
                let taken = cell.taken.borrow(cs);
                !taken.replace(true)
            })
        });
        let Some(cell) = cell else {
            crate::cs::with(|cs| {
                let refused = self.refused.borrow(cs);
                refused.set(refused.get().saturating_add(1));
            });
            return Err(PumpsFull);
        };
        // The cell is taken: the mark is what the table holds now, if that is the most so far.
        #[cfg(feature = "pool-monitor")]
        {
            let held = self.in_use();
            crate::cs::with(|cs| {
                let high = self.high.borrow(cs);
                let mut mark = high.get();
                mark.note(held);
                high.set(mark);
            });
        }
        #[cfg(feature = "reassembly")]
        let arena = {
            // SAFETY: the cell is `taken` by this call alone, and its pool is only
            // ever reached through the pump built here.
            let place = unsafe { &mut *cell.pool.get() };
            ReassemblyArena::new(PoolStorage::zeroed_in(place))
        };
        // The reassembly is the session's, so it is built from the session's own snapshot.
        #[cfg(feature = "reassembly")]
        let reasm = in_place_reassembly(arena, &actions.params.policy);
        // SAFETY: the cell is `taken` by this call alone, and its pump is
        // uninitialised: either it was never written or its last pump was dropped
        // in place by the `PumpRef` that freed the cell. The pump is built in the cell,
        // not returned and written: no copy of it is on this stack.
        unsafe {
            SessionPump::build_in(
                &mut *cell.pump.get(),
                runtime,
                PumpFields {
                    link,
                    actions,
                    entropy,
                    clock,
                    config,
                },
                // `MaybeUninit::write` lends back the place it wrote, so the receive is written.
                #[cfg(feature = "reassembly")]
                |rx| {
                    let _ = UnicastRx::init_in(rx, |slot| slot.write(reasm));
                },
                #[cfg(not(feature = "reassembly"))]
                |rx| {
                    let _ = UnicastRx::init_in(rx, |slot| slot.write(()));
                },
            );
        }
        Ok(PumpRef { cell })
    }
}

#[cfg(feature = "session-slot")]
impl<
        C: ClockSource,
        L: SessionDatagramLink + 'static,
        const N: usize,
        D: BoxedLinkDriver + ?Sized + 'static,
    > Default for PumpSlots<C, L, N, D>
{
    fn default() -> Self {
        Self::new()
    }
}

/// The table says its state as a pool (`pool-monitor`): its cells, those taken, the most taken at
/// once where the build keeps the mark, and the claims it refused.
#[cfg(feature = "session-slot")]
impl<
        C: ClockSource,
        L: SessionDatagramLink + 'static,
        const N: usize,
        D: BoxedLinkDriver + ?Sized + 'static,
    > wz_session_core::pool_gauge::PoolGauge for PumpSlots<C, L, N, D>
{
    fn pool_stat(&self, name: &'static str) -> wz_session_core::pool_gauge::PoolStat {
        wz_session_core::pool_gauge::PoolStat {
            name,
            capacity: u32::try_from(N).unwrap_or(u32::MAX),
            in_use: u32::try_from(self.in_use()).unwrap_or(u32::MAX),
            high_water: crate::cs::with(|cs| self.high.borrow(cs).get().get()),
            refused: u64::from(self.refused()),
        }
    }
}

/// The exclusive handle to a pump in its cell. Dropping it drops the pump in place
/// and frees the cell. The task that drives a pump ([`pump_task`]) owns it.
#[cfg(feature = "session-slot")]
pub struct PumpRef<
    C: ClockSource + 'static,
    L: SessionDatagramLink + 'static,
    D: BoxedLinkDriver + ?Sized + 'static = dyn BoxedLinkDriver,
> {
    cell: &'static PumpCell<C, L, D>,
}

#[cfg(feature = "session-slot")]
impl<C: ClockSource, L: SessionDatagramLink + 'static, D: BoxedLinkDriver + ?Sized + 'static> Deref
    for PumpRef<C, L, D>
{
    type Target = SessionPump<C, L, D>;

    fn deref(&self) -> &SessionPump<C, L, D> {
        // SAFETY: a `PumpRef` exists only for a cell whose pump was written by
        // `claim` and not yet dropped, and it is the cell's one reference.
        unsafe { (*self.cell.pump.get()).assume_init_ref() }
    }
}

#[cfg(feature = "session-slot")]
impl<C: ClockSource, L: SessionDatagramLink + 'static, D: BoxedLinkDriver + ?Sized + 'static>
    DerefMut for PumpRef<C, L, D>
{
    fn deref_mut(&mut self) -> &mut SessionPump<C, L, D> {
        // SAFETY: as for `deref`, and `&mut self` is the cell's one reference.
        unsafe { (*self.cell.pump.get()).assume_init_mut() }
    }
}

#[cfg(feature = "session-slot")]
impl<C: ClockSource, L: SessionDatagramLink + 'static, D: BoxedLinkDriver + ?Sized + 'static> Drop
    for PumpRef<C, L, D>
{
    fn drop(&mut self) {
        // SAFETY: the cell holds this handle's pump, written by `claim` and dropped
        // only here; the flag is cleared after, so no claim can write over it first.
        unsafe { (*self.cell.pump.get()).assume_init_drop() };
        crate::cs::with(|cs| self.cell.taken.borrow(cs).set(false));
    }
}

/// The session AS A TASK over a pump in a cell: awaits [`yield_now`] between
/// iterations as `session_task` does, and ends with the same [`DriverOutcome`].
/// The future is the pump's handle and the observer and a loop's state, and the pump stays
/// where its table put it.
///
/// An `async move` block and not an `async fn`: the arguments of an `async fn` are kept twice in
/// its future (once as what it was given, once as the locals its body moved them into), and an
/// observer's registries are kilobytes, so the future was twice what it holds. A block uses what
/// it captured where it was put. (Clippy's `manual_async_fn` would write it back as an
/// `async fn`, which is the form this one is written to avoid.)
#[cfg(feature = "session-slot")]
#[allow(clippy::manual_async_fn)]
pub fn pump_task<C, L, D, F>(
    mut pump: PumpRef<C, L, D>,
    mut on_event: F,
) -> impl core::future::Future<Output = DriverOutcome>
where
    C: ClockSource,
    L: SessionDatagramLink + 'static,
    D: BoxedLinkDriver + ?Sized + 'static,
    F: EventSink,
{
    async move {
        loop {
            if let Some(outcome) = pump.step(&mut on_event) {
                return outcome;
            }
            yield_now().await;
        }
    }
}

/// The bytes of a task cell that holds the task of a session ([`pump_task`]) over these types:
/// the size an image declares for its runtime's cells, as a constant of the types it names, so
/// that a layer that grows is a number that follows and not a spawn that is refused
/// ([`crate::executor::SpawnRefusal::TooLarge`]).
#[cfg(feature = "session-slot")]
pub const fn pump_task_cell_bytes<C, L, D, F>() -> usize
where
    C: ClockSource,
    L: SessionDatagramLink + 'static,
    D: BoxedLinkDriver + ?Sized + 'static,
    F: EventSink,
{
    crate::executor::cell_bytes_of(pump_task::<C, L, D, F>)
}

/// Host the pump in `pump` as a task of `local` and return its join handle, or say
/// why not. A refusal is counted (by the pump table when no cell was free, by the
/// runtime's task table otherwise) and the pump, which this call owns, is dropped
/// with its cell and the session it was to run.
#[cfg(feature = "session-slot")]
pub fn spawn_pump<C, L, D, F>(
    local: &CoopLocalSet<C>,
    pump: PumpRef<C, L, D>,
    on_event: F,
) -> Result<CoopLocalJoinHandle<DriverOutcome>, SessionSpawnRefused>
where
    C: ClockSource + 'static,
    L: SessionDatagramLink + 'static,
    D: BoxedLinkDriver + ?Sized + 'static,
    F: EventSink + 'static,
{
    // Made in the cell: the task holds the observer, whose registries are kilobytes, and a
    // future passed by value through the spawn is that size on the stack several times over.
    local
        .spawn_local_with(move || pump_task(pump, on_event))
        .map_err(SessionSpawnRefused::Task)
}

#[cfg(all(
    test,
    feature = "session-unicast",
    feature = "alloc",
    not(feature = "session-slot")
))]
mod wake_budget_tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use wz_session_core::link::{LinkSendOutcome, RxFrame};
    use wz_session_core::reliability::Reliability;
    use wz_session_core::session_init_params::SessionInitParams;
    use wz_session_core::session_timeouts::SessionTimeouts;
    use wz_session_core::signing_key::SigningKey;

    #[cfg(feature = "session-unicast-accept")]
    use wz_session_core::driver_loop::DriverLoopOutcome;

    use crate::session_runtime::{new_session_actions, SessionEntropy};
    use crate::time::{ClockSource, CoopTime};
    use crate::CoopRuntime;

    #[derive(Clone, Copy)]
    struct Stopped;
    impl ClockSource for Stopped {
        fn now_us(&self) -> u64 {
            1_000_000
        }
    }

    /// A link that takes the permission to wait and records what it was told it could wait, and
    /// says it is gone when the test says so.
    #[derive(Default)]
    struct Recording {
        budgets: RefCell<Vec<u64>>,
        gone: core::cell::Cell<Option<LostCause>>,
        /// Whether the link's owner holds its input back.
        holding: core::cell::Cell<bool>,
        /// How many times the link was asked for a datagram.
        reads: core::cell::Cell<u32>,
    }

    impl SessionDatagramLink for Recording {
        fn service(&self) {}
        fn service_within(&self, max_wait_ms: u64) {
            self.budgets.borrow_mut().push(max_wait_ms);
        }
        fn uses_wake_budget(&self) -> bool {
            true
        }
        fn try_recv(&self) -> Option<RxFrame> {
            self.reads.set(self.reads.get() + 1);
            None
        }
        fn lost(&self) -> Option<LostCause> {
            self.gone.get()
        }
        fn takes_input(&self) -> bool {
            !self.holding.get()
        }
    }

    struct Null;
    impl BoxedLinkDriver for Null {
        fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
            LinkSendOutcome::Sent
        }
        fn open_blocking(&self) {}
        fn close_blocking(&self) {}
    }

    struct Counting(u8);
    impl wz_session_core::entropy::EntropySource for Counting {
        fn try_fill_bytes(
            &mut self,
            buf: &mut [u8],
        ) -> Result<(), wz_session_core::entropy::EntropyUnavailable> {
            for slot in buf.iter_mut() {
                *slot = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    fn params() -> SessionInitParams {
        SessionInitParams {
            whatami: wz_session_core::WhatAmI::Peer,
            zid: [0x0A, 0x0B, 0x0C, 0x0D].into(),
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 1024,
            lease_ms: 10_000,
            keep_alive: wz_session_core::session_init_params::KeepAliveConf::PICO,
            initial_sn: 0,
            cookie: vec![0u8; 16],
            tx_queue: wz_session_core::session_init_params::TxQueueConf::of_snapshot(
                &wz_session_core::policy::SessionPolicy::defaults(),
                &wz_session_core::limits::SessionLimits::BUILD,
            ),
            link_rx: wz_session_core::session_init_params::LinkRxConf::default(),
            policy: wz_session_core::policy::SessionPolicy::defaults(),
            limits: wz_session_core::limits::SessionLimits::BUILD,
            cookie_signing_key: SigningKey::new(vec![7u8; 32]).expect(">=32-byte key"),
        }
    }

    /// What one step of an acceptor pump tells its link it may wait, after the application layer
    /// stated a deadline `in_ms` from now (or nothing).
    fn waited(in_ms: Option<u64>) -> u64 {
        let runtime = CoopRuntime::new(Stopped);
        let clock = CoopTime::new(&runtime);
        let sink = crate::link_cells::heap_sink(Null);
        let actions = new_session_actions(sink, params(), clock.clone());
        let entropy = SessionEntropy::new(Counting(0));
        // The session's own clock, whose epoch is its runtime's and not the board's.
        let now_ms = clock.now_monotonic_ms();
        actions.set_app_wake_deadline_ms(in_ms.map(|ms| now_ms + ms));
        let link = Rc::new(Recording::default());
        let config = SessionDriveConfig {
            timeouts: SessionTimeouts::from_build(),
            role: SessionRole::Acceptor,
            max_iters: None,
        };
        let mut pump = SessionPump::new(runtime, link.clone(), actions, entropy, clock, config);
        let _ = pump.step(&mut |_event: IterationEvent<'_, '_>| {});
        let waited = *link.budgets.borrow().last().expect("the link was serviced");
        waited
    }

    /// The events a pump raises over one step, after the application layer stated a deadline
    /// `in_ms` from now, and the deadline left afterwards.
    fn raised(in_ms: Option<u64>) -> (usize, Option<u64>) {
        let runtime = CoopRuntime::new(Stopped);
        let clock = CoopTime::new(&runtime);
        let sink = crate::link_cells::heap_sink(Null);
        let actions = new_session_actions(sink, params(), clock.clone());
        let entropy = SessionEntropy::new(Counting(0));
        let now_ms = clock.now_monotonic_ms();
        actions.set_app_wake_deadline_ms(in_ms.map(|ms| now_ms + ms));
        let link = Rc::new(Recording::default());
        let config = SessionDriveConfig {
            timeouts: SessionTimeouts::from_build(),
            role: SessionRole::Acceptor,
            max_iters: None,
        };
        let mut pump = SessionPump::new(runtime, link, actions.clone(), entropy, clock, config);
        let mut wakes = 0;
        let _ = pump.step(&mut |event: IterationEvent<'_, '_>| {
            if matches!(event, IterationEvent::AppWake) {
                wakes += 1;
            }
        });
        (wakes, actions.app_wake_deadline_ms())
    }

    /// The rest of a datagram already read waits while the link's owner holds its input back, and
    /// is dispatched by the first step after it lets go: a step hands the session nothing while
    /// held, not even what it had read. The copying receive's: a receive in place parks nothing
    /// of a datagram, which it reads where the link holds it.
    #[cfg(not(feature = "rx-in-place"))]
    #[test]
    fn a_held_link_leaves_the_rest_of_a_datagram_parked() {
        let runtime = CoopRuntime::new(Stopped);
        let clock = CoopTime::new(&runtime);
        let sink = crate::link_cells::heap_sink(Null);
        let actions = new_session_actions(sink, params(), clock.clone());
        let entropy = SessionEntropy::new(Counting(0));
        let link = Rc::new(Recording::default());
        let config = SessionDriveConfig {
            timeouts: SessionTimeouts::from_build(),
            role: SessionRole::Acceptor,
            max_iters: None,
        };
        let mut pump = SessionPump::new(
            runtime,
            link.clone(),
            actions.clone(),
            entropy,
            clock,
            config,
        );
        link.holding.set(true);
        actions.park_pending_batch(&[0xFF]);
        let _ = pump.step(&mut |_event: IterationEvent<'_, '_>| {});
        let kept = actions.take_pending_batch();
        assert!(kept.is_some(), "held: the rest stays parked");
        actions.park_pending_batch(&[0xFF]);
        link.holding.set(false);
        let _ = pump.step(&mut |_event: IterationEvent<'_, '_>| {});
        assert!(
            actions.take_pending_batch().is_none(),
            "let go: the rest is dispatched"
        );
    }

    #[test]
    fn a_deadline_that_has_come_due_raises_one_event_and_is_spent() {
        // The session's steady state raises no event of its own, so without this one the layer
        // that stated a deadline would run only when a datagram or the lease happened to.
        assert_eq!(raised(Some(0)), (1, None), "due: one event, and none left");
        let (wakes, left) = raised(Some(5));
        assert_eq!(wakes, 0, "not yet due: no event");
        assert!(left.is_some(), "and the deadline is kept for when it is");
        assert_eq!(raised(None), (0, None), "none stated: no event");
    }

    /// A stream whose peer closed it: the loop tells the session, which ends, and the pump stops
    /// on the next step. A link that is not gone raises nothing of the kind.
    ///
    /// The session is an acceptor's, whose machine is compiled only with the accept path: without
    /// it the role has no activation and a lost link ends nothing.
    #[cfg(feature = "session-unicast-accept")]
    #[test]
    fn a_link_that_is_gone_ends_its_session() {
        let runtime = CoopRuntime::new(Stopped);
        let clock = CoopTime::new(&runtime);
        let sink = crate::link_cells::heap_sink(Null);
        let actions = new_session_actions(sink, params(), clock.clone());
        let entropy = SessionEntropy::new(Counting(0));
        let link = Rc::new(Recording::default());
        let config = SessionDriveConfig {
            timeouts: SessionTimeouts::from_build(),
            role: SessionRole::Acceptor,
            max_iters: None,
        };
        let mut pump = SessionPump::new(runtime, link.clone(), actions, entropy, clock, config);
        let mut lost = Vec::new();
        let mut record = |event: IterationEvent<'_, '_>| {
            if let IterationEvent::Poll(DriverLoopOutcome::LinkLost(cause)) = event {
                lost.push(*cause);
            }
        };
        assert_eq!(pump.step(&mut record), None);
        link.gone.set(Some(LostCause::PeerClosed));
        assert_eq!(
            pump.step(&mut record),
            None,
            "the step that tells the session"
        );
        assert_eq!(pump.step(&mut record), Some(DriverOutcome::Terminated));
        assert_eq!(
            lost,
            vec![LostCause::PeerClosed],
            "told once, with its cause"
        );
    }

    /// A test's Router maker: it counts its runs and builds a Router that stages its own chains.
    #[cfg(feature = "reassembly")]
    struct CountedRouter {
        made: Rc<core::cell::Cell<u32>>,
        policy: wz_session_core::policy::SessionPolicy,
    }

    #[cfg(feature = "reassembly")]
    impl MakeRouter<crate::reassembly_rx::CoopReassembly> for CountedRouter {
        fn make_in(
            self,
            place: &mut MaybeUninit<crate::reassembly_rx::CoopReassembly>,
        ) -> &mut crate::reassembly_rx::CoopReassembly {
            self.made.set(self.made.get() + 1);
            crate::reassembly_rx::CoopReassembly::init_in(
                place,
                crate::reassembly_rx::mcu_reassembly_config(&self.policy),
                wz_session_core::chain_staging::BuildsOwnStorage::new(),
            )
        }
    }

    /// The event sink of a test's session, a type that can be named.
    #[cfg(feature = "reassembly")]
    fn ignore(_event: IterationEvent<'_, '_>) {}

    /// A session spawned over a Router its maker writes in the pump: the maker runs once, when the
    /// task first runs and not before; the pump it was written in steps its link; and the pump,
    /// with the handle to the session it holds, goes with its task when the task is dropped.
    #[cfg(feature = "reassembly")]
    #[test]
    fn a_session_spawned_over_a_router_made_in_place_runs_and_goes_with_its_task() {
        let runtime = CoopRuntime::new(Stopped);
        let local = CoopLocalSet::new(&runtime);
        let clock = CoopTime::new(&runtime);
        let sink = crate::link_cells::heap_sink(Null);
        let actions = new_session_actions(sink, params(), clock.clone());
        let entropy = SessionEntropy::new(Counting(0));
        let link = Rc::new(Recording::default());
        let made = Rc::new(core::cell::Cell::new(0u32));
        let before = crate::link_cells::CellRc::handles(&actions);
        let task = spawn_session_with_router(
            &local,
            PumpFields {
                link: Rc::clone(&link),
                actions: actions.clone(),
                entropy,
                clock,
                config: SessionDriveConfig {
                    timeouts: SessionTimeouts::from_build(),
                    role: SessionRole::Acceptor,
                    max_iters: None,
                },
            },
            CountedRouter {
                made: Rc::clone(&made),
                policy: wz_session_core::policy::SessionPolicy::defaults(),
            },
            ignore as fn(IterationEvent<'_, '_>),
        )
        .expect("a grown table takes every task");
        assert_eq!(made.get(), 0, "nothing is built before the task runs");
        local.run_until_idle();
        assert_eq!(
            made.get(),
            1,
            "the Router is made once, when the task first runs"
        );
        assert!(
            !link.budgets.borrow().is_empty(),
            "the pump built in the task stepped its link"
        );
        let running = crate::link_cells::CellRc::handles(&actions);
        assert!(running > before, "the pump holds the handle to its session");
        task.abort();
        local.run_until_idle();
        assert_eq!(made.get(), 1, "a dropped task makes nothing more");
        assert!(
            crate::link_cells::CellRc::handles(&actions) < running,
            "the pump, and the handles it held, went with its task"
        );
    }

    /// A session over the Router its session lends it reads its link inside the lend alone: a
    /// pass of its task outside the lend steps the link and asks it for nothing, which leaves the
    /// link's input with the link, and a pass inside the lend asks it. The CONTROL is the step of
    /// the link in the pass outside the lend.
    #[cfg(all(feature = "reassembly", not(feature = "session-slot")))]
    #[test]
    fn a_session_over_a_lent_router_reads_its_link_inside_the_lend_alone() {
        use wz_session_core::unicast_rx::RouterLend;
        type Router = crate::reassembly_rx::CoopReassembly;
        let runtime = CoopRuntime::new(Stopped);
        let local = CoopLocalSet::new(&runtime);
        let clock = CoopTime::new(&runtime);
        let sink = crate::link_cells::heap_sink(Null);
        let actions = new_session_actions(sink, params(), clock.clone());
        let entropy = SessionEntropy::new(Counting(0));
        let link = Rc::new(Recording::default());
        let lend = RouterLend::<Router>::new();
        let mut router = crate::reassembly_rx::mcu_reassembly(
            &wz_session_core::policy::SessionPolicy::defaults(),
        );
        let task = spawn_session_with_router(
            &local,
            PumpFields {
                link: Rc::clone(&link),
                actions: actions,
                entropy,
                clock,
                config: SessionDriveConfig {
                    timeouts: SessionTimeouts::from_build(),
                    role: SessionRole::Acceptor,
                    max_iters: None,
                },
            },
            lend.clone(),
            ignore as fn(IterationEvent<'_, '_>),
        )
        .expect("a grown table takes every task");
        local.run_until_idle();
        assert!(
            !link.budgets.borrow().is_empty(),
            "CONTROL: the pass stepped the link"
        );
        assert_eq!(
            link.reads.get(),
            0,
            "outside the lend the link is asked nothing"
        );
        lend.lend_for(&mut router, || local.run_until_idle());
        assert!(link.reads.get() > 0, "inside the lend the link is asked");
        task.abort();
        local.run_until_idle();
    }

    /// The bytes of a session's task are a constant of its types: a runtime reserved with cells of
    /// exactly that size hosts the session, and one with a byte less refuses it, counted, without
    /// running its maker.
    #[cfg(feature = "reassembly")]
    #[test]
    fn a_runtime_reserved_with_a_session_tasks_bytes_hosts_the_session_and_one_byte_less_does_not()
    {
        type Link = Rc<Recording>;
        type Router = crate::reassembly_rx::CoopReassembly;
        type Sink = fn(IterationEvent<'_, '_>);
        let bytes = router_session_task_bytes::<Stopped, Link, Router, CountedRouter, Sink>();
        for (cell, fits) in [(bytes, true), (bytes - 1, false)] {
            let runtime = CoopRuntime::reserved(
                Stopped,
                crate::RuntimeRows {
                    tasks: 1,
                    task_bytes: cell,
                    timers: 0,
                },
            );
            let local = CoopLocalSet::new(&runtime);
            let clock = CoopTime::new(&runtime);
            let sink = crate::link_cells::heap_sink(Null);
            let actions = new_session_actions(sink, params(), clock.clone());
            let entropy = SessionEntropy::new(Counting(0));
            let made = Rc::new(core::cell::Cell::new(0u32));
            let spawned = spawn_session_with_router(
                &local,
                PumpFields {
                    link: Rc::new(Recording::default()),
                    actions: actions,
                    entropy,
                    clock,
                    config: SessionDriveConfig {
                        timeouts: SessionTimeouts::from_build(),
                        role: SessionRole::Acceptor,
                        max_iters: None,
                    },
                },
                CountedRouter {
                    made: Rc::clone(&made),
                    policy: wz_session_core::policy::SessionPolicy::defaults(),
                },
                ignore as Sink,
            );
            local.run_until_idle();
            assert_eq!(made.get(), u32::from(fits), "a refused task makes nothing");
            assert_eq!(runtime.task_refusals().too_large, u32::from(!fits));
            match spawned {
                Ok(task) => {
                    assert!(
                        fits,
                        "a cell of {cell} bytes, too small, hosted the session"
                    );
                    assert!(!task.is_finished(), "the session runs in its cell");
                    task.abort();
                    local.run_until_idle();
                }
                Err(why) => {
                    assert!(
                        !fits,
                        "a cell of {cell} bytes, which fits, refused the session"
                    );
                    assert_eq!(why, crate::executor::SpawnRefusal::TooLarge);
                }
            }
        }
    }

    /// The engine's shape of a session: a runtime reserved when the session opens and sealed, the
    /// session's task on a local set, its pump holding a handle of the runtime. Letting go of every
    /// handle outside the table lets go of the runtime, and its clock with it: the table keeps no
    /// task past its set, so a task's handle does not keep the runtime that keeps the task.
    #[cfg(feature = "reassembly")]
    #[test]
    fn a_sealed_runtime_whose_session_task_holds_it_is_let_go_with_its_local_set() {
        use core::sync::atomic::{AtomicU32, Ordering};
        static RELEASED: AtomicU32 = AtomicU32::new(0);
        /// A clock that counts its drops: the runtime that holds it is gone when it is.
        struct Released;
        impl ClockSource for Released {
            fn now_us(&self) -> u64 {
                1_000_000
            }
        }
        impl Drop for Released {
            fn drop(&mut self) {
                RELEASED.fetch_add(1, Ordering::SeqCst);
            }
        }
        type Link = Rc<Recording>;
        type Router = crate::reassembly_rx::CoopReassembly;
        type Sink = fn(IterationEvent<'_, '_>);
        let task_bytes = router_session_task_bytes::<Released, Link, Router, CountedRouter, Sink>();
        let runtime = CoopRuntime::opening(
            Released,
            crate::RuntimeRows {
                tasks: 1,
                task_bytes,
                timers: 1,
            },
            0,
        );
        runtime.seal();
        let local = CoopLocalSet::new(&runtime);
        let clock = CoopTime::new(&runtime);
        let sink = crate::link_cells::heap_sink(Null);
        let actions = new_session_actions(sink, params(), clock.clone());
        let entropy = SessionEntropy::new(Counting(0));
        let task = spawn_session_with_router(
            &local,
            PumpFields {
                link: Rc::new(Recording::default()),
                actions: actions,
                entropy,
                clock,
                config: SessionDriveConfig {
                    timeouts: SessionTimeouts::from_build(),
                    role: SessionRole::Acceptor,
                    max_iters: None,
                },
            },
            CountedRouter {
                made: Rc::new(core::cell::Cell::new(0u32)),
                policy: wz_session_core::policy::SessionPolicy::defaults(),
            },
            ignore as Sink,
        )
        .expect("the cell reserved for the session");
        local.run_until_idle();
        assert!(!task.is_finished(), "the session runs");
        drop(task);
        drop(runtime);
        assert_eq!(
            RELEASED.load(Ordering::SeqCst),
            0,
            "the local set still holds the runtime"
        );
        drop(local);
        assert_eq!(
            RELEASED.load(Ordering::SeqCst),
            1,
            "the runtime went with the set its session's task was on, though the task held it"
        );
    }

    #[test]
    fn the_application_layers_deadline_bounds_what_the_link_may_wait() {
        // An idle acceptor with no peer has no deadline of its own nearer than its handshake's.
        let free = waited(None);
        let bounded = waited(Some(7));
        assert!(
            bounded <= 7,
            "a deadline 7 ms away allows at most 7 ms, and the link was told {bounded}"
        );
        assert!(
            free > 7,
            "without the layer's deadline the same session may wait longer, and was told {free}"
        );
        // A deadline that is now is a wait of nothing.
        assert_eq!(waited(Some(0)), 0);
    }

    /// An acceptor's pump over the test's link, and the session's clock reading when it was made.
    fn acceptor() -> (SessionPump<Stopped, Rc<Recording>>, u64) {
        let runtime = CoopRuntime::new(Stopped);
        let clock = CoopTime::new(&runtime);
        let sink = crate::link_cells::heap_sink(Null);
        let actions = new_session_actions(sink, params(), clock.clone());
        let entropy = SessionEntropy::new(Counting(0));
        let now_ms = clock.now_monotonic_ms();
        let config = SessionDriveConfig {
            timeouts: SessionTimeouts::from_build(),
            role: SessionRole::Acceptor,
            max_iters: None,
        };
        let link = Rc::new(Recording::default());
        (
            SessionPump::new(runtime, link, actions, entropy, clock, config),
            now_ms,
        )
    }

    /// The session's timers name the nearest of its deadlines: the application layer's when it is
    /// nearer than any of the transport's, and with none stated nothing that near.
    #[test]
    fn the_session_timers_name_the_nearest_deadline() {
        let (mut pump, now_ms) = acceptor();
        let unprompted = pump.timers.next_due_ms(&pump.engine, &pump.actions, now_ms);
        assert!(
            !unprompted.is_some_and(|due| due <= now_ms + 3),
            "an idle session has nothing due within 3 ms, and named {unprompted:?}"
        );
        pump.actions.set_app_wake_deadline_ms(Some(now_ms + 3));
        assert_eq!(
            pump.timers.next_due_ms(&pump.engine, &pump.actions, now_ms),
            Some(now_ms + 3)
        );
    }

    /// An acceptor's handshake bound is armed when its timers first see its state, and its timeout
    /// moves the machine on once the bound has passed and not a millisecond before; the loop is
    /// told nothing of it, the machine is.
    #[cfg(feature = "session-unicast-accept")]
    #[test]
    fn the_session_timers_raise_the_handshake_timeout_at_its_deadline_and_not_before() {
        let (mut pump, now_ms) = acceptor();
        let state = pump.engine.get_current_state();
        let window = wz_session_core::session_timeouts::handshake_deadline_for(
            state,
            &SessionTimeouts::from_build(),
        )
        .expect("an activated acceptor waits on its handshake's bound")
        .deadline_ms;
        assert_eq!(
            pump.timers.next_due_ms(&pump.engine, &pump.actions, now_ms),
            Some(now_ms + window)
        );
        let mut events = 0;
        let mut count = |_event: IterationEvent<'_, '_>| events += 1;
        pump.timers.fire_due(
            &mut pump.engine,
            &pump.actions,
            now_ms + window - 1,
            &mut count,
        );
        assert!(
            pump.engine.get_current_state() == state,
            "not yet due: the machine is where it was"
        );
        pump.timers
            .fire_due(&mut pump.engine, &pump.actions, now_ms + window, &mut count);
        assert!(
            pump.engine.get_current_state() != state,
            "due: the timeout moved the machine on"
        );
        assert_eq!(events, 0, "the handshake's timeout is the machine's event");
    }
}

#[cfg(all(test, feature = "reassembly", not(feature = "session-slot")))]
mod in_place_tests {
    use super::Becomes;
    use alloc::boxed::Box;
    use core::cell::Cell;

    /// Counts its drops in the cell it was made with.
    struct Counted<'a>(&'a Cell<u32>);

    impl Drop for Counted<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    /// The parts are handed to the maker, which writes the value where they lay; the value is
    /// lent on each time after and dropped once, with the place, and the parts are not dropped
    /// again.
    #[test]
    fn the_value_is_built_of_the_parts_in_their_place_and_each_is_dropped_once() {
        let (parts_drops, value_drops) = (Cell::new(0), Cell::new(0));
        {
            let mut place = Becomes::new(Counted(&parts_drops));
            let value = place
                .build(|parts, slot| {
                    drop(parts);
                    Some(slot.write(Counted(&value_drops)))
                })
                .expect("written in its place");
            assert_eq!(value.0.get(), 0, "built and lent, not dropped");
            assert_eq!(parts_drops.get(), 1, "the parts were taken and let go of");
            assert!(
                place.build(|_parts, _slot| None).is_some(),
                "built once, lent again"
            );
        }
        assert_eq!(value_drops.get(), 1, "dropped once, with the place");
        assert_eq!(parts_drops.get(), 1);
    }

    /// Parts never built into a value are dropped once, with the place.
    #[test]
    fn parts_never_built_are_dropped_with_the_place() {
        let drops = Cell::new(0);
        {
            let _place = Becomes::<Counted<'_>, u32>::new(Counted(&drops));
        }
        assert_eq!(drops.get(), 1);
    }

    /// A maker that lends back a value it did not write in the place is refused, and the place,
    /// its parts taken and nothing built, lends nothing and drops nothing from then on.
    #[test]
    fn a_maker_that_lends_back_another_value_is_refused() {
        let elsewhere: &'static mut u32 = Box::leak(Box::new(7));
        let mut place = Becomes::<(), u32>::new(());
        assert!(place.build(|(), _slot| Some(elsewhere)).is_none());
        assert!(
            place.build(|(), _slot| None).is_none(),
            "nothing was built, and the parts are gone"
        );
    }
}
