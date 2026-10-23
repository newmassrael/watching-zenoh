// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The acceptor of the `session-slot` profile: ONE listening socket that holds up
//! to `LANES` accepted sessions, and claims what a session needs BEFORE it answers
//! the peer that asked for it (fixed-memory step S6, exhaustion case R1).
//!
//! ## Why a listener, and why the claim comes first
//!
//! UDP has no connections: every peer that wants a session sends its `InitSyn` to
//! the one port the node listens on, and lwIP will not bind a second socket to
//! that port. A node that holds several sessions on one port therefore reads
//! them all from ONE socket and tells the peers apart by the address each
//! datagram came from, which is what upstream's UDP listener does with a link per
//! source address.
//!
//! The session is what answers a peer, so the answer cannot come before the
//! session exists: this listener never replies by itself. It reads the head of
//! the socket's queue and decides, for the peer that sent it:
//!
//! - a peer that already has a session (a lane): the datagram stays where it is
//!   for that session to read; the listener does nothing with it;
//! - a datagram that is not an `InitSyn` from a peer with no session: dropped
//!   and counted ([`ListenerCounts::strays`]), since a stray must not cost a
//!   slot;
//! - an `InitSyn` from a peer with no session: the listener RESERVES a lane,
//!   then offers the image the means to build the session ([`Admission`]).
//!   Whatever the image claims for it (a session slot, a pump cell, a task
//!   cell: see `SessionHost::open`) is claimed before the session can run, and a
//!   session that cannot run is never built, so nothing is sent. Only when the
//!   image says yes does the datagram stay at the head, now a peer with a
//!   session, for the new session to read and answer. When it says no, or no
//!   lane is free, the datagram is DROPPED and the refusal is COUNTED
//!   ([`ListenerCounts::refused`], by reason): the peer gets no `InitAck` and no
//!   `Close`, because a `Close` would need the very slot that was not there, and
//!   it retries on its own timer.
//!
//! Nothing here allocates: the lanes are a fixed table in the `static` the image
//! declares, the sessions' sockets are the one socket, and a refusal is a counter.
//!
//! ## The shared queue
//!
//! The sessions of one listener read from one receive queue, each taking only the
//! datagrams its own peer sent: its driver is bound to the peer of its
//! [`LaneGuard`], which [`LwipSessionLink`](crate::session_drive::LwipSessionLink)
//! holds, and leaves the others' where they are. That keeps the
//! in-place receive (a datagram is read where the socket's queue holds it, and a
//! frame a MAC lent is read where the controller wrote it) for accepted sessions
//! too, at one cost the image should know: the queue is one session's size, not N
//! of them, so a peer that sends faster than its session reads can crowd the
//! others' datagrams out (they are dropped and counted by the socket,
//! `rx_drop_count`). A session whose task has ended gives its lane back, so its
//! peer's datagrams are strays from then on and cannot hold the queue.
//!
//! Like the session table, the listener is `Sync` by the profile's rule (one
//! cooperative task on one core drives every session), not by anything a compiler
//! can check.

use core::cell::{Cell, OnceCell, RefCell};

use wz_link_lwip::rx_sockets::SessionRxSocket;
use wz_link_lwip::LwipLink;
use wz_session_core::datagram_peer::is_init_syn;

use crate::driver::{LwipUdpDriver, SessionSocket};
use crate::session_host::OpenRefused;

/// A remote end as lwIP names it: the address word and the port.
type Peer = (u32, u16);

/// What a listener has decided, since it was placed. Every datagram it did not
/// leave for a session is in exactly one of these.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ListenerCounts {
    /// `InitSyn`s whose session was built and left at the head to be read.
    pub admitted: u32,
    /// `InitSyn`s dropped because every lane was taken.
    pub refused_no_lane: u32,
    /// `InitSyn`s dropped because the session table had no slot.
    pub refused_no_session_slot: u32,
    /// `InitSyn`s dropped because the pump table had no cell.
    pub refused_no_pump_cell: u32,
    /// `InitSyn`s dropped because the task table refused the session's task.
    pub refused_no_task_cell: u32,
    /// Datagrams from a peer with no session that were not an `InitSyn`.
    pub strays: u32,
}

impl ListenerCounts {
    /// `InitSyn`s answered with nothing, whatever table said no.
    pub fn refused(&self) -> u32 {
        self.refused_no_lane
            .saturating_add(self.refused_no_session_slot)
            .saturating_add(self.refused_no_pump_cell)
            .saturating_add(self.refused_no_task_cell)
    }
}

/// What one [`SessionListener::accept_pass`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AcceptPass {
    /// Sessions admitted (at most one per pass: the new session reads its
    /// `InitSyn` before anything behind it is looked at).
    pub admitted: u32,
    /// `InitSyn`s dropped for want of a lane or a table cell.
    pub refused: u32,
    /// Strays dropped.
    pub strays: u32,
}

/// What the image is given for an `InitSyn` it may admit: the driver of the new
/// session, which reads and sends through the listener's socket, and the lane
/// that keeps the session's peer apart from the others'. Both go into the
/// session (`SessionHost::open`); dropping them, which is what a refusal does,
/// gives the lane back.
pub struct Admission {
    /// The link driver of the session about to be built.
    pub driver: LwipUdpDriver,
    /// The lane the session reads its datagrams through.
    pub lane: LaneGuard,
}

impl Admission {
    /// The peer that sent the `InitSyn`, as lwIP names it (the address word in
    /// network byte order, and the port).
    pub fn peer(&self) -> (u32, u16) {
        self.lane.peer
    }
}

/// The table the lanes live in, with its capacity erased: a lane gives itself
/// back through this when it drops.
trait LaneTable {
    fn release(&self, index: usize);
}

/// One accepted session's claim on a lane of its listener: the peer the session
/// belongs to, to which the session's driver is bound, and which is how the
/// session picks its datagrams out of the one queue (the driver reads only a
/// datagram whose source is [`peer`](Self::peer) and leaves the others').
/// Dropping it frees the lane, so the table is free again exactly when the
/// session's link is.
pub struct LaneGuard {
    table: &'static dyn LaneTable,
    index: usize,
    peer: Peer,
}

impl LaneGuard {
    /// The peer this lane belongs to.
    pub fn peer(&self) -> (u32, u16) {
        self.peer
    }
}

impl Drop for LaneGuard {
    fn drop(&mut self) {
        self.table.release(self.index);
    }
}

/// The listener an image declares: one socket, up to `LANES` accepted sessions.
///
/// ```ignore
/// static LISTENER: SessionListener<3> = SessionListener::new();
/// LISTENER.listen(bind_session_rx(&link, 7447)?)?;
/// // once per executor pass, from a task or the firmware's tick:
/// LISTENER.accept_pass(&link, &mut |admission| host.admit(admission, ..).map(drop));
/// ```
///
/// `LANES` is how many sessions the listener can have open at once. An image whose
/// session table also holds sessions it dialled declares the listener with the
/// number it accepts at most; the session table still bounds the sum.
pub struct SessionListener<const LANES: usize> {
    socket: OnceCell<RefCell<SessionRxSocket>>,
    peers: [Cell<Option<Peer>>; LANES],
    counts: Cell<ListenerCounts>,
}

// SAFETY: the profile's rule, stated in the module's last paragraph. The listener is
// touched by the one cooperative task that drives its sessions, never from an
// interrupt, so no two threads reach it; `Sync` is what a `static` needs of it.
unsafe impl<const LANES: usize> Sync for SessionListener<LANES> {}

impl<const LANES: usize> LaneTable for SessionListener<LANES> {
    fn release(&self, index: usize) {
        self.peers[index].set(None);
    }
}

impl<const LANES: usize> SessionListener<LANES> {
    /// A listener with no socket and every lane free, for a `static`.
    pub const fn new() -> Self {
        Self {
            socket: OnceCell::new(),
            peers: [const { Cell::new(None) }; LANES],
            counts: Cell::new(ListenerCounts {
                admitted: 0,
                refused_no_lane: 0,
                refused_no_session_slot: 0,
                refused_no_pump_cell: 0,
                refused_no_task_cell: 0,
                strays: 0,
            }),
        }
    }

    /// Start listening on `socket`, a session socket bound on the port the node
    /// accepts on. Once: a listener that already has a socket hands the new one
    /// back.
    pub fn listen(&'static self, socket: SessionRxSocket) -> Result<(), SessionRxSocket> {
        self.socket
            .set(RefCell::new(socket))
            .map_err(RefCell::into_inner)
    }

    /// How many sessions the listener can hold open.
    pub const fn capacity(&self) -> usize {
        LANES
    }

    /// How many lanes belong to a session now.
    pub fn in_use(&self) -> usize {
        self.peers
            .iter()
            .filter(|lane| lane.get().is_some())
            .count()
    }

    /// What the listener has decided so far.
    pub fn counts(&self) -> ListenerCounts {
        self.counts.get()
    }

    /// How many `InitSyn`s were answered with nothing, whichever table said no.
    pub fn refused(&self) -> u32 {
        self.counts.get().refused()
    }

    /// How many datagrams the listening socket dropped because its queue was full
    /// (`LwipUdpSocket::rx_drop_count`), `0` before it listens.
    pub fn rx_drops(&self) -> u32 {
        self.socket
            .get()
            .map_or(0, |socket| socket.borrow().rx_drop_count())
    }

    fn count(&self, bump: impl FnOnce(&mut ListenerCounts)) {
        let mut counts = self.counts.get();
        bump(&mut counts);
        self.counts.set(counts);
    }

    fn lane_of(&self, peer: Peer) -> Option<usize> {
        self.peers.iter().position(|lane| lane.get() == Some(peer))
    }

    fn reserve(&'static self, peer: Peer) -> Option<LaneGuard> {
        let index = self.peers.iter().position(|lane| lane.get().is_none())?;
        self.peers[index].set(Some(peer));
        Some(LaneGuard {
            table: self,
            index,
            peer,
        })
    }

    /// Drop the datagram at the head of the queue, unread.
    fn drop_head(socket: &RefCell<SessionRxSocket>) {
        socket.borrow_mut().consume_recv();
    }

    /// Decide what to do with what has arrived, as far as it can be decided
    /// without a session to read it: drive lwIP's input path, then look at the
    /// head of the socket's queue until something is left for a session to read.
    ///
    /// `admit` is offered an [`Admission`] for each `InitSyn` from a peer with no
    /// session and answers whether it built the session. It must claim everything
    /// the session needs before it returns `Ok`, and build nothing it does not
    /// keep: that is the whole of the claim-before-answer rule, since the
    /// listener sends nothing itself and a session that does not exist cannot.
    /// Call it once per executor pass.
    pub fn accept_pass(
        &'static self,
        link: &LwipLink,
        admit: &mut dyn FnMut(Admission) -> Result<(), OpenRefused>,
    ) -> AcceptPass {
        let mut pass = AcceptPass::default();
        let Some(socket) = self.socket.get() else {
            return pass;
        };
        link.poll_loopback();
        link.check_timeouts();
        loop {
            let head = socket.borrow().peek_recv().map(|datagram| {
                (
                    (datagram.src_addr, datagram.src_port),
                    is_init_syn(datagram.data),
                )
            });
            let Some((peer, init_syn)) = head else {
                return pass;
            };
            if self.lane_of(peer).is_some() {
                // A peer with a session: its session reads the datagram.
                return pass;
            }
            if !init_syn {
                Self::drop_head(socket);
                self.count(|counts| counts.strays = counts.strays.saturating_add(1));
                pass.strays += 1;
                continue;
            }
            let Some(lane) = self.reserve(peer) else {
                Self::drop_head(socket);
                self.count(|counts| {
                    counts.refused_no_lane = counts.refused_no_lane.saturating_add(1);
                });
                pass.refused += 1;
                continue;
            };
            let driver = LwipUdpDriver::new(SessionSocket::listened(socket), peer.0, peer.1);
            match admit(Admission { driver, lane }) {
                Ok(()) => {
                    self.count(|counts| counts.admitted = counts.admitted.saturating_add(1));
                    pass.admitted += 1;
                    return pass;
                }
                Err(why) => {
                    Self::drop_head(socket);
                    self.count(|counts| match why {
                        OpenRefused::SessionSlot => {
                            counts.refused_no_session_slot =
                                counts.refused_no_session_slot.saturating_add(1);
                        }
                        OpenRefused::PumpCell => {
                            counts.refused_no_pump_cell =
                                counts.refused_no_pump_cell.saturating_add(1);
                        }
                        OpenRefused::Task(_) => {
                            counts.refused_no_task_cell =
                                counts.refused_no_task_cell.saturating_add(1);
                        }
                    });
                    pass.refused += 1;
                }
            }
        }
    }
}

impl<const LANES: usize> Default for SessionListener<LANES> {
    fn default() -> Self {
        Self::new()
    }
}
