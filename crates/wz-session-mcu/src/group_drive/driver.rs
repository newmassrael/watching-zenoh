// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A group's send socket as the driver of the one link its transmit state sends on
//! (`wz_session_core::transport_tx::GroupTx`): the walk a unicast session writes with lends a
//! slot of it, encodes a frame into the slot and hands the slot over, and the driver offers the
//! frame to the socket from where it was encoded, as zenoh-pico's multicast send writes its
//! buffer to the socket (`vendor/zenoh-pico/src/transport/common/tx.c` @
//! `static z_result_t _z_transport_tx_send_n_msg_inner(`).
//!
//! What a socket with no room makes of a frame is the build's (`multicast-send-hold`). Without
//! it the send waits on the socket until it takes the frame, as zenoh-pico's blocking socket
//! does, and holds nothing. With it the frame's slot is held, the send returns, and the next ask
//! for room offers the held frame first and waits on the socket while it is refused, as a link
//! whose queue is full answers its senders.
//!
//! Either wait is the host's ([`GroupTxPace`]): its tasks run and the socket's writability is
//! waited on, so a socket that stays full is offered a frame once a wait, and never twice in a
//! row. A frame whose ask for room allowed no wait (a group's own step answers with such sends,
//! from inside the wait its senders wait with) waits in no build: refused by a full socket it is
//! a congestion drop, counted ([`HeldFrame::congested`]). The transport's own wait (`GroupTransport::wait_for_room`) is not asked: a stack whose
//! socket can be full but which gives no wait of its own answers it at once, and an offer after
//! such an answer is an offer after none.

use wz_runtime_coop::group_transport::{GroupSend, GroupTransport};
use wz_runtime_coop::link_cells::{CellRc, CountKind};
use wz_runtime_coop::link_storage::{copied_send, HeapTx, TxLender};
#[cfg(feature = "multicast-send-hold")]
use wz_session_core::inbound::{frame_lane, FrameLane};
use wz_session_core::link::{
    BoxedLinkDriver, LinkDropCause, LinkSendOutcome, TxSlot, TxSlotGrant, SESSION_TX_SLOTS,
};
use wz_session_core::link::{LinkRoom, RoomAnswer, RoomWait};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;

use super::{GroupLink, GroupTxPace};

/// The slots the driver lends: what a session needs of its link, and with the hold one more,
/// which the frame the socket refused keeps out.
const SLOTS: usize = if cfg!(feature = "multicast-send-hold") {
    SESSION_TX_SLOTS.saturating_add(1)
} else {
    SESSION_TX_SLOTS
};

/// The frame a full socket refused, held in its slot until the socket takes it.
#[cfg(feature = "multicast-send-hold")]
#[derive(Clone, Copy)]
struct Held {
    slot: TxSlot,
    start: usize,
    len: usize,
}

/// What a group's step and its JOIN read of the driver its sends leave by, past the walk: the frame
/// a full socket refused, which the step offers again before anything else of the group and whose
/// number the JOIN advertises in place of the next, and the frames a send the stack failed lost.
/// Without `multicast-send-hold` nothing is held, and the answers say so.
pub trait HeldFrame {
    /// Whether a frame the socket refused is held.
    fn holds(&self) -> bool;

    /// Offer the held frame to the socket again, without waiting: whether it is still refused. A
    /// frame the socket took, or lost, is let go.
    fn offer_held(&self) -> bool;

    /// How many frames a send the stack failed lost since the driver was made.
    fn lost(&self) -> u32;

    /// How many frames the walk handed over that the driver dropped for want of room on the
    /// socket since it was made: one whose ask allowed no wait, and one handed over with no ask
    /// while another is held. Congestion drops the walk's answer does not carry, since the frame
    /// had its number when the socket refused it.
    fn congested(&self) -> u32;

    /// The lane of the held frame, read off its head: its priority, channel and number. The
    /// group's JOIN advertises that number on its lane, so a member told the group's numbers while
    /// the frame waits still takes it when it leaves. `None` while nothing is held.
    #[cfg(feature = "multicast-send-hold")]
    fn held_lane(&self) -> Option<FrameLane>;
}

/// A group's socket as a link driver: the transport it shares with the group's session task, the
/// host's wait for the socket's room (`P`), and the slots its frames are encoded into, each a
/// batch of the group.
pub struct GroupDriver<T, P> {
    link: GroupLink<T>,
    pace: P,
    tx: TxLender<HeapTx>,
    /// How many frames a send the stack failed lost.
    lost: core::cell::Cell<u32>,
    /// How many frames handed over were dropped for want of room.
    congested: core::cell::Cell<u32>,
    /// Whether the frame handed over next may wait for the socket: what the last ask for room
    /// allowed, taken by the send. A frame handed over with no ask (a window's flush) may.
    #[cfg(not(feature = "multicast-send-hold"))]
    may_wait: core::cell::Cell<bool>,
    #[cfg(feature = "multicast-send-hold")]
    held: core::cell::Cell<Option<Held>>,
}

impl<T: GroupTransport, P: GroupTxPace> GroupDriver<T, P> {
    /// The driver of `link`, whose frames are at most `batch` bytes, waiting on the socket's
    /// room with `pace`.
    pub fn new(link: GroupLink<T>, pace: P, batch: usize) -> Self {
        Self {
            link,
            pace,
            tx: TxLender::new(HeapTx::new(SLOTS, batch)),
            lost: core::cell::Cell::new(0),
            congested: core::cell::Cell::new(0),
            #[cfg(not(feature = "multicast-send-hold"))]
            may_wait: core::cell::Cell::new(true),
            #[cfg(feature = "multicast-send-hold")]
            held: core::cell::Cell::new(None),
        }
    }

    /// A frame handed over that the socket had no room for and that may not wait: dropped and
    /// counted ([`HeldFrame::congested`]).
    fn congestion_drop(&self) -> LinkSendOutcome {
        self.congested.set(self.congested.get().saturating_add(1));
        LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot)
    }

    /// Offer `frame` to the socket: whether it is done with, taken or lost, or the socket had no
    /// room. `None` where nothing may be written now: the session does not hold the link open,
    /// or its task has the transport in hand.
    fn offer(&self, frame: &[u8]) -> Option<GroupSend> {
        self.link.send_now(frame)
    }

    /// The outcome the session counts of a frame the socket was offered. A failed send loses the
    /// frame and nothing else: a group's next datagram may well leave, so the link stays open
    /// and the loss is a drop, counted ([`HeldFrame::lost`]).
    fn outcome(&self, sent: Option<GroupSend>) -> LinkSendOutcome {
        match sent {
            Some(GroupSend::Sent) => LinkSendOutcome::Sent,
            Some(GroupSend::Failed) => {
                self.lost.set(self.lost.get().saturating_add(1));
                LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot)
            }
            Some(GroupSend::Full) | None => LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot),
        }
    }

    /// Offer the held frame again: whether the socket still refuses it. A frame the socket took,
    /// or lost, gives its slot back.
    #[cfg(feature = "multicast-send-hold")]
    fn offer_again(&self) -> bool {
        let Some(held) = self.held.get() else {
            return false;
        };
        let (base, _) = self.tx.storage(held.slot);
        // SAFETY: the held slot was handed over by the session and is the driver's until it is
        // released below; `start .. start + len` was found inside it when it was held.
        let frame = unsafe { core::slice::from_raw_parts(base.wrapping_add(held.start), held.len) };
        let sent = self.offer(frame);
        if sent == Some(GroupSend::Full) {
            return true;
        }
        let _ = self.outcome(sent);
        self.held.set(None);
        self.tx.release(held.slot);
        false
    }
}

impl<T: GroupTransport, P: GroupTxPace> HeldFrame for GroupDriver<T, P> {
    fn holds(&self) -> bool {
        #[cfg(feature = "multicast-send-hold")]
        {
            self.held.get().is_some()
        }
        #[cfg(not(feature = "multicast-send-hold"))]
        {
            false
        }
    }

    fn offer_held(&self) -> bool {
        #[cfg(feature = "multicast-send-hold")]
        {
            self.offer_again()
        }
        #[cfg(not(feature = "multicast-send-hold"))]
        {
            false
        }
    }

    fn lost(&self) -> u32 {
        self.lost.get()
    }

    fn congested(&self) -> u32 {
        self.congested.get()
    }

    #[cfg(feature = "multicast-send-hold")]
    fn held_lane(&self) -> Option<FrameLane> {
        let held = self.held.get()?;
        let (base, _) = self.tx.storage(held.slot);
        // SAFETY: as in `offer_again`: the held slot is the driver's until it is released, and
        // `start .. start + len` was found inside it when it was held.
        let frame = unsafe { core::slice::from_raw_parts(base.wrapping_add(held.start), held.len) };
        frame_lane(frame)
    }
}

// The engine keeps a counted handle on the driver beside the erased one its group's transmit state
// sends through (`CellRc::into_sink`), and reads the driver through it.
impl<X: HeldFrame + ?Sized, N: CountKind> HeldFrame for CellRc<X, N> {
    fn holds(&self) -> bool {
        (**self).holds()
    }

    fn offer_held(&self) -> bool {
        (**self).offer_held()
    }

    fn lost(&self) -> u32 {
        (**self).lost()
    }

    fn congested(&self) -> u32 {
        (**self).congested()
    }

    #[cfg(feature = "multicast-send-hold")]
    fn held_lane(&self) -> Option<FrameLane> {
        (**self).held_lane()
    }
}

impl<T: GroupTransport, P: GroupTxPace> BoxedLinkDriver for GroupDriver<T, P> {
    // Bytes built apart (a transport message, a frame of a build that lends no slot) are copied
    // into a slot and sent as one, so the socket has one sender.
    fn send_blocking(&self, bytes: &[u8], reliability: Reliability) -> LinkSendOutcome {
        copied_send(self, bytes, reliability, Priority::DEFAULT)
    }

    // The socket writes the datagram's headers itself, so a frame starts at its slot's front.
    fn tx_slot_acquire(&self, _want: usize, _priority: Priority) -> Option<TxSlotGrant> {
        self.tx.acquire(0)
    }

    fn tx_slot_storage(&self, slot: TxSlot) -> (*mut u8, usize) {
        self.tx.storage(slot)
    }

    #[cfg(not(feature = "multicast-send-hold"))]
    fn tx_slot_send(
        &self,
        slot: TxSlot,
        start: usize,
        len: usize,
        _reliability: Reliability,
        _priority: Priority,
    ) -> LinkSendOutcome {
        let may_wait = self.may_wait.replace(true);
        let Some(frame) = self.tx.take(slot, start, len) else {
            return LinkSendOutcome::Dropped(LinkDropCause::Oversize);
        };
        loop {
            match self.offer(frame) {
                // A frame whose ask allowed no wait is not waited for: its sender may be the
                // group's own step, which runs inside the wait the host would pass to.
                Some(GroupSend::Full) if !may_wait => return self.congestion_drop(),
                // A group whose session ended is written by nothing: the frame is lost with its
                // link, as a stage's wait answers a producer of an ended group.
                Some(GroupSend::Full) if self.pace.ended() => {
                    return LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot);
                }
                Some(GroupSend::Full) => {
                    self.pace.pass();
                    let _ = self.pace.wait_writable(u64::MAX);
                }
                sent => return self.outcome(sent),
            }
        }
    }

    #[cfg(feature = "multicast-send-hold")]
    fn tx_slot_send(
        &self,
        slot: TxSlot,
        start: usize,
        len: usize,
        _reliability: Reliability,
        _priority: Priority,
    ) -> LinkSendOutcome {
        // A frame handed over while another is held, which only a send that asks no room makes
        // (the flush of a window), finds the one hold taken: it is a drop.
        if self.offer_again() {
            self.tx.release(slot);
            return self.congestion_drop();
        }
        let Some((start, end)) = self.tx.seal(slot, start, len, |_, start| Some(start)) else {
            self.tx.release(slot);
            return LinkSendOutcome::Dropped(LinkDropCause::Oversize);
        };
        let len = end.saturating_sub(start);
        // SAFETY: the session handed the slot over, so the driver alone holds it until it is
        // released, and `seal` found `start .. end` inside it.
        let frame = unsafe { self.tx.held(slot, start, end) };
        match self.offer(frame) {
            Some(GroupSend::Full) => {
                self.held.set(Some(Held { slot, start, len }));
                LinkSendOutcome::Sent
            }
            sent => {
                self.tx.release(slot);
                self.outcome(sent)
            }
        }
    }

    fn tx_slot_abort(&self, slot: TxSlot) {
        self.tx.release(slot);
    }

    // Without the hold there is nothing to offer before the frame is built: the room is the
    // socket's at the send, which waits there only if this ask allowed a wait.
    #[cfg(not(feature = "multicast-send-hold"))]
    fn wait_for_room(&self, _priority: Priority, wait: RoomWait) -> RoomAnswer {
        self.may_wait.set(wait.wait_us() > 0);
        RoomAnswer::at_once(LinkRoom::Free)
    }

    // A link whose queue is full: the held frame is offered first, and while the socket refuses
    // it the ask runs the host's tasks and waits on the socket, once, for as long as it may.
    #[cfg(feature = "multicast-send-hold")]
    fn wait_for_room(&self, _priority: Priority, wait: RoomWait) -> RoomAnswer {
        if !self.offer_again() {
            return RoomAnswer::at_once(LinkRoom::Free);
        }
        let wait_us = wait.wait_us();
        if wait_us > 0 && !self.pace.ended() {
            let started = self.pace.now_us();
            self.pace.pass();
            let room = self.pace.wait_writable(wait_us);
            if room && !self.offer_again() {
                return RoomAnswer {
                    room: LinkRoom::Free,
                    waited_us: self.pace.now_us().saturating_sub(started).min(wait_us),
                };
            }
        }
        RoomAnswer {
            room: LinkRoom::Congested,
            waited_us: wait_us,
        }
    }

    // The group's session task opens and closes the transport.
    fn open_blocking(&self) {}

    fn close_blocking(&self) {}
}

#[cfg(test)]
mod tests {
    use alloc::rc::Rc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use core::net::SocketAddr;

    use wz_runtime_coop::group_transport::{GroupSend, GroupTransport};
    use wz_session_core::link::{BoxedLinkDriver, LinkDropCause, LinkSendOutcome};
    use wz_session_core::reliability::Reliability;

    use super::super::{GroupLink, GroupTxPace};
    use super::{GroupDriver, HeldFrame};

    /// What the socket took and was offered, how many more it takes before it is full, and what
    /// the host did while it was: a wait of the host frees one datagram's room once `fills` is
    /// spent, as a socket that drains does; a wait asked of the transport itself frees nothing,
    /// as a stack that gives no wait of its own answers at once.
    #[derive(Default)]
    struct Wire {
        seen: Vec<Vec<u8>>,
        offers: usize,
        room: usize,
        /// How many of the host's waits find the socket still full before one frees room.
        fills: usize,
        waits: usize,
        passes: usize,
        socket_waits: usize,
        ended: bool,
        /// Whether the stack fails each send.
        fail: bool,
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

        fn send_to_group(&mut self, datagram: &[u8]) {
            self.0.borrow_mut().seen.push(datagram.to_vec());
        }

        fn try_send_to_group(&mut self, datagram: &[u8]) -> GroupSend {
            let mut wire = self.0.borrow_mut();
            wire.offers += 1;
            if wire.fail {
                return GroupSend::Failed;
            }
            if wire.room == 0 {
                return GroupSend::Full;
            }
            wire.room -= 1;
            wire.seen.push(datagram.to_vec());
            GroupSend::Sent
        }

        fn wait_for_room(&self, _timeout_us: u64) -> bool {
            self.0.borrow_mut().socket_waits += 1;
            true
        }

        fn recv_with(&mut self, _f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
            false
        }
    }

    /// The host the driver waits with: its passes and waits counted on the wire.
    struct Host(Rc<RefCell<Wire>>);

    impl GroupTxPace for Host {
        fn pass(&self) {
            self.0.borrow_mut().passes += 1;
        }

        fn now_us(&self) -> u64 {
            0
        }

        fn wait_writable(&self, _wait_us: u64) -> bool {
            let mut wire = self.0.borrow_mut();
            wire.waits += 1;
            if wire.fills > 0 {
                wire.fills -= 1;
                return false;
            }
            wire.room += 1;
            true
        }

        fn ended(&self) -> bool {
            self.0.borrow().ended
        }
    }

    /// A driver over a socket with `room` datagrams of room, its link opened by the session when
    /// `open`, and the socket's record.
    fn driver(room: usize, open: bool) -> (GroupDriver<Socket, Host>, Rc<RefCell<Wire>>) {
        let wire = Rc::new(RefCell::new(Wire {
            room,
            ..Wire::default()
        }));
        let mut link = GroupLink::new(Socket(Rc::clone(&wire)));
        if open {
            assert!(link.open());
        }
        (GroupDriver::new(link, Host(Rc::clone(&wire)), 64), wire)
    }

    /// A frame handed over leaves on the socket as it was written, from the slot it was copied
    /// into. Turned red by a send that offers the socket other bytes, or none.
    #[test]
    fn a_frame_leaves_on_the_socket_as_it_was_written() {
        let (driver, wire) = driver(1, true);
        assert_eq!(
            driver.send_blocking(&[1, 2, 3], Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        assert_eq!(wire.borrow().seen, [vec![1, 2, 3]]);
        assert_eq!(
            wire.borrow().waits,
            0,
            "a socket with room is not waited on"
        );
    }

    /// A link the session does not hold open sends nothing, and the frame is a drop that leaves
    /// the link open. Turned red by a send on a link not opened, or one answered as a writer
    /// that is gone, which would close the group's gate for good.
    #[test]
    fn a_frame_on_a_link_not_open_is_a_drop() {
        let (driver, wire) = driver(1, false);
        assert_eq!(
            driver.send_blocking(&[1], Reliability::Reliable),
            LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot)
        );
        assert!(wire.borrow().seen.is_empty());
    }

    /// A send the stack fails loses its frame, counted, holds nothing, and leaves the link open for
    /// the next frame. Turned red by a failure not counted, one counted twice, or one that closes
    /// the link or is held as a full socket's refusal is.
    #[test]
    fn a_frame_a_send_failed_is_lost_and_counted() {
        let (driver, wire) = driver(1, true);
        wire.borrow_mut().fail = true;
        assert_eq!(
            driver.send_blocking(&[1], Reliability::Reliable),
            LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot)
        );
        assert_eq!(driver.lost(), 1);
        assert!(!driver.holds(), "a lost frame is not held");
        wire.borrow_mut().fail = false;
        assert_eq!(
            driver.send_blocking(&[2], Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        assert_eq!(wire.borrow().seen, [vec![2]]);
        assert_eq!(driver.lost(), 1);
    }

    /// Without the hold a full socket is waited on inside the send until it takes the frame, and
    /// nothing is held: each refusal is followed by one pass of the host and one wait on the
    /// socket's writability before the frame is offered again, and the transport's own wait,
    /// which answers at once here, is never what the send waits on. Turned red by a send that
    /// returns on a full socket, offers the frame twice with no wait between (a spin), or waits on
    /// the transport's wait instead of the host's (which here never frees room, so the send would
    /// not end).
    #[cfg(not(feature = "multicast-send-hold"))]
    #[test]
    fn a_full_socket_is_waited_on_before_each_offer_inside_the_send() {
        let (driver, wire) = driver(0, true);
        wire.borrow_mut().fills = 2;
        assert_eq!(
            driver.send_blocking(&[7], Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        let wire = wire.borrow();
        assert_eq!(wire.seen, [vec![7]]);
        assert_eq!(wire.offers, 4, "three refusals and the offer taken");
        assert_eq!(wire.waits, 3, "one wait after each refusal");
        assert_eq!(wire.passes, 3, "one pass of the host before each wait");
        assert_eq!(
            wire.socket_waits, 0,
            "the transport's own wait is not asked"
        );
    }

    /// Without the hold a frame whose ask for room allowed no wait is not waited for: a full socket
    /// refusing it is a counted congestion drop, with no pass of the host and no wait on the
    /// socket, and the next frame, handed over with no ask, waits as before. The CONTROL is a frame
    /// whose ask allowed a wait, which waits once and leaves. Turned red by an at-once frame that
    /// passes or waits, one not counted, or an ask whose zero wait outlives its frame.
    #[cfg(not(feature = "multicast-send-hold"))]
    #[test]
    fn a_frame_asked_at_once_is_not_waited_for_on_a_full_socket() {
        use wz_session_core::link::{LinkRoom, RoomWait};
        use wz_session_core::qos::Priority;

        let (driver, wire) = driver(0, true);
        let answer = driver.wait_for_room(Priority::DEFAULT, RoomWait::Drop { wait_us: 0 });
        assert_eq!(answer.room, LinkRoom::Free, "nothing is held to refuse it");
        assert_eq!(
            driver.send_blocking(&[7], Reliability::Reliable),
            LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot)
        );
        assert_eq!(
            (
                wire.borrow().offers,
                wire.borrow().waits,
                wire.borrow().passes
            ),
            (1, 0, 0),
            "offered once, with no wait and no pass"
        );
        assert_eq!((driver.congested(), driver.lost()), (1, 0));

        let _ = driver.wait_for_room(Priority::DEFAULT, RoomWait::Block { wait_us: 1_000 });
        assert_eq!(
            driver.send_blocking(&[8], Reliability::Reliable),
            LinkSendOutcome::Sent,
            "CONTROL: a frame that may wait waits and leaves"
        );
        assert_eq!((wire.borrow().waits, wire.borrow().passes), (1, 1));

        let _ = driver.wait_for_room(Priority::DEFAULT, RoomWait::Block { wait_us: 0 });
        assert_eq!(
            driver.send_blocking(&[9], Reliability::Reliable),
            LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot),
            "a blocking message asked at once is not waited for either"
        );
        assert_eq!(
            driver.send_blocking(&[10], Reliability::Reliable),
            LinkSendOutcome::Sent,
            "a frame with no ask of its own waits"
        );
        let wire = wire.borrow();
        assert_eq!(wire.seen, [vec![8], vec![10]]);
        assert_eq!((wire.waits, wire.passes), (2, 2));
        assert_eq!(driver.congested(), 2);
    }

    /// Without the hold a frame a full socket refuses after the group's session ended is a drop,
    /// and nothing waits for a socket nothing will drain. Turned red by a send that waits on an
    /// ended group.
    #[cfg(not(feature = "multicast-send-hold"))]
    #[test]
    fn a_full_socket_of_an_ended_group_is_a_drop() {
        let (driver, wire) = driver(0, true);
        wire.borrow_mut().ended = true;
        assert_eq!(
            driver.send_blocking(&[7], Reliability::Reliable),
            LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot)
        );
        let wire = wire.borrow();
        assert!(wire.seen.is_empty());
        assert_eq!((wire.offers, wire.waits, wire.passes), (1, 0, 0));
    }

    /// With the hold a frame a full socket refuses is kept and the send returns; the next ask
    /// for room offers it first, waits on the host once, and is answered once the socket took it,
    /// which the frames after it then follow. Turned red by a held frame lost, sent twice, or
    /// overtaken, or by an ask that waits on the transport's own wait.
    #[cfg(feature = "multicast-send-hold")]
    #[test]
    fn a_frame_a_full_socket_refused_is_held_and_offered_first() {
        use wz_session_core::link::{LinkRoom, RoomWait};
        use wz_session_core::qos::Priority;

        let (driver, wire) = driver(0, true);
        assert_eq!(
            driver.send_blocking(&[7], Reliability::Reliable),
            LinkSendOutcome::Sent,
            "the frame is the link's"
        );
        assert!(wire.borrow().seen.is_empty(), "the socket took nothing");
        let answer = driver.wait_for_room(Priority::DEFAULT, RoomWait::Block { wait_us: 1_000 });
        assert_eq!(answer.room, LinkRoom::Free, "the wait freed the room");
        assert_eq!((wire.borrow().waits, wire.borrow().passes), (1, 1));
        assert_eq!(wire.borrow().socket_waits, 0);
        wire.borrow_mut().room = 1;
        assert_eq!(
            driver.send_blocking(&[8], Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        assert_eq!(wire.borrow().seen, [vec![7], vec![8]]);
        assert_eq!(wire.borrow().offers, 4, "each frame offered once a wait");
    }

    /// With the hold the frame a full socket refused answers its lane off its head while it is
    /// held, and none once it left. Turned red by a lane read off another slot's bytes, or one
    /// still answered after the socket took the frame.
    #[cfg(feature = "multicast-send-hold")]
    #[test]
    fn a_held_frame_answers_its_lane_until_it_leaves() {
        use wz_session_core::inbound::FrameLane;
        use wz_session_core::link::RoomWait;
        use wz_session_core::qos::Priority;

        let (driver, wire) = driver(0, true);
        assert_eq!(driver.held_lane(), None, "nothing held");
        assert_eq!(
            driver.send_blocking(&[0x25, 0x07, 0xAA], Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        assert_eq!(
            driver.held_lane(),
            Some(FrameLane {
                priority: Priority::DEFAULT,
                reliable: true,
                sn: 7,
            })
        );
        let _ = driver.wait_for_room(Priority::DEFAULT, RoomWait::Block { wait_us: 1_000 });
        assert_eq!(wire.borrow().seen, [vec![0x25, 0x07, 0xAA]]);
        assert_eq!(driver.held_lane(), None, "the frame left");
    }

    /// With the hold a group's step offers the held frame again without waiting, through the
    /// counted handle the engine keeps beside the erased one: refused, it stays held; taken, it is
    /// let go. Turned red by an offer that waits, a frame let go while refused, or a handle that
    /// answers another driver's state.
    #[cfg(feature = "multicast-send-hold")]
    #[test]
    fn a_held_frame_is_offered_again_by_the_step_without_a_wait() {
        use wz_runtime_coop::link_cells::{CellRc, OneTask};

        let (driver, wire) = driver(0, true);
        let handle = CellRc::<_, OneTask>::try_on_heap(driver).expect("the heap takes the driver");
        assert_eq!(
            handle.send_blocking(&[7], Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        assert!(HeldFrame::holds(&handle));
        assert!(HeldFrame::offer_held(&handle), "still refused");
        assert!(HeldFrame::holds(&handle));
        wire.borrow_mut().room = 1;
        assert!(!HeldFrame::offer_held(&handle), "taken");
        assert!(!HeldFrame::holds(&handle));
        let wire = wire.borrow();
        assert_eq!(wire.seen, [vec![7]]);
        assert_eq!(
            (wire.waits, wire.passes),
            (0, 0),
            "the step waits on nothing"
        );
    }

    /// With the hold a frame handed over with no ask while another is held (a window's flush) is a
    /// counted congestion drop, and the held frame stays first. Turned red by a drop not counted,
    /// or one that lets the held frame go or overtakes it.
    #[cfg(feature = "multicast-send-hold")]
    #[test]
    fn a_frame_handed_over_while_one_is_held_is_a_counted_drop() {
        let (driver, wire) = driver(0, true);
        assert_eq!(
            driver.send_blocking(&[7], Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        assert_eq!(
            driver.send_blocking(&[8], Reliability::Reliable),
            LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot)
        );
        assert_eq!((driver.congested(), driver.lost()), (1, 0));
        assert!(driver.holds(), "the first frame is still held");
        wire.borrow_mut().room = 1;
        assert!(!driver.offer_held(), "taken");
        assert_eq!(wire.borrow().seen, [vec![7]]);
    }

    /// With the hold an ask for room whose wait finds the socket still full is congested, and
    /// the held frame stays first. Turned red by an ask answered free while the frame is held.
    #[cfg(feature = "multicast-send-hold")]
    #[test]
    fn a_held_frame_a_wait_did_not_free_leaves_the_link_congested() {
        use wz_session_core::link::{LinkRoom, RoomWait};
        use wz_session_core::qos::Priority;

        let (driver, wire) = driver(0, true);
        wire.borrow_mut().fills = 1;
        assert_eq!(
            driver.send_blocking(&[7], Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        let answer = driver.wait_for_room(Priority::DEFAULT, RoomWait::Block { wait_us: 1_000 });
        assert_eq!(answer.room, LinkRoom::Congested);
        assert_eq!(answer.waited_us, 1_000, "the whole wait was spent");
        wire.borrow_mut().room = 1;
        let answer = driver.wait_for_room(Priority::DEFAULT, RoomWait::Block { wait_us: 1_000 });
        assert_eq!(answer.room, LinkRoom::Free, "the held frame left first");
        assert_eq!(wire.borrow().seen, [vec![7]]);
    }
}
