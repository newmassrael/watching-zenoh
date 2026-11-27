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

use wz_runtime_coop::group_transport::{GroupSend, GroupTransport};
use wz_runtime_coop::link_storage::{copied_send, HeapTx, TxLender};
use wz_session_core::link::{
    BoxedLinkDriver, LinkDropCause, LinkSendOutcome, TxSlot, TxSlotGrant, SESSION_TX_SLOTS,
};
#[cfg(feature = "multicast-send-hold")]
use wz_session_core::link::{LinkRoom, RoomAnswer, RoomWait};
use wz_session_core::qos::Priority;
use wz_session_core::reliability::Reliability;

use super::GroupLink;

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

/// A group's socket as a link driver: the transport it shares with the group's session task, and
/// the slots its frames are encoded into, each a batch of the group.
pub struct GroupDriver<T> {
    link: GroupLink<T>,
    tx: TxLender<HeapTx>,
    #[cfg(feature = "multicast-send-hold")]
    held: core::cell::Cell<Option<Held>>,
}

impl<T: GroupTransport> GroupDriver<T> {
    /// The driver of `link`, whose frames are at most `batch` bytes.
    pub fn new(link: GroupLink<T>, batch: usize) -> Self {
        Self {
            link,
            tx: TxLender::new(HeapTx::new(SLOTS, batch)),
            #[cfg(feature = "multicast-send-hold")]
            held: core::cell::Cell::new(None),
        }
    }

    /// Offer `frame` to the socket: whether it is done with, taken or lost, or the socket had no
    /// room. `None` where nothing may be written now: the session does not hold the link open,
    /// or its task has the transport in hand.
    fn offer(&self, frame: &[u8]) -> Option<GroupSend> {
        self.link.send_now(frame)
    }

    /// The outcome the session counts of a frame the socket was offered. A failed send loses the
    /// frame and nothing else: a group's next datagram may well leave, so the link stays open
    /// and the loss is a drop.
    fn outcome(sent: Option<GroupSend>) -> LinkSendOutcome {
        match sent {
            Some(GroupSend::Sent) => LinkSendOutcome::Sent,
            Some(GroupSend::Full | GroupSend::Failed) | None => {
                LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot)
            }
        }
    }

    /// Offer the held frame again: whether the socket still refuses it. A frame the socket took,
    /// or lost, gives its slot back.
    #[cfg(feature = "multicast-send-hold")]
    fn offer_held(&self) -> bool {
        let Some(held) = self.held.get() else {
            return false;
        };
        let (base, _) = self.tx.storage(held.slot);
        // SAFETY: the held slot was handed over by the session and is the driver's until it is
        // released below; `start .. start + len` was found inside it when it was held.
        let frame = unsafe { core::slice::from_raw_parts(base.wrapping_add(held.start), held.len) };
        if self.offer(frame) == Some(GroupSend::Full) {
            return true;
        }
        self.held.set(None);
        self.tx.release(held.slot);
        false
    }
}

impl<T: GroupTransport> BoxedLinkDriver for GroupDriver<T> {
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
        let Some(frame) = self.tx.take(slot, start, len) else {
            return LinkSendOutcome::Dropped(LinkDropCause::Oversize);
        };
        loop {
            match self.offer(frame) {
                // The socket's own wait; one that cannot tell answers at once and is offered the
                // frame again.
                Some(GroupSend::Full) => {
                    let _ = self.link.wait_room(u64::MAX);
                }
                sent => return Self::outcome(sent),
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
        if self.offer_held() {
            self.tx.release(slot);
            return LinkSendOutcome::Dropped(LinkDropCause::NoTxSlot);
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
                Self::outcome(sent)
            }
        }
    }

    fn tx_slot_abort(&self, slot: TxSlot) {
        self.tx.release(slot);
    }

    // A link whose queue is full: the held frame is offered first, and while the socket refuses
    // it the ask waits on the socket, once, for as long as it may.
    #[cfg(feature = "multicast-send-hold")]
    fn wait_for_room(&self, _priority: Priority, wait: RoomWait) -> RoomAnswer {
        if !self.offer_held() {
            return RoomAnswer::at_once(LinkRoom::Free);
        }
        let wait_us = wait.wait_us();
        if wait_us > 0 && self.link.wait_room(wait_us) && !self.offer_held() {
            return RoomAnswer {
                room: LinkRoom::Free,
                waited_us: 0,
            };
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

    use super::super::GroupLink;
    use super::GroupDriver;

    /// What the socket took, and how many more it takes before it is full. A wait on it frees
    /// one datagram's room, as a socket that drains does.
    #[derive(Default)]
    struct Wire {
        seen: Vec<Vec<u8>>,
        room: usize,
        waits: usize,
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
            if wire.room == 0 {
                return GroupSend::Full;
            }
            wire.room -= 1;
            wire.seen.push(datagram.to_vec());
            GroupSend::Sent
        }

        fn wait_for_room(&self, _timeout_us: u64) -> bool {
            let mut wire = self.0.borrow_mut();
            wire.waits += 1;
            wire.room += 1;
            true
        }

        fn recv_with(&mut self, _f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
            false
        }
    }

    /// A driver over a socket with `room` datagrams of room, its link opened by the session when
    /// `open`, and the socket's record.
    fn driver(room: usize, open: bool) -> (GroupDriver<Socket>, Rc<RefCell<Wire>>) {
        let wire = Rc::new(RefCell::new(Wire {
            room,
            ..Wire::default()
        }));
        let mut link = GroupLink::new(Socket(Rc::clone(&wire)));
        if open {
            assert!(link.open());
        }
        (GroupDriver::new(link, 64), wire)
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

    /// Without the hold a full socket is waited on inside the send until it takes the frame, and
    /// nothing is held. Turned red by a send that returns on a full socket.
    #[cfg(not(feature = "multicast-send-hold"))]
    #[test]
    fn a_full_socket_is_waited_on_inside_the_send() {
        let (driver, wire) = driver(0, true);
        assert_eq!(
            driver.send_blocking(&[7], Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        assert_eq!(wire.borrow().seen, [vec![7]]);
        assert_eq!(wire.borrow().waits, 1, "one wait freed the room");
    }

    /// With the hold a frame a full socket refuses is kept and the send returns; the next ask
    /// for room offers it first and is answered once the socket took it, which the frames after
    /// it then follow. Turned red by a held frame lost, sent twice, or overtaken.
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
        wire.borrow_mut().room = 1;
        assert_eq!(
            driver.send_blocking(&[8], Reliability::Reliable),
            LinkSendOutcome::Sent
        );
        assert_eq!(wire.borrow().seen, [vec![7], vec![8]]);
    }
}
