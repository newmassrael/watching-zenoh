// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A slot a link lent for one outbound frame, as a [`TxBuf`].
//!
//! ARCHITECTURE section 9.1: the codec writes directly into a pool slot and the
//! link sends that slot. [`BoxedLinkDriver::tx_slot_acquire`] is the link
//! lending the slot; [`TxLease`] is the session holding it. The lease is a
//! [`TxBuf`] over the slot's memory after the headroom the link reserved, so
//! every outbound encoder that writes to a `TxBuf` writes into the link's own
//! slot with no change, and [`TxLease::send`] gives the slot back to the link
//! by ownership. A lease that is dropped unsent returns the slot through
//! [`BoxedLinkDriver::tx_slot_abort`], so no path out of the encoder leaks one.
//!
//! The lease holds a raw pointer, which makes it neither `Send` nor `Sync`:
//! it lives for one synchronous encode-and-send under the conduit's lock and
//! is never stored. A frame that stays open across calls (a batch, which the
//! session fills one message per call) is put down as a [`HeldSlot`], which is
//! the slot's name and lengths without the pointer or the borrow, and picked up
//! again with [`TxLease::resume`] on the driver that lent it.
//!
//! The targets are spelled out in full: this page's text is merged with the
//! outer doc on `pub mod tx_lease;` and the merged text resolves its relative
//! links from the crate root, so a bare name would not be found.
//!
//! [`TxBuf`]: crate::tx_buf::TxBuf
//! [`TxLease`]: crate::tx_lease::TxLease
//! [`TxLease::send`]: crate::tx_lease::TxLease::send
//! [`TxLease::resume`]: crate::tx_lease::TxLease::resume
//! [`HeldSlot`]: crate::tx_lease::HeldSlot
//! [`BoxedLinkDriver::tx_slot_acquire`]: crate::link::BoxedLinkDriver::tx_slot_acquire
//! [`BoxedLinkDriver::tx_slot_abort`]: crate::link::BoxedLinkDriver::tx_slot_abort

use core::ptr;
use core::slice;

use sce_forge_runtime::codec::CodecError;

use crate::link::{BoxedLinkDriver, LinkSendOutcome, TxSlot};
use crate::qos::Priority;
use crate::reliability::Reliability;
use crate::tx_buf::TxBuf;

/// A lent outbound slot being filled.
pub struct TxLease<'a> {
    driver: &'a dyn BoxedLinkDriver,
    slot: TxSlot,
    /// First byte of the slot (the headroom's first byte).
    base: *mut u8,
    /// The slot's whole length, headroom included.
    total: usize,
    /// Bytes at the front that belong to the link's framing.
    headroom: usize,
    /// Frame bytes written after the headroom.
    len: usize,
    /// The slot has been handed to the link, or put down as a [`HeldSlot`];
    /// either way dropping the lease must not abort it.
    sent: bool,
}

/// A lent slot with a frame still open in it, put down between two calls.
///
/// It is a [`TxLease`] without the borrow of its driver and without the pointer
/// into the slot: the slot's name, the headroom the link asked for and the frame
/// bytes written so far. That is what lets it be kept where a lease cannot be,
/// in state the session reaches again on a later call (the batching window keeps
/// one per open frame), and what makes it `Send`, which a raw pointer is not.
///
/// The slot is still LENT while this value exists, so it must end in exactly one
/// of [`TxLease::resume`] on the driver that lent it, or [`Self::abort`] on that
/// driver. It has no driver to give the slot back to on its own, so dropping it
/// would keep the slot out of the link's pool for good; the type is `#[must_use]`
/// for that reason, and the session's holder aborts what it still keeps when it
/// is dropped itself.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a held slot is still lent: resume it or abort it on the driver that lent it"]
pub struct HeldSlot {
    slot: TxSlot,
    headroom: usize,
    len: usize,
}

impl HeldSlot {
    /// Frame bytes the slot holds after its headroom.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Nothing written: no frame is open in the slot.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Give the slot back unsent, on `driver`, which must be the driver that
    /// lent it.
    pub fn abort(self, driver: &dyn BoxedLinkDriver) {
        driver.tx_slot_abort(self.slot);
    }
}

impl<'a> TxLease<'a> {
    /// Ask `driver` to lend a slot for a frame of up to `want` bytes.
    ///
    /// `None` means encode on the heap: the link lends nothing (the default),
    /// every slot is in flight, or the grant did not describe usable memory. A
    /// grant that does not (a null pointer, or headroom past the slot) is handed
    /// straight back, so a misbehaving driver costs a heap frame and not a slot.
    pub fn acquire(
        driver: &'a dyn BoxedLinkDriver,
        want: usize,
        priority: Priority,
    ) -> Option<Self> {
        let grant = driver.tx_slot_acquire(want, priority)?;
        let (base, total) = driver.tx_slot_storage(grant.slot);
        if base.is_null() || grant.headroom > total {
            driver.tx_slot_abort(grant.slot);
            return None;
        }
        Some(Self {
            driver,
            slot: grant.slot,
            base,
            total,
            headroom: grant.headroom,
            len: 0,
            sent: false,
        })
    }

    /// Pick a [`HeldSlot`] up again on `driver`, the driver that lent it, with
    /// its frame as it was put down. The slot's memory is asked of the driver
    /// again rather than remembered, because a pointer kept across calls is
    /// exactly what a held slot does not carry.
    ///
    /// `None` when the driver no longer describes the slot as memory that holds
    /// the frame (a null pointer, or a slot shorter than the headroom and the
    /// bytes already written), which only a driver breaking the
    /// [`BoxedLinkDriver::tx_slot_storage`] contract answers. The slot is then
    /// given back, so even that costs the open frame and not the slot.
    pub fn resume(driver: &'a dyn BoxedLinkDriver, held: HeldSlot) -> Option<Self> {
        let (base, total) = driver.tx_slot_storage(held.slot);
        if base.is_null() || held.headroom + held.len > total {
            held.abort(driver);
            return None;
        }
        Some(Self {
            driver,
            slot: held.slot,
            base,
            total,
            headroom: held.headroom,
            len: held.len,
            sent: false,
        })
    }

    /// Put the lease down without settling it: the slot stays lent and keeps
    /// its frame, and the returned [`HeldSlot`] is how a later call finds it.
    pub fn hold(mut self) -> HeldSlot {
        self.sent = true;
        HeldSlot {
            slot: self.slot,
            headroom: self.headroom,
            len: self.len,
        }
    }

    /// How many frame bytes the slot can hold after its headroom.
    pub fn capacity(&self) -> usize {
        self.total - self.headroom
    }

    /// Hand the written frame to the link and give it the slot. From here the
    /// slot is the link's; it returns to the pool when the bytes are written.
    pub fn send(mut self, reliability: Reliability, priority: Priority) -> LinkSendOutcome {
        self.hand_over(reliability, priority)
    }

    /// [`Self::send`] for a caller that holds the lease by reference (the
    /// session's single emit seam takes `Option<&mut TxLease>` so that the
    /// bytes it needs for compression and the slot it sends are one object).
    /// After this call the slot is the link's: the lease is spent, dropping it
    /// aborts nothing, and writing to it again is a contract violation the
    /// caller has no reason to commit.
    pub(crate) fn hand_over(
        &mut self,
        reliability: Reliability,
        priority: Priority,
    ) -> LinkSendOutcome {
        self.sent = true;
        self.driver
            .tx_slot_send(self.slot, self.headroom, self.len, reliability, priority)
    }
}

impl TxBuf for TxLease<'_> {
    fn len(&self) -> usize {
        self.len
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: `base` points at a slot of `total` bytes the driver granted to
        // this lease alone (`BoxedLinkDriver::tx_slot_acquire`'s contract: the
        // slot is the session's until it is sent or aborted, and neither has
        // happened while the lease is alive). `headroom + len <= total` holds by
        // construction: `acquire` refuses `headroom > total` and `append` never
        // writes past `total`.
        unsafe { slice::from_raw_parts(self.base.add(self.headroom), self.len) }
    }

    fn truncate(&mut self, len: usize) {
        if len < self.len {
            self.len = len;
        }
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        if self.capacity() - self.len < bytes.len() {
            return Err(CodecError::BufferOverflow);
        }
        // SAFETY: the destination `[headroom + len, headroom + len + n)` lies in
        // the slot (checked above), the slot is this lease's alone (see
        // `as_slice`), and `bytes` is a borrowed slice of the caller's, which
        // cannot overlap a slot the link granted exclusively.
        unsafe {
            ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.base.add(self.headroom + self.len),
                bytes.len(),
            );
        }
        self.len += bytes.len();
        Ok(())
    }
}

impl Drop for TxLease<'_> {
    fn drop(&mut self) {
        if !self.sent {
            self.driver.tx_slot_abort(self.slot);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::TxSlotGrant;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use core::sync::atomic::{AtomicUsize, Ordering};

    const SLOTS: usize = 2;
    const SLOT_LEN: usize = 16;
    const HEADROOM: usize = 4;

    /// A link that lends from a small fixed pool and records what it was given.
    struct LendingLink {
        storage: RefCell<[[u8; SLOT_LEN]; SLOTS]>,
        granted: RefCell<[bool; SLOTS]>,
        sent: RefCell<Vec<(usize, Vec<u8>)>>,
        aborts: RefCell<usize>,
        // How many times the lease asked where a slot's memory is: the record
        // that says the `null_storage` answer below was actually given.
        storage_queries: AtomicUsize,
        // Misbehaviour switches for the grant the lease must refuse.
        null_storage: bool,
        headroom: usize,
    }

    impl LendingLink {
        fn new() -> Self {
            Self {
                storage: RefCell::new([[0u8; SLOT_LEN]; SLOTS]),
                granted: RefCell::new([false; SLOTS]),
                sent: RefCell::new(Vec::new()),
                aborts: RefCell::new(0),
                storage_queries: AtomicUsize::new(0),
                null_storage: false,
                headroom: HEADROOM,
            }
        }

        fn free(&self) -> usize {
            self.granted.borrow().iter().filter(|g| !**g).count()
        }
    }

    impl BoxedLinkDriver for LendingLink {
        fn send_blocking(&self, _bytes: &[u8], _reliability: Reliability) -> LinkSendOutcome {
            LinkSendOutcome::Sent
        }
        fn open_blocking(&self) {}
        fn close_blocking(&self) {}

        fn tx_slot_acquire(&self, want: usize, _priority: Priority) -> Option<TxSlotGrant> {
            // The most a slot can take after the headroom this link names. A
            // headroom past the slot leaves nothing to lend against, but the
            // grant is still made so the lease's own check is what refuses it.
            if want > SLOT_LEN.saturating_sub(self.headroom) {
                return None;
            }
            let mut granted = self.granted.borrow_mut();
            let idx = granted.iter().position(|g| !*g)?;
            granted[idx] = true;
            Some(TxSlotGrant {
                slot: TxSlot(idx as u32),
                headroom: self.headroom,
            })
        }

        fn tx_slot_storage(&self, slot: TxSlot) -> (*mut u8, usize) {
            self.storage_queries.fetch_add(1, Ordering::Relaxed);
            if self.null_storage {
                return (ptr::null_mut(), 0);
            }
            let mut storage = self.storage.borrow_mut();
            (storage[slot.0 as usize].as_mut_ptr(), SLOT_LEN)
        }

        fn tx_slot_send(
            &self,
            slot: TxSlot,
            start: usize,
            len: usize,
            _reliability: Reliability,
            _priority: Priority,
        ) -> LinkSendOutcome {
            let bytes = self.storage.borrow()[slot.0 as usize][start..start + len].to_vec();
            self.sent.borrow_mut().push((start, bytes));
            // The link owns the slot now and, having "written" it, returns it.
            self.granted.borrow_mut()[slot.0 as usize] = false;
            LinkSendOutcome::Sent
        }

        fn tx_slot_abort(&self, slot: TxSlot) {
            *self.aborts.borrow_mut() += 1;
            self.granted.borrow_mut()[slot.0 as usize] = false;
        }
    }

    #[test]
    fn a_frame_written_into_a_lease_is_what_the_link_is_handed() {
        let link = LendingLink::new();
        let mut lease = TxLease::acquire(&link, 8, Priority::DEFAULT).expect("a slot is free");
        lease.append(&[1, 2, 3]).unwrap();
        lease.append_byte(4).unwrap();
        assert_eq!(lease.as_slice(), &[1, 2, 3, 4]);
        assert_eq!(
            lease.send(Reliability::Reliable, Priority::DEFAULT),
            LinkSendOutcome::Sent
        );
        // The frame begins after the headroom, and the link was told where.
        assert_eq!(
            *link.sent.borrow(),
            alloc::vec![(HEADROOM, alloc::vec![1, 2, 3, 4])]
        );
        assert_eq!(link.free(), SLOTS, "the sent slot is back in the pool");
        assert_eq!(*link.aborts.borrow(), 0, "a sent slot is never aborted too");
    }

    #[test]
    fn the_links_headroom_is_never_written_by_the_frame() {
        let link = LendingLink::new();
        let mut lease = TxLease::acquire(&link, 8, Priority::DEFAULT).unwrap();
        lease.append(&[0xEE; 8]).unwrap();
        let slot = lease.slot;
        drop(lease);
        // The first HEADROOM bytes are the link's to write when it takes the
        // slot; encoding must not have touched them.
        assert_eq!(
            &link.storage.borrow()[slot.0 as usize][..HEADROOM],
            &[0u8; HEADROOM]
        );
    }

    #[test]
    fn a_lease_dropped_unsent_gives_the_slot_back_exactly_once() {
        let link = LendingLink::new();
        {
            let mut lease = TxLease::acquire(&link, 8, Priority::DEFAULT).unwrap();
            lease.append(&[9]).unwrap();
            assert_eq!(link.free(), SLOTS - 1);
        }
        assert_eq!(link.free(), SLOTS, "the dropped lease returned its slot");
        assert_eq!(*link.aborts.borrow(), 1);
        assert!(link.sent.borrow().is_empty(), "nothing reached the link");
    }

    #[test]
    fn an_exhausted_pool_lends_nothing_and_a_freed_slot_is_lent_again() {
        let link = LendingLink::new();
        let a = TxLease::acquire(&link, 8, Priority::DEFAULT).unwrap();
        let b = TxLease::acquire(&link, 8, Priority::DEFAULT).unwrap();
        assert!(
            TxLease::acquire(&link, 8, Priority::DEFAULT).is_none(),
            "every slot is in flight: the heap path, not an error"
        );
        drop(a);
        assert!(TxLease::acquire(&link, 8, Priority::DEFAULT).is_some());
        drop(b);
    }

    #[test]
    fn a_frame_past_the_slot_is_refused_and_the_lease_stays_usable() {
        let link = LendingLink::new();
        let mut lease = TxLease::acquire(&link, 8, Priority::DEFAULT).unwrap();
        assert_eq!(lease.capacity(), SLOT_LEN - HEADROOM);
        lease.append(&[1; SLOT_LEN - HEADROOM - 1]).unwrap();
        assert_eq!(lease.append(&[2, 2]), Err(CodecError::BufferOverflow));
        // The refusal wrote nothing, so a byte that does fit still lands.
        lease.append_byte(3).unwrap();
        assert_eq!(lease.len(), SLOT_LEN - HEADROOM);
        assert_eq!(*lease.as_slice().last().unwrap(), 3);
    }

    #[test]
    fn a_request_larger_than_the_slot_is_not_lent() {
        let link = LendingLink::new();
        assert!(TxLease::acquire(&link, SLOT_LEN, Priority::DEFAULT).is_none());
        assert_eq!(link.free(), SLOTS, "a refusal takes no slot");
    }

    #[test]
    fn a_grant_that_describes_no_memory_is_handed_back_and_costs_a_heap_frame() {
        let mut link = LendingLink::new();
        link.null_storage = true;
        assert!(TxLease::acquire(&link, 8, Priority::DEFAULT).is_none());
        assert_eq!(link.free(), SLOTS, "the bad grant was returned, not leaked");
        assert_eq!(*link.aborts.borrow(), 1);

        let mut link = LendingLink::new();
        link.headroom = SLOT_LEN + 1;
        assert!(TxLease::acquire(&link, 0, Priority::DEFAULT).is_none());
        assert_eq!(
            link.free(),
            SLOTS,
            "headroom past the slot was returned too"
        );
        assert_eq!(*link.aborts.borrow(), 1);
    }

    /// A frame put down between two calls and picked up again keeps its bytes,
    /// grows after them, and settles the slot once: no abort while it is held.
    #[test]
    fn a_held_frame_resumes_where_it_was_put_down_and_is_sent_once() {
        let link = LendingLink::new();
        let mut lease = TxLease::acquire(&link, 8, Priority::DEFAULT).unwrap();
        lease.append(&[1, 2]).unwrap();
        let held = lease.hold();
        assert_eq!(held.len(), 2);
        assert_eq!(*link.aborts.borrow(), 0, "a held slot is not given back");
        assert_eq!(link.free(), SLOTS - 1, "and stays lent");
        let mut lease = TxLease::resume(&link, held).expect("the slot is still described");
        assert_eq!(lease.as_slice(), &[1, 2]);
        lease.append(&[3]).unwrap();
        assert_eq!(
            lease.send(Reliability::Reliable, Priority::DEFAULT),
            LinkSendOutcome::Sent
        );
        assert_eq!(
            *link.sent.borrow(),
            alloc::vec![(HEADROOM, alloc::vec![1, 2, 3])]
        );
        assert_eq!((link.free(), *link.aborts.borrow()), (SLOTS, 0));
    }

    /// A held slot given up is aborted on its driver exactly once.
    #[test]
    fn a_held_slot_aborted_returns_to_the_pool() {
        let link = LendingLink::new();
        let held = TxLease::acquire(&link, 8, Priority::DEFAULT)
            .unwrap()
            .hold();
        held.abort(&link);
        assert_eq!((link.free(), *link.aborts.borrow()), (SLOTS, 1));
        assert!(link.sent.borrow().is_empty());
    }

    /// A driver that no longer describes a held slot costs the open frame and
    /// not the slot.
    ///
    /// The double is switched to answer "no memory" only AFTER the lease was
    /// granted and held, so the one place that answer can be given is the
    /// question `resume` asks. The test reads that it was asked (one query at
    /// the grant, one more at the resume) and that the slot came back only
    /// then: nothing was given back while the slot was held, so the abort is
    /// the resume's refusal and not an earlier one of the fixture's.
    #[test]
    fn a_held_slot_the_driver_no_longer_describes_is_given_back() {
        let mut link = LendingLink::new();
        let mut lease = TxLease::acquire(&link, 8, Priority::DEFAULT).unwrap();
        lease.append(&[7]).unwrap();
        let held = lease.hold();
        assert_eq!(
            (
                link.storage_queries.load(Ordering::Relaxed),
                *link.aborts.borrow()
            ),
            (1, 0),
            "the grant asked for the slot's memory once and holding gave nothing back"
        );
        assert_eq!(link.free(), SLOTS - 1, "the held slot is still lent");
        link.null_storage = true;
        assert!(TxLease::resume(&link, held).is_none());
        assert_eq!(
            link.storage_queries.load(Ordering::Relaxed),
            2,
            "resume asked the driver for the slot's memory again"
        );
        assert_eq!(
            (link.free(), *link.aborts.borrow()),
            (SLOTS, 1),
            "the slot the driver no longer describes was given back, once"
        );
        assert!(link.sent.borrow().is_empty(), "the open frame was not sent");
    }

    /// A driver that does not override the slot methods lends nothing, which is
    /// the guarantee that adding them changed no existing link.
    #[test]
    fn a_link_that_overrides_nothing_lends_nothing() {
        struct Plain;
        impl BoxedLinkDriver for Plain {
            fn send_blocking(&self, _b: &[u8], _r: Reliability) -> LinkSendOutcome {
                LinkSendOutcome::Sent
            }
            fn open_blocking(&self) {}
            fn close_blocking(&self) {}
        }
        assert!(TxLease::acquire(&Plain, 8, Priority::DEFAULT).is_none());
    }
}
