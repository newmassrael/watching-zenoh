// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The memory a link lends its session to encode outbound frames into, and the book of which
//! slots of it are out: written once for every link of this crate, the datagram link
//! (`udp_link`) and the stream link (`stream_link`), because which slot may be lent and when it
//! comes back is the same decision whatever carries the frame. A link differs only in the bytes it
//! asks to have left free in front of a frame
//! ([`TxSlotGrant::headroom`](wz_session_core::link::TxSlotGrant::headroom)): none for a datagram,
//! whose socket writes its own headers, and the length a streamed batch carries for a stream.
//!
//! Where the memory lies is the storage's alone: a table the image declares (`ByteBuf`), buffers
//! the link allocated (`HeapTx`), or a buffer of the tables a session lays out in the memory it
//! reserves when it opens ([`LinkTables`], cut into slots by [`SlottedTx`]).

use core::cell::Cell;

// The heap profile's form (`HeapTx`) exists only in the heap profile: under `session-slot` the
// crate does not link `alloc` at all, which `lib.rs` keeps so that a use creeping back into the
// slot profile is a compile error and not a silent allocation.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::vec::Vec;

use wz_session_core::byte_cells::{ByteBuf, LentByteCells};
use wz_session_core::link::{TxSlot, TxSlotGrant};

/// Where a driver's outbound frames are built: memory of its own that it lends the session to
/// encode a frame into (`BoxedLinkDriver::tx_slot_acquire`), so the frame is written once, where
/// the socket reads it, and no buffer is allocated for it.
///
/// A driver whose storage is empty (a `HeapTx` of no bytes) lends nothing: the session builds
/// each frame in a buffer of its own (the heap) and hands the bytes to `send_blocking`. A driver
/// with storage lends it, and its link then also states the frames it carries
/// (`BoxedLinkDriver::link_mtu`, `link_rx_capacity`), because its buffers are the bound. The
/// storage is a buffer of a table the image declares ([`ByteBuf`], the fixed-memory profile's,
/// whose sessions have no heap to build a frame on) or buffers the link allocated once (`HeapTx`,
/// the heap profile's).
///
/// The storage is some number of slots of one length. A session that batches holds one slot open
/// while it fills a batch and encodes the next message that does not join it into another, so a
/// batching session needs two; one that does not batch needs one. The driver lends a slot at a
/// time and takes it back at its send or abort.
pub trait TxStore {
    /// How many slots there are to lend, all of the length [`Self::slot_len`].
    fn slots(&self) -> usize;

    /// The length of every slot.
    fn slot_len(&self) -> usize;

    /// The first byte of slot `slot` (below [`Self::slots`]). The driver reads and writes it only
    /// while it has lent the slot, and to one holder.
    fn slot_base(&self, slot: usize) -> *mut u8;

    /// Whether there is storage to lend.
    fn lends(&self) -> bool {
        self.slots() != 0 && self.slot_len() != 0
    }
}

/// The fixed-memory profile's outbound storage: a buffer lent by a table the image declares, one
/// slot. The socket writes a frame before the session builds the next, and a session that does not
/// batch has no frame open beside it.
impl TxStore for ByteBuf {
    fn slots(&self) -> usize {
        1
    }

    fn slot_len(&self) -> usize {
        self.raw().1
    }

    fn slot_base(&self, _slot: usize) -> *mut u8 {
        self.raw().0
    }
}

/// The heap profile's outbound storage: `slots` buffers of `slot_len` bytes, allocated together
/// when the link is made and never again, so the frames of the link are encoded into them and a
/// frame costs no allocation. Of no bytes it lends nothing, which is the link as it was before the
/// profile lent.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub struct HeapTx {
    cells: Vec<core::cell::UnsafeCell<u8>>,
    slot_len: usize,
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl HeapTx {
    /// `slots` slots of `slot_len` bytes each (none, with either 0).
    pub fn new(slots: usize, slot_len: usize) -> Self {
        let len = slots.saturating_mul(slot_len);
        Self {
            cells: (0..len).map(|_| core::cell::UnsafeCell::new(0)).collect(),
            slot_len,
        }
    }
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl TxStore for HeapTx {
    fn slots(&self) -> usize {
        self.cells.len().checked_div(self.slot_len).unwrap_or(0)
    }

    fn slot_len(&self) -> usize {
        self.slot_len
    }

    fn slot_base(&self, slot: usize) -> *mut u8 {
        // `UnsafeCell<u8>` is a `u8`, and a pointer to a cell may be written through.
        self.cells
            .as_ptr()
            .cast::<u8>()
            .cast_mut()
            .wrapping_add(slot * self.slot_len)
    }
}

/// Outbound storage cut from one buffer of a table: as many slots of one length as the buffer holds
/// whole, laid end to end as `HeapTx` lays them in its vector. What a link whose buffers a session's
/// tables lend encodes its frames into ([`LinkTables`]): a batching session holds a slot open while
/// it encodes the next message into another, so one buffer carries every slot the link lends.
pub struct SlottedTx {
    buf: ByteBuf,
    slot_len: usize,
}

impl SlottedTx {
    /// The slots of `slot_len` bytes that `buf` holds whole: none with a `slot_len` of 0, which
    /// lends nothing.
    pub fn new(buf: ByteBuf, slot_len: usize) -> Self {
        Self { buf, slot_len }
    }
}

impl TxStore for SlottedTx {
    fn slots(&self) -> usize {
        self.buf.raw().1.checked_div(self.slot_len).unwrap_or(0)
    }

    fn slot_len(&self) -> usize {
        self.slot_len
    }

    fn slot_base(&self, slot: usize) -> *mut u8 {
        self.buf.raw().0.wrapping_add(slot * self.slot_len)
    }
}

/// The buffers a session's links take from the memory the session reserved when it opened: a table
/// of receive buffers and a table of outbound storage, one buffer of each for every link the
/// session may hold at once, the outbound one cut into slots of `slot_len` bytes ([`SlottedTx`]).
/// A link claims one of each when it opens and gives them back when it is dropped, so the session's
/// links take what its arena holds and no link allocates a buffer: a link the tables have no buffer
/// left for is not opened, and the stack answers that it is exhausted.
///
/// A handle, as the tables are: copies name the same buffers. The tables' memory is the session's
/// arena, which is given back once every link of the session is gone.
#[derive(Clone, Copy, Debug)]
pub struct LinkTables {
    rx: LentByteCells,
    tx: LentByteCells,
    slot_len: usize,
}

impl LinkTables {
    /// The links' receive buffers in `rx` and their outbound storage in `tx`, each buffer of which
    /// is cut into slots of `slot_len` bytes.
    pub const fn new(rx: LentByteCells, tx: LentByteCells, slot_len: usize) -> Self {
        Self { rx, tx, slot_len }
    }

    /// The receive buffer and the outbound storage of one link, or `None` when either table has
    /// none left; a receive buffer claimed for a link the other table could not serve is back in
    /// its table when this returns.
    pub fn claim(&self) -> Option<(ByteBuf, SlottedTx)> {
        let rx = self.rx.claim()?;
        let tx = self.tx.claim()?;
        Some((rx, SlottedTx::new(tx, self.slot_len)))
    }

    /// The length of every receive buffer: the largest batch a link of these tables takes.
    pub const fn rx_len(&self) -> usize {
        self.rx.size()
    }

    /// How many links hold buffers of these tables now.
    pub fn in_use(&self) -> usize {
        self.rx.in_use()
    }
}

/// A link's receive buffer on the heap profile: allocated when the link opens, or lent by its
/// session's tables ([`LinkTables`]).
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub enum RxBuffer {
    /// The link's own allocation.
    Owned(Vec<u8>),
    /// A buffer of the session's tables.
    Lent(ByteBuf),
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl AsMut<[u8]> for RxBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Owned(bytes) => bytes.as_mut_slice(),
            Self::Lent(buf) => buf.as_mut_slice(),
        }
    }
}

/// A link's outbound storage on the heap profile: the slots it allocated when it opened
/// ([`HeapTx`], none for a link that lends nothing), or a buffer of its session's tables cut into
/// slots ([`SlottedTx`]).
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub enum TxBuffer {
    /// The link's own allocation.
    Owned(HeapTx),
    /// A buffer of the session's tables.
    Lent(SlottedTx),
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl TxStore for TxBuffer {
    fn slots(&self) -> usize {
        match self {
            Self::Owned(store) => store.slots(),
            Self::Lent(store) => store.slots(),
        }
    }

    fn slot_len(&self) -> usize {
        match self {
            Self::Owned(store) => store.slot_len(),
            Self::Lent(store) => store.slot_len(),
        }
    }

    fn slot_base(&self, slot: usize) -> *mut u8 {
        match self {
            Self::Owned(store) => store.slot_base(slot),
            Self::Lent(store) => store.slot_base(slot),
        }
    }
}

/// The buffers of a heap profile's link that opens now: claimed from its session's tables when the
/// session lent some, and refused as exhausted when they have none left, so a session whose tables
/// are full opens no link; otherwise allocated, a receive buffer of `rx` bytes and `tx_slots`
/// slots of `tx_len` bytes (none lends nothing, and the session builds its frames itself).
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub(crate) fn heap_link_buffers(
    lent: Option<&LinkTables>,
    rx: usize,
    tx_slots: usize,
    tx_len: usize,
) -> Result<(RxBuffer, TxBuffer), crate::session_drive::LinkOpenError> {
    match lent {
        Some(tables) => {
            let (rx, tx) = tables
                .claim()
                .ok_or(crate::session_drive::LinkOpenError::Exhausted)?;
            Ok((RxBuffer::Lent(rx), TxBuffer::Lent(tx)))
        }
        None => Ok((
            RxBuffer::Owned(alloc::vec![0u8; rx]),
            TxBuffer::Owned(HeapTx::new(tx_slots, tx_len)),
        )),
    }
}

/// A link's [`TxStore`] and the book of which of its slots are out with the session, between a
/// slot's grant and its send or abort. At most eight slots are lent (the book is a byte), which
/// is four times what a batching session holds.
pub struct TxLender<T: TxStore> {
    store: T,
    /// Which slots are out, bit by slot number.
    lent: Cell<u8>,
}

impl<T: TxStore> TxLender<T> {
    /// The book of `store`, with nothing lent.
    pub fn new(store: T) -> Self {
        Self {
            store,
            lent: Cell::new(0),
        }
    }

    /// Whether there is storage to lend.
    pub fn lends(&self) -> bool {
        self.store.lends()
    }

    /// The length of every slot, the headroom included.
    pub fn slot_len(&self) -> usize {
        self.store.slot_len()
    }

    /// Lend a free slot, with `headroom` bytes in front of the frame left to the link; `None` when
    /// there is no storage, the slot could not hold a byte of frame past the headroom, or every slot
    /// is out (which the lend-only profile counts rather than answering from the heap).
    pub fn acquire(&self, headroom: usize) -> Option<TxSlotGrant> {
        if self.store.slot_len() <= headroom {
            return None;
        }
        let slots = self.store.slots().min(u8::BITS as usize);
        let lent = self.lent.get();
        let free = (0..slots).find(|slot| lent & (1 << slot) == 0)?;
        self.lent.set(lent | (1 << free));
        Some(TxSlotGrant {
            slot: TxSlot(free as u32),
            headroom,
        })
    }

    /// The first byte of `slot` and its whole length (the headroom is the first part of it).
    pub fn storage(&self, slot: TxSlot) -> (*mut u8, usize) {
        (self.store.slot_base(slot.0 as usize), self.store.slot_len())
    }

    /// Take `slot` back without sending it.
    pub fn release(&self, slot: TxSlot) {
        self.lent.set(self.lent.get() & !(1 << slot.0));
    }

    /// Take `slot` back for its send, and the bytes `start .. start + len` of it, which the session
    /// encoded and the link writes. `None` when that range is not inside the slot (the frame is
    /// dropped as oversize); the slot is back either way.
    ///
    /// The bytes are the link's alone until the next grant of this slot: the session's grant of it
    /// ended here, and a link writes them before it lends anything again.
    pub fn take(&self, slot: TxSlot, start: usize, len: usize) -> Option<&[u8]> {
        self.take_prefixed(slot, start, len, &[])
    }

    /// Write `prefix` into the headroom just in front of the frame `start .. start + len` of
    /// `slot`, and answer where the bytes to write are, prefix included, as a range of the slot;
    /// the slot stays out of the pool, held by the link until it has written them
    /// ([`Self::held`] reads them, [`Self::release`] ends the hold). `None` when the frame is
    /// not inside the slot or the headroom is shorter than `prefix`, the slot still out.
    pub fn frame_prefixed(
        &self,
        slot: TxSlot,
        start: usize,
        len: usize,
        prefix: &[u8],
    ) -> Option<(usize, usize)> {
        let (base, capacity) = self.storage(slot);
        let from = start.checked_sub(prefix.len())?;
        let end = start.checked_add(len).filter(|&end| end <= capacity)?;
        // SAFETY: `base` is the first byte of a slot of the store, `capacity` bytes long, and
        // `from .. start` is within it. The session handed the slot over, so nothing else writes
        // it, and the prefix goes into the headroom, which the session left untouched.
        unsafe { core::ptr::copy_nonoverlapping(prefix.as_ptr(), base.add(from), prefix.len()) };
        Some((from, end))
    }

    /// A free slot held by the link from here, its first `len` bytes written by `fill`: where a
    /// link keeps what it owes its stream of a frame the session handed it as bytes. `None` when
    /// no slot is free or `len` passes a slot.
    pub fn hold_filled(&self, len: usize, fill: impl FnOnce(&mut [u8])) -> Option<TxSlot> {
        if len > self.store.slot_len() {
            return None;
        }
        let grant = self.acquire(0)?;
        let (base, _) = self.storage(grant.slot);
        // SAFETY: `base` is the first byte of a slot of `slot_len` bytes, at least `len`, which
        // was just granted, to the link and nobody else.
        fill(unsafe { core::slice::from_raw_parts_mut(base, len) });
        Some(grant.slot)
    }

    /// The bytes `from .. end` of `slot`, cut to the slot.
    ///
    /// # Safety
    ///
    /// The slot is held by the link ([`Self::frame_prefixed`], [`Self::hold_filled`]) and not
    /// with the session: nothing writes it while the bytes are borrowed.
    pub unsafe fn held(&self, slot: TxSlot, from: usize, end: usize) -> &[u8] {
        let (base, capacity) = self.storage(slot);
        let end = end.min(capacity);
        let from = from.min(end);
        // SAFETY: `from .. end` is within the slot, and the caller holds it (see above).
        unsafe { core::slice::from_raw_parts(base.add(from), end - from) }
    }

    /// [`Self::take`], with `prefix` written into the headroom just in front of the frame, and the
    /// bytes returned starting at it: a stream link's length in front of its batch, so prefix and
    /// batch leave in one write. `None` too when the headroom is shorter than `prefix`.
    pub fn take_prefixed(
        &self,
        slot: TxSlot,
        start: usize,
        len: usize,
        prefix: &[u8],
    ) -> Option<&[u8]> {
        let (base, capacity) = self.storage(slot);
        self.release(slot);
        let from = start.checked_sub(prefix.len())?;
        let end = start.checked_add(len).filter(|&end| end <= capacity)?;
        // SAFETY: `base` is the first byte of a slot of the store, `capacity` bytes long, and
        // `from..end` is within it. The slot was granted to the session alone and has just been
        // taken back by this call, so nothing else reads or writes the bytes while the link uses
        // them; the prefix is written into the headroom, which the session left untouched.
        unsafe {
            core::ptr::copy_nonoverlapping(prefix.as_ptr(), base.add(from), prefix.len());
            Some(core::slice::from_raw_parts(base.add(from), end - from))
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::NonNull;
    use wz_session_core::bounded::{Arena, ARENA_ALIGN};

    /// One block of an arena's memory in a test, aligned as an arena's spans start.
    #[derive(Clone, Copy)]
    #[repr(C, align(16))]
    struct Block([u8; ARENA_ALIGN]);

    /// An arena over `bytes` bytes the test process leaks, so it outlives every table and every
    /// buffer lent from it.
    fn arena_of(bytes: usize) -> Arena {
        let blocks = bytes.div_ceil(ARENA_ALIGN).max(1);
        let region: &'static mut [Block] = std::vec![Block([0; ARENA_ALIGN]); blocks].leak();
        // SAFETY: the region is aligned to `ARENA_ALIGN`, as its blocks are, holds at least
        // `bytes` bytes, and is leaked, so nothing else uses it and it outlives every table.
        unsafe { Arena::over(NonNull::from(region).cast::<u8>(), bytes) }
    }

    /// Tables of `rx_links` receive buffers of `rx_len` bytes and `tx_links` outbound buffers of
    /// `slots` slots of `slot_len` bytes, lent from an arena of their own.
    fn tables(
        rx_links: usize,
        rx_len: usize,
        tx_links: usize,
        slots: usize,
        slot_len: usize,
    ) -> LinkTables {
        let tx_len = slots * slot_len;
        let bytes = Arena::byte_cells_bytes(rx_len, rx_links)
            .and_then(|rx| Arena::byte_cells_bytes(tx_len, tx_links).map(|tx| rx + tx))
            .expect("a test's tables fit the address space");
        let mut arena = arena_of(bytes);
        let rx = arena
            .lend_byte_cells(rx_len, rx_links)
            .expect("the receive table");
        let tx = arena
            .lend_byte_cells(tx_len, tx_links)
            .expect("the outbound table");
        LinkTables::new(rx, tx, slot_len)
    }

    /// Each link takes a receive buffer and its slots from the session's tables until it goes: a
    /// link past them is refused, and one the outbound table cannot serve gives its receive
    /// buffer back.
    #[test]
    fn a_sessions_tables_lend_each_link_its_buffers_until_it_goes() {
        let one = tables(1, 16, 1, 2, 8);
        assert_eq!(one.rx_len(), 16);
        let (mut rx, tx) = one.claim().expect("the first link's buffers");
        assert_eq!(rx.as_mut_slice().len(), 16);
        assert_eq!((tx.slots(), tx.slot_len()), (2, 8));
        assert_eq!(one.in_use(), 1);
        assert!(one.claim().is_none(), "a second link is refused");
        drop((rx, tx));
        assert_eq!(one.in_use(), 0);
        assert!(
            one.claim().is_some(),
            "the buffers are back once the link goes"
        );

        let short = tables(2, 16, 1, 2, 8);
        let held = short.claim().expect("the first link's buffers");
        assert!(
            short.claim().is_none(),
            "no outbound buffer for a second link"
        );
        assert_eq!(
            short.in_use(),
            1,
            "the second link's receive buffer went back"
        );
        drop(held);
    }

    /// A link whose slots its session's tables lend refuses a slot once every one is out, which is
    /// what the session counts as a send with no slot, and lends it again once one is back.
    #[test]
    fn a_lent_link_refuses_a_slot_once_every_slot_is_out() {
        let lent = tables(1, 16, 1, 2, 8);
        let (_rx, tx) = lent.claim().expect("the link's buffers");
        let lender = TxLender::new(tx);
        assert!(lender.lends());
        let first = lender.acquire(2).expect("a first slot");
        let second = lender.acquire(2).expect("a second slot");
        let (a, b) = (lender.storage(first.slot), lender.storage(second.slot));
        assert_eq!((a.1, b.1), (8, 8));
        assert_eq!(
            (b.0 as usize).abs_diff(a.0 as usize),
            8,
            "the slots are end to end"
        );
        assert!(lender.acquire(2).is_none(), "every slot is out");
        lender.release(first.slot);
        assert!(lender.acquire(2).is_some(), "a slot back is lent again");
        assert!(
            lender.acquire(8).is_none(),
            "a slot with no byte past its headroom is no slot"
        );
    }

    /// The heap profile's forms read the buffers they hold, whichever the link took.
    #[cfg(all(feature = "alloc", not(feature = "session-slot")))]
    #[test]
    fn a_heap_links_buffers_are_its_own_or_its_sessions() {
        let lent = tables(1, 16, 1, 2, 8);
        let (rx, tx) = lent.claim().expect("the link's buffers");
        let mut rx = RxBuffer::Lent(rx);
        let tx = TxBuffer::Lent(tx);
        assert_eq!(rx.as_mut().len(), 16);
        assert_eq!((tx.slots(), tx.slot_len()), (2, 8));

        let mut own = RxBuffer::Owned(std::vec![0u8; 4]);
        let none = TxBuffer::Owned(HeapTx::new(0, 0));
        assert_eq!(own.as_mut().len(), 4);
        assert!(!none.lends(), "a link of no slots lends nothing");
    }
}
