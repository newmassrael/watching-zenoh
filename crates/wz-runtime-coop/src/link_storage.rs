// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The memory a link lends its session to encode outbound frames into, and the book of which
//! slots of it are out: written once for every link of this crate, the datagram link
//! (`udp_link`) and the stream link (`stream_link`), because which slot may be lent and when it
//! comes back is the same decision whatever carries the frame. A link differs only in the bytes it
//! asks to have left free in front of a frame
//! ([`TxSlotGrant::headroom`](wz_session_core::link::TxSlotGrant::headroom)): none for a datagram,
//! whose socket writes its own headers, and the length a streamed batch carries for a stream.

use core::cell::Cell;

// The heap profile's form (`HeapTx`) exists only in the heap profile: under `session-slot` the
// crate does not link `alloc` at all, which `lib.rs` keeps so that a use creeping back into the
// slot profile is a compile error and not a silent allocation.
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
use alloc::vec::Vec;

use wz_session_core::byte_cells::ByteBuf;
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
