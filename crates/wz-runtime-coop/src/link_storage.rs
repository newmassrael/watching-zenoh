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

/// Where a driver receives into: its own buffer, which it holds for its life, or a buffer of its
/// session's pool ([`PooledRx`]), which it holds only while the buffer holds something of the
/// link's own.
///
/// Every buffer a type has as its own (`AsMut<[u8]>`: a `Vec<u8>`, a buffer of an image's table)
/// is one, always there and never given back.
pub trait RxStore {
    /// The length of the buffer the link receives into: the largest batch it takes whole.
    fn capacity(&mut self) -> usize;

    /// The buffer's bytes, claimed from the pool first when the link holds none; `None` when it
    /// holds none and the pool has none free, and the link then reads nothing.
    fn bytes(&mut self) -> Option<&mut [u8]>;

    /// The link holds nothing of its own in the buffer any more (no part of a batch, nothing it
    /// was asked to keep): a pooled buffer goes back to its pool, for any link to read into. What
    /// the last receive lent may be read until any link of the pool is next asked to receive or be
    /// serviced, which the session's step holds back while a sample lies in it.
    fn idle(&mut self) {}

    /// Whether the last ask for the bytes found the pool dry and it is dry still: the link has
    /// input it cannot read until another link's buffer goes back.
    fn starved(&self) -> bool {
        false
    }

    /// Whether the buffer is a pool's, given back when idle: what a driver reads to leave out the
    /// bookkeeping of giving it back for a buffer of the link's own.
    const POOLED: bool = false;
}

impl<B: AsMut<[u8]>> RxStore for B {
    fn capacity(&mut self) -> usize {
        self.as_mut().len()
    }

    fn bytes(&mut self) -> Option<&mut [u8]> {
        Some(self.as_mut())
    }
}

/// A link's receive buffer taken from its session's pool ([`LinkTables`]) for as long as the link
/// holds something of its own in it: a stream's partial length or batch, or a batch or datagram it
/// was asked to keep, as zenoh-pico keeps a stream peer's partial batch in a buffer of the peer's
/// (`vendor/zenoh-pico/src/transport/unicast/read.c` @
/// `static z_result_t _z_unicast_handle_remaining_data(_z_transport_unicast_t *ztu, _z_transport_peer_unicast_t *peer,`)
/// and reads every peer into the transport's one buffer otherwise. The facts about what the bytes
/// are stay the link's (`StreamDriver`'s `held` and `spent`); only the bytes come from the pool.
pub struct PooledRx {
    pool: LentByteCells,
    held: Option<ByteBuf>,
    starved: bool,
}

impl PooledRx {
    /// A link's place in `pool`, holding no buffer yet.
    pub const fn of(pool: LentByteCells) -> Self {
        Self {
            pool,
            held: None,
            starved: false,
        }
    }

    /// Whether the link holds a buffer of the pool now.
    pub fn holds(&self) -> bool {
        self.held.is_some()
    }
}

impl RxStore for PooledRx {
    fn capacity(&mut self) -> usize {
        self.pool.size()
    }

    fn bytes(&mut self) -> Option<&mut [u8]> {
        if self.held.is_none() {
            self.held = self.pool.claim();
        }
        self.starved = self.held.is_none();
        self.held.as_mut().map(ByteBuf::as_mut_slice)
    }

    fn idle(&mut self) {
        self.held = None;
    }

    fn starved(&self) -> bool {
        self.starved && self.pool.in_use() >= self.pool.capacity()
    }

    const POOLED: bool = true;
}

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

    /// Take the memory of slot `slot` for a grant. Storage of the link's own is always there; a
    /// slot of a pool its session's links share is claimed here, and `false` is a pool with none
    /// free.
    fn claim(&self, slot: usize) -> bool {
        let _ = slot;
        true
    }

    /// The memory of slot `slot` is not the link's any more: a pooled slot goes back to its pool.
    fn give_back(&self, slot: usize) {
        let _ = slot;
    }

    /// Whether a grant would find a slot now: storage of the link's own always may be asked
    /// (its own book says whether one is out); a pool may, while the link holds its slot or the
    /// pool has one free.
    fn claimable(&self) -> bool {
        true
    }

    /// Whether the slot the link holds may stay held past the call that holds it by the session's
    /// choice (a batch frame left open for the messages after it): storage of the link's own
    /// always may; a slot of a pool may while the pool keeps another free for the session's other
    /// links. A frame the stream took in part keeps its slot whatever this says: what it owes is
    /// written by the link's steps as the stream takes it, and a link that finds no slot free
    /// meanwhile is congested ([`Self::claimable`]).
    fn spare(&self) -> bool {
        true
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
            .wrapping_add(slot.saturating_mul(self.slot_len))
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
        self.buf
            .raw()
            .0
            .wrapping_add(slot.saturating_mul(self.slot_len))
    }
}

/// A link's receive storage of its session's tables: in a build that accepts links
/// (`session-unicast-accept`), whose sessions hold many, a place in the pool they share
/// ([`PooledRx`]); in one that only dials, whose session holds its dial and the faces it
/// attaches, a buffer of its own, with none of a pool's bookkeeping.
#[cfg(feature = "session-unicast-accept")]
pub type LinkRx = PooledRx;
/// A link's receive storage of its session's tables (see the twin above): a buffer of its own.
#[cfg(not(feature = "session-unicast-accept"))]
pub type LinkRx = ByteBuf;

/// A link's outbound storage of its session's tables: one slot at a time of the pool the links
/// share in a build that accepts links ([`LinkTx`]), a buffer of its own cut into slots in one
/// that only dials ([`SlottedTx`]).
#[cfg(feature = "session-unicast-accept")]
pub type LinkTxStore = LinkTx;
/// A link's outbound storage of its session's tables (see the twin above): a buffer of its own.
#[cfg(not(feature = "session-unicast-accept"))]
pub type LinkTxStore = SlottedTx;

/// A link's outbound storage of its session's tables: a buffer of its own, cut into slots
/// ([`SlottedTx`]), or one slot at a time of a pool the session's links share ([`PooledTx`]).
pub enum LinkTx {
    /// A buffer of the link's own.
    Own(SlottedTx),
    /// A place in the session's pool.
    Pooled(PooledTx),
}

impl TxStore for LinkTx {
    fn slots(&self) -> usize {
        match self {
            Self::Own(store) => store.slots(),
            Self::Pooled(store) => store.slots(),
        }
    }

    fn slot_len(&self) -> usize {
        match self {
            Self::Own(store) => store.slot_len(),
            Self::Pooled(store) => store.slot_len(),
        }
    }

    fn slot_base(&self, slot: usize) -> *mut u8 {
        match self {
            Self::Own(store) => store.slot_base(slot),
            Self::Pooled(store) => store.slot_base(slot),
        }
    }

    fn claim(&self, slot: usize) -> bool {
        match self {
            Self::Own(store) => store.claim(slot),
            Self::Pooled(store) => store.claim(slot),
        }
    }

    fn give_back(&self, slot: usize) {
        match self {
            Self::Own(store) => store.give_back(slot),
            Self::Pooled(store) => store.give_back(slot),
        }
    }

    fn claimable(&self) -> bool {
        match self {
            Self::Own(store) => store.claimable(),
            Self::Pooled(store) => store.claimable(),
        }
    }

    fn spare(&self) -> bool {
        match self {
            Self::Own(store) => store.spare(),
            Self::Pooled(store) => store.spare(),
        }
    }
}

/// A link's outbound slot taken from its session's pool for a grant and given back at its send
/// or abort, or once a frame the stream took in part is written: one slot at a time, as a link
/// lent a buffer of its own lends one (`LINK_TX_SLOTS` of `wz-capi-coop`), so a link of a pool
/// encodes and sends as it did. The link also holds its place among the session's links, which
/// is what bounds how many links open.
pub struct PooledTx {
    pool: LentByteCells,
    /// The table of the links' places, to tell whether the pool has a slot for every link.
    links: LentByteCells,
    /// This link's place, held for its life.
    _place: ByteBuf,
    held: core::cell::RefCell<Option<ByteBuf>>,
}

impl PooledTx {
    /// Whether the link holds a slot of the pool now.
    pub fn holds(&self) -> bool {
        self.held.borrow().is_some()
    }
}

impl TxStore for PooledTx {
    fn slots(&self) -> usize {
        1
    }

    fn slot_len(&self) -> usize {
        self.pool.size()
    }

    fn slot_base(&self, _slot: usize) -> *mut u8 {
        self.held
            .borrow()
            .as_ref()
            .map_or(core::ptr::null_mut(), |buf| buf.raw().0)
    }

    fn claim(&self, _slot: usize) -> bool {
        let mut held = self.held.borrow_mut();
        if held.is_none() {
            *held = self.pool.claim();
        }
        held.is_some()
    }

    fn give_back(&self, _slot: usize) {
        *self.held.borrow_mut() = None;
    }

    fn claimable(&self) -> bool {
        self.holds() || self.pool.in_use() < self.pool.capacity()
    }

    fn spare(&self) -> bool {
        self.pool.capacity() >= self.links.capacity() || self.pool.in_use() < self.pool.capacity()
    }
}

/// The buffers a session's links take from the memory the session reserved when it opened: a pool
/// of receive buffers the links share, and outbound storage, either a buffer for every link the
/// session may hold at once, cut into slots of `slot_len` bytes ([`SlottedTx`]), or a pool of
/// slots the links share beside a table of the links' places ([`PooledTx`]). A link claims its
/// outbound buffer, or its place, when it opens and gives it back when it is dropped, so a link
/// the tables have none left for is not opened, and the stack answers that it is exhausted; it
/// takes a receive buffer of the pool only while that buffer holds something of its own
/// ([`PooledRx`]). The session's links take what its arena holds and no link allocates a buffer.
///
/// A handle, as the tables are: copies name the same buffers. The tables' memory is the session's
/// arena, which is given back once every link of the session is gone.
#[derive(Clone, Copy, Debug)]
pub struct LinkTables {
    rx: LentByteCells,
    tx: LentByteCells,
    /// The links' places when `tx` is a pool of slots the links share; `None` when `tx` holds a
    /// buffer for each link.
    places: Option<LentByteCells>,
    slot_len: usize,
    /// The receive buffers of the multicast groups the session may join, one for each, which a
    /// group claims when it is joined; `None` when the session lent none, and a group's stack
    /// then gives it a buffer of its own.
    group_rx: Option<LentByteCells>,
    /// The slots the session's udp ports read their datagrams into and hold them in until the
    /// links of their peers take them, which the ports share; `None` when the session lent none,
    /// and a port's stack then gives it memory of its own.
    port_rx: Option<LentByteCells>,
}

impl LinkTables {
    /// The links' pool of receive buffers in `rx` and their outbound storage in `tx`, each buffer
    /// of which is cut into slots of `slot_len` bytes.
    pub const fn new(rx: LentByteCells, tx: LentByteCells, slot_len: usize) -> Self {
        Self {
            rx,
            tx,
            places: None,
            slot_len,
            group_rx: None,
            port_rx: None,
        }
    }

    /// The links' pool of receive buffers in `rx`, a pool of outbound slots in `tx`, each one
    /// slot, which the links share, and a place in `places` for each link the session may hold.
    pub const fn pooled(rx: LentByteCells, tx: LentByteCells, places: LentByteCells) -> Self {
        Self {
            rx,
            tx,
            places: Some(places),
            slot_len: tx.size(),
            group_rx: None,
            port_rx: None,
        }
    }

    /// These tables with `group_rx`, a receive buffer for each multicast group the session may
    /// join: a group joined claims one, and gives it back when it is left.
    #[must_use]
    pub const fn with_group_rx(self, group_rx: LentByteCells) -> Self {
        Self {
            group_rx: Some(group_rx),
            ..self
        }
    }

    /// These tables with `port_rx`, the slots the session's udp ports share for their datagrams:
    /// a port claims one to read a datagram into, holds it while the datagram waits for its peer's
    /// link, and gives it back once the link took it.
    #[must_use]
    pub const fn with_port_rx(self, port_rx: LentByteCells) -> Self {
        Self {
            port_rx: Some(port_rx),
            ..self
        }
    }

    /// The table the session's udp ports claim their datagrams' slots from: `None` when the
    /// session lent none, and a port's stack gives it memory of its own. A datagram that finds
    /// every slot of a lent table held is dropped and counted, as a full socket buffer drops one.
    pub const fn port_rx(&self) -> Option<LentByteCells> {
        self.port_rx
    }

    /// The table a group the session joins claims its receive buffer from: `None` when the
    /// session lent none, and a joined group's stack gives it a buffer of its own. A group that
    /// finds every buffer of a lent table held is refused, as a link that finds no storage is.
    pub const fn group_rx(&self) -> Option<LentByteCells> {
        self.group_rx
    }

    /// The receive and the outbound storage of one link ([`LinkRx`], [`LinkTxStore`]), or `None`
    /// when the tables have none left for another link.
    #[cfg(feature = "session-unicast-accept")]
    pub fn claim(&self) -> Option<(LinkRx, LinkTxStore)> {
        let tx = match self.places {
            Some(places) => LinkTx::Pooled(PooledTx {
                pool: self.tx,
                links: places,
                _place: places.claim()?,
                held: core::cell::RefCell::new(None),
            }),
            None => LinkTx::Own(SlottedTx::new(self.tx.claim()?, self.slot_len)),
        };
        Some((PooledRx::of(self.rx), tx))
    }

    /// The receive buffer and the outbound storage of one link, or `None` when either table has
    /// none left; a receive buffer claimed for a link the other table could not serve is back in
    /// its table when this returns.
    #[cfg(not(feature = "session-unicast-accept"))]
    pub fn claim(&self) -> Option<(LinkRx, LinkTxStore)> {
        let rx = self.rx.claim()?;
        let tx = self.tx.claim()?;
        Some((rx, SlottedTx::new(tx, self.slot_len)))
    }

    /// How many links the tables hold storage for: the session's link places.
    pub const fn links(&self) -> usize {
        match self.places {
            Some(places) => places.capacity(),
            None => self.tx.capacity(),
        }
    }

    /// The length of every receive buffer: the largest batch a link of these tables takes.
    pub const fn rx_len(&self) -> usize {
        self.rx.size()
    }

    /// How many links hold buffers of these tables now.
    pub fn in_use(&self) -> usize {
        self.places.unwrap_or(self.tx).in_use()
    }

    /// How many outbound slots of the pool links hold now; with a buffer for each link, how many
    /// of those are held.
    pub fn tx_in_use(&self) -> usize {
        self.tx.in_use()
    }

    /// How many receive buffers of the pool links hold now.
    pub fn rx_in_use(&self) -> usize {
        self.rx.in_use()
    }
}

/// A link's receive buffer on the heap profile: allocated when the link opens, or taken from its
/// session's pool while it holds something ([`LinkTables`]).
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub enum RxBuffer {
    /// The link's own allocation.
    Owned(Vec<u8>),
    /// Storage of the session's tables.
    Lent(LinkRx),
}

#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
impl RxStore for RxBuffer {
    fn capacity(&mut self) -> usize {
        match self {
            Self::Owned(bytes) => bytes.len(),
            Self::Lent(lent) => lent.capacity(),
        }
    }

    fn bytes(&mut self) -> Option<&mut [u8]> {
        match self {
            Self::Owned(bytes) => Some(bytes.as_mut_slice()),
            Self::Lent(lent) => lent.bytes(),
        }
    }

    fn idle(&mut self) {
        if let Self::Lent(lent) = self {
            lent.idle();
        }
    }

    fn starved(&self) -> bool {
        match self {
            Self::Owned(_) => false,
            Self::Lent(lent) => lent.starved(),
        }
    }

    const POOLED: bool = <LinkRx as RxStore>::POOLED;
}

/// A link's outbound storage on the heap profile: the slots it allocated when it opened
/// ([`HeapTx`], none for a link that lends nothing), or its session's tables' ([`LinkTx`]).
#[cfg(all(feature = "alloc", not(feature = "session-slot")))]
pub enum TxBuffer {
    /// The link's own allocation.
    Owned(HeapTx),
    /// Storage of the session's tables.
    Lent(LinkTxStore),
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

    fn claim(&self, slot: usize) -> bool {
        match self {
            Self::Owned(store) => store.claim(slot),
            Self::Lent(store) => store.claim(slot),
        }
    }

    fn give_back(&self, slot: usize) {
        match self {
            Self::Owned(store) => store.give_back(slot),
            Self::Lent(store) => store.give_back(slot),
        }
    }

    fn claimable(&self) -> bool {
        match self {
            Self::Owned(store) => store.claimable(),
            Self::Lent(store) => store.claimable(),
        }
    }

    fn spare(&self) -> bool {
        match self {
            Self::Owned(store) => store.spare(),
            Self::Lent(store) => store.spare(),
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
        // A slot of a pool the session's links share is there only while the pool has one free.
        if !self.store.claim(free) {
            return None;
        }
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

    /// Take `slot` back without sending it, or once what was sent of it is written: a slot of a
    /// pool goes back to the pool.
    pub fn release(&self, slot: TxSlot) {
        self.lent.set(self.lent.get() & !(1 << slot.0));
        self.store.give_back(slot.0 as usize);
    }

    /// Whether a slot the link holds may stay held past the call that holds it
    /// ([`TxStore::spare`]).
    pub fn spare(&self) -> bool {
        self.store.spare()
    }

    /// Whether a grant would find a slot of the store now ([`TxStore::claimable`]).
    pub fn claimable(&self) -> bool {
        self.store.claimable()
    }

    /// Take `slot` back for its send, and the bytes `start .. start + len` of it, which the session
    /// encoded and the link writes. `None` when that range is not inside the slot (the frame is
    /// dropped as oversize); the slot is back either way.
    ///
    /// The bytes are the link's alone until the next grant of this slot, or for a slot of a pool
    /// until any link of the pool is next granted one: the session's grant of it ended here, and a
    /// link writes them before it, or any link of its pool, lends anything again.
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
        unsafe { core::slice::from_raw_parts(base.add(from), end.saturating_sub(from)) }
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
            Some(core::slice::from_raw_parts(
                base.add(from),
                end.saturating_sub(from),
            ))
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

    /// Each link takes its slots from the session's tables until it goes, and a link past them is
    /// refused; its place in the receive pool takes no buffer until it reads.
    #[test]
    fn a_sessions_tables_lend_each_link_its_buffers_until_it_goes() {
        let one = tables(1, 16, 1, 2, 8);
        assert_eq!(one.rx_len(), 16);
        let (mut rx, tx) = one.claim().expect("the first link's buffers");
        assert_eq!(rx.capacity(), 16);
        assert_eq!(
            one.rx_in_use(),
            usize::from(!<LinkRx as RxStore>::POOLED),
            "a pool's place takes no buffer before a read; a buffer of its own is the link's"
        );
        assert_eq!((tx.slots(), tx.slot_len()), (2, 8));
        assert_eq!(one.in_use(), 1);
        assert!(one.claim().is_none(), "a second link is refused");
        drop((rx, tx));
        assert_eq!(one.in_use(), 0);
        assert!(
            one.claim().is_some(),
            "the buffers are back once the link goes"
        );
    }

    /// Links share the receive pool: each holds a buffer from its first ask for the bytes until it
    /// is idle, a link that finds the pool dry gets none and says so, and a buffer given back is
    /// the next link's. A link that goes gives its buffer back with it.
    #[cfg(feature = "session-unicast-accept")]
    #[test]
    fn links_hold_a_buffer_of_the_pool_only_until_they_are_idle() {
        let shared = tables(1, 16, 2, 1, 8);
        let (mut first, _first_tx) = shared.claim().expect("the first link");
        let (mut second, _second_tx) = shared.claim().expect("the second link");
        first.bytes().expect("the pool's one buffer")[0] = 7;
        assert!(first.holds() && !first.starved());
        assert_eq!(shared.rx_in_use(), 1);
        assert_eq!(
            first.bytes().map(|bytes| bytes[0]),
            Some(7),
            "a link that holds a buffer reads it again"
        );
        assert!(second.bytes().is_none(), "the pool is dry");
        assert!(second.starved() && !second.holds());
        first.idle();
        assert!(!first.holds());
        assert_eq!(shared.rx_in_use(), 0);
        assert!(!second.starved(), "a buffer is free for it now");
        assert!(second.bytes().is_some(), "the buffer given back is lent");
        assert!(!second.starved());
        drop(second);
        assert_eq!(shared.rx_in_use(), 0, "a link that goes gives it back");
    }

    /// Pooled tables of `places` links sharing `slots` outbound slots of `slot_len` bytes and one
    /// receive buffer of 16, lent from an arena of their own.
    #[cfg(feature = "session-unicast-accept")]
    fn pooled(places: usize, slots: usize, slot_len: usize) -> LinkTables {
        let bytes = [(16, 1), (slot_len, slots), (0, places)]
            .iter()
            .map(|&(size, count)| Arena::byte_cells_bytes(size, count).expect("fits"))
            .sum();
        let mut arena = arena_of(bytes);
        let rx = arena.lend_byte_cells(16, 1).expect("the receive pool");
        let tx = arena
            .lend_byte_cells(slot_len, slots)
            .expect("the slot pool");
        let at = arena.lend_byte_cells(0, places).expect("the places");
        LinkTables::pooled(rx, tx, at)
    }

    /// Links of a pool claim a place each when they open, and a slot only for a grant: a slot
    /// given back is the next link's, a link past the places is refused, and a link that asks
    /// while every slot is out gets none. A slot may stay held past its call only while the pool
    /// keeps another free, or when the pool has a slot for every link.
    #[cfg(feature = "session-unicast-accept")]
    #[test]
    fn links_of_a_pool_take_a_slot_for_a_grant_and_may_keep_it_while_one_is_spare() {
        let tables = pooled(3, 2, 8);
        let mut held: std::vec::Vec<TxLender<LinkTx>> = (0..3)
            .map(|_| TxLender::new(tables.claim().expect("a place").1))
            .collect();
        assert!(tables.claim().is_none(), "a fourth link has no place");
        assert_eq!((tables.in_use(), tables.tx_in_use()), (3, 0));
        let a = held[0].acquire(2).expect("a slot for a grant");
        assert_eq!(tables.tx_in_use(), 1);
        assert!(held[0].spare(), "another slot is free");
        let b = held[1].acquire(2).expect("the last slot");
        assert!(!held[1].spare(), "none is free besides");
        assert!(held[2].acquire(2).is_none(), "every slot is out");
        held[0].release(a.slot);
        assert_eq!(tables.tx_in_use(), 1);
        let c = held[2].acquire(2).expect("the slot given back");
        held[1].release(b.slot);
        held[2].release(c.slot);
        assert_eq!(tables.tx_in_use(), 0);
        held.clear();
        assert_eq!(tables.in_use(), 0, "the places are back once the links go");

        let roomy = pooled(2, 2, 8);
        let only = TxLender::new(roomy.claim().expect("a place").1);
        let _slot = only.acquire(2).expect("a slot");
        let other = TxLender::new(roomy.claim().expect("a place").1);
        let _second = other.acquire(2).expect("a slot");
        assert!(
            only.spare() && other.spare(),
            "a slot for every link: each keeps its own"
        );
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
        assert_eq!(rx.capacity(), 16);
        assert_eq!(rx.bytes().map(|bytes| bytes.len()), Some(16));
        assert_eq!(lent.rx_in_use(), 1);
        rx.idle();
        assert_eq!(
            lent.rx_in_use(),
            usize::from(!RxBuffer::POOLED),
            "a pool's buffer goes back when idle; one of its own stays"
        );
        assert_eq!((tx.slots(), tx.slot_len()), (2, 8));

        let mut own = RxBuffer::Owned(std::vec![0u8; 4]);
        let none = TxBuffer::Owned(HeapTx::new(0, 0));
        assert_eq!(own.capacity(), 4);
        own.idle();
        assert_eq!(
            own.bytes().map(|bytes| bytes.len()),
            Some(4),
            "its own stays"
        );
        assert!(!none.lends(), "a link of no slots lends nothing");
    }

    /// Tables lent a group receive table hand it on, each buffer claimed once until given back,
    /// and tables lent none have none. Turned red by a table the tables lose, or one they hand
    /// out to a group past its buffers.
    #[test]
    fn the_group_receive_table_is_the_one_the_tables_were_lent() {
        let plain = tables(1, 16, 1, 1, 16);
        assert!(plain.group_rx().is_none(), "tables lent no group table");
        let mut arena = arena_of(Arena::byte_cells_bytes(32, 1).expect("fits"));
        let groups = arena.lend_byte_cells(32, 1).expect("the group table");
        let lent = plain.with_group_rx(groups);
        let table = lent.group_rx().expect("the group table");
        assert_eq!(table.size(), 32);
        let held = table.claim().expect("the one buffer");
        assert!(table.claim().is_none(), "a second group finds none");
        drop(held);
        assert!(
            table.claim().is_some(),
            "the buffer given back is claimed again"
        );
    }
}
