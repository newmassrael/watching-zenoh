// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ARCHITECTURE section 9.1 on the AP links: the TRANSMIT POOL a link's
//! outbound frames live in, and the generated lifecycle that governs each slot.
//!
//! ## What this replaces
//!
//! A write half used to hand its writer task an owned vector per frame: the
//! stream links drew it from a spare list of at most four buffers of at most
//! 16 KiB, the datagram links copied every frame into a fresh one, and the
//! generated pools' transmit lifecycle governed none of it. Under
//! `runtime-zero-copy` a link's writer queue owns its own [`TxPools`] and every
//! outbound byte lies in one of its slots, from the lend to the end of the
//! write.
//!
//! | what happens to the slot | edge of the generated pool |
//! |---|---|
//! | a frame needs a slot and none of its lane has room | `pool_acquire_for_encode` (free to cpu-mut) |
//! | the frame is encoded into it (a lend) or copied in (the byte door) | none: the slot stays cpu-mut while the CPU may still write it |
//! | the writer takes it off its lane | `link_arm_tx` (cpu-mut to dma-armed-tx) |
//! | the writer begins the write | `dma_start_tx` (to dma-busy-tx) |
//! | the write ended, written or failed | `tx_complete` (dma-busy-tx to free) |
//! | taken but never started (the writer stopped first) | `un_arm_tx` then `pool_return` |
//! | never taken (the queue was dropped, or a lend was given back empty) | `pool_return` (cpu-mut to free) |
//!
//! On this row of ARCHITECTURE section 9.5 the bus master is the kernel's copy out
//! of the slot (or, for the QUIC datagram link, quinn holding the bytes until it
//! has packetised them), so "start" and "complete" bracket the write; the edge
//! actions are the no-op the epoll row names. A failed write has ended too, which
//! is why it takes the completion edge and not the un-arm one: the generated
//! lifecycle has no other edge out of dma-busy-tx.
//!
//! ## Two shapes of pool
//!
//! * A STREAM or SERIAL link owns one size class, `session_tx_pool_ap`, whose
//!   slot holds the largest frame such a link can be handed (the const
//!   assertion below fails the build otherwise). Frames pack back to back in a
//!   lane's newest slot, because on a byte stream the concatenation is the wire,
//!   which keeps the class's sixteen slots enough for the lanes' byte bound.
//! * A DATAGRAM link (UDP, QUIC datagram, websocket, multicast) owns two:
//!   `session_tx_pool_ap_small` sized for the datagrams the sessions send, and
//!   `session_tx_pool_ap` for the rest. A datagram is its own boundary, so a slot
//!   carries one frame and nothing is packed; a frame takes the smallest class it
//!   fits and, when that class is out, the next larger one. Each class's
//!   per-link BUDGET is derived from the queue shape ([`TxPools::size_budgets`]),
//!   so the slot counts follow the configuration that sizes the lanes.
//!
//! ## The accounting
//!
//! [`TxPoolStats`] counts each edge as it is taken, and the pools' own
//! `free_count` and `slot_state` are what the tests adjudicate against, never
//! this module's bookkeeping alone.

/// The largest frame a stream write half can hand its writer: the 4-byte
/// lowlatency prefix and a `u16::MAX` payload.
pub const MAX_STREAM_FRAME: usize = 4 + u16::MAX as usize;

// THE DIMENSION THE LARGE CLASS EXISTS FOR, enforced at COMPILE time, as
// `link_rx_pool` enforces it for the receive table: a slot that could not hold
// the largest frame would turn that frame back into a heap vector. Every
// datagram (at most 65507 bytes of UDP, a 65535-byte batch on the others) is
// under it too.
const _: () = assert!(
    crate::session_tx_pool_ap::SLOT_SIZE >= MAX_STREAM_FRAME,
    "the large transmit class must hold prefix + u16::MAX payload"
);

/// The datagram the sessions send in steady state: `UDP_LINK_MTU`, zenoh-pico's
/// 1450, and above every QUIC datagram quinn's path-MTU bound admits. The small
/// class must hold it (`sources/network/session_tx_pool_ap_small.scxml`).
pub const STEADY_DATAGRAM: usize = 1450;

const _: () = assert!(
    crate::session_tx_pool_ap_small::SLOT_SIZE >= STEADY_DATAGRAM,
    "the small transmit class must hold the steady-state datagram"
);
const _: () = assert!(
    crate::session_tx_pool_ap_small::SLOT_SIZE < crate::session_tx_pool_ap::SLOT_SIZE,
    "the classes are ordered small then large"
);

/// A slot's place in the generated lifecycle, one enum for every class (the
/// emits each declare their own).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxSlotState {
    Free,
    CpuMut,
    DmaArmedTx,
    DmaBusyTx,
    DmaArmedRx,
    DmaBusyRx,
    CpuRef,
}

/// What a link's transmit pool has done since it was built. Each slot acquired
/// is counted once in `acquired`, and then once in exactly one of `returned`
/// (never armed), `completed` (its write ended) or `unarmed` (armed, never
/// started) when it goes home.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxPoolStats {
    /// Slots taken off the freelist for a lane.
    pub acquired: u64,
    /// Frames encoded into a slot by a lend and committed.
    pub lent: u64,
    /// Frames copied into a slot by the byte door.
    pub copied: u64,
    /// Slots the writer took off a lane (cpu-mut to dma-armed-tx).
    pub armed: u64,
    /// Writes the writer began from a slot (to dma-busy-tx).
    pub started: u64,
    /// Writes that ended, written or failed (dma-busy-tx to free).
    pub completed: u64,
    /// Of those, the writes that failed or were abandoned mid-write.
    pub failed: u64,
    /// Slots armed and never started, un-armed and returned.
    pub unarmed: u64,
    /// Slots returned without being armed: a lend given back empty, or a lane
    /// dropped with its queue.
    pub returned: u64,
}

impl std::ops::Add for TxPoolStats {
    type Output = Self;
    fn add(self, o: Self) -> Self {
        Self {
            acquired: self.acquired + o.acquired,
            lent: self.lent + o.lent,
            copied: self.copied + o.copied,
            armed: self.armed + o.armed,
            started: self.started + o.started,
            completed: self.completed + o.completed,
            failed: self.failed + o.failed,
            unarmed: self.unarmed + o.unarmed,
            returned: self.returned + o.returned,
        }
    }
}

/// One generated `sce:kind="buffer-pool"` table, as the transmit side walks it.
///
/// Every emit has the same author API under its own type names, so this is that
/// API once, implemented for each table by `impl_tx_table!`. The method names
/// differ from the emit's on purpose: an inherent method of the same name would
/// win the call and these would recurse.
pub trait TxTable: Send + 'static {
    /// The handle the emit gives for a slot the CPU writes (`Slot<CpuMut>`).
    type Mut: Send;
    const SLOT_SIZE: usize;
    const SLOT_COUNT: usize;
    fn take_free(&mut self) -> Option<Self::Mut>;
    fn index_of(slot: &Self::Mut) -> usize;
    fn base_of(&mut self, slot: &mut Self::Mut) -> *mut u8;
    fn return_free(&mut self, slot: Self::Mut);
    fn arm_tx(&mut self, slot: Self::Mut);
    fn armed_base(&self, idx: usize) -> Option<*const u8>;
    /// # Safety
    /// The write of armed slot `idx` is about to begin.
    unsafe fn start_tx(&mut self, idx: usize) -> bool;
    /// # Safety
    /// The write of busy slot `idx` has ended.
    unsafe fn complete_tx(&mut self, idx: usize) -> bool;
    /// # Safety
    /// Armed slot `idx` will never be started.
    unsafe fn unarm_tx(&mut self, idx: usize) -> Option<Self::Mut>;
    fn free_slots(&self) -> usize;
    fn state_of(&self, idx: usize) -> Option<TxSlotState>;
}

macro_rules! impl_tx_table {
    ($module:ident, $table:ident) => {
        const _: () = assert!(
            crate::$module::SlotState::Free as u8 == 0,
            "a pool of zeroes is a pool of free slots only while free is the state 0"
        );
        impl TxTable for crate::$module::$table {
            type Mut = crate::$module::Slot<crate::$module::CpuMut>;
            const SLOT_SIZE: usize = crate::$module::SLOT_SIZE;
            const SLOT_COUNT: usize = crate::$module::SLOT_COUNT;
            fn take_free(&mut self) -> Option<Self::Mut> {
                self.pool_acquire_for_encode()
            }
            fn index_of(slot: &Self::Mut) -> usize {
                slot.idx()
            }
            fn base_of(&mut self, slot: &mut Self::Mut) -> *mut u8 {
                slot.write(self).as_mut_ptr()
            }
            fn return_free(&mut self, slot: Self::Mut) {
                slot.pool_return(self)
            }
            fn arm_tx(&mut self, slot: Self::Mut) {
                slot.link_arm_tx(self)
            }
            fn armed_base(&self, idx: usize) -> Option<*const u8> {
                self.dma_armed_tx_ptr(idx)
            }
            unsafe fn start_tx(&mut self, idx: usize) -> bool {
                // SAFETY: the caller's contract.
                unsafe { self.dma_start_tx(idx) }
            }
            unsafe fn complete_tx(&mut self, idx: usize) -> bool {
                // SAFETY: the caller's contract.
                unsafe { self.tx_complete(idx) }
            }
            unsafe fn unarm_tx(&mut self, idx: usize) -> Option<Self::Mut> {
                // SAFETY: the caller's contract.
                unsafe { self.un_arm_tx(idx) }
            }
            fn free_slots(&self) -> usize {
                self.free_count()
            }
            fn state_of(&self, idx: usize) -> Option<TxSlotState> {
                use crate::$module::SlotState as S;
                self.slot_state(idx).map(|state| match state {
                    S::Free => TxSlotState::Free,
                    S::CpuMut => TxSlotState::CpuMut,
                    S::DmaArmedTx => TxSlotState::DmaArmedTx,
                    S::DmaBusyTx => TxSlotState::DmaBusyTx,
                    S::DmaArmedRx => TxSlotState::DmaArmedRx,
                    S::DmaBusyRx => TxSlotState::DmaBusyRx,
                    S::CpuRef => TxSlotState::CpuRef,
                })
            }
        }
    };
}

impl_tx_table!(session_tx_pool_ap, SessionTxPoolAp);
impl_tx_table!(session_tx_pool_ap_small, SessionTxPoolApSmall);

/// One size class of a link's pool, named by slot index: the generated table, the
/// emit's handle for every slot the CPU holds (so each edge is still taken through
/// the phantom-typed API), the class's per-link budget and its counters.
pub trait TxClass: Send {
    /// Bytes per slot.
    fn slot_size(&self) -> usize;
    /// Slots in the table.
    fn capacity(&self) -> usize;
    /// How many of them this link may hold at once.
    fn budget(&self) -> usize;
    fn set_budget(&mut self, budget: usize);
    /// Slots off the freelist now, by the table's own count.
    fn in_use(&self) -> usize {
        self.capacity() - self.free_count()
    }
    /// Whether one more slot may be taken: under budget, and free.
    fn has_room(&self) -> bool {
        self.in_use() < self.budget() && self.free_count() > 0
    }
    /// A free slot for the CPU to write (free to cpu-mut), within budget:
    /// its index and its first byte.
    fn acquire(&mut self) -> Option<(usize, *mut u8)>;
    /// Give back a slot never armed (cpu-mut to free).
    fn give_back(&mut self, idx: usize) -> bool;
    /// The writer takes slot `idx` (cpu-mut to dma-armed-tx): its first byte by
    /// the table's own answer for an armed slot.
    fn arm(&mut self, idx: usize) -> Option<*const u8>;
    /// Dma-armed-tx to dma-busy-tx; `false` when not armed.
    fn start(&mut self, idx: usize) -> bool;
    /// Dma-busy-tx to free; `false` when not busy.
    fn complete(&mut self, idx: usize, written: bool) -> bool;
    /// Dma-armed-tx to cpu-mut to free; `false` when not armed.
    fn unarm(&mut self, idx: usize) -> bool;
    fn free_count(&self) -> usize;
    fn slot_state(&self, idx: usize) -> Option<TxSlotState>;
    fn stats(&self) -> TxPoolStats;
    fn note_lent(&mut self);
    fn note_copied(&mut self);
}

/// One class over generated table `T`.
pub struct TxPool<T: TxTable> {
    table: Box<T>,
    /// The emit's handle for each slot the CPU holds (cpu-mut), by index.
    held: Vec<Option<T::Mut>>,
    budget: usize,
    stats: TxPoolStats,
}

impl<T: TxTable> TxPool<T> {
    /// A class of free slots with its whole table as budget, built without a
    /// stack temporary (the table is allocated zeroed; see `link_rx_pool`).
    pub fn new() -> Self {
        Self {
            table: zeroed_table::<T>(),
            held: (0..T::SLOT_COUNT).map(|_| None).collect(),
            budget: T::SLOT_COUNT,
            stats: TxPoolStats::default(),
        }
    }
}

impl<T: TxTable> Default for TxPool<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: TxTable> TxClass for TxPool<T> {
    fn slot_size(&self) -> usize {
        T::SLOT_SIZE
    }
    fn capacity(&self) -> usize {
        T::SLOT_COUNT
    }
    fn budget(&self) -> usize {
        self.budget
    }
    fn set_budget(&mut self, budget: usize) {
        self.budget = budget.min(T::SLOT_COUNT);
    }
    fn acquire(&mut self) -> Option<(usize, *mut u8)> {
        if self.in_use() >= self.budget {
            return None;
        }
        let mut slot = self.table.take_free()?;
        let idx = T::index_of(&slot);
        let base = self.table.base_of(&mut slot);
        self.held[idx] = Some(slot);
        self.stats.acquired += 1;
        Some((idx, base))
    }
    fn give_back(&mut self, idx: usize) -> bool {
        let Some(slot) = self.held.get_mut(idx).and_then(Option::take) else {
            return false;
        };
        self.table.return_free(slot);
        self.stats.returned += 1;
        true
    }
    fn arm(&mut self, idx: usize) -> Option<*const u8> {
        let slot = self.held.get_mut(idx).and_then(Option::take)?;
        self.table.arm_tx(slot);
        self.stats.armed += 1;
        self.table.armed_base(idx)
    }
    fn start(&mut self, idx: usize) -> bool {
        // SAFETY: the "peripheral" on this row is the writer's own write of the
        // slot's bytes, which the caller is about to begin; the table refuses a
        // slot that is not armed, so no other slot moves.
        let started = unsafe { self.table.start_tx(idx) };
        if started {
            self.stats.started += 1;
        }
        started
    }
    fn complete(&mut self, idx: usize, written: bool) -> bool {
        // SAFETY: the write the slot was started for has ended, so nothing reads
        // the slot any more; the table refuses a slot that is not busy.
        let done = unsafe { self.table.complete_tx(idx) };
        if done {
            self.stats.completed += 1;
            if !written {
                self.stats.failed += 1;
            }
        }
        done
    }
    fn unarm(&mut self, idx: usize) -> bool {
        // SAFETY: the slot was armed and its write never began, so nothing reads
        // it; the table refuses a slot that is not armed.
        match unsafe { self.table.unarm_tx(idx) } {
            Some(slot) => {
                self.table.return_free(slot);
                self.stats.unarmed += 1;
                true
            }
            None => false,
        }
    }
    fn free_count(&self) -> usize {
        self.table.free_slots()
    }
    fn slot_state(&self, idx: usize) -> Option<TxSlotState> {
        self.table.state_of(idx)
    }
    fn stats(&self) -> TxPoolStats {
        self.stats
    }
    fn note_lent(&mut self) {
        self.stats.lent += 1;
    }
    fn note_copied(&mut self) {
        self.stats.copied += 1;
    }
}

/// A link's transmit pool: its size classes, smallest first, and whether frames
/// pack into a slot (a byte stream) or take one each (a datagram).
pub struct TxPools {
    packs: bool,
    classes: Vec<Box<dyn TxClass>>,
}

impl TxPools {
    /// A stream or serial link's pool: the one large class, packing.
    pub fn stream() -> Self {
        Self {
            packs: true,
            classes: vec![Box::new(
                TxPool::<crate::session_tx_pool_ap::SessionTxPoolAp>::new(),
            )],
        }
    }

    /// A datagram link's pool: the small class and the large one, one frame per
    /// slot. The budgets start at the tables' sizes; the queue sizes them from
    /// its shape ([`Self::size_budgets`]).
    pub fn datagram() -> Self {
        Self {
            packs: false,
            classes: vec![
                Box::new(TxPool::<
                    crate::session_tx_pool_ap_small::SessionTxPoolApSmall,
                >::new()),
                Box::new(TxPool::<crate::session_tx_pool_ap::SessionTxPoolAp>::new()),
            ],
        }
    }

    /// Whether frames pack back to back into a slot.
    pub fn packs(&self) -> bool {
        self.packs
    }

    /// The largest frame a slot of this pool holds.
    pub fn max_frame(&self) -> usize {
        self.classes.last().map_or(0, |c| c.slot_size())
    }

    /// Bytes per slot of class `class`.
    pub fn slot_size(&self, class: usize) -> usize {
        self.classes[class].slot_size()
    }

    /// Whether some class may hand out one more slot.
    pub fn has_room(&self) -> bool {
        self.classes.iter().any(|c| c.has_room())
    }

    /// A slot for a frame of `need` bytes: the smallest class that holds it and
    /// has room, else the next larger one. Its class, index and first byte.
    pub fn acquire(&mut self, need: usize) -> Option<(usize, usize, *mut u8)> {
        self.classes
            .iter_mut()
            .enumerate()
            .filter(|(_, c)| c.slot_size() >= need)
            .find_map(|(class, c)| c.acquire().map(|(idx, base)| (class, idx, base)))
    }

    /// Class `class` of this pool.
    pub fn class(&mut self, class: usize) -> &mut dyn TxClass {
        self.classes[class].as_mut()
    }

    /// Class `class`, read-only.
    pub fn class_ref(&self, class: usize) -> &dyn TxClass {
        self.classes[class].as_ref()
    }

    /// How many classes there are.
    pub fn classes(&self) -> usize {
        self.classes.len()
    }

    /// Free slots over every class.
    pub fn free_count(&self) -> usize {
        self.classes.iter().map(|c| c.free_count()).sum()
    }

    /// Slots over every class.
    pub fn capacity(&self) -> usize {
        self.classes.iter().map(|c| c.capacity()).sum()
    }

    /// R3250 — how many slots this link may hold at once, over every class: the
    /// sum of the class budgets, so the most batches its queue can have on its
    /// lanes (each batch holds one slot).
    pub fn budget(&self) -> usize {
        self.classes.iter().map(|c| c.budget()).sum()
    }

    /// Counters over every class.
    pub fn stats(&self) -> TxPoolStats {
        self.classes
            .iter()
            .fold(TxPoolStats::default(), |sum, c| sum + c.stats())
    }

    /// R3239 — size each class's per-link BUDGET from the queue's lanes, the
    /// rule `sources/network/session_tx_pool_ap_small.scxml` derives: per lane,
    /// `ceil(bound / slot_size) + 1` (the lane's byte bound filled with frames
    /// of the slot's size, plus the one frame that may take the lane past its
    /// bound), summed over the lanes, and clamped to the table. `lane_bounds`
    /// are the lanes' bounds in bytes, `queue_size * batch_bytes` each, which
    /// the queue takes from the configuration through its session's shape.
    ///
    /// A packing pool keeps its whole table: its frames share slots, so the
    /// byte bound, not a count, is what limits it.
    pub fn size_budgets(&mut self, lane_bounds: &[usize]) {
        if self.packs {
            return;
        }
        for class in &mut self.classes {
            let size = class.slot_size();
            let budget: usize = lane_bounds.iter().map(|b| b.div_ceil(size) + 1).sum();
            class.set_budget(budget);
        }
    }
}

/// Table `T`, allocated ZEROED and owned through a box, so no temporary of its
/// size is ever put on the stack. `link_rx_pool::heap_pool` gives the full
/// argument; the zero pattern is a table of free slots because every byte of a
/// slot is a plain byte and the free state is 0 (asserted per table above).
fn zeroed_table<T: TxTable>() -> Box<T> {
    // SAFETY: `alloc_zeroed` returns a block of `Layout::new::<T>()`, sized and
    // aligned for it, and the all-zero pattern is a valid generated table (its
    // storage is bytes and its states read free), so the block holds an
    // initialised value before `from_raw` owns it.
    let table = unsafe {
        let layout = core::alloc::Layout::new::<T>();
        let raw = std::alloc::alloc_zeroed(layout) as *mut T;
        if raw.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        Box::from_raw(raw)
    };
    debug_assert_eq!(
        table.free_slots(),
        T::SLOT_COUNT,
        "the zero pattern is no longer the pool's initial state"
    );
    table
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_tx_pool_ap::{SessionTxPoolAp, SLOT_COUNT};
    use crate::session_tx_pool_ap_small::SessionTxPoolApSmall;

    fn large() -> TxPool<SessionTxPoolAp> {
        TxPool::new()
    }

    /// The largest stream frame is writable end to end in one large slot, which
    /// is what makes the const assertion a live property rather than arithmetic.
    #[test]
    fn the_largest_stream_frame_fits_one_slot() {
        let mut pool = large();
        let (idx, base) = pool.acquire().expect("a fresh pool has slots");
        // SAFETY: `base` is the first byte of a slot of SLOT_SIZE bytes this test
        // holds for writing, and MAX_STREAM_FRAME <= SLOT_SIZE.
        unsafe { base.add(MAX_STREAM_FRAME - 1).write(0xAB) };
        assert!(pool.give_back(idx));
        assert_eq!(pool.free_count(), SLOT_COUNT);
    }

    /// The writer's walk, read off the table's own states: acquired, armed,
    /// started, complete, and free again.
    #[test]
    fn a_written_slot_walks_the_transmit_arms_and_goes_home() {
        let mut pool = large();
        let (idx, _) = pool.acquire().expect("free");
        assert_eq!(pool.slot_state(idx), Some(TxSlotState::CpuMut));
        assert!(pool.arm(idx).is_some());
        assert_eq!(pool.slot_state(idx), Some(TxSlotState::DmaArmedTx));
        assert!(pool.start(idx));
        assert_eq!(pool.slot_state(idx), Some(TxSlotState::DmaBusyTx));
        assert!(pool.complete(idx, true));
        assert_eq!(pool.slot_state(idx), Some(TxSlotState::Free));
        assert_eq!(pool.free_count(), SLOT_COUNT);
        let stats = pool.stats();
        assert_eq!(
            (stats.acquired, stats.armed, stats.started, stats.completed),
            (1, 1, 1, 1)
        );
    }

    /// A second completion is refused by the generated edge, so a writer that
    /// completed twice cannot free a slot a later frame is being written into.
    #[test]
    fn a_second_completion_is_refused() {
        let mut pool = large();
        let (idx, _) = pool.acquire().expect("free");
        pool.arm(idx).expect("armed");
        assert!(pool.start(idx));
        assert!(pool.complete(idx, true));
        let (next, _) = pool.acquire().expect("free");
        assert_eq!(next, idx, "the freed slot is the next one taken");
        assert!(
            !pool.complete(idx, true),
            "completing again must not free the slot the next frame holds"
        );
        assert_eq!(pool.slot_state(idx), Some(TxSlotState::CpuMut));
        assert!(pool.give_back(next));
    }

    /// A write cannot start from a slot that was never armed: skipping the arm
    /// is refused, and the slot stays the sender's.
    #[test]
    fn a_start_without_an_arm_is_refused() {
        let mut pool = large();
        let (idx, _) = pool.acquire().expect("free");
        assert!(!pool.start(idx), "cpu-mut has no edge to dma-busy-tx");
        assert_eq!(pool.slot_state(idx), Some(TxSlotState::CpuMut));
        assert!(pool.give_back(idx));
        assert_eq!(pool.free_count(), SLOT_COUNT);
    }

    /// An armed slot whose write never began goes home through un-arm, and only
    /// an armed one does; a slot not held cannot be given back or armed.
    #[test]
    fn an_armed_slot_never_started_is_unarmed_and_returned() {
        let mut pool = large();
        let (idx, _) = pool.acquire().expect("free");
        pool.arm(idx).expect("armed");
        assert!(!pool.give_back(idx), "an armed slot is not the CPU's");
        assert!(pool.unarm(idx));
        assert_eq!(pool.slot_state(idx), Some(TxSlotState::Free));
        assert!(!pool.unarm(idx), "a free slot is not armed");
        assert!(pool.arm(idx).is_none(), "nor can a free slot be armed");
        assert_eq!(pool.stats().unarmed, 1);
    }

    /// Fresh tables are all free by the emit's own count, in both classes.
    #[test]
    fn a_fresh_pool_is_all_free() {
        let pools = TxPools::datagram();
        assert_eq!(pools.free_count(), pools.capacity());
        for class in 0..pools.classes() {
            let c = pools.class_ref(class);
            for idx in 0..c.capacity() {
                assert_eq!(c.slot_state(idx), Some(TxSlotState::Free));
            }
        }
        assert_eq!(
            pools.capacity(),
            crate::session_tx_pool_ap_small::SLOT_COUNT + SLOT_COUNT
        );
    }

    /// Exhaustion is a refusal, not an error and not an allocation: past the
    /// budget the class answers `None`, and a slot given back is taken again.
    #[test]
    fn an_exhausted_pool_refuses_and_recovers() {
        let mut pool = large();
        let held: Vec<usize> = (0..SLOT_COUNT)
            .map(|_| pool.acquire().expect("within SLOT_COUNT").0)
            .collect();
        assert!(pool.acquire().is_none());
        assert!(pool.give_back(held[3]));
        assert_eq!(pool.acquire().expect("one came back").0, held[3]);
        for idx in held {
            assert!(pool.give_back(idx));
        }
        assert_eq!(pool.free_count(), SLOT_COUNT);
    }

    /// The BUDGET is the class's limit for this link, below the table: a class
    /// budgeted at two refuses the third slot though its table has more.
    #[test]
    fn a_budget_limits_a_class_below_its_table() {
        let mut pool: TxPool<SessionTxPoolApSmall> = TxPool::new();
        pool.set_budget(2);
        let a = pool.acquire().expect("one").0;
        let b = pool.acquire().expect("two").0;
        assert!(pool.acquire().is_none(), "the budget, not the table");
        assert!(pool.free_count() > 2);
        assert!(pool.give_back(a) && pool.give_back(b));
        pool.set_budget(usize::MAX);
        assert_eq!(pool.budget(), pool.capacity(), "clamped to the table");
    }

    /// The budget rule, worked: the defaults before a session shapes the queue
    /// (8 lanes of 2 x 65535 bytes) ask for exactly the small table and are
    /// clamped on the large one; an established UDP session without QoS (one
    /// lane of 2 x 1450) asks for 3 small and 2 large; with QoS, 8 times that.
    #[test]
    fn budgets_follow_the_lane_bounds() {
        let mut pools = TxPools::datagram();
        pools.size_budgets(&[2 * 65535; 8]);
        assert_eq!(pools.class_ref(0).budget(), 728);
        assert_eq!(pools.class_ref(0).budget(), pools.class_ref(0).capacity());
        assert_eq!(pools.class_ref(1).budget(), SLOT_COUNT, "24 asked, 16 held");
        pools.size_budgets(&[2 * 1450]);
        assert_eq!(
            (pools.class_ref(0).budget(), pools.class_ref(1).budget()),
            (3, 2)
        );
        pools.size_budgets(&[2 * 1450; 8]);
        assert_eq!(
            (pools.class_ref(0).budget(), pools.class_ref(1).budget()),
            (24, 16)
        );
        // A packing pool keeps its table whatever the lanes say.
        let mut stream = TxPools::stream();
        stream.size_budgets(&[1]);
        assert_eq!(stream.class_ref(0).budget(), SLOT_COUNT);
    }

    /// A frame takes the smallest class that holds it, and the next larger one
    /// when that class is out; past the largest, nothing.
    #[test]
    fn a_frame_takes_the_smallest_class_with_room() {
        let mut pools = TxPools::datagram();
        pools.size_budgets(&[2 * 1450]);
        let small = pools.acquire(1450).expect("small");
        assert_eq!(small.0, 0);
        let big = pools.acquire(1473).expect("past the small slot");
        assert_eq!(big.0, 1);
        let mut more = vec![small, big];
        more.push(pools.acquire(10).expect("small"));
        more.push(pools.acquire(10).expect("small"));
        let spill = pools.acquire(10).expect("small budget spent: large");
        assert_eq!(spill.0, 1);
        more.push(spill);
        assert!(pools.acquire(10).is_none(), "both budgets spent");
        assert!(!pools.has_room());
        assert!(pools.acquire(65601).is_none(), "no class holds it");
        for (class, idx, _) in more {
            assert!(pools.class(class).give_back(idx));
        }
        assert_eq!(pools.free_count(), pools.capacity());
    }
}

/// The pool as the pooled writer queue walks it: what a sender, the writer and
/// teardown each do to a slot, read off the pool's own count and states.
///
/// In this module rather than `writer_queue`'s so the lane that runs the pool's
/// tests by module path (`--lib link_tx_`) runs these too.
#[cfg(test)]
mod queue {
    use std::time::Duration;

    use tokio::io::AsyncWriteExt;
    use wz_session_core::link::RoomWait;
    use wz_session_core::qos::Priority;

    use super::TxSlotState as SlotState;
    use crate::session_tx_pool_ap::{SLOT_COUNT, SLOT_SIZE};
    use crate::writer_queue::{
        outbound_channel_pooled, OutboundTx, PooledSendError, Room, WriterHandle,
    };

    const P: Priority = Priority::DEFAULT;

    fn free(tx: &OutboundTx) -> usize {
        tx.tx_pool_stats().expect("a pooled queue").1
    }

    /// Frames copied in while the writer is not looking pack into ONE slot, and
    /// the writer is handed them as one run of bytes: the concatenation, which on
    /// a byte stream is the wire.
    #[test]
    fn frames_queued_together_share_one_slot_and_leave_as_one_run() {
        let (tx, mut rx) = outbound_channel_pooled();
        tx.send_framed(P, &[1, 0], b"a").expect("queued");
        tx.send_framed(P, &[2, 0], b"bc").expect("queued");
        tx.send_framed(P, &[3, 0], b"def").expect("queued");
        assert_eq!(tx.tx_pool_stats().expect("pooled").0.acquired, 1);
        let (_, wire) = rx.try_recv_wire_tagged().expect("one run");
        assert!(wire.is_pooled());
        assert_eq!(wire, [1, 0, b'a', 2, 0, b'b', b'c', 3, 0, b'd', b'e', b'f']);
        assert!(rx.try_recv_wire_tagged().is_none(), "and nothing else");
        drop(wire);
        assert_eq!(free(&tx), SLOT_COUNT);
    }

    /// The writer's walk on the pool's own states: a taken slot is ARMED, a
    /// started one BUSY, and a written one FREE again; every slot comes home.
    #[test]
    fn a_taken_slot_is_armed_then_busy_then_free() {
        let (tx, mut rx) = outbound_channel_pooled();
        tx.send_framed(P, &[1, 0], b"x").expect("queued");
        let (_, mut wire) = rx.try_recv_wire_tagged().expect("taken");
        let idx = wire.slot_index().expect("a slot");
        assert_eq!(tx.tx_slot_state(0, idx), Some(SlotState::DmaArmedTx));
        wire.begin_write();
        assert_eq!(tx.tx_slot_state(0, idx), Some(SlotState::DmaBusyTx));
        drop(wire);
        assert_eq!(tx.tx_slot_state(0, idx), Some(SlotState::Free));
        let (stats, free_now) = tx.tx_pool_stats().expect("pooled");
        assert_eq!(free_now, SLOT_COUNT);
        assert_eq!(
            (stats.acquired, stats.armed, stats.started, stats.completed),
            (1, 1, 1, 1)
        );
    }

    /// A slot taken and never started (the writer stopped before writing it)
    /// goes home through un-arm, not through the completion edge.
    #[test]
    fn a_slot_taken_and_never_started_is_unarmed() {
        let (tx, mut rx) = outbound_channel_pooled();
        tx.send_framed(P, &[1, 0], b"x").expect("queued");
        let (_, wire) = rx.try_recv_wire_tagged().expect("taken");
        drop(wire);
        let (stats, free_now) = tx.tx_pool_stats().expect("pooled");
        assert_eq!(
            (stats.unarmed, stats.completed, free_now),
            (1, 0, SLOT_COUNT)
        );
    }

    /// Through the real writer task: written slots come home through the
    /// completion edge counted as written, and the peer reads the frames.
    #[cfg(feature = "transport-link-tcp")]
    #[tokio::test]
    async fn the_writer_task_completes_every_slot_it_writes() {
        use tokio::io::AsyncReadExt;
        let (tx, rx) = outbound_channel_pooled();
        let (near, mut far) = tokio::io::duplex(1 << 16);
        let writer = WriterHandle::spawn_on(tokio::runtime::Handle::current(), rx, |queue| {
            crate::stream_link::writer_task(near, queue)
        });
        for round in 0..5u8 {
            tx.send_framed(P, &[1, 0], &[round]).expect("queued");
            let mut got = [0u8; 3];
            far.read_exact(&mut got).await.expect("the frame");
            assert_eq!(got, [1, 0, round]);
        }
        writer.drain().await;
        let mut tail = Vec::new();
        far.read_to_end(&mut tail).await.expect("eof");
        assert!(tail.is_empty());
        // Every slot the writer took, it started and completed as written.
        let (stats, free_now) = tx.tx_pool_stats().expect("pooled");
        assert_eq!(free_now, SLOT_COUNT);
        assert_eq!(stats.armed, stats.started);
        assert_eq!(stats.started, stats.completed);
        assert_eq!(stats.failed, 0);
        assert!(stats.completed >= 1);
    }

    /// A write that FAILS has ended too: its slot goes home through the
    /// completion edge, counted as failed, and nothing is left out.
    #[cfg(feature = "transport-link-tcp")]
    #[tokio::test]
    async fn a_failed_write_returns_its_slot() {
        struct Broken;
        impl tokio::io::AsyncWrite for Broken {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                _buf: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
            }
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }
        let (tx, rx) = outbound_channel_pooled();
        tx.send_framed(P, &[1, 0], b"x").expect("queued");
        let writer = WriterHandle::spawn_on(tokio::runtime::Handle::current(), rx, |queue| {
            crate::stream_link::writer_task(Broken, queue)
        });
        writer
            .into_join()
            .await
            .expect("the writer ends on the error");
        let (stats, free_now) = tx.tx_pool_stats().expect("pooled");
        assert_eq!(
            (stats.started, stats.completed, stats.failed, free_now),
            (1, 1, 1, SLOT_COUNT)
        );
        // And a frame sent after the writer has gone is refused, holding nothing.
        assert_eq!(
            tx.send_framed(P, &[1, 0], b"y"),
            Err(PooledSendError::Closed)
        );
        assert_eq!(free(&tx), SLOT_COUNT);
    }

    /// A CLOSING connection returns its slots: when the receiving half is
    /// dropped with frames still queued, nothing will write them, and every slot
    /// they held is free at once, though a sender still holds the queue.
    #[test]
    fn dropping_the_receiver_returns_every_queued_slot() {
        let (tx, rx) = outbound_channel_pooled();
        let big = vec![0x5Au8; SLOT_SIZE / 2 + 1];
        for _ in 0..3 {
            tx.send_framed(P, &[], &big).expect("queued");
        }
        assert_eq!(free(&tx), SLOT_COUNT - 3, "three frames that do not pack");
        drop(rx);
        let (stats, free_now) = tx.tx_pool_stats().expect("pooled");
        assert_eq!((stats.returned, free_now), (3, SLOT_COUNT));
    }

    /// A lend in progress when the receiver goes keeps its slot until the lend is
    /// settled, and then the slot goes home whatever the lend says.
    #[test]
    fn a_lend_open_when_the_receiver_goes_is_returned_when_settled() {
        let (tx, rx) = outbound_channel_pooled();
        let lend = tx.lend(P, 16).expect("lent");
        drop(rx);
        assert_eq!(free(&tx), SLOT_COUNT - 1, "the lend's slot is still lent");
        assert_eq!(tx.commit(lend, 4), Err(PooledSendError::Closed));
        assert_eq!(free(&tx), SLOT_COUNT);
    }

    /// A lend into a slot that already holds frames keeps the writer off that
    /// slot until it is committed, and the committed frame follows the earlier
    /// ones in the same run.
    #[test]
    fn a_lend_behind_queued_frames_holds_the_writer_until_committed() {
        let (tx, mut rx) = outbound_channel_pooled();
        tx.send_framed(P, &[1, 0], b"a").expect("queued");
        let lend = tx.lend(P, 8).expect("lent behind it");
        assert!(
            rx.try_recv_wire_tagged().is_none(),
            "the slot is being written by the lend"
        );
        // SAFETY: the lend is this test's, and 3 <= its capacity.
        unsafe { std::ptr::copy_nonoverlapping([1u8, 0, b'b'].as_ptr(), lend.base(), 3) };
        tx.commit(lend, 3).expect("committed");
        let (_, wire) = rx.try_recv_wire_tagged().expect("now taken");
        assert_eq!(wire, [1, 0, b'a', 1, 0, b'b']);
        assert_eq!(tx.tx_pool_stats().expect("pooled").0.acquired, 1);
    }

    /// A lend into a FRESH slot holds no frame yet, so frames queued after it
    /// leave first; the lent frame leaves when it is committed.
    #[test]
    fn an_empty_lend_does_not_hold_back_the_frames_behind_it() {
        let (tx, mut rx) = outbound_channel_pooled();
        let lend = tx.lend(P, 8).expect("lent");
        tx.send_framed(P, &[1, 0], b"z")
            .expect("queued after the lend");
        let (_, first) = rx.try_recv_wire_tagged().expect("the byte frame");
        assert_eq!(first, [1, 0, b'z']);
        // SAFETY: the lend is this test's, and 3 <= its capacity.
        unsafe { std::ptr::copy_nonoverlapping([1u8, 0, b'y'].as_ptr(), lend.base(), 3) };
        tx.commit(lend, 3).expect("committed");
        let (_, second) = rx.try_recv_wire_tagged().expect("the lent frame");
        assert_eq!(second, [1, 0, b'y']);
    }

    /// A lend given back holds no frame: its slot goes home.
    #[test]
    fn an_aborted_lend_returns_its_slot() {
        let (tx, mut rx) = outbound_channel_pooled();
        let lend = tx.lend(P, 8).expect("lent");
        assert_eq!(free(&tx), SLOT_COUNT - 1);
        tx.abort_lend(lend);
        assert_eq!(free(&tx), SLOT_COUNT);
        assert!(rx.try_recv_wire_tagged().is_none(), "and nothing is queued");
    }

    /// A DRY pool is congestion: room is refused while every slot is out, and
    /// given again when one comes home. The byte bound is far from full, so the
    /// answer is the pool's.
    #[test]
    fn a_dry_pool_is_no_room_until_a_slot_comes_home() {
        let (tx, _rx) = outbound_channel_pooled();
        let lends: Vec<_> = (0..SLOT_COUNT)
            .map(|_| tx.lend(P, SLOT_SIZE).expect("a whole slot each"))
            .collect();
        assert_eq!(free(&tx), 0);
        let now = RoomWait::Block { wait_us: 0 };
        assert_eq!(tx.wait_for_room(P, now), Room::Congested);
        let mut lends = lends.into_iter();
        tx.abort_lend(lends.next().expect("one"));
        assert_eq!(tx.wait_for_room(P, now), Room::Free);
        for lend in lends {
            tx.abort_lend(lend);
        }
        assert_eq!(free(&tx), SLOT_COUNT);
    }

    /// R3250 — every lane already has room for as many entries as the pool has
    /// slots, so a lane holding the whole pool (a burst the writer has not
    /// caught up with) never grew to hold it: its capacity is the one it had
    /// before the first frame.
    #[test]
    fn a_lane_holds_the_whole_pool_without_growing() {
        let (tx, _rx) = outbound_channel_pooled();
        let reserved = tx.lane_capacities();
        assert!(
            reserved.iter().all(|&room| room >= SLOT_COUNT),
            "every lane can hold every slot: {reserved:?}"
        );
        let lends: Vec<_> = (0..SLOT_COUNT)
            .map(|_| tx.lend(P, SLOT_SIZE).expect("a whole slot each"))
            .collect();
        assert_eq!(free(&tx), 0, "one lane holds the whole pool");
        assert_eq!(tx.lane_capacities(), reserved, "and it did not grow");
        for lend in lends {
            tx.abort_lend(lend);
        }
    }

    /// Past the pool a frame does not allocate and is not lost: the byte door
    /// WAITS for the writer to free a slot, and is released by it; and a sender
    /// waiting when the queue closes is told so.
    #[test]
    fn a_sender_past_the_pool_waits_for_the_writer_and_is_released_by_close() {
        let (tx, mut rx) = outbound_channel_pooled();
        let big = vec![0xA5u8; SLOT_SIZE / 2 + 1];
        for _ in 0..SLOT_COUNT {
            tx.send_framed(P, &[], &big).expect("queued");
        }
        assert_eq!(free(&tx), 0);
        // The waiter reports through a channel read with a deadline, so a slot
        // that never comes home reds this test instead of hanging the lane.
        let spawn_waiter = |big: Vec<u8>| {
            let tx = tx.clone();
            let (done, outcome) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = done.send(tx.send_framed(P, &[], &big));
            });
            outcome
        };
        let bound = Duration::from_secs(10);
        let outcome = spawn_waiter(big.clone());
        assert!(
            outcome.recv_timeout(Duration::from_millis(30)).is_err(),
            "no slot: the sender waits"
        );
        let (_, wire) = rx.try_recv_wire_tagged().expect("the writer takes one");
        drop(wire);
        assert_eq!(
            outcome
                .recv_timeout(bound)
                .expect("released by the slot coming home"),
            Ok(())
        );

        let outcome = spawn_waiter(big);
        assert!(outcome.recv_timeout(Duration::from_millis(30)).is_err());
        rx.close();
        assert_eq!(
            outcome.recv_timeout(bound).expect("released by the close"),
            Err(PooledSendError::Closed)
        );
    }

    /// No stream frame is too large for a slot, and the queue refuses the one
    /// that would be rather than spilling it to the heap.
    #[test]
    fn the_largest_stream_frame_is_queued_and_a_larger_one_refused() {
        let (tx, mut rx) = outbound_channel_pooled();
        let payload = vec![7u8; u16::MAX as usize];
        tx.send_framed(P, &[0xFF, 0xFF, 0, 0], &payload)
            .expect("fits one slot");
        let (_, wire) = rx.try_recv_wire_tagged().expect("taken");
        assert_eq!(wire.len(), super::MAX_STREAM_FRAME);
        assert_eq!(
            tx.send_framed(P, &[], &vec![0u8; SLOT_SIZE + 1]),
            Err(PooledSendError::TooLarge)
        );
    }

    /// A frame the link encodes in place takes the bytes it wrote and no more,
    /// so the next frame packs behind it; an encoder that fails queues nothing
    /// and gives back the slot it was handed.
    #[test]
    fn a_link_encoded_frame_takes_what_it_wrote_and_a_failed_one_nothing() {
        let (tx, mut rx) = outbound_channel_pooled();
        tx.send_encoded(P, 1516, |dst| {
            dst[..3].copy_from_slice(b"abc");
            Some(3)
        })
        .expect("queued");
        tx.send_framed(P, &[], b"de").expect("packed behind it");
        assert_eq!(
            tx.send_encoded(P, 1516, |_| None),
            Err(PooledSendError::Unencodable)
        );
        let (_, wire) = rx.try_recv_wire_tagged().expect("one run");
        assert_eq!(wire, *b"abcde");
        drop(wire);
        assert_eq!(free(&tx), SLOT_COUNT);
        // A failing encoder handed a FRESH slot gives it back.
        assert_eq!(
            tx.send_encoded(P, 1516, |_| None),
            Err(PooledSendError::Unencodable)
        );
        assert_eq!(free(&tx), SLOT_COUNT);
        assert!(rx.try_recv_wire_tagged().is_none());
    }

    /// A heap queue is untouched by all of this: it lends nothing from a pool and
    /// reports no pool.
    #[tokio::test]
    async fn a_heap_queue_has_no_pool() {
        let (tx, mut rx) = crate::writer_queue::outbound_channel();
        assert!(!tx.is_pooled());
        assert!(tx.tx_pool_stats().is_none());
        assert!(tx.lend(P, 8).is_none());
        tx.send(P, vec![1, 2]).expect("queued");
        let wire = rx.recv_wire().await.expect("a frame");
        assert!(!wire.is_pooled());
        let mut sink = Vec::new();
        sink.write_all(&wire).await.expect("write");
        assert_eq!(sink, [1, 2]);
    }
}

/// The DATAGRAM queue: one frame per slot, two classes, budgets from the shape.
#[cfg(test)]
mod datagram {
    use wz_session_core::link::{RoomWait, TxQueueShape};
    use wz_session_core::qos::Priority;

    use super::TxSlotState;
    use crate::writer_queue::{outbound_channel_datagram, OutboundTx, PooledSendError, Room};

    const P: Priority = Priority::DEFAULT;

    fn free(tx: &OutboundTx) -> usize {
        tx.tx_pool_stats().expect("a pooled queue").1
    }

    /// The shape an established UDP session without QoS gives its queue.
    fn udp_shape() -> TxQueueShape {
        TxQueueShape {
            sizes: [2; Priority::NUM],
            qos: false,
            batch_bytes: 1450,
        }
    }

    /// Datagrams are NOT packed: each is its own slot and its own frame, in
    /// order, and each takes the small class.
    #[test]
    fn each_datagram_is_one_slot_and_one_frame() {
        let (tx, mut rx) = outbound_channel_datagram();
        tx.send_framed(P, &[], b"one").expect("queued");
        tx.send_framed(P, &[], b"two").expect("queued");
        let (_, first) = rx.try_recv_wire_tagged().expect("first");
        let (_, second) = rx.try_recv_wire_tagged().expect("second");
        assert_eq!(
            (first, second),
            (b"one".to_vec().into(), b"two".to_vec().into())
        );
        let stats = tx.tx_pool_stats().expect("pooled").0;
        assert_eq!(stats.acquired, 2, "a slot each");
    }

    /// A frame larger than the small slot takes the large class; the largest
    /// datagram fits; past it, refused.
    #[test]
    fn a_large_datagram_takes_the_large_class() {
        let (tx, mut rx) = outbound_channel_datagram();
        tx.send_framed(P, &[], &[1u8; 1473]).expect("queued");
        let (_, wire) = rx.try_recv_wire_tagged().expect("taken");
        assert_eq!(wire.slot_class(), Some(1));
        assert_eq!(wire.len(), 1473);
        drop(wire);
        tx.send_framed(P, &[], &[2u8; 65507])
            .expect("the largest UDP datagram");
        assert_eq!(
            tx.send_framed(P, &[], &vec![0u8; 65601]),
            Err(PooledSendError::TooLarge)
        );
    }

    /// The budgets follow the shape: an established UDP session without QoS may
    /// hold 3 small slots and 2 large ones; past them the queue says "no room",
    /// and room comes back when a slot does.
    #[test]
    fn the_shape_sets_the_slot_budget_and_room_follows_it() {
        let (tx, mut rx) = outbound_channel_datagram();
        tx.reshape(udp_shape());
        for _ in 0..5 {
            tx.send_framed(P, &[], b"d").expect("within the budgets");
        }
        let now = RoomWait::Block { wait_us: 0 };
        assert_eq!(
            tx.wait_for_room(P, now),
            Room::Congested,
            "3 small + 2 large"
        );
        let (_, wire) = rx.try_recv_wire_tagged().expect("taken");
        drop(wire);
        assert_eq!(tx.wait_for_room(P, now), Room::Free);
        while let Some((_, wire)) = rx.try_recv_wire_tagged() {
            drop(wire);
        }
        assert_eq!(free(&tx), tx.tx_pool_capacity().expect("pooled"));
    }

    /// R3250 — the lanes' room follows the slot budget the shape sets: a session
    /// without QoS has one lane, with room for its whole budget (3 small + 2
    /// large), which it fills without growing; the lanes it no longer uses keep
    /// nothing. With QoS every lane has room for the whole budget again.
    #[test]
    fn the_lane_room_follows_the_slot_budget() {
        let (tx, mut rx) = outbound_channel_datagram();
        tx.reshape(udp_shape());
        let lane = P.wire_byte() as usize;
        let reserved = tx.lane_capacities();
        assert!(
            reserved[lane] >= 5,
            "the one lane holds the budget: {reserved:?}"
        );
        for (i, &room) in reserved.iter().enumerate() {
            if i != lane {
                assert_eq!(room, 0, "lane {i} is unreachable without QoS");
            }
        }
        let lends: Vec<_> = (0..5)
            .map(|_| tx.lend(P, 64).expect("within the budget"))
            .collect();
        assert_eq!(
            tx.lane_capacities(),
            reserved,
            "the full budget did not grow it"
        );
        for lend in lends {
            tx.abort_lend(lend);
        }
        while let Some((_, wire)) = rx.try_recv_wire_tagged() {
            drop(wire);
        }
        tx.reshape(TxQueueShape {
            qos: true,
            ..udp_shape()
        });
        let budget = 8 * (3 + 2);
        assert!(
            tx.lane_capacities().iter().all(|&room| room >= budget),
            "with QoS every lane can hold the whole budget"
        );
    }

    /// A lent datagram is a slot of its own, written in place and handed to the
    /// writer as it is; the pool records it armed.
    #[test]
    fn a_lent_datagram_is_its_slot() {
        let (tx, mut rx) = outbound_channel_datagram();
        let lend = tx.lend(P, 64).expect("lent");
        let at = lend.base() as usize;
        // SAFETY: the lend is this test's, and 5 <= its capacity.
        unsafe { std::ptr::copy_nonoverlapping(b"hello".as_ptr(), lend.base(), 5) };
        tx.commit(lend, 5).expect("committed");
        let (_, wire) = rx.try_recv_wire_tagged().expect("taken");
        assert_eq!(wire, *b"hello");
        assert_eq!(wire.as_ptr() as usize, at, "the very slot bytes");
        let idx = wire.slot_index().expect("a slot");
        assert_eq!(tx.tx_slot_state(0, idx), Some(TxSlotState::DmaArmedTx));
    }

    /// A lend after another frame on the same lane does not go behind it: the
    /// next datagram gets a fresh slot.
    #[test]
    fn a_lend_never_packs_behind_a_datagram() {
        let (tx, _rx) = outbound_channel_datagram();
        tx.send_framed(P, &[], b"x").expect("queued");
        let lend = tx.lend(P, 8).expect("lent");
        assert_eq!(tx.tx_pool_stats().expect("pooled").0.acquired, 2);
        tx.abort_lend(lend);
    }
}
