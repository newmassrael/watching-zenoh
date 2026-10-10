// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y589 — `runtime-zero-copy`: reassembly staged into the SCE-generated
//! buffer pool instead of on-demand heap buffers.
//!
//! This module is the FIRST CONSUMER of an `sce:kind="buffer-pool"` emit.
//! `sources/network/reassembly_pool_ap.scxml` has generated
//! [`crate::reassembly_pool_ap`] for many rounds and wz read only its
//! CONSTANTS out of it (`SLOT_COUNT` / `SLOT_SIZE` / `PER_PEER_QUOTA` /
//! `REASSEMBLY_TIMEOUT_MS`, in [`crate::reassembly`]); the seven-state
//! lifecycle FSM and its phantom-typed `Slot<S>` API had zero callers, which
//! is why `runtime-zero-copy` was a Cargo.toml flag that toggled nothing and
//! `preset-ap-full`'s "201 of 213" headline counted an atom that did not
//! exist (`scripts/lib/apfull_membership.py`, the INERT-MEMBER gate).
//!
//! ## What it buys, stated as a trade rather than an improvement
//!
//! The default arena ([`wz_session_core::chain_staging::HeapStaging`]) grows a
//! `Vec` per chain on demand: zero idle cost, and a chain's cost is what it
//! actually staged. This one reserves `SLOT_COUNT * SLOT_SIZE` bytes once, at
//! construction, and never allocates again.
//!
//! For a general deploy that is strictly worse. For the deploy `preset-ap-full`
//! names it is the point: an AUTOSAR-adjacent node wants its reassembly arena
//! sized before the first packet, so a chain cannot fail on an allocator under
//! load and the resident figure is knowable from the SCXML rather than from a
//! traffic pattern. Same protocol, different deploy decision — which is exactly
//! the axis [`ChainStaging`] was cut along.
//!
//! ## Which half of the pool FSM this uses, and why not the other
//!
//! MEASURED against the emit, not assumed: the author-reachable subgraph of the
//! generated FSM is `free -> cpu-mut -> {free, dma-armed-tx}`. `Slot<CpuRef>`
//! has methods but nothing constructs one, and `Slot<DmaArmedRx>` has no `impl`
//! block at all — the emit says the `dma-armed-rx -> dma-busy-rx -> cpu-ref`
//! progression happens "via IRQ handlers (not exposed in this atomic)".
//!
//! So this consumer uses `pool_acquire_for_encode` / `write` / `read` /
//! `pool_return`, and that is the honest fit rather than a fallback: a chain's
//! fragments are copied into the slot by the CPU, so there is no bus master to
//! arm it for. The DMA arms belong to the rows that have one.
//!
//! R3037 -- CORRECTED. The measurement above was true of the emit it read and
//! is not true of the tree: the emit now carries the `dma-armed-rx` arms, the
//! lwip link tier constructs them in `DescriptorRingRx`, and the link-RX arena
//! (`crate::link_rx_arena`) walks `free -> dma-armed-rx -> dma-busy-rx ->
//! cpu-ref -> free` for every frame it serves, with the reader as the bus
//! master and the table's no-op edge action. What this module says about ITS OWN
//! consumer, the reassembly staging, is unchanged: it writes by CPU.

//!
//! ## A completed chain is DELIVERED FROM its slot (ARCHITECTURE section 9.3)
//!
//! The Router used to hand a completed chain to its caller as a borrow of the
//! slot and reclaim the slot as the call returned, so the receive loop copied
//! the whole message out before decoding it. The arena now LENDS the slot
//! (`ChainStaging::lend`): the reassembled bytes are handed up as shared storage
//! that IS the slot, every message decoded out of them is a range of it, and the
//! slot stays out of the pool until the last range drops.
//!
//! The slot goes home LAZILY, and that is what keeps the steady state free of
//! allocation. Each pool slot has one shared view, made the first time the slot
//! is lent and kept by the arena; lending again reuses it, so a chain costs a
//! reference count and not an allocation. The arena knows a view has been let
//! go of when it holds the only reference to it, and it looks at the next
//! acquire (and whenever it is asked how much it has left): a slot whose view
//! is the arena's alone is returned to the pool then, through the generated
//! lifecycle's own `pool_return`. `PooledStaging::reclaim` does the same on
//! demand.
//!
//! The generated lifecycle offers no edge from `cpu-mut` to the shared-read
//! state for a slot the CPU wrote (its `cpu-ref` is reached only from a bus
//! master's completion), so a lent chain's slot stays in `cpu-mut` while it is
//! shared; what makes it read-only is that the arena keeps the handle and the
//! shared view has no way to write. Adding that edge is the buffer-pool
//! template's to decide (SCE owns it).

use std::sync::{Arc, Mutex};

use wz_session_core::chain_staging::{ChainStaging, StagingError};
use wz_session_core::link::{RxBytes, RxStorage};

use crate::reassembly_pool_ap::{CpuMut, ReassemblyPoolAp, Slot, SLOT_COUNT, SLOT_SIZE};

/// The arena's slot table, behind the lock that serialises acquire and return.
/// Shared with the views of lent slots, which keep the storage alive (and at
/// its address) for as long as any range of them lives.
struct PoolHome {
    slots: Mutex<Box<ReassemblyPoolAp>>,
}

/// One chain's reservation: a pool slot plus how much of it is written.
///
/// The `Slot<CpuMut>` handle is the reservation — the generated type is
/// `#[must_use]` and its transitions consume `self`, so a chain cannot hand its
/// slot to the link's TX path and keep staging into it. Rust rejects that at
/// compile time here, where the pre-seam `BoundedVec` had nothing to reject.
///
/// `data` is the slot's first byte, taken from the generated `write` accessor
/// when the slot was acquired, so staging into the chain needs no lock: the
/// handle is this chain's alone, and nothing else reads or writes the slot
/// until it is released or lent.
pub struct PooledChain {
    slot: Slot<CpuMut>,
    data: *mut u8,
    len: usize,
    /// Bytes lent out by the most recent [`ChainStaging::buf`] and not yet
    /// resolved by [`ChainStaging::commit`].
    ///
    /// This backing never grows to lend -- the slot is already full width --
    /// so the reservation is bookkeeping rather than storage. It is here so
    /// `commit` can refuse a caller that reports more than it was lent, which
    /// the heap backing refuses by construction, and the two arms answer the
    /// same.
    reserved: usize,
}

// SAFETY: the only reason this is not automatic is the raw pointer, and it
// names a slot this chain's handle reserved exclusively. A chain is only ever
// passed back to the arena that produced it, and that arena keeps the slot table
// (its `PoolHome`) alive and unmoved, so moving the chain between threads moves
// an exclusive, live reference and nothing else.
unsafe impl Send for PooledChain {}

impl PooledChain {
    /// Pool index of this chain's slot. Tracing / test observability, and the
    /// `buf_index` [`crate::uring`] submits under; the Router never reads it.
    pub fn slot_idx(&self) -> usize {
        self.slot.idx()
    }

    /// Bytes staged so far — the offset the next append lands at.
    pub fn staged_len(&self) -> usize {
        self.len
    }
}

/// A completed chain's slot as shared storage: what [`ChainStaging::lend`]
/// hands up. Read-only by construction (it has no way to write), and the slot
/// table it points into is kept alive by `home` for as long as any range of it
/// lives.
struct LentSlot {
    /// Held, never read: it is what keeps `data` pointing at live storage.
    _home: Arc<PoolHome>,
    /// First byte of the slot; valid for `SLOT_SIZE` bytes while `home` lives.
    data: *const u8,
    /// The chain's length, set by the arena each time it lends the slot, which
    /// it can do only while it holds the view's one reference.
    len: usize,
}

// SAFETY: the raw pointer names a slot the arena lent and does not write while
// any range of this view exists: the arena writes a slot again only after it has
// reacquired it, which it does only once it holds the only reference to this
// view (`Arc::get_mut` succeeds), so no reader can see a write. Every method
// here reads. `home` keeps the boxed table alive and at its address.
unsafe impl Send for LentSlot {}
// SAFETY: as for `Send`; shared readers only ever read.
unsafe impl Sync for LentSlot {}

impl RxStorage for LentSlot {
    fn as_slice(&self) -> &[u8] {
        // SAFETY: see the `Send` impl: `data` is the first byte of a slot of the
        // table `_home` keeps alive, `len <= CAP <= SLOT_SIZE` was checked when
        // the chain was staged, and no one writes the slot while this exists.
        unsafe { std::slice::from_raw_parts(self.data, self.len) }
    }
}

/// One pool slot's lend state, kept by the arena.
#[derive(Default)]
struct Lent {
    /// The slot's shared view, made the first time the slot is lent and reused
    /// on every lend after, so a lend costs no allocation.
    view: Option<Arc<LentSlot>>,
    /// The slot's handle while the slot is lent out and not yet home.
    handle: Option<Slot<CpuMut>>,
}

impl Lent {
    /// The slot is lent out and every range of it has been dropped: the view is
    /// the arena's alone again.
    fn is_home(&self) -> bool {
        self.handle.is_some()
            && self
                .view
                .as_ref()
                .is_some_and(|v| Arc::strong_count(v) == 1)
    }
}

/// The reserved arena: the SCE-generated pool, heap-placed, vending one slot
/// per in-flight chain.
///
/// `SLOTS` / `CAP` are the Router's dims and are checked against the pool's own
/// in [`ChainStaging::new`], so a Router asking for more than the SCXML
/// declares fails at construction rather than by refusing chains at runtime.
pub struct PooledStaging<const SLOTS: usize, const CAP: usize> {
    home: Arc<PoolHome>,
    /// Per pool slot, indexed by the slot's own index: what the arena keeps of
    /// a slot it lent.
    lent: [Lent; SLOT_COUNT],
    /// Chains being staged (acquired, neither released nor lent). With the lent
    /// slots still held, this is what the arena holds against the Router's
    /// `SLOTS`: the table may be larger, and a lent slot is no longer the
    /// Router's to count, so the arena enforces the dims itself.
    staged: usize,
}

impl<const SLOTS: usize, const CAP: usize> PooledStaging<SLOTS, CAP> {
    /// Slots on the generated pool's own freelist: the lifecycle FSM's answer,
    /// not this arena's bookkeeping. A lent slot whose last range has dropped is
    /// counted here only once it has been reclaimed ([`Self::reclaim`]).
    pub fn free_count(&self) -> usize {
        self.home
            .slots
            .lock()
            .map(|pool| pool.free_count())
            .unwrap_or(0)
    }

    /// The lifecycle state the generated pool records for slot `idx`.
    pub fn slot_state(&self, idx: usize) -> Option<crate::reassembly_pool_ap::SlotState> {
        self.home
            .slots
            .lock()
            .ok()
            .and_then(|pool| pool.slot_state(idx))
    }

    /// Which LENT slot an address lies inside, if any: the witness that bytes
    /// handed up are the slot and not a copy of it.
    ///
    /// The pool resolves only a slot's exact base (an interior pointer is
    /// refused rather than rounded down), and a decoded payload is interior. So
    /// the base is taken from the slot's view, the address is tested against
    /// `[base, base + SLOT_SIZE)`, and the base itself is then confirmed by the
    /// pool's own `slot_index_of_ptr`, so the answer is the pool's and not this
    /// arena's arithmetic.
    pub fn slot_of(&self, addr: *const u8) -> Option<usize> {
        let addr = addr as usize;
        let (idx, base) = self.lent.iter().enumerate().find_map(|(idx, lent)| {
            let base = lent.view.as_ref()?.data;
            let start = base as usize;
            (start <= addr && addr < start + SLOT_SIZE).then_some((idx, base))
        })?;
        let pool = self.home.slots.lock().ok()?;
        (pool.slot_index_of_ptr(base) == Some(idx)).then_some(idx)
    }

    /// Slots lent out (a completed chain handed up) and not yet home.
    pub fn lent_out(&self) -> usize {
        self.lent.iter().filter(|l| l.handle.is_some()).count()
    }

    /// Lent slots some range of which is still alive: out of the pool for good
    /// reason, unlike a lent slot only waiting to be reclaimed.
    fn held_by_the_application(&self) -> usize {
        self.lent
            .iter()
            .filter(|l| l.handle.is_some() && !l.is_home())
            .count()
    }

    /// Return to the pool every lent slot whose last range has dropped, through
    /// the generated lifecycle's `pool_return`. Run at every acquire; callable
    /// on its own so the pool's free count can be read settled. Returns how
    /// many slots went home.
    pub fn reclaim(&mut self) -> usize {
        if !self.lent.iter().any(Lent::is_home) {
            return 0;
        }
        // A poisoned lock forfeits the slots until a later call finds it whole
        // again; the only code that holds it does freelist bookkeeping.
        let Ok(mut guard) = self.home.slots.lock() else {
            return 0;
        };
        let pool: &mut ReassemblyPoolAp = &mut guard;
        let mut home = 0;
        for lent in self.lent.iter_mut() {
            if lent.is_home() {
                if let Some(handle) = lent.handle.take() {
                    handle.pool_return(pool);
                    home += 1;
                }
            }
        }
        home
    }

    // R311y589's `acquire_raw`, `release_raw` and `slot_ptr` STOOD HERE and
    // R2746 removed them, recorded rather than done quietly — the same way
    // R2736 recorded `commit_external` below, and for a reason one step
    // further on.
    //
    // All three existed for ONE caller, `crate::uring::FixedSlotRing::register`,
    // which needed every slot's address at once without starting chains. R2746
    // repointed that registration at the LINK-RX table: what `READ_FIXED` reads
    // off a socket is a FRAME, and a reassembly chain is one decode step later
    // and one granularity finer, so the adapter had been registering the wrong
    // pool. With the caller gone these are three `pub(crate)` methods nothing
    // can reach, and `-D dead-code` said so on the first build of the repoint.
    //
    // ⚠ Removing them is NOT a claim that reaching a slot's address is wrong.
    // It is that this arena is no longer where that is done: `LinkRxArena`
    // hands out a frame whose bytes are a slot, and `slot_of` maps an address
    // back to its index, so the address seam moved WITH the registration
    // instead of being left behind here.

    // R311y589's `commit_external` STOOD HERE and R2736 removed it, which is
    // recorded rather than done quietly. It recorded that an external writer
    // had put `n` bytes into a chain's slot -- the io_uring completion path --
    // and it was this arena's own method rather than part of the staging seam.
    //
    // `ChainStaging::commit` is now that, for both arenas, and the reason to
    // fold them is not tidiness: a chain's length is one fact, and this type
    // had two ways to move it. The uring path reached for the private one
    // because the trait had no answer; now it does, and `buf` hands out the
    // destination the same call would otherwise have derived by pointer
    // arithmetic on the slot.
}

impl<const SLOTS: usize, const CAP: usize> ChainStaging<SLOTS, CAP> for PooledStaging<SLOTS, CAP> {
    type Chain = PooledChain;

    fn new() -> Self {
        assert!(
            SLOTS <= SLOT_COUNT,
            "the Router wants more chains than the pool has slots"
        );
        assert!(
            CAP <= SLOT_SIZE,
            "the Router's per-chain cap exceeds the pool's slot width"
        );
        Self {
            home: Arc::new(PoolHome {
                slots: Mutex::new(heap_pool()),
            }),
            lent: core::array::from_fn(|_| Lent::default()),
            staged: 0,
        }
    }

    fn acquire(&mut self) -> Option<Self::Chain> {
        // A slot whose last range dropped since the previous acquire is the
        // pool's again before this one looks.
        self.reclaim();
        // The Router's dims, held here: a slot the application keeps is one of
        // them as surely as a chain being staged is.
        if self.staged + self.lent_out() >= SLOTS {
            return None;
        }
        let mut guard = self.home.slots.lock().ok()?;
        let pool: &mut ReassemblyPoolAp = &mut guard;
        let mut slot = pool.pool_acquire_for_encode()?;
        let data = slot.write(pool).as_mut_ptr();
        self.staged += 1;
        Some(PooledChain {
            slot,
            data,
            len: 0,
            reserved: 0,
        })
    }

    fn release(&mut self, chain: Self::Chain) {
        self.staged = self.staged.saturating_sub(1);
        // A poisoned lock forfeits the slot rather than panicking on a path a
        // peer can drive; the only code that holds it does freelist bookkeeping.
        if let Ok(mut guard) = self.home.slots.lock() {
            chain.slot.pool_return(&mut guard);
        }
    }

    fn append(&mut self, chain: &mut Self::Chain, payload: &[u8]) -> Result<(), StagingError> {
        let end = chain
            .len
            .checked_add(payload.len())
            .ok_or(StagingError::ChainCapExceeded)?;
        if end > CAP {
            return Err(StagingError::ChainCapExceeded);
        }
        // SAFETY: `[len, end)` lies in the slot (`end <= CAP <= SLOT_SIZE`), the
        // slot is this chain's alone (its handle), and `payload` is a borrow of
        // the caller's, which cannot overlap a slot the pool reserved.
        unsafe {
            std::ptr::copy_nonoverlapping(
                payload.as_ptr(),
                chain.data.add(chain.len),
                payload.len(),
            );
        }
        chain.len = end;
        Ok(())
    }

    fn bytes<'a>(&'a self, chain: &'a Self::Chain) -> &'a [u8] {
        // SAFETY: the first `len` bytes of the chain's own slot, which only
        // this chain writes and which the arena's table keeps alive.
        unsafe { std::slice::from_raw_parts(chain.data, chain.len) }
    }

    fn buf<'a>(
        &'a mut self,
        chain: &'a mut Self::Chain,
        want: usize,
    ) -> Result<&'a mut [u8], StagingError> {
        // THE POINT OF THE WHOLE SEAM: the slot is already `SLOT_SIZE` wide, so
        // this hands back a window into it and nothing is allocated, zeroed or
        // moved. A filler writing here writes where the chain already is, which
        // is what makes `append`'s copy avoidable rather than merely cheaper.
        let start = chain.len;
        let end = start
            .checked_add(want)
            .ok_or(StagingError::ChainCapExceeded)?;
        if end > CAP {
            return Err(StagingError::ChainCapExceeded);
        }
        // The chain's length does NOT advance here -- `commit` records what the
        // filler actually used. Keeping the two apart is why a short read
        // cannot stage bytes nobody wrote.
        chain.reserved = want;
        // SAFETY: `[start, end)` lies in the slot (`end <= CAP <= SLOT_SIZE`)
        // and the slot is this chain's alone; the returned borrow is tied to
        // `&mut chain`, so nothing else can reach the bytes while it lives.
        Ok(unsafe { std::slice::from_raw_parts_mut(chain.data.add(start), want) })
    }

    fn commit(&mut self, chain: &mut Self::Chain, filled: usize) -> Result<(), StagingError> {
        if filled > chain.reserved {
            return Err(StagingError::ChainCapExceeded);
        }
        let end = chain
            .len
            .checked_add(filled)
            .ok_or(StagingError::ChainCapExceeded)?;
        if end > CAP {
            return Err(StagingError::ChainCapExceeded);
        }
        // Nothing is copied or truncated: the bytes are already in the slot and
        // only the length moves. The heap backing gives its unused tail back
        // instead -- opposite mechanics, identical observable.
        chain.len = end;
        chain.reserved = 0;
        Ok(())
    }

    /// The live figure: the Router's `SLOTS` less the chains being staged and
    /// the lent slots some range of which still lives. A lent slot whose last
    /// range has dropped counts as available (it goes home at the next
    /// acquire); one the application still holds does not, which is what makes
    /// a pool the application keeps hold of run dry, and the Router refuse.
    fn available(&self) -> usize {
        SLOTS.saturating_sub(self.staged + self.held_by_the_application())
    }

    /// ARCHITECTURE section 9.3 -- the completed chain handed up AS its slot.
    /// The slot's shared view is reused when the slot has been lent before
    /// (no allocation), and made once otherwise; the handle is kept here until
    /// the last range of the view drops and the slot is reclaimed.
    fn lend(&mut self, chain: Self::Chain) -> Result<RxBytes, Self::Chain> {
        let PooledChain {
            slot, data, len, ..
        } = chain;
        let lent = &mut self.lent[slot.idx()];
        debug_assert!(lent.handle.is_none(), "a slot is lent once at a time");
        let view = match lent.view.as_mut() {
            Some(view) => {
                // The slot came out of the pool, so it was reclaimed, so this
                // arena holds the view's only reference.
                let Some(unique) = Arc::get_mut(view) else {
                    // Unreachable by the argument above; giving the chain back
                    // keeps the bytes correct (it is delivered borrowed).
                    return Err(PooledChain {
                        slot,
                        data,
                        len,
                        reserved: 0,
                    });
                };
                unique.len = len;
                view.clone()
            }
            None => lent
                .view
                .insert(Arc::new(LentSlot {
                    _home: self.home.clone(),
                    data,
                    len,
                }))
                .clone(),
        };
        lent.handle = Some(slot);
        self.staged = self.staged.saturating_sub(1);
        let storage: Arc<dyn RxStorage> = view;
        Ok(RxBytes::shared(storage, 0..len).expect("the chain lies in its slot"))
    }
}

/// Build the pool IN the heap allocation, never on the stack.
///
/// R311y589 — `Box::new(ReassemblyPoolAp::new())` does not do this, and that is
/// MEASURED rather than inferred from what `opt-level=0` is said to do: the
/// naive form was written first and
/// `a_debug_build_can_construct_the_ap_pool` reported
/// `has overflowed its stack / fatal runtime error: stack overflow`. The emit's
/// `new()` returns `Self { storage: [[0u8; SLOT_SIZE]; SLOT_COUNT], .. }` BY
/// VALUE — 32 MiB for the AP pool — and `Box::new` receives that value, so the
/// temporary exists before the allocation does. A release build may elide it;
/// a debug build aborts with SIGABRT and no diagnostic naming the pool.
///
/// So the allocation is made first and zeroed in place. That is the correct
/// value rather than a convenient one: `storage` is `[[u8; _]; _]`, for which
/// all-zero is the same array `new()` writes, and `slot_states` is
/// `[SlotState; _]` whose `Free` variant carries the explicit discriminant `0`
/// in the emit — so the zero pattern IS `new()`'s result, field for field.
///
/// The `debug_assert` re-establishes that against the constructed pool instead
/// of trusting the paragraph. A regenerated emit that renumbered `SlotState`
/// would leave every slot in a state nobody declared, and this is what turns
/// that into a failing test rather than a pool that quietly refuses every
/// acquire.
fn heap_pool() -> Box<ReassemblyPoolAp> {
    // SAFETY: `alloc_zeroed` returns a block of `Layout::new::<T>()` — correctly
    // sized AND correctly aligned, which a `vec![0u8; size_of::<T>()]` cast
    // would not be. The all-zero pattern is a valid, intended `ReassemblyPoolAp`
    // (see above), so the block holds an initialised value before `from_raw`
    // takes ownership of it.
    let pool = unsafe {
        let layout = core::alloc::Layout::new::<ReassemblyPoolAp>();
        let raw = std::alloc::alloc_zeroed(layout) as *mut ReassemblyPoolAp;
        if raw.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        Box::from_raw(raw)
    };
    debug_assert_eq!(
        pool.free_count(),
        SLOT_COUNT,
        "the zero pattern is no longer the pool's initial state: the emit's \
         SlotState discriminants moved and heap_pool must be rewritten"
    );
    pool
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reassembly_pool_ap::SlotState;
    use wz_session_core::chain_staging::HeapStaging;
    use wz_session_core::extfragment::FragmentMarkers;
    use wz_session_core::qos::Priority;
    use wz_session_core::reassembly_dispatch::{
        Fragment, IngestOutcome, ReassemblyConfig, ReassemblyDispatcher,
    };

    /// Test dims: small enough that arena exhaustion is reachable, and a real
    /// SUBSET of what the AP Router asks for, so `PooledStaging::new`'s dim
    /// assertions are exercised on their passing side.
    const SLOTS: usize = 4;
    const CAP: usize = 64;
    const MASK: u64 = 0xFF;

    type Pooled = ReassemblyDispatcher<SLOTS, CAP, PooledStaging<SLOTS, CAP>>;
    type Heaped = ReassemblyDispatcher<SLOTS, CAP, HeapStaging<SLOTS, CAP>>;

    fn frag<'a>(peer: &'a [u8], sn: u64, more: u8, payload: &'a [u8]) -> Fragment<'a> {
        Fragment {
            peer_key: peer,
            reliable: true,
            sn,
            more,
            payload,
            priority: Priority::DEFAULT,
            markers: FragmentMarkers::NONE,
        }
    }

    /// Drive one three-fragment chain and return what was delivered.
    ///
    /// Generic over the arena so both arms below run the SAME sequence — a
    /// hand-copied second sequence could drift, and the comparison would then
    /// be measuring the fixtures rather than the arenas.
    fn run_one_chain<S>(router: &mut ReassemblyDispatcher<SLOTS, CAP, S>) -> Option<Vec<u8>>
    where
        S: ChainStaging<SLOTS, CAP>,
    {
        let mut got: Option<Vec<u8>> = None;
        for (sn, more, part) in [
            (0u64, 1u8, b"hello ".as_slice()),
            (1, 1, b"pooled ".as_slice()),
            (2, 0, b"world".as_slice()),
        ] {
            router.ingest(frag(b"peer-a", sn, more, part), MASK, 0, |bytes| {
                got = Some(bytes.to_vec())
            });
        }
        got
    }

    /// THE MEASUREMENT this module's constructor exists for.
    ///
    /// The AP arena is 32 MiB of storage. Built by value and then moved into a
    /// `Box`, that value lives on the stack first and a debug build has no
    /// optimiser to elide it — measured, and the reason `heap_pool` is not the
    /// one-liner it looks like it should be.
    #[test]
    fn a_debug_build_can_construct_the_ap_pool() {
        let arena: PooledStaging<SLOT_COUNT, SLOT_SIZE> = ChainStaging::new();
        assert_eq!(arena.free_count(), SLOT_COUNT);
        assert_eq!(
            ChainStaging::<SLOT_COUNT, SLOT_SIZE>::available(&arena),
            SLOT_COUNT
        );
    }

    /// THE COMPARISON. The seam swaps only WHERE the bytes land, so both
    /// arenas must deliver the same message for the same fragments. The chain
    /// FSM, the SN gate and the quota are literally the same code on both
    /// sides, so a disagreement can only be a staging bug.
    #[test]
    fn the_two_arenas_reassemble_the_same_bytes() {
        let mut heap: Heaped = ReassemblyDispatcher::new(ReassemblyConfig::new(4, 5_000));
        let mut pooled: Pooled = ReassemblyDispatcher::new(ReassemblyConfig::new(4, 5_000));

        let from_heap = run_one_chain(&mut heap);
        let from_pool = run_one_chain(&mut pooled);

        assert_eq!(from_heap.as_deref(), Some(b"hello pooled world".as_slice()));
        assert_eq!(from_pool, from_heap);
    }

    /// THE PROPERTY `buf` EXISTS FOR: a filler writes where the chain ALREADY
    /// IS, so the bytes it produces are never moved afterwards.
    ///
    /// Asserted by ADDRESS, and that is the whole design of this test. A `buf`
    /// that handed back a scratch buffer and copied it in on `commit` would
    /// satisfy every assertion about length and content -- so those assertions
    /// cannot fail for the defect being ruled out, and a test made of them
    /// would be green against the implementation this seam exists to replace.
    /// The address is the one observable the copy cannot reproduce.
    #[test]
    fn a_pooled_buf_is_the_chains_own_bytes_rather_than_a_copy() {
        let mut arena: PooledStaging<SLOTS, CAP> = ChainStaging::new();
        let mut chain = ChainStaging::<SLOTS, CAP>::acquire(&mut arena).expect("slots");

        let lent = ChainStaging::<SLOTS, CAP>::buf(&mut arena, &mut chain, 8).expect("room for 8");
        assert_eq!(lent.len(), 8, "buf lends exactly what was asked for");
        let written_at = lent.as_ptr() as usize;
        lent.copy_from_slice(b"pooled!!");

        ChainStaging::<SLOTS, CAP>::commit(&mut arena, &mut chain, 8).expect("8 of 8");

        let read = ChainStaging::<SLOTS, CAP>::bytes(&arena, &chain);
        assert_eq!(read, b"pooled!!", "the bytes the filler wrote are staged");
        assert_eq!(
            read.as_ptr() as usize,
            written_at,
            "the staged bytes must BE the ones the filler wrote, not a copy of them"
        );

        ChainStaging::<SLOTS, CAP>::release(&mut arena, chain);
    }

    /// A SHORT FILL stages what was written and not what was lent.
    ///
    /// This is why `buf` and `commit` are two calls rather than one. A socket
    /// read returns fewer bytes than its buffer whenever the peer sent fewer,
    /// which is the ordinary case; a seam that staged the reservation itself
    /// would append whatever the slot happened to hold after the short read.
    ///
    /// Run over BOTH arenas in one test, because the two resolve a short fill
    /// by opposite mechanics -- the pooled one advances a length it never
    /// moved, the heap one gives back a tail it had to materialise -- and the
    /// thing being asserted is that those are observationally the same. Two
    /// separate tests could each pass while the arenas disagreed.
    #[test]
    fn a_short_fill_stages_only_what_was_written_on_both_arenas() {
        let mut pooled: PooledStaging<SLOTS, CAP> = ChainStaging::new();
        let mut pooled_chain = ChainStaging::<SLOTS, CAP>::acquire(&mut pooled).expect("slots");
        let lent = ChainStaging::<SLOTS, CAP>::buf(&mut pooled, &mut pooled_chain, 8).expect("8");
        lent[..3].copy_from_slice(b"abc");
        ChainStaging::<SLOTS, CAP>::commit(&mut pooled, &mut pooled_chain, 3).expect("3 of 8");
        let from_pool = ChainStaging::<SLOTS, CAP>::bytes(&pooled, &pooled_chain).to_vec();

        let mut heaped: HeapStaging<SLOTS, CAP> = ChainStaging::new();
        let mut heap_chain = ChainStaging::<SLOTS, CAP>::acquire(&mut heaped).expect("slots");
        let lent = ChainStaging::<SLOTS, CAP>::buf(&mut heaped, &mut heap_chain, 8).expect("8");
        lent[..3].copy_from_slice(b"abc");
        ChainStaging::<SLOTS, CAP>::commit(&mut heaped, &mut heap_chain, 3).expect("3 of 8");
        let from_heap = ChainStaging::<SLOTS, CAP>::bytes(&heaped, &heap_chain).to_vec();

        assert_eq!(from_pool, b"abc", "the five unwritten bytes are not staged");
        assert_eq!(
            from_heap, from_pool,
            "both arenas resolve a short fill alike"
        );

        ChainStaging::<SLOTS, CAP>::release(&mut pooled, pooled_chain);
        ChainStaging::<SLOTS, CAP>::release(&mut heaped, heap_chain);
    }

    /// `commit` refuses a caller that reports more than it was lent, on both
    /// arenas. The heap one would otherwise truncate below where the chain
    /// started; the pooled one would stage slot bytes nobody wrote.
    #[test]
    fn commit_refuses_more_than_was_lent_on_both_arenas() {
        let mut pooled: PooledStaging<SLOTS, CAP> = ChainStaging::new();
        let mut pooled_chain = ChainStaging::<SLOTS, CAP>::acquire(&mut pooled).expect("slots");
        ChainStaging::<SLOTS, CAP>::buf(&mut pooled, &mut pooled_chain, 4).expect("4");
        assert!(ChainStaging::<SLOTS, CAP>::commit(&mut pooled, &mut pooled_chain, 5).is_err());

        let mut heaped: HeapStaging<SLOTS, CAP> = ChainStaging::new();
        let mut heap_chain = ChainStaging::<SLOTS, CAP>::acquire(&mut heaped).expect("slots");
        ChainStaging::<SLOTS, CAP>::buf(&mut heaped, &mut heap_chain, 4).expect("4");
        assert!(ChainStaging::<SLOTS, CAP>::commit(&mut heaped, &mut heap_chain, 5).is_err());

        ChainStaging::<SLOTS, CAP>::release(&mut pooled, pooled_chain);
        ChainStaging::<SLOTS, CAP>::release(&mut heaped, heap_chain);
    }

    /// The RESERVATION is bounded by `CAP` too, which is the other direction
    /// from the test above: that one refuses a commit LARGER than what was
    /// lent, this one refuses lending past the chain's ceiling at all.
    ///
    /// R2746 moved this here from `crate::uring`, where it had been the bound
    /// on a `READ_FIXED` destination. That module now reads into a LINK-RX
    /// frame and touches no chain, so the test had outlived its module while
    /// remaining true about this one — and its twin above is the reason this is
    /// where a reader looks for it.
    ///
    /// Each commit resolves its own reservation, which is why this reserves
    /// first: a `buf` call with nothing outstanding is refused on a different
    /// rule and would pass for the wrong reason.
    #[test]
    fn a_reservation_past_the_cap_is_refused() {
        let mut pooled: PooledStaging<SLOTS, CAP> = ChainStaging::new();
        let mut chain = ChainStaging::<SLOTS, CAP>::acquire(&mut pooled).expect("slots");

        ChainStaging::<SLOTS, CAP>::buf(&mut pooled, &mut chain, CAP)
            .expect("a full-CAP reservation");
        assert!(ChainStaging::<SLOTS, CAP>::commit(&mut pooled, &mut chain, CAP).is_ok());

        assert!(
            ChainStaging::<SLOTS, CAP>::buf(&mut pooled, &mut chain, 1).is_err(),
            "one byte past CAP must be refused at the reservation"
        );
        ChainStaging::<SLOTS, CAP>::release(&mut pooled, chain);
    }

    /// The GENERATED FSM is what moved, not just this module's counter.
    ///
    /// `available()` alone would pass while the pool sat untouched — an arena
    /// could stage into a private `Vec` and decrement a number. So the
    /// assertion is on `slot_state`, which only the emit's own transitions
    /// write: `free -> cpu-mut` on acquire, `cpu-mut -> free` on return.
    #[test]
    fn a_live_chain_holds_its_pool_slot_in_cpu_mut() {
        let mut router: Pooled = ReassemblyDispatcher::new(ReassemblyConfig::new(4, 5_000));
        assert_eq!(router.staging().free_count(), SLOT_COUNT);

        router.ingest(frag(b"peer-a", 0, 1, b"part"), MASK, 0, |_| {});
        assert_eq!(router.active_chains(), 1);
        assert_eq!(
            router.staging().free_count(),
            SLOT_COUNT - 1,
            "a live chain must hold a pool slot"
        );
        assert_eq!(
            (0..SLOT_COUNT)
                .filter(|i| router.staging().slot_state(*i) == Some(SlotState::CpuMut))
                .count(),
            1,
            "exactly one slot must be in cpu-mut while one chain is live"
        );

        router.ingest(frag(b"peer-a", 1, 0, b"-end"), MASK, 0, |_| {});
        assert_eq!(router.active_chains(), 0);
        assert_eq!(
            router.staging().free_count(),
            SLOT_COUNT,
            "a completed chain must return its pool slot"
        );
    }

    /// THE LEAK CHECK, and the reason `available()` is on the trait.
    ///
    /// Every terminal path — completion, capacity overflow, out-of-order abort,
    /// deadline sweep — must return the chain's staging. A path that forgot
    /// would free the Router's OWN slot either way, so `active_chains()` would
    /// look right and the arena would run dry `SLOTS` chains later in an
    /// unrelated test. This catches it at the leak.
    #[test]
    fn every_terminal_path_returns_the_chains_staging() {
        let mut router: Pooled = ReassemblyDispatcher::new(ReassemblyConfig::new(4, 5_000));
        fn quiescent(r: &Pooled) -> bool {
            r.active_chains() + r.staging_available() == SLOTS
        }

        // 1. Completion.
        run_one_chain(&mut router);
        assert!(quiescent(&router), "completion leaked staging");

        // 2. Capacity overflow: CAP is 64, so a 100-byte first fragment aborts.
        let big = [0xABu8; 100];
        assert!(matches!(
            router.ingest(frag(b"peer-b", 0, 1, &big), MASK, 0, |_| {}),
            IngestOutcome::Aborted(_)
        ));
        assert!(quiescent(&router), "capacity overflow leaked staging");

        // 3. Out-of-order abort mid-chain.
        router.ingest(frag(b"peer-c", 0, 1, b"a"), MASK, 0, |_| {});
        assert!(matches!(
            router.ingest(frag(b"peer-c", 9, 1, b"b"), MASK, 0, |_| {}),
            IngestOutcome::Aborted(_)
        ));
        assert!(quiescent(&router), "out-of-order abort leaked staging");

        // 4. The deadline sweep.
        router.ingest(frag(b"peer-d", 0, 1, b"a"), MASK, 0, |_| {});
        assert_eq!(router.sweep(1_000_000), 1);
        assert!(quiescent(&router), "the sweep leaked staging");

        assert_eq!(
            router.staging().free_count(),
            SLOT_COUNT,
            "the generated pool must agree that every slot came back"
        );
    }

    /// The reserved arena really is bounded: `SLOTS` live chains fill it and
    /// the Router refuses the next rather than allocating. This is the property
    /// the feature exists for, so it is asserted rather than inferred from the
    /// absence of a `Vec` in the type.
    #[test]
    fn the_arena_is_exhaustible_and_the_router_refuses_rather_than_growing() {
        let mut router: Pooled =
            ReassemblyDispatcher::new(ReassemblyConfig::new(SLOTS as u16, 5_000));
        for i in 0..SLOTS {
            let peer = [b'p', b'0' + i as u8];
            assert!(
                matches!(
                    router.ingest(frag(&peer, 0, 1, b"x"), MASK, 0, |_| {}),
                    IngestOutcome::Begun
                ),
                "chain {i} should have started"
            );
        }
        assert_eq!(router.staging_available(), 0);
        assert_eq!(router.staging().free_count(), SLOT_COUNT - SLOTS);

        assert!(
            matches!(
                router.ingest(frag(b"pz", 0, 1, b"x"), MASK, 0, |_| {}),
                IngestOutcome::Refused(_)
            ),
            "a full arena must refuse, not grow"
        );
    }

    // ARCHITECTURE section 9.3 -- the completed chain LENT out of the arena.

    use wz_session_core::link::RxBytes;
    use wz_session_core::reassembly_dispatch::ChainBytes;

    /// Drive a three-fragment chain through the lending ingest and keep what
    /// was delivered.
    fn lend_one_chain<S>(router: &mut ReassemblyDispatcher<SLOTS, CAP, S>, peer: &[u8]) -> RxBytes
    where
        S: ChainStaging<SLOTS, CAP>,
    {
        let mut got: Option<RxBytes> = None;
        for (sn, more, part) in [
            (0u64, 1u8, b"hello ".as_slice()),
            (1, 1, b"pooled ".as_slice()),
            (2, 0, b"world".as_slice()),
        ] {
            let outcome = router.ingest_lending(frag(peer, sn, more, part), MASK, 0, |chain| {
                got = Some(match chain {
                    ChainBytes::Lent(bytes) => bytes,
                    ChainBytes::Borrowed(_) => panic!("both arenas lend a completed chain"),
                })
            });
            assert!(!matches!(
                outcome,
                IngestOutcome::Aborted(_) | IngestOutcome::Refused(_)
            ));
        }
        got.expect("the chain completed")
    }

    /// THE CLAIM: the delivered bytes ARE the slot, by address, and the slot
    /// stays out of the pool while any range of it lives -- a clone or a
    /// sub-range included -- and goes home once the last one drops.
    #[test]
    fn a_lent_chain_is_its_slot_until_its_last_range_drops() {
        let mut router: Pooled = ReassemblyDispatcher::new(ReassemblyConfig::new(4, 5_000));
        let bytes = lend_one_chain(&mut router, b"peer-a");
        assert_eq!(bytes.as_slice(), b"hello pooled world");
        let idx = router
            .staging()
            .slot_of(bytes.as_ptr())
            .expect("the delivered bytes lie in a pool slot, not in a copy");
        assert!(bytes.is_shared(), "shared storage, not an owned vector");
        assert_eq!(router.active_chains(), 0, "the Router's own slot is free");
        assert_eq!(router.staging().lent_out(), 1);
        assert_eq!(router.staging_available(), SLOTS - 1);
        assert_eq!(router.staging().slot_state(idx), Some(SlotState::CpuMut));

        let world = bytes.subslice(13..18).expect("a range of it");
        let copy = bytes.clone();
        drop(bytes);
        drop(copy);
        assert_eq!(world.as_slice(), b"world");
        assert_eq!(
            router.staging_available(),
            SLOTS - 1,
            "a range of the chain still holds its slot"
        );
        drop(world);
        assert_eq!(
            router.staging_available(),
            SLOTS,
            "the last range dropped: the slot is available"
        );
        assert_eq!(
            router.staging_mut_reclaim(),
            1,
            "and goes home through the pool"
        );
        assert_eq!(router.staging().slot_state(idx), Some(SlotState::Free));
        assert_eq!(router.staging().free_count(), SLOT_COUNT);
        assert_eq!(router.staging().lent_out(), 0);
    }

    /// Lending again reuses the slot's view: a steady stream of chains through
    /// one slot keeps arriving in the same slot, and the bytes of each are its
    /// own (the previous chain's are never read back).
    #[test]
    fn a_slot_lent_again_delivers_the_new_chain_where_the_old_one_was() {
        let mut router: Pooled = ReassemblyDispatcher::new(ReassemblyConfig::new(4, 5_000));
        let first = lend_one_chain(&mut router, b"peer-a");
        let at = first.as_ptr();
        drop(first);
        let second = lend_one_chain(&mut router, b"peer-b");
        assert_eq!(second.as_slice(), b"hello pooled world");
        assert_eq!(
            router.staging().lent_out(),
            1,
            "the first slot went home first"
        );
        assert_eq!(
            router.staging().slot_of(second.as_ptr()),
            router.staging().slot_of(at),
            "the reclaimed slot is the one reused"
        );
    }

    /// A pool the application keeps hold of runs DRY: the Router refuses the
    /// next chain, counted as pool exhaustion, rather than allocating; and once
    /// one held chain is dropped the next chain is admitted.
    #[test]
    fn a_pool_the_application_holds_runs_dry_and_the_router_refuses_the_next_chain() {
        let mut router: Pooled =
            ReassemblyDispatcher::new(ReassemblyConfig::new(SLOTS as u16, 5_000));
        let held: Vec<RxBytes> = (0..SLOTS)
            .map(|i| lend_one_chain(&mut router, &[b'p', b'0' + i as u8]))
            .collect();
        assert_eq!(router.staging_available(), 0);
        assert_eq!(
            router.ingest(frag(b"pz", 0, 1, b"x"), MASK, 0, |_| {}),
            IngestOutcome::Refused(
                wz_session_core::reassembly_dispatch::RefuseReason::PoolExhausted
            ),
            "a dry pool is an explicit refusal"
        );
        assert_eq!(router.active_chains(), 0, "the refusal left nothing staged");
        drop(held);
        assert!(matches!(
            router.ingest(frag(b"pz", 0, 1, b"x"), MASK, 0, |_| {}),
            IngestOutcome::Begun
        ));
    }

    /// THE LEAK CHECK on the lending path: completion lent then dropped,
    /// capacity overflow, out-of-order abort and the sweep all leave the arena
    /// whole, and the generated pool agrees once reclaimed.
    #[test]
    fn every_terminal_path_of_the_lending_ingest_returns_the_slot() {
        let mut router: Pooled = ReassemblyDispatcher::new(ReassemblyConfig::new(4, 5_000));
        fn quiescent(r: &Pooled) -> bool {
            r.active_chains() + r.staging_available() == SLOTS
        }
        drop(lend_one_chain(&mut router, b"peer-a"));
        assert!(quiescent(&router), "a lent completion leaked its slot");
        let big = [0xABu8; 100];
        assert!(matches!(
            router.ingest_lending(frag(b"peer-b", 0, 1, &big), MASK, 0, |_| {}),
            IngestOutcome::Aborted(_)
        ));
        assert!(quiescent(&router), "capacity overflow leaked staging");
        router.ingest_lending(frag(b"peer-c", 0, 1, b"a"), MASK, 0, |_| {});
        assert!(matches!(
            router.ingest_lending(frag(b"peer-c", 9, 1, b"b"), MASK, 0, |_| {}),
            IngestOutcome::Aborted(_)
        ));
        assert!(quiescent(&router), "out-of-order abort leaked staging");
        router.ingest_lending(frag(b"peer-d", 0, 1, b"a"), MASK, 0, |_| {});
        assert_eq!(router.sweep(1_000_000), 1);
        assert!(quiescent(&router), "the sweep leaked staging");
        router.staging_mut_reclaim();
        assert_eq!(router.staging().free_count(), SLOT_COUNT);
    }

    /// THE COMPARISON on the lending path: both arenas lend, and they lend the
    /// same bytes. The heap arena's are its buffer moved, the pooled arena's
    /// its slot; neither is a copy made at completion.
    #[test]
    fn the_two_arenas_lend_the_same_bytes() {
        let mut heap: Heaped = ReassemblyDispatcher::new(ReassemblyConfig::new(4, 5_000));
        let mut pooled: Pooled = ReassemblyDispatcher::new(ReassemblyConfig::new(4, 5_000));
        let from_heap = lend_one_chain(&mut heap, b"peer-a");
        let from_pool = lend_one_chain(&mut pooled, b"peer-a");
        assert_eq!(from_heap.as_slice(), from_pool.as_slice());
        assert!(from_heap.is_shared() && from_pool.is_shared());
        assert_eq!(
            heap.active_chains() + heap.staging_available(),
            SLOTS,
            "the heap arena counts a lent buffer back at once"
        );
    }

    /// The Router's reach to its arena for a reclaim, for these tests: the
    /// dispatcher hands out only a shared borrow of its staging.
    trait ReclaimThroughRouter {
        fn staging_mut_reclaim(&mut self) -> usize;
    }

    impl ReclaimThroughRouter for Pooled {
        fn staging_mut_reclaim(&mut self) -> usize {
            // A chain start reclaims; a refused one stages nothing. A peer key
            // no test uses and a fragment that completes at once leave the
            // Router as they found it.
            let before = self.staging().lent_out();
            self.ingest(frag(b"reclaim", 0, 0, b""), MASK, 0, |_| {});
            before - self.staging().lent_out()
        }
    }
}
