// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! `pool_return`, and that is the honest fit rather than a fallback: a tokio
//! host has no DMA controller, so the RX arm has no meaning here. The DMA arms
//! belong to the lwip pools (`out/wz-link-lwip/*_rx_pool_mcu.rs`), and when a
//! consumer for those lands it will exercise the half this one cannot.

use wz_session_core::chain_staging::{ChainStaging, StagingError};

use crate::reassembly_pool_ap::{CpuMut, ReassemblyPoolAp, Slot, SLOT_COUNT, SLOT_SIZE};

/// One chain's reservation: a pool slot plus how much of it is written.
///
/// The `Slot<CpuMut>` handle is the reservation — the generated type is
/// `#[must_use]` and its transitions consume `self`, so a chain cannot hand its
/// slot to the link's TX path and keep staging into it. Rust rejects that at
/// compile time here, where the pre-seam `BoundedVec` had nothing to reject.
pub struct PooledChain {
    slot: Slot<CpuMut>,
    len: usize,
}

impl PooledChain {
    /// Pool index of this chain's slot. Tracing / test observability; the
    /// Router never reads it.
    pub fn slot_idx(&self) -> usize {
        self.slot.idx()
    }
}

/// The reserved arena: the SCE-generated pool, heap-placed, vending one slot
/// per in-flight chain.
///
/// `SLOTS` / `CAP` are the Router's dims and are checked against the pool's own
/// in [`ChainStaging::new`], so a Router asking for more than the SCXML
/// declares fails at construction rather than by refusing chains at runtime.
pub struct PooledStaging<const SLOTS: usize, const CAP: usize> {
    pool: Box<ReassemblyPoolAp>,
    /// Slots currently out. The pool has `free_count()` of its own, but it
    /// counts the whole table; this counts what THIS arena handed out, so the
    /// two disagreeing is a bug rather than a configuration.
    outstanding: usize,
}

impl<const SLOTS: usize, const CAP: usize> PooledStaging<SLOTS, CAP> {
    /// Read-only view of the generated pool, for tests that assert on the
    /// lifecycle FSM's own state (`slot_state` / `free_count`) rather than on
    /// this arena's bookkeeping. Asserting only on `available()` would pass
    /// while the FSM went untouched, which is the whole thing being proved.
    pub fn pool(&self) -> &ReassemblyPoolAp {
        &self.pool
    }
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
            pool: heap_pool(),
            outstanding: 0,
        }
    }

    fn acquire(&mut self) -> Option<Self::Chain> {
        let slot = self.pool.pool_acquire_for_encode()?;
        self.outstanding += 1;
        Some(PooledChain { slot, len: 0 })
    }

    fn release(&mut self, chain: Self::Chain) {
        chain.slot.pool_return(&mut self.pool);
        self.outstanding = self.outstanding.saturating_sub(1);
    }

    fn append(&mut self, chain: &mut Self::Chain, payload: &[u8]) -> Result<(), StagingError> {
        let end = chain
            .len
            .checked_add(payload.len())
            .ok_or(StagingError::ChainCapExceeded)?;
        if end > CAP {
            return Err(StagingError::ChainCapExceeded);
        }
        chain.slot.write(&mut self.pool)[chain.len..end].copy_from_slice(payload);
        chain.len = end;
        Ok(())
    }

    fn bytes<'a>(&'a self, chain: &'a Self::Chain) -> &'a [u8] {
        &chain.slot.read(&self.pool)[..chain.len]
    }

    fn available(&self) -> usize {
        SLOTS.saturating_sub(self.outstanding)
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
        assert_eq!(arena.pool().free_count(), SLOT_COUNT);
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

    /// The GENERATED FSM is what moved, not just this module's counter.
    ///
    /// `available()` alone would pass while the pool sat untouched — an arena
    /// could stage into a private `Vec` and decrement a number. So the
    /// assertion is on `slot_state`, which only the emit's own transitions
    /// write: `free -> cpu-mut` on acquire, `cpu-mut -> free` on return.
    #[test]
    fn a_live_chain_holds_its_pool_slot_in_cpu_mut() {
        let mut router: Pooled = ReassemblyDispatcher::new(ReassemblyConfig::new(4, 5_000));
        assert_eq!(router.staging().pool().free_count(), SLOT_COUNT);

        router.ingest(frag(b"peer-a", 0, 1, b"part"), MASK, 0, |_| {});
        assert_eq!(router.active_chains(), 1);
        assert_eq!(
            router.staging().pool().free_count(),
            SLOT_COUNT - 1,
            "a live chain must hold a pool slot"
        );
        assert_eq!(
            (0..SLOT_COUNT)
                .filter(|i| router.staging().pool().slot_state(*i) == Some(SlotState::CpuMut))
                .count(),
            1,
            "exactly one slot must be in cpu-mut while one chain is live"
        );

        router.ingest(frag(b"peer-a", 1, 0, b"-end"), MASK, 0, |_| {});
        assert_eq!(router.active_chains(), 0);
        assert_eq!(
            router.staging().pool().free_count(),
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
            router.staging().pool().free_count(),
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
        assert_eq!(router.staging().pool().free_count(), SLOT_COUNT - SLOTS);

        assert!(
            matches!(
                router.ingest(frag(b"pz", 0, 1, b"x"), MASK, 0, |_| {}),
                IngestOutcome::Refused(_)
            ),
            "a full arena must refuse, not grow"
        );
    }
}
