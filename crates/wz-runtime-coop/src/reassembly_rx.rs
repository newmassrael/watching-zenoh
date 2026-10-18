// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311in carry[3] — the MCU-profile live reassembly seam.
//!
//! This is the MCU sibling of the AP host's reassembly drive (the
//! `wz-runtime-tokio::session_glue::TokioReassembly` +
//! `report_outcome_reassembling` path). It binds the engine-free
//! [`ReassemblyDispatcher`] to the MCU machine's pool policy — sourced
//! from the SCE-codegen'd buffer-pool constants whose SSOT is
//! `sources/network/reassembly_pool_mcu.scxml` (carry [0] established the
//! same pattern for the AP profile).
//!
//! ## What "drives" the dispatcher
//!
//! The dispatcher is the consumer: [`ReassemblyDispatcher::ingest`] takes
//! one decoded `T_MID_FRAGMENT` and [`ReassemblyDispatcher::sweep`]
//! reclaims deadline-elapsed chains. This module supplies the typed
//! constructor [`mcu_reassembly`] (MCU dims + config from the scxml) and
//! re-exports the driving types, so the MCU main loop owns one dispatcher
//! and drives it:
//!
//! ```ignore
//! let mut reasm = wz_runtime_coop::reassembly_rx::mcu_reassembly();
//! // on each decoded inbound fragment (zid from the established session;
//! // sn_mask = the session's negotiated SN ring, `negotiated_sn_mask()`):
//! reasm.ingest(frag, sn_mask, now_ms, |msg| { /* re-parse + dispatch */ });
//! // once per tick, with the hardware monotonic clock:
//! reasm.sweep(now_ms);
//! ```
//!
//! ## No-alloc + MCU-resident
//!
//! The dispatcher stages each chain into an inline [`BoundedVec`], so
//! this seam composes on the no-alloc MCU profile (default features, no
//! `alloc`) — the same profile Layer G.9 proves the seam cross-compiles
//! under. The no_std `ReassemblyDispatcher<4, 4096>` is ~22 KiB
//! (vendor/sce 4ec1aa642 elided the inline W3C event metadata, and
//! `fragment_chunk_schema.scxml` dropped its vestigial 1472-byte payload
//! field), so a `static` instance fits the MCU's 128 KiB SRAM region.
//!
//! `now_ms` is a caller parameter (not read from a
//! [`crate::time::ClockSource`]) so the seam needs no executor / timer:
//! the no-alloc main loop supplies the monotonic clock from its SysTick /
//! RTC read, mirroring how the dispatcher itself takes `now_ms`. The
//! `alloc`-profile auto-sweep (a timer task on the [`crate::executor`])
//! lands with the MCU session drive loop.
//!
//! [`ReassemblyDispatcher`]: wz_session_core::reassembly_dispatch::ReassemblyDispatcher
//! [`BoundedVec`]: wz_session_core::bounded::BoundedVec

use wz_session_core::reassembly_dispatch::{ReassemblyConfig, ReassemblyDispatcher};

// Re-export the types the MCU loop needs to drive the dispatcher, so a
// consumer reaches them through the seam without naming wz-session-core
// directly (symmetric with how the AP host re-exports its reassembly
// surface through wz-runtime-tokio).
pub use wz_session_core::reassembly_dispatch::{Fragment, IngestOutcome};

/// MCU reassembly slot count — the dispatcher const generic, from the
/// SCE-codegen'd buffer-pool SSOT ([`crate::reassembly_pool_mcu`]).
pub const MCU_REASSEMBLY_SLOTS: usize = crate::reassembly_pool_mcu::SLOT_COUNT;

/// MCU reassembly per-slot byte cap — the dispatcher const generic, from
/// the same SCE-codegen'd buffer-pool SSOT.
pub const MCU_REASSEMBLY_SLOT_SIZE: usize = crate::reassembly_pool_mcu::SLOT_SIZE;

/// The MCU profile's reassembly Router type. The no-alloc backing keeps
/// each chain's staging buffer inline (`BoundedVec<u8, SLOT_SIZE>`);
/// `MCU_REASSEMBLY_SLOT_SIZE` is the per-chain cap the dispatcher
/// enforces, so reassembly is genuinely bounded on the MCU profile.
pub type CoopReassembly = ReassemblyDispatcher<MCU_REASSEMBLY_SLOTS, MCU_REASSEMBLY_SLOT_SIZE>;

/// Reassembly config (`per_peer_quota` / `reassembly_timeout_ms`) from
/// the MCU buffer-pool SSOT. The emit types them as `u32`;
/// [`ReassemblyConfig`] takes `u16` / `u64`, so the two widening casts
/// are the only adaptation.
pub fn mcu_reassembly_config() -> ReassemblyConfig {
    ReassemblyConfig::new(
        crate::reassembly_pool_mcu::PER_PEER_QUOTA as u16,
        crate::reassembly_pool_mcu::REASSEMBLY_TIMEOUT_MS as u64,
    )
}

/// Construct the MCU reassembly Router with the deploy-sourced MCU pool
/// dims + config. The MCU main loop owns the returned dispatcher and
/// drives it via [`ReassemblyDispatcher::ingest`] /
/// [`ReassemblyDispatcher::sweep`] (see the module docs).
pub fn mcu_reassembly() -> CoopReassembly {
    CoopReassembly::new(mcu_reassembly_config())
}

#[cfg(feature = "rx-in-place")]
pub use in_place::{
    in_place_reassembly, ArenaChain, InPlaceReassembly, PoolStorage, ReassemblyArena,
};

/// ARCHITECTURE section 9.3 on the MCU: reassembly staged into the slots of
/// the SCE-generated `reassembly_pool_mcu` table, so a fragment's payload is
/// copied once, from where its unit lies into its chain's slot, and the
/// completed message is read in that slot.
///
/// The table is not a hidden static. A static would make it one per IMAGE, and
/// a program can run two sessions (a client session beside a group session,
/// or two clients), each of which needs a table of its own; the emit says as
/// much (`crate::reassembly_pool_mcu::SECTION`: placing it is a different
/// author API, a singleton). So the arena is a VALUE owned by the session that
/// stages into it, built over storage handed to it: the image's own placed
/// table ([`PoolStorage::Static`]) or one the arena owns on the heap
/// (`PoolStorage::owned`, absent under `session-slot`), allocated once when the
/// session is built.
///
/// The slot lifecycle is the generated one, walked by its own edges and
/// nothing else: a chain's slot is taken `free -> cpu-mut`
/// (`pool_acquire_for_encode`), written and read through the handle, and given
/// back `cpu-mut -> free` (`pool_return`) when the chain completes, aborts or
/// times out. The handle IS the reservation, and its type makes the illegal
/// orders a compile error.
///
/// A completed chain is delivered BORROWED, for the synchronous dispatch: the
/// slot goes home as the delivery call returns, so nothing decoded out of it
/// may be kept (a consumer that keeps something copies it, as the subscriber
/// sample does). The MCU profile has no shared-bytes storage to lend it as.
#[cfg(feature = "rx-in-place")]
mod in_place {
    #[cfg(not(feature = "session-slot"))]
    use alloc::boxed::Box;

    use wz_session_core::chain_staging::{ChainStaging, StagingError};
    use wz_session_core::reassembly_dispatch::ReassemblyDispatcher;

    use super::{mcu_reassembly_config, MCU_REASSEMBLY_SLOTS, MCU_REASSEMBLY_SLOT_SIZE};
    use crate::reassembly_pool_mcu::{
        CpuMut, ReassemblyPoolMcu, Slot, SlotState, SLOT_COUNT, SLOT_SIZE,
    };

    // The arena serves the pool's own dims and nothing else.
    const _: () = assert!(MCU_REASSEMBLY_SLOTS == SLOT_COUNT);
    const _: () = assert!(MCU_REASSEMBLY_SLOT_SIZE == SLOT_SIZE);

    /// Where an arena's slot table lives. Handed to [`ReassemblyArena::new`];
    /// the table must have every slot free.
    pub enum PoolStorage {
        /// A table the image placed and gives this arena for good, in the
        /// section its memory map names. One per session: two sessions take
        /// two tables.
        Static(&'static mut ReassemblyPoolMcu),
        /// A table this arena owns on the heap. [`PoolStorage::owned`] builds
        /// one. Absent under `session-slot`: a session in a slot has a table in
        /// its pump's cell, never one it allocates.
        #[cfg(not(feature = "session-slot"))]
        Owned(Box<ReassemblyPoolMcu>),
    }

    impl PoolStorage {
        /// A table of its own, every slot free, written in place into `place`: what
        /// a pump in a cell of a `PumpSlots` table stages into under `session-slot`.
        ///
        /// All-zero IS the table's initial value (the storage is bytes, and
        /// `SlotState::Free` is the explicit discriminant `0`), so the cell is
        /// zeroed where it lies and nothing is built on the stack, which a 16 KiB
        /// table built by value would be. The assertion re-establishes it against
        /// the table that results.
        #[cfg(feature = "session-slot")]
        pub fn zeroed_in(place: &'static mut core::mem::MaybeUninit<ReassemblyPoolMcu>) -> Self {
            // SAFETY: `place` is valid for a write of one table, and the all-zero
            // pattern is a valid table (the assertion below is the witness for the
            // one thing that could make it not be).
            let pool = unsafe {
                core::ptr::write_bytes(place.as_mut_ptr(), 0, 1);
                place.assume_init_mut()
            };
            assert_eq!(
                pool.free_count(),
                SLOT_COUNT,
                "the zero pattern is no longer the pool's initial state: the emit's \
                 SlotState discriminants moved and PoolStorage::zeroed_in must be rewritten"
            );
            Self::Static(pool)
        }

        /// A table of its own, every slot free, allocated once here and never
        /// again: what a session that is handed nothing stages into.
        ///
        /// Built IN the heap allocation, never on the stack: the emit's
        /// `ReassemblyPoolMcu::new` returns the table BY VALUE (16 KiB of
        /// slots), which a debug build would put on the stack before the
        /// allocation exists, as the AP pool's twin measured
        /// (`wz-runtime-tokio`'s reassembly arena). The block is zeroed in
        /// place instead, and all-zero IS `new`'s value: the storage is bytes,
        /// and `SlotState::Free` is the explicit discriminant `0`. The
        /// assertion re-establishes that against the built table.
        #[cfg(not(feature = "session-slot"))]
        pub fn owned() -> Self {
            let layout = core::alloc::Layout::new::<ReassemblyPoolMcu>();
            // SAFETY: `alloc_zeroed` returns a block of `layout`, sized and
            // aligned for the table; the all-zero pattern is a valid table
            // (above), so the block holds an initialised value before
            // `from_raw` takes ownership of it.
            let pool = unsafe {
                let raw = alloc::alloc::alloc_zeroed(layout) as *mut ReassemblyPoolMcu;
                if raw.is_null() {
                    alloc::alloc::handle_alloc_error(layout);
                }
                Box::from_raw(raw)
            };
            assert_eq!(
                pool.free_count(),
                SLOT_COUNT,
                "the zero pattern is no longer the pool's initial state: the emit's \
                 SlotState discriminants moved and PoolStorage::owned must be rewritten"
            );
            Self::Owned(pool)
        }

        fn pool(&self) -> &ReassemblyPoolMcu {
            match self {
                Self::Static(pool) => pool,
                #[cfg(not(feature = "session-slot"))]
                Self::Owned(pool) => pool,
            }
        }

        fn pool_mut(&mut self) -> &mut ReassemblyPoolMcu {
            match self {
                Self::Static(pool) => pool,
                #[cfg(not(feature = "session-slot"))]
                Self::Owned(pool) => pool,
            }
        }
    }

    /// One chain's reservation: its slot's handle and how much of the slot is
    /// written.
    pub struct ArenaChain {
        slot: Slot<CpuMut>,
        len: usize,
        /// Bytes lent by the latest [`ChainStaging::buf`] and not yet resolved
        /// by [`ChainStaging::commit`]; bookkeeping, since the slot is already
        /// full width.
        reserved: usize,
    }

    impl ArenaChain {
        /// The pool index of this chain's slot.
        pub fn slot_idx(&self) -> usize {
            self.slot.idx()
        }
    }

    /// The MCU reassembly arena over a `reassembly_pool_mcu` table. See the
    /// module documentation.
    pub struct ReassemblyArena {
        storage: PoolStorage,
    }

    impl ReassemblyArena {
        /// An arena over `storage`, whose every slot must be free: a table with
        /// a slot already out would serve fewer chains than the Router counts
        /// on, so a table that is not empty is refused here, where the image
        /// sees it, and not by a chain refused later.
        pub fn new(storage: PoolStorage) -> Self {
            assert_eq!(
                storage.pool().free_count(),
                SLOT_COUNT,
                "a reassembly table handed to an arena must have every slot free"
            );
            Self { storage }
        }

        /// Slots on the generated pool's freelist: the lifecycle's own answer.
        pub fn free_count(&self) -> usize {
            self.storage.pool().free_count()
        }

        /// The lifecycle state the generated pool records for slot `idx`.
        pub fn slot_state(&self, idx: usize) -> Option<SlotState> {
            self.storage.pool().slot_state(idx)
        }

        /// Which slot of this arena's table an address lies inside, if any: the
        /// witness that bytes handed up are a slot and not a copy of it.
        ///
        /// The table's slots are its first field (`#[repr(C)]`), so they start
        /// at the table's own address; the candidate slot's base is then
        /// confirmed by the pool's `slot_index_of_ptr`, which resolves only an
        /// exact slot base, so the answer is the pool's and not this
        /// arithmetic's.
        pub fn slot_of(&self, addr: *const u8) -> Option<usize> {
            let pool = self.storage.pool();
            let start = pool as *const ReassemblyPoolMcu as usize;
            let offset = (addr as usize).checked_sub(start)?;
            let idx = offset / SLOT_SIZE;
            if idx >= SLOT_COUNT {
                return None;
            }
            let base = (start + idx * SLOT_SIZE) as *const u8;
            (pool.slot_index_of_ptr(base) == Some(idx)).then_some(idx)
        }
    }

    impl ChainStaging<MCU_REASSEMBLY_SLOTS, MCU_REASSEMBLY_SLOT_SIZE> for ReassemblyArena {
        type Chain = ArenaChain;

        fn acquire(&mut self) -> Option<ArenaChain> {
            let slot = self.storage.pool_mut().pool_acquire_for_encode()?;
            Some(ArenaChain {
                slot,
                len: 0,
                reserved: 0,
            })
        }

        fn release(&mut self, chain: ArenaChain) {
            chain.slot.pool_return(self.storage.pool_mut());
        }

        fn append(&mut self, chain: &mut ArenaChain, payload: &[u8]) -> Result<(), StagingError> {
            let end = chain
                .len
                .checked_add(payload.len())
                .filter(|end| *end <= MCU_REASSEMBLY_SLOT_SIZE)
                .ok_or(StagingError::ChainCapExceeded)?;
            chain.slot.write(self.storage.pool_mut())[chain.len..end].copy_from_slice(payload);
            chain.len = end;
            Ok(())
        }

        fn bytes<'a>(&'a self, chain: &'a ArenaChain) -> &'a [u8] {
            &chain.slot.read(self.storage.pool())[..chain.len]
        }

        fn buf<'a>(
            &'a mut self,
            chain: &'a mut ArenaChain,
            want: usize,
        ) -> Result<&'a mut [u8], StagingError> {
            let start = chain.len;
            let end = start
                .checked_add(want)
                .filter(|end| *end <= MCU_REASSEMBLY_SLOT_SIZE)
                .ok_or(StagingError::ChainCapExceeded)?;
            chain.reserved = want;
            Ok(&mut chain.slot.write(self.storage.pool_mut())[start..end])
        }

        fn commit(&mut self, chain: &mut ArenaChain, filled: usize) -> Result<(), StagingError> {
            if filled > chain.reserved {
                return Err(StagingError::ChainCapExceeded);
            }
            chain.len = chain
                .len
                .checked_add(filled)
                .filter(|end| *end <= MCU_REASSEMBLY_SLOT_SIZE)
                .ok_or(StagingError::ChainCapExceeded)?;
            chain.reserved = 0;
            Ok(())
        }

        /// The generated pool's free count: the slots the lifecycle itself
        /// says are free.
        fn available(&self) -> usize {
            self.free_count()
        }
    }

    /// The MCU reassembly Router over the pooled arena: what a session that
    /// reads its units in place reassembles with.
    pub type InPlaceReassembly =
        ReassemblyDispatcher<MCU_REASSEMBLY_SLOTS, MCU_REASSEMBLY_SLOT_SIZE, ReassemblyArena>;

    /// The Router over `arena`, with the MCU pool's config.
    pub fn in_place_reassembly(arena: ReassemblyArena) -> InPlaceReassembly {
        InPlaceReassembly::with_staging(mcu_reassembly_config(), arena)
    }
}

/// The pooled arena against the heap one, driven by the same Router through
/// the same fragments: identical outcomes, identical bytes delivered, and the
/// generated pool's own slot accounting agreeing with the Router's at every
/// quiescent point.
#[cfg(all(test, feature = "rx-in-place", not(feature = "session-slot")))]
mod in_place_tests {
    use super::*;
    use alloc::vec::Vec;
    use wz_session_core::qos::Priority;
    use wz_session_core::reassembly_dispatch::{AbortReason, RefuseReason};

    use crate::reassembly_pool_mcu::{ReassemblyPoolMcu, SlotState};

    const MASK: u64 = wz_session_core::sn::mask_from_res(0x02);

    fn frag<'a>(peer: &'a [u8], sn: u64, more: bool, payload: &'a [u8]) -> Fragment<'a> {
        Fragment {
            peer_key: peer,
            reliable: true,
            sn,
            more: u8::from(more),
            payload,
            priority: Priority::DEFAULT,
            markers: wz_session_core::extfragment::FragmentMarkers::NONE,
        }
    }

    /// One ingest on each Router: the two outcomes, and the bytes each
    /// delivered (if it completed a chain).
    type Step = (IngestOutcome, Option<Vec<u8>>);

    fn ingest_both(
        heap: &mut CoopReassembly,
        pooled: &mut InPlaceReassembly,
        f: Fragment<'_>,
        now_ms: u64,
    ) -> (Step, Step) {
        let mut from_heap = None;
        let a = heap.ingest(f, MASK, now_ms, |m| from_heap = Some(m.to_vec()));
        let mut from_pool = None;
        let b = pooled.ingest(f, MASK, now_ms, |m| from_pool = Some(m.to_vec()));
        ((a, from_heap), (b, from_pool))
    }

    /// The accounting identity, on both arenas, plus the pooled arena's own
    /// answer agreeing with the generated pool's freelist.
    fn quiescent(heap: &CoopReassembly, pooled: &InPlaceReassembly) {
        let slots = MCU_REASSEMBLY_SLOTS;
        assert_eq!(heap.active_chains() + heap.staging_available(), slots);
        assert_eq!(pooled.active_chains() + pooled.staging_available(), slots);
        assert_eq!(pooled.staging().free_count(), pooled.staging_available());
        assert_eq!(heap.active_chains(), pooled.active_chains());
    }

    fn pair() -> (CoopReassembly, InPlaceReassembly) {
        (
            mcu_reassembly(),
            in_place_reassembly(ReassemblyArena::new(PoolStorage::owned())),
        )
    }

    /// The message of `len` bytes, every byte distinct from its neighbours.
    fn message(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 + 7) as u8).collect()
    }

    /// Every length around the slot's end, cut into every fragment size around
    /// it and a few small ones: a chain of one fragment, of two, of many, the
    /// slot filled exactly, and one byte past it.
    #[test]
    fn the_pooled_arena_reassembles_exactly_what_the_heap_arena_does() {
        let (mut heap, mut pooled) = pair();
        let mut sn = 0u64;
        let cap = MCU_REASSEMBLY_SLOT_SIZE;
        for len in [1, 2, 7, 1471, 1472, 1473, cap - 1, cap, cap + 1, 2 * cap] {
            let body = message(len);
            for chunk in [1, 2, 7, 1472, cap - 1, cap, cap + 1] {
                let pieces: Vec<&[u8]> = body.chunks(chunk).collect();
                let mut completed = 0;
                for (i, piece) in pieces.iter().enumerate() {
                    let more = i + 1 < pieces.len();
                    let (a, b) =
                        ingest_both(&mut heap, &mut pooled, frag(b"peer", sn, more, piece), 0);
                    sn += 1;
                    assert_eq!(a, b, "len {len}, chunk {chunk}, fragment {i}");
                    if let IngestOutcome::Reassembled = a.0 {
                        completed += 1;
                        assert_eq!(a.1.as_deref(), Some(&body[..]), "len {len}, chunk {chunk}");
                    }
                    if let IngestOutcome::Aborted(_) = a.0 {
                        // The rest of the chain finds no chain open; stop it here.
                        break;
                    }
                }
                let fits = len <= cap;
                assert_eq!(completed, usize::from(fits), "len {len}, chunk {chunk}");
                quiescent(&heap, &pooled);
            }
        }
    }

    /// A duplicate and a gap each end the chain on both arenas alike, and the
    /// slot goes home.
    #[test]
    fn a_duplicate_or_a_gap_ends_the_chain_on_both_arenas_alike() {
        let (mut heap, mut pooled) = pair();
        for (first, second) in [(10u64, 10u64), (20, 22)] {
            let (a, b) = ingest_both(&mut heap, &mut pooled, frag(b"p", first, true, b"abc"), 0);
            assert_eq!(a, b);
            assert_eq!(a.0, IngestOutcome::Begun);
            let (a, b) = ingest_both(&mut heap, &mut pooled, frag(b"p", second, false, b"def"), 0);
            assert_eq!(a, b);
            assert_eq!(a.0, IngestOutcome::Aborted(AbortReason::OutOfOrder));
            quiescent(&heap, &pooled);
            assert_eq!(pooled.staging().free_count(), MCU_REASSEMBLY_SLOTS);
        }
    }

    /// Two chains interleaved on two peers land in two slots and each is
    /// delivered whole: a fragment is staged into its own chain's slot.
    #[test]
    fn interleaved_chains_stage_into_their_own_slots() {
        let (mut heap, mut pooled) = pair();
        let one = message(3000);
        let two: Vec<u8> = message(2500).iter().map(|b| b ^ 0x5a).collect();
        let a_parts: Vec<&[u8]> = one.chunks(1000).collect();
        let b_parts: Vec<&[u8]> = two.chunks(1000).collect();
        let mut got = Vec::new();
        for i in 0..3 {
            for (peer, parts) in [(&b"peer-a"[..], &a_parts), (&b"peer-b"[..], &b_parts)] {
                if let Some(piece) = parts.get(i) {
                    let more = i + 1 < parts.len();
                    let (a, b) =
                        ingest_both(&mut heap, &mut pooled, frag(peer, i as u64, more, piece), 0);
                    assert_eq!(a, b);
                    if let Some(bytes) = b.1 {
                        got.push(bytes);
                    }
                }
            }
            if i == 0 {
                // Both chains open, each in a slot of its own.
                assert_eq!(pooled.staging().free_count(), MCU_REASSEMBLY_SLOTS - 2);
            }
        }
        // Both complete on the third round, peer-a's first.
        assert_eq!(got, [one, two]);
        quiescent(&heap, &pooled);
    }

    /// The pool runs dry: two peers hold two chains each (their quota), so the
    /// table's four slots are out and a third peer's chain is REFUSED, counted
    /// by the Router's outcome, on both arenas alike. The deadline sweep then
    /// returns every slot to the pool's freelist through the generated edge.
    #[test]
    fn a_dry_pool_refuses_and_the_sweep_returns_every_slot() {
        let (mut heap, mut pooled) = pair();
        let mut opened = 0;
        for peer in [&b"peer-a"[..], &b"peer-b"[..]] {
            for reliable in [true, false] {
                let f = Fragment {
                    reliable,
                    ..frag(peer, 1, true, b"x")
                };
                let (a, b) = ingest_both(&mut heap, &mut pooled, f, 0);
                assert_eq!(a, b);
                assert_eq!(a.0, IngestOutcome::Begun);
                opened += 1;
            }
        }
        assert_eq!(opened, MCU_REASSEMBLY_SLOTS);
        assert_eq!(pooled.staging().free_count(), 0);
        for idx in 0..MCU_REASSEMBLY_SLOTS {
            assert_eq!(pooled.staging().slot_state(idx), Some(SlotState::CpuMut));
        }
        let (a, b) = ingest_both(&mut heap, &mut pooled, frag(b"peer-c", 1, true, b"x"), 0);
        assert_eq!(a, b);
        assert_eq!(a.0, IngestOutcome::Refused(RefuseReason::PoolExhausted));
        quiescent(&heap, &pooled);

        let timeout = mcu_reassembly_config().reassembly_timeout_ms;
        assert_eq!(heap.sweep(timeout), MCU_REASSEMBLY_SLOTS);
        assert_eq!(pooled.sweep(timeout), MCU_REASSEMBLY_SLOTS);
        quiescent(&heap, &pooled);
        assert_eq!(pooled.staging().free_count(), MCU_REASSEMBLY_SLOTS);
        for idx in 0..MCU_REASSEMBLY_SLOTS {
            assert_eq!(pooled.staging().slot_state(idx), Some(SlotState::Free));
        }
    }

    /// Two sessions, two tables: each arena stages into the table it was handed
    /// (one the image placed, one of its own), the delivered message lies in
    /// that table, and one arena's chains take nothing from the other's.
    #[test]
    fn each_arena_stages_into_the_table_it_was_handed() {
        // The image's placed table, stood in for by a leaked one: a static the
        // test cannot declare (the emit's constructor is not `const`).
        let placed: &'static mut ReassemblyPoolMcu = match PoolStorage::owned() {
            PoolStorage::Owned(table) => alloc::boxed::Box::leak(table),
            PoolStorage::Static(_) => unreachable!("owned() owns"),
        };
        let placed_at = placed as *const ReassemblyPoolMcu as usize;
        let mut first = in_place_reassembly(ReassemblyArena::new(PoolStorage::Static(placed)));
        let mut second = in_place_reassembly(ReassemblyArena::new(PoolStorage::owned()));

        first.ingest(frag(b"p", 1, true, b"hello "), MASK, 0, |_| {
            panic!("not final")
        });
        assert_eq!(first.staging().free_count(), MCU_REASSEMBLY_SLOTS - 1);
        assert_eq!(second.staging().free_count(), MCU_REASSEMBLY_SLOTS);

        let mut seen = None;
        first.ingest(frag(b"p", 2, false, b"slot"), MASK, 0, |m| {
            seen = Some((m.as_ptr() as usize, m.to_vec()));
        });
        let (at, bytes) = seen.expect("completed");
        assert_eq!(bytes, b"hello slot");
        assert!(at >= placed_at && at < placed_at + core::mem::size_of::<ReassemblyPoolMcu>());
        assert!(first.staging().slot_of(at as *const u8).is_some());
        assert!(second.staging().slot_of(at as *const u8).is_none());

        let mut seen = None;
        second.ingest(frag(b"p", 1, false, b"own"), MASK, 0, |m| {
            seen = Some(m.as_ptr() as usize)
        });
        let at = seen.expect("completed");
        assert!(second.staging().slot_of(at as *const u8).is_some());
        assert!(first.staging().slot_of(at as *const u8).is_none());
        assert_eq!(first.staging().free_count(), MCU_REASSEMBLY_SLOTS);
        assert_eq!(second.staging().free_count(), MCU_REASSEMBLY_SLOTS);
    }

    /// A table handed over with a slot already out is refused at construction.
    #[test]
    #[should_panic(expected = "every slot free")]
    fn a_table_with_a_slot_out_is_refused() {
        let mut storage = PoolStorage::owned();
        let PoolStorage::Owned(table) = &mut storage else {
            unreachable!("owned() owns")
        };
        // The handle is let go of without the return edge: the slot stays out.
        let _out = table.pool_acquire_for_encode().expect("a free slot");
        let _ = ReassemblyArena::new(storage);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::qos::Priority;

    const ZID: &[u8] = &[0x11; 16];

    /// The default-resolution (0x02, 28-bit) ring the tests compare at.
    const MASK: u64 = wz_session_core::sn::mask_from_res(0x02);

    fn frag<'a>(sn: u64, more: u8, payload: &'a [u8]) -> Fragment<'a> {
        Fragment {
            peer_key: ZID,
            reliable: true,
            sn,
            more,
            payload,
            // Pre-QoS MCU unicast chain: DEFAULT collapses the §2.3 key
            // back to the (peer, reliable) form these tests assert on.
            priority: Priority::DEFAULT,
            // R311y578 — the MCU seam's config leaves the chain-boundary
            // rules off (`ReassemblyConfig::new`), matching a peer whose
            // negotiated patch level is 0, so a marker-less descriptor is
            // the shape under test here.
            markers: wz_session_core::extfragment::FragmentMarkers::NONE,
        }
    }

    /// The MCU seam constructs the dispatcher with the SCE-sourced MCU
    /// pool dims: 4 slots / 4096-byte cap / quota 2 (from
    /// `reassembly_pool_mcu.scxml`).
    #[test]
    fn mcu_dims_come_from_the_buffer_pool_ssot() {
        assert_eq!(MCU_REASSEMBLY_SLOTS, 4);
        assert_eq!(MCU_REASSEMBLY_SLOT_SIZE, 4096);
        let cfg = mcu_reassembly_config();
        assert_eq!(cfg.per_peer_quota, 2);
        assert_eq!(cfg.reassembly_timeout_ms, 500);
    }

    /// Driving the MCU seam exactly as the main loop will: a two-fragment
    /// chain reassembles its concatenated payload in SN order, no alloc.
    #[test]
    fn mcu_seam_reassembles_a_two_fragment_chain() {
        let mut reasm = mcu_reassembly();

        let r0 = reasm.ingest(frag(7, 1, b"lwip "), MASK, 0, |_| panic!("not final"));
        assert_eq!(r0, IngestOutcome::Begun);
        assert_eq!(reasm.active_chains(), 1);

        let mut delivered = false;
        let r1 = reasm.ingest(frag(8, 0, b"reassembly"), MASK, 0, |msg| {
            assert_eq!(msg, &b"lwip reassembly"[..]);
            delivered = true;
        });
        assert_eq!(r1, IngestOutcome::Reassembled);
        assert!(delivered, "completion delivered the reassembled message");
        assert_eq!(reasm.active_chains(), 0);
    }

    /// The deadline sweep — the per-tick half of the drive loop — reclaims
    /// a chain past the MCU pool's 500 ms window.
    #[test]
    fn mcu_seam_sweep_times_out_a_stale_chain() {
        let mut reasm = mcu_reassembly();
        reasm.ingest(frag(1, 1, b"partial"), MASK, 0, |_| {});
        assert_eq!(reasm.active_chains(), 1);
        // Before the deadline: nothing reclaimed.
        assert_eq!(reasm.sweep(499), 0);
        assert_eq!(reasm.active_chains(), 1);
        // At/after the 500 ms deadline: the chain is reclaimed.
        assert_eq!(reasm.sweep(500), 1);
        assert_eq!(reasm.active_chains(), 0);
    }
}
