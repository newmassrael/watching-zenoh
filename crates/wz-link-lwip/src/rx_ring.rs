// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y606 — the MCU receive seam's ARMING half: slots a bus master fills.
//!
//! ## Why this lands now and not with [`rx_pool`](crate::rx_pool)
//!
//! `rx_pool`'s docs recorded a blocker: a descriptor-ring adapter needs the
//! ADDRESS of a slot that is armed but not yet filled, and the emitted
//! `Slot<DmaArmedRx>` carried only `idx()` while the pool's `storage` was
//! private. That was measured, sent upstream, and answered — vendor/sce
//! `62794d8c4b` emits `Slot<DmaArmedRx>::dma_armed_rx_ptr` (the outbound leg)
//! and `slot_index_of_ptr` (the return leg), both derived from the FSM rather
//! than hardcoded: the states that publish an address are exactly the
//! DMA-owned ones entered from a non-DMA-owned state, which is the definition
//! of a hand-off.
//!
//! So the blocker is gone, and this module is what it was blocking.
//!
//! ## The driver shape this models
//!
//! A descriptor-ring MAC does not reserve-then-fill. It asks software for a
//! buffer address, writes the frame there itself, and reports completion by
//! handing the SAME address back:
//!
//! ```text
//!     MAC: "give me a buffer"        -> provide_buffer()  -> *mut u8
//!     MAC writes the frame by DMA
//!     MAC: "frame at <addr>, <len>"  -> frame_received(addr, len)
//! ```
//!
//! Both halves are addresses, and the pool's edges are all keyed by slot
//! index. [`DescriptorRingRx`] is the translation, and it exists so the driver
//! does not keep a shadow table of a layout the pool already knows — a shadow
//! table that drifts advances the wrong slot, which is a data corruption with
//! no assertion anywhere near it.
//!
//! ## Why arming and starting are one call here
//!
//! The FSM separates `dma-armed-rx` (address published, peripheral not yet
//! looking) from `dma-busy-rx` (peripheral owns the slot), and that split is
//! real for a controller with an explicit start register. A buffer-REQUEST
//! callback has no such split: returning the address from `rxgetbuff` IS the
//! hand-off, because the MAC descriptor is armed by the return value. So
//! [`DescriptorRingRx::provide_buffer`] walks both edges and the intermediate
//! handle never escapes — which is also why it is the only place in this
//! module that needs `unsafe`, and why the safety comment there is about the
//! CALLER's driver contract rather than about memory.
//!
//! A controller with a separate start register wants the split back. That is
//! [`ArmedRxSlots`], which this adapter is written on top of rather than
//! around: the trait keeps both edges reachable for a driver that needs them.
//!
//! ## What a host test can and cannot witness
//!
//! It CAN witness the address contract: that the published pointer names the
//! slot the pool thinks it does, that it satisfies the declared DMA alignment,
//! that it round-trips through [`ArmedRxSlots::index_of_ptr`], and that a
//! frame written ONLY through that pointer is the frame read back after
//! completion. The tests below fill through the raw pointer for exactly that
//! reason — filling through the emit's `write()` accessor would pass on a pool
//! that published no address at all, which is the proof this seam needs most.
//!
//! It CANNOT witness cache maintenance. All six pools in this tree declare
//! `cache-policy: none`, so no `sce_dcache_*` call is emitted to observe, and
//! the host has no bus master to invalidate against. That half stays
//! UNWITNESSED here and is named so rather than implied by the rest passing.

use crate::rx_pool::RxSlots;

/// The arming half of the receive seam: a slot handed to a bus master.
///
/// A supertrait of [`RxSlots`] rather than a sibling, because a pool that can
/// be armed can always also be CPU-filled — the freelist is one — and every
/// consumer of an armed slot needs `free_count` for the same accounting reason
/// the CPU half does.
///
/// The associated types are deliberately distinct from `RxSlots::Slot`. An
/// armed slot is not writable by the CPU and a filled slot is not writable at
/// all; the emit encodes both as separate phantom states, and flattening them
/// here would hand that guarantee back.
pub trait ArmedRxSlots: RxSlots {
    /// A slot armed for a bus master to fill. Carries no bytes: the CPU must
    /// not read them yet.
    type Armed;

    /// A slot a bus master has finished filling. Readable, not writable.
    type Filled;

    /// Take a slot off the freelist and arm it, or `None` when every slot is
    /// out. `None` is back-pressure exactly as [`RxSlots::reserve`]'s is.
    fn arm(&mut self) -> Option<Self::Armed>;

    /// The address a bus master writes the frame to.
    ///
    /// Raw pointer, not `&mut [u8]`: a live Rust reference to memory a
    /// peripheral is about to write is the aliasing `dma-armed-rx` exists to
    /// deny. Obtaining the address is safe; every use of it is `unsafe` at the
    /// point of use, which is where the contract actually binds.
    fn armed_ptr(&mut self, armed: &Self::Armed) -> *mut u8;

    /// Which slot an address names, or `None` for anything the pool did not
    /// publish.
    ///
    /// Only an exact slot start resolves. An interior pointer does NOT round
    /// down to its containing slot: a completion signal carrying an address
    /// the pool never handed out is a driver defect, and rounding turns it
    /// into a plausible index.
    fn index_of_ptr(&self, ptr: *const u8) -> Option<usize>;

    /// Pool index of an armed slot, for tracing and for tests that assert on
    /// the emit's own `slot_state`.
    fn armed_idx(armed: &Self::Armed) -> usize;

    /// Hand the armed slot to the bus master.
    ///
    /// # Safety
    /// The caller must have armed the peripheral with this slot's address.
    /// Advancing without doing so leaves a slot the pool believes is owned by
    /// hardware that was never told about it, and nothing will complete it.
    unsafe fn start(&mut self, armed: Self::Armed);

    /// Take back a slot the bus master has finished with.
    ///
    /// Returns `None` for a slot that is not in flight, so a spurious or
    /// replayed completion cannot advance an unrelated slot.
    ///
    /// # Safety
    /// The caller must have observed the completion signal for this slot.
    /// Calling early publishes memory the peripheral still owns.
    unsafe fn complete(&mut self, idx: usize) -> Option<Self::Filled>;

    /// Readable bytes of a filled slot, full width. The caller pairs this with
    /// the length the completion signal carried; the pool tracks no lengths,
    /// for the same reason [`RxSlots::bytes`] does not.
    fn filled_bytes<'a>(&'a self, filled: &'a Self::Filled) -> &'a [u8];

    /// Return a filled slot to the freelist.
    fn release_filled(&mut self, filled: Self::Filled);
}

/// Implement [`ArmedRxSlots`] over one SCE-generated buffer-pool emit.
///
/// Per-pool rather than generic for the same reason [`impl_rx_slots`] is: the
/// emitted `Slot<S>` types are distinct by construction, and keeping them
/// apart is what makes returning a scout slot to the session pool a compile
/// error.
///
/// [`impl_rx_slots`]: crate::rx_pool
macro_rules! impl_armed_rx_slots {
    ($pool_mod:ident, $pool_ty:ident) => {
        impl ArmedRxSlots for crate::$pool_mod::$pool_ty {
            type Armed = crate::$pool_mod::Slot<crate::$pool_mod::DmaArmedRx>;
            type Filled = crate::$pool_mod::Slot<crate::$pool_mod::CpuRef>;

            fn arm(&mut self) -> Option<Self::Armed> {
                self.link_arm_rx()
            }

            fn armed_ptr(&mut self, armed: &Self::Armed) -> *mut u8 {
                armed.dma_armed_rx_ptr(self)
            }

            fn index_of_ptr(&self, ptr: *const u8) -> Option<usize> {
                <crate::$pool_mod::$pool_ty>::slot_index_of_ptr(self, ptr)
            }

            fn armed_idx(armed: &Self::Armed) -> usize {
                armed.idx()
            }

            unsafe fn start(&mut self, armed: Self::Armed) {
                // SAFETY: forwarded. The trait's own contract is the emit's.
                unsafe { armed.dma_start_rx(self) }
            }

            unsafe fn complete(&mut self, idx: usize) -> Option<Self::Filled> {
                // SAFETY: forwarded. The trait's own contract is the emit's.
                unsafe { <crate::$pool_mod::$pool_ty>::rx_complete(self, idx) }
            }

            fn filled_bytes<'a>(&'a self, filled: &'a Self::Filled) -> &'a [u8] {
                &filled.read(self)[..]
            }

            fn release_filled(&mut self, filled: Self::Filled) {
                filled.pool_return(self);
            }
        }
    };
}

impl_armed_rx_slots!(scout_rx_pool_mcu, ScoutRxPoolMcu);
impl_armed_rx_slots!(session_rx_pool_mcu_multicast, SessionRxPoolMcuMulticast);

// The unicast session pool is ONE module under two names, never both
// (`lib.rs:116,136`). Same gate as the module it names — see `rx_pool`'s
// sibling pair for why the cfg belongs on the impl and not only on the tests.
#[cfg(not(feature = "buffer-pool-session-rx-slim"))]
impl_armed_rx_slots!(session_rx_pool_mcu, SessionRxPoolMcu);
#[cfg(feature = "buffer-pool-session-rx-slim")]
impl_armed_rx_slots!(session_rx_pool_mcu_minimal, SessionRxPoolMcuMinimal);

/// What a completion signal named.
///
/// Three outcomes rather than an `Option` so the ways a completion can be
/// wrong stay distinguishable at the call site. A driver that collapses them
/// logs "dropped a frame" for a bug that is actually "the MAC handed us an
/// address we never published", and those two have nothing in common.
#[derive(Debug, PartialEq, Eq)]
pub enum Completion<R> {
    /// The address resolved, the slot was in flight, and the consumer ran.
    Delivered {
        /// The slot the address named.
        idx: usize,
        /// Whatever the consumer returned.
        value: R,
    },
    /// The address is not one this pool published. A driver defect: the pool
    /// deliberately does not round an interior pointer down to its slot, so a
    /// bad address stays a bad address instead of becoming a plausible index.
    ForeignAddress,
    /// The address resolved, but the slot is not in flight — a spurious or
    /// replayed completion. The pool refused it and nothing advanced.
    NotInFlight(usize),
    /// The completion claimed more bytes than a slot holds. The slot IS
    /// returned to the freelist; the frame is not delivered, because the only
    /// alternatives are truncating a frame silently or panicking in a path
    /// that runs next to an interrupt.
    Overlong {
        /// The slot the address named.
        idx: usize,
        /// The length the completion claimed.
        len: usize,
    },
}

/// Drives an [`ArmedRxSlots`] pool from a descriptor-ring driver's two
/// callbacks.
///
/// Holds no shadow table. Every question it answers — which slot an address
/// names, whether that slot is in flight — is answered by the pool, which is
/// the whole reason the upstream emit grew a reverse map instead of the driver
/// growing a table.
pub struct DescriptorRingRx<P: ArmedRxSlots> {
    pool: P,
    /// Frames the pool refused to complete. Counted rather than ignored: a
    /// driver handing back addresses the pool never published is silent
    /// otherwise, and it is the failure mode a shadow table would have
    /// produced.
    rejected: u32,
}

impl<P: ArmedRxSlots> Default for DescriptorRingRx<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: ArmedRxSlots> DescriptorRingRx<P> {
    /// A ring over a fresh pool, every slot on the freelist.
    pub fn new() -> Self {
        Self {
            pool: <P as RxSlots>::new(),
            rejected: 0,
        }
    }

    /// Answer a MAC's buffer request: arm a slot and publish its address.
    ///
    /// `None` is back-pressure — every slot is in flight or held — and a
    /// driver answers it by leaving the descriptor unarmed, which is what
    /// makes the MAC drop rather than overwrite.
    ///
    /// Walks `arm` and `start` together because a buffer-request callback has
    /// no separate start: returning the address IS the hand-off. A controller
    /// with an explicit start register drives [`ArmedRxSlots`] directly.
    pub fn provide_buffer(&mut self) -> Option<*mut u8> {
        let armed = self.pool.arm()?;
        let ptr = self.pool.armed_ptr(&armed);
        // SAFETY: `ptr` is this slot's address and it is what we return to the
        // caller, whose contract is to write it into the descriptor it is
        // filling. The hand-off and the return value are the same event, so
        // there is no window in which the slot is `dma-busy-rx` while the
        // peripheral has not been told about it.
        unsafe { self.pool.start(armed) };
        Some(ptr)
    }

    /// Answer a MAC's completion signal, which names the buffer by address.
    ///
    /// Lends the frame's bytes to `f` and returns the slot before returning,
    /// the same borrow-then-return discipline
    /// [`PooledUdpRx::recv_with`](crate::rx_pool::PooledUdpRx::recv_with) uses
    /// on the CPU-fill side, and for the same reason: a caller that could hold
    /// the slot could hold it forever, and the freelist is the only place that
    /// would show.
    ///
    /// # Safety
    /// The caller must have observed the completion for this address. Calling
    /// early hands out memory the peripheral still owns — the pool checks that
    /// the slot is in flight, which is a different question from whether the
    /// hardware is done with it.
    pub unsafe fn frame_received<R>(
        &mut self,
        addr: *const u8,
        len: usize,
        f: impl FnOnce(&[u8]) -> R,
    ) -> Completion<R> {
        let Some(idx) = self.pool.index_of_ptr(addr) else {
            self.rejected += 1;
            return Completion::ForeignAddress;
        };
        // SAFETY: forwarded from this fn's own contract.
        let Some(filled) = (unsafe { self.pool.complete(idx) }) else {
            self.rejected += 1;
            return Completion::NotInFlight(idx);
        };
        if len > <P as RxSlots>::SLOT_SIZE {
            self.pool.release_filled(filled);
            self.rejected += 1;
            return Completion::Overlong { idx, len };
        }
        let value = f(&self.pool.filled_bytes(&filled)[..len]);
        self.pool.release_filled(filled);
        Completion::Delivered { idx, value }
    }

    /// Completions the pool refused. Nonzero means a driver defect, not load.
    pub fn rejected(&self) -> u32 {
        self.rejected
    }

    /// Slots on the freelist. The accounting gate — a ring that leaks slots
    /// shows up here and nowhere else.
    pub fn free_count(&self) -> usize {
        self.pool.free_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The ACTIVE unicast session pool under either feature arm, for the same
    // reason `rx_pool`'s tests pick it this way: a `#[cfg]` on the tests
    // themselves would leave the slim lane asserting nothing while still
    // reporting green.
    #[cfg(not(feature = "buffer-pool-session-rx-slim"))]
    use crate::session_rx_pool_mcu::{SessionRxPoolMcu as ActiveSessionPool, SlotState, ALIGNMENT};
    #[cfg(feature = "buffer-pool-session-rx-slim")]
    use crate::session_rx_pool_mcu_minimal::{
        SessionRxPoolMcuMinimal as ActiveSessionPool, SlotState, ALIGNMENT,
    };

    /// Stand in for the bus master: write `bytes` through the published
    /// address and NOTHING else.
    ///
    /// This is the point of the whole module's tests. Filling through the
    /// emit's `write()` accessor would exercise the FSM edges just as well and
    /// would pass on a pool that published no address at all — which is
    /// exactly the state this tree was in before vendor/sce `62794d8c4b`.
    ///
    /// # Safety
    /// `ptr` must be a slot address the pool published for a slot currently in
    /// flight, and `bytes` must fit the slot.
    unsafe fn peripheral_writes(ptr: *mut u8, bytes: &[u8]) {
        // SAFETY: the caller guarantees `ptr` names a slot of at least
        // `bytes.len()` bytes that no one else is reading — which is what
        // `dma-busy-rx` means.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len()) };
    }

    /// The published address must name the slot the pool thinks it does, and
    /// must satisfy the pool's declared DMA alignment.
    ///
    /// Both halves matter and neither implies the other: an address that
    /// round-trips through `index_of_ptr` but is misaligned is one a MAC can
    /// reject at runtime, and that was the live defect upstream found while
    /// wiring this — `<sce:alignment>` rode the TABLE, so only slot 0 was on
    /// the boundary.
    #[test]
    fn every_published_address_names_its_own_slot_and_is_aligned() {
        let mut pool = <ActiveSessionPool as RxSlots>::new();
        let count = <ActiveSessionPool as RxSlots>::SLOT_COUNT;

        let mut armed = std::vec::Vec::new();
        for i in 0..count {
            armed.push(
                pool.arm()
                    .unwrap_or_else(|| std::panic!("slot {i} of {count} refused arming")),
            );
        }
        for a in &armed {
            let idx = <ActiveSessionPool as ArmedRxSlots>::armed_idx(a);
            let ptr = pool.armed_ptr(a);
            std::assert_eq!(
                pool.index_of_ptr(ptr),
                Some(idx),
                "slot {idx}: the published address must resolve back to it"
            );
            std::assert_eq!(
                ptr as usize % ALIGNMENT as usize,
                0,
                "slot {idx}: a published address must satisfy <sce:alignment> {ALIGNMENT}"
            );
        }

        // Unwind: the FSM has no armed -> free edge, so drive them through.
        for a in armed {
            let idx = <ActiveSessionPool as ArmedRxSlots>::armed_idx(&a);
            // SAFETY: test-local peripheral; nothing was armed for real.
            unsafe { pool.start(a) };
            // SAFETY: same.
            let filled = unsafe { pool.complete(idx) }.expect("in flight");
            pool.release_filled(filled);
        }
        std::assert_eq!(pool.free_count(), count);
    }

    /// A full ring cycle where the ONLY write is through the published
    /// address, and the completion names the buffer by address rather than by
    /// index — the driver contract end to end.
    #[test]
    fn a_frame_written_only_through_the_published_address_reads_back() {
        let mut ring = DescriptorRingRx::<ActiveSessionPool>::new();
        let count = <ActiveSessionPool as RxSlots>::SLOT_COUNT;
        std::assert_eq!(ring.free_count(), count);

        let frame: &[u8] = b"r311y606 descriptor-ring frame";
        let addr = ring.provide_buffer().expect("a fresh pool arms");
        std::assert_eq!(
            ring.free_count(),
            count - 1,
            "an armed slot is off the freelist"
        );

        // SAFETY: `addr` is the address the ring just published for a slot it
        // put in flight, and the frame fits a slot.
        unsafe { peripheral_writes(addr, frame) };

        // SAFETY: the write above IS the completion this test observes.
        let seen =
            unsafe { ring.frame_received(addr, frame.len(), |bytes| std::vec::Vec::from(bytes)) };
        match seen {
            Completion::Delivered { value, .. } => std::assert_eq!(&value[..], frame),
            other => std::panic!("expected delivery, got {other:?}"),
        }
        std::assert_eq!(
            ring.free_count(),
            count,
            "the slot must be back on the freelist"
        );
        std::assert_eq!(ring.rejected(), 0);
    }

    /// THE ACCOUNTING GATE for the arm path. Cycle every slot several rounds
    /// and require the freelist back at `SLOT_COUNT` each time.
    ///
    /// Same shape as `rx_pool`'s, and it exists separately because the arm
    /// path walks four FSM edges the CPU path never touches — a missing return
    /// edge on THIS path would leave the CPU path's gate green.
    #[test]
    fn the_ring_returns_every_slot_every_round() {
        let mut ring = DescriptorRingRx::<ActiveSessionPool>::new();
        let count = <ActiveSessionPool as RxSlots>::SLOT_COUNT;

        for round in 0..3u8 {
            let mut addrs = std::vec::Vec::new();
            for i in 0..count {
                addrs.push(
                    ring.provide_buffer()
                        .unwrap_or_else(|| std::panic!("round {round}: slot {i} refused")),
                );
            }
            std::assert_eq!(
                ring.free_count(),
                0,
                "round {round}: ring should be drained"
            );
            std::assert!(
                ring.provide_buffer().is_none(),
                "round {round}: a drained ring must refuse, not overcommit"
            );

            for (i, addr) in addrs.into_iter().enumerate() {
                let tag = [round, i as u8];
                // SAFETY: each `addr` is in flight and two bytes fit.
                unsafe { peripheral_writes(addr, &tag) };
                // SAFETY: the write above is the completion.
                let seen =
                    unsafe { ring.frame_received(addr, tag.len(), |bytes| [bytes[0], bytes[1]]) };
                match seen {
                    Completion::Delivered { value, .. } => std::assert_eq!(value, tag),
                    other => std::panic!("round {round} slot {i}: {other:?}"),
                }
            }
            std::assert_eq!(
                ring.free_count(),
                count,
                "round {round}: every slot must be back"
            );
        }
        std::assert_eq!(ring.rejected(), 0);
    }

    /// An address the pool never published is refused, and is NOT rounded down
    /// to the slot that contains it.
    ///
    /// The negative arm that makes the positive one a claim: without it,
    /// `index_of_ptr` returning `Some(0)` for everything would satisfy every
    /// test above.
    #[test]
    fn an_interior_or_foreign_address_is_refused_not_rounded() {
        let mut ring = DescriptorRingRx::<ActiveSessionPool>::new();
        let count = <ActiveSessionPool as RxSlots>::SLOT_COUNT;
        let addr = ring.provide_buffer().expect("armed");

        // One byte into a slot the pool DID publish. A shadow table that
        // rounded down would call this slot 0 and complete it.
        // SAFETY: pointer arithmetic within the slot; never dereferenced.
        let interior = unsafe { addr.add(1) };
        // SAFETY: nothing completed; the call only resolves an address.
        let seen = unsafe { ring.frame_received(interior, 1, |_| ()) };
        std::assert_eq!(seen, Completion::ForeignAddress);

        let outside = 0x1000usize as *const u8;
        // SAFETY: same — the address is refused before any slot is touched.
        let seen = unsafe { ring.frame_received(outside, 1, |_| ()) };
        std::assert_eq!(seen, Completion::ForeignAddress);

        std::assert_eq!(ring.rejected(), 2);
        std::assert_eq!(
            ring.free_count(),
            count - 1,
            "a refused completion must not advance or release anything"
        );

        // The real address still completes, so the refusals above did not
        // wedge the slot they were aimed at.
        // SAFETY: in flight, and the consumer reads nothing.
        let seen = unsafe { ring.frame_received(addr, 0, |_| ()) };
        std::assert!(matches!(seen, Completion::Delivered { .. }), "{seen:?}");
        std::assert_eq!(ring.free_count(), count);
    }

    /// A replayed completion is refused, and the slot it names is untouched.
    #[test]
    fn a_replayed_completion_is_refused() {
        let mut ring = DescriptorRingRx::<ActiveSessionPool>::new();
        let count = <ActiveSessionPool as RxSlots>::SLOT_COUNT;
        let addr = ring.provide_buffer().expect("armed");

        // SAFETY: in flight.
        let first = unsafe { ring.frame_received(addr, 0, |_| ()) };
        let idx = match first {
            Completion::Delivered { idx, .. } => idx,
            other => std::panic!("{other:?}"),
        };
        std::assert_eq!(ring.free_count(), count);

        // SAFETY: the address is still a valid pool address; the pool decides.
        let again = unsafe { ring.frame_received(addr, 0, |_| ()) };
        std::assert_eq!(again, Completion::NotInFlight(idx));
        std::assert_eq!(ring.rejected(), 1);
        std::assert_eq!(
            ring.free_count(),
            count,
            "a replay must not double-release the slot"
        );
    }

    /// A completion claiming more bytes than a slot holds returns the slot and
    /// refuses the frame, rather than truncating it or panicking.
    #[test]
    fn an_overlong_completion_returns_the_slot_and_refuses_the_frame() {
        let mut ring = DescriptorRingRx::<ActiveSessionPool>::new();
        let count = <ActiveSessionPool as RxSlots>::SLOT_COUNT;
        let slot_size = <ActiveSessionPool as RxSlots>::SLOT_SIZE;
        let addr = ring.provide_buffer().expect("armed");

        // SAFETY: in flight; the consumer would only run on the happy path.
        let seen = unsafe { ring.frame_received(addr, slot_size + 1, |_| ()) };
        std::assert_eq!(
            seen,
            Completion::Overlong {
                idx: ring
                    .pool
                    .index_of_ptr(addr)
                    .expect("the address is the pool's"),
                len: slot_size + 1,
            }
        );
        std::assert_eq!(ring.rejected(), 1);
        std::assert_eq!(
            ring.free_count(),
            count,
            "an overlong frame must still return its slot"
        );
    }

    /// The emit's own lifecycle states are what moves — not this adapter's
    /// bookkeeping, of which it has none beyond the reject counter.
    #[test]
    fn the_arm_path_moves_the_emitted_states() {
        let mut pool = <ActiveSessionPool as RxSlots>::new();
        let armed = pool.arm().expect("armed");
        let idx = <ActiveSessionPool as ArmedRxSlots>::armed_idx(&armed);
        std::assert_eq!(pool.slot_state(idx), Some(SlotState::DmaArmedRx));

        // SAFETY: test-local peripheral.
        unsafe { pool.start(armed) };
        std::assert_eq!(pool.slot_state(idx), Some(SlotState::DmaBusyRx));

        // SAFETY: same.
        let filled = unsafe { pool.complete(idx) }.expect("in flight");
        std::assert_eq!(pool.slot_state(idx), Some(SlotState::CpuRef));

        pool.release_filled(filled);
        std::assert_eq!(pool.slot_state(idx), Some(SlotState::Free));
    }
}
