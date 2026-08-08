// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y599 — the MCU receive seam: slots the reader borrows and returns,
//! over the SCE-generated buffer-pool lifecycle FSM.
//!
//! ## Why this exists
//!
//! Until this module the four `out/wz-link-lwip/*_pool_mcu.rs` emits were
//! consumed for their CONSTANTS only — [`rx_sockets`](crate::rx_sockets)
//! turned `SLOT_COUNT` / `SLOT_SIZE` into `LwipUdpSocket<N, Q>` const
//! generics and the seven-state slot lifecycle had zero callers. The pool was
//! a dimension oracle, not a pool. [`RxSlots`] is the seam that makes it one.
//!
//! ## The seam's shape, and what it deliberately hides
//!
//! A reader asks for the bytes of a received datagram and says when it is
//! done. It does NOT learn how the bytes got into the slot. That is the whole
//! point: on the host / QEMU profile the CPU copies them out of an lwIP
//! `pbuf`, and on a descriptor-ring MAC the peripheral writes them directly.
//! Both end at the same place — a slot holding `len` bytes, borrowed then
//! returned — so both can sit behind this trait without the session tier
//! branching on which one it got.
//!
//! ## What this trait is NOT, stated so it is not stretched later
//!
//! It is the pool-facing half: reserve, fill, read, release. It does not
//! model the ARMING half (`link_arm_rx` -> `dma_start_rx` -> `rx_complete`),
//! because arming needs something this API cannot yet give: the ADDRESS of a
//! slot that is armed but not yet filled, to hand to a MAC's buffer-request
//! callback. The emitted `Slot<DmaArmedRx>` carries only `idx()` and the
//! pool's `storage` is private, so a descriptor-ring adapter cannot be built
//! on the arm path today (measured against `out/wz-link-lwip/
//! session_rx_pool_mcu.rs` at vendor/sce `ef4c2fe4d5`). A CPU-fill adapter
//! needs none of that, which is why this half lands first.
//!
//! Nor does it model a CIRCULAR-DMA source (zenoh-pico's serial port,
//! `vendor/zenoh-pico/src/system/threadx/stm32/network.c:4`), where the
//! peripheral writes a ring continuously and software reads behind it. That
//! shape has no reserve/release pair at all and must not be forced through
//! this one.
//!
//! ## The accounting gate
//!
//! [`RxSlots::free_count`] is the reason this seam is worth having beyond
//! tidiness: a reader that drops a slot instead of releasing it shows up as a
//! freelist that never returns to `SLOT_COUNT`. That is exactly the failure
//! SCE shipped and fixed at `4f31430001` — a pool whose arm edge had no
//! return path died on first use, and no consumer could see it because no
//! consumer counted. The tests below count.

/// A pool of fixed-size receive slots with a borrow-then-return discipline.
///
/// Implemented over each SCE-generated `sce:kind="buffer-pool"` emit by
/// [`impl_rx_slots`]. The associated [`Slot`](RxSlots::Slot) is the emit's own
/// phantom-typed handle, so the lifecycle rules the generator encodes —
/// `pool_return` on a slot the peripheral owns is a type error, not a runtime
/// check — survive being seen through this trait.
pub trait RxSlots {
    /// Slots in the pool. From the buffer-pool SSOT, not chosen here.
    const SLOT_COUNT: usize;
    /// Bytes per slot. From the same SSOT.
    const SLOT_SIZE: usize;

    /// A reserved slot. Opaque: the reader holds it and gives it back.
    type Slot;

    /// A pool with every slot on the freelist.
    fn new() -> Self;

    /// Take a slot off the freelist, or `None` when every slot is out.
    ///
    /// `None` is back-pressure, not an error: the caller drops the datagram
    /// and counts it, which is what a bounded receive path must do.
    fn reserve(&mut self) -> Option<Self::Slot>;

    /// Writable bytes of a reserved slot — where a CPU filler copies to, and
    /// the full [`SLOT_SIZE`](RxSlots::SLOT_SIZE) width regardless of how much
    /// the filler will use.
    fn buf<'a>(&'a mut self, slot: &'a mut Self::Slot) -> &'a mut [u8];

    /// Readable bytes of a slot, full width. The caller pairs this with the
    /// length it recorded at fill time; the pool does not track lengths,
    /// because a length belongs to a datagram and a slot outlives none.
    fn bytes<'a>(&'a self, slot: &'a Self::Slot) -> &'a [u8];

    /// Return a slot to the freelist. Consumes the handle, so a reader cannot
    /// keep reading bytes it has released.
    fn release(&mut self, slot: Self::Slot);

    /// Slots currently on the freelist. The accounting gate — see the module
    /// docs.
    fn free_count(&self) -> usize;

    /// Pool index of a held slot, for tracing and for the tests that assert on
    /// the emit's own `slot_state` rather than on this trait's bookkeeping.
    fn slot_idx(slot: &Self::Slot) -> usize;
}

/// Implement [`RxSlots`] over one SCE-generated buffer-pool emit.
///
/// Every emit has the same shape (`pool_acquire_for_encode` / `write` /
/// `read` / `pool_return` / `free_count`), so the impl is mechanical — but it
/// is written out per pool rather than made generic because the emitted
/// `Slot<CpuMut>` types are DISTINCT per pool by construction: a slot from the
/// scout pool must not be returnable to the session pool, and keeping the
/// types apart is what makes that a compile error.
macro_rules! impl_rx_slots {
    ($pool_mod:ident, $pool_ty:ident) => {
        impl RxSlots for crate::$pool_mod::$pool_ty {
            const SLOT_COUNT: usize = crate::$pool_mod::SLOT_COUNT;
            const SLOT_SIZE: usize = crate::$pool_mod::SLOT_SIZE;

            type Slot = crate::$pool_mod::Slot<crate::$pool_mod::CpuMut>;

            fn new() -> Self {
                <crate::$pool_mod::$pool_ty>::new()
            }

            fn reserve(&mut self) -> Option<Self::Slot> {
                self.pool_acquire_for_encode()
            }

            fn buf<'a>(&'a mut self, slot: &'a mut Self::Slot) -> &'a mut [u8] {
                &mut slot.write(self)[..]
            }

            fn bytes<'a>(&'a self, slot: &'a Self::Slot) -> &'a [u8] {
                &slot.read(self)[..]
            }

            fn release(&mut self, slot: Self::Slot) {
                slot.pool_return(self);
            }

            fn free_count(&self) -> usize {
                <crate::$pool_mod::$pool_ty>::free_count(self)
            }

            fn slot_idx(slot: &Self::Slot) -> usize {
                slot.idx()
            }
        }
    };
}

impl_rx_slots!(scout_rx_pool_mcu, ScoutRxPoolMcu);
impl_rx_slots!(session_rx_pool_mcu_multicast, SessionRxPoolMcuMulticast);

// The unicast session pool is ONE module under two names: the default emit or
// the slim one, never both (`lib.rs:116,136`). The impl carries the same gate
// as the module it names — a helper whose cfg is narrower than the item it
// calls is the G7 shape, and here it is the emit that is gated, so the impl
// must be too.
#[cfg(not(feature = "buffer-pool-session-rx-slim"))]
impl_rx_slots!(session_rx_pool_mcu, SessionRxPoolMcu);
#[cfg(feature = "buffer-pool-session-rx-slim")]
impl_rx_slots!(session_rx_pool_mcu_minimal, SessionRxPoolMcuMinimal);

#[cfg(test)]
mod tests {
    use super::*;

    // The ACTIVE unicast session pool under either feature arm, so the slim
    // lane runs these tests too rather than compiling them out. A `#[cfg]` on
    // the tests themselves would leave the slim build asserting nothing about
    // the seam while still reporting green.
    #[cfg(not(feature = "buffer-pool-session-rx-slim"))]
    use crate::session_rx_pool_mcu::{SessionRxPoolMcu as ActiveSessionPool, SlotState};
    #[cfg(feature = "buffer-pool-session-rx-slim")]
    use crate::session_rx_pool_mcu_minimal::{
        SessionRxPoolMcuMinimal as ActiveSessionPool, SlotState,
    };

    /// The dims reaching the trait are the SSOT's. Asserted against
    /// [`crate::rx_sockets`]' constants rather than against literals, because
    /// those two are the pool's only consumers and the whole hazard is them
    /// disagreeing: `rx_sockets` sizes the socket, this seam sizes the slots,
    /// and a pool whose two readers picked different numbers would truncate
    /// silently.
    #[test]
    fn the_trait_carries_the_same_dims_the_socket_tier_reads() {
        std::assert_eq!(
            <ActiveSessionPool as RxSlots>::SLOT_COUNT,
            crate::rx_sockets::SESSION_RX_SLOTS
        );
        std::assert_eq!(
            <ActiveSessionPool as RxSlots>::SLOT_SIZE,
            crate::rx_sockets::SESSION_RX_SLOT_SIZE
        );
    }

    /// A full reserve -> fill -> read -> release cycle, driving the EMIT's
    /// lifecycle rather than this trait's bookkeeping: the slot's state is
    /// read back out of the generated `slot_state`, so a trait that "worked"
    /// while leaving the FSM untouched would fail here.
    #[test]
    fn one_cycle_moves_the_emitted_state_and_returns_the_slot() {
        let mut pool = <ActiveSessionPool as RxSlots>::new();
        std::assert_eq!(
            pool.free_count(),
            <ActiveSessionPool as RxSlots>::SLOT_COUNT
        );

        let mut slot = pool.reserve().expect("a fresh pool has a free slot");
        let idx = <ActiveSessionPool as RxSlots>::slot_idx(&slot);
        std::assert_eq!(pool.slot_state(idx), Some(SlotState::CpuMut));
        std::assert_eq!(
            pool.free_count(),
            <ActiveSessionPool as RxSlots>::SLOT_COUNT - 1
        );

        let payload: &[u8] = b"r311y599 cpu-filled slot";
        pool.buf(&mut slot)[..payload.len()].copy_from_slice(payload);
        std::assert_eq!(&pool.bytes(&slot)[..payload.len()], payload);

        pool.release(slot);
        std::assert_eq!(pool.slot_state(idx), Some(SlotState::Free));
        std::assert_eq!(
            pool.free_count(),
            <ActiveSessionPool as RxSlots>::SLOT_COUNT
        );
    }

    /// THE ACCOUNTING GATE. Cycle every slot in the pool several times over
    /// and require the freelist back at `SLOT_COUNT` each round.
    ///
    /// This is the shape of the defect SCE shipped and fixed at `4f31430001`:
    /// a pool whose slots left the freelist and had no path back died after
    /// `SLOT_COUNT` uses, silently, because nothing counted. Asserting only
    /// that `reserve` returned `Some` would pass on that pool for exactly one
    /// round and then wedge, so the loop runs three.
    #[test]
    fn the_freelist_returns_to_full_after_every_round() {
        let mut pool = <ActiveSessionPool as RxSlots>::new();
        let count = <ActiveSessionPool as RxSlots>::SLOT_COUNT;

        for round in 0..3 {
            let mut held = std::vec::Vec::new();
            for i in 0..count {
                let slot = pool
                    .reserve()
                    .unwrap_or_else(|| std::panic!("round {round}: slot {i} of {count} refused"));
                held.push(slot);
            }
            std::assert_eq!(
                pool.free_count(),
                0,
                "round {round}: pool should be drained"
            );
            std::assert!(
                pool.reserve().is_none(),
                "round {round}: a drained pool must refuse, not overcommit"
            );

            for slot in held {
                pool.release(slot);
            }
            std::assert_eq!(
                pool.free_count(),
                count,
                "round {round}: every slot must be back on the freelist"
            );
        }
    }

    /// Slots are distinct: filling one does not disturb another. Guards the
    /// index arithmetic the emit does on its `storage` array — an off-by-one
    /// there would alias two readers onto one buffer, which no state assertion
    /// would catch.
    #[test]
    fn two_slots_do_not_alias() {
        let mut pool = <ActiveSessionPool as RxSlots>::new();
        let mut a = pool.reserve().expect("slot a");
        let mut b = pool.reserve().expect("slot b");
        std::assert_ne!(
            <ActiveSessionPool as RxSlots>::slot_idx(&a),
            <ActiveSessionPool as RxSlots>::slot_idx(&b)
        );

        pool.buf(&mut a)[..4].copy_from_slice(b"AAAA");
        pool.buf(&mut b)[..4].copy_from_slice(b"BBBB");

        std::assert_eq!(&pool.bytes(&a)[..4], b"AAAA");
        std::assert_eq!(&pool.bytes(&b)[..4], b"BBBB");

        pool.release(a);
        pool.release(b);
        std::assert_eq!(
            pool.free_count(),
            <ActiveSessionPool as RxSlots>::SLOT_COUNT
        );
    }

    /// Each pool is a SEPARATE implementor with its own dims, so the scout
    /// pool's 8 / 256 cannot be mistaken for the session pool's 16 / 1536.
    /// The types being distinct is what stops a scout slot being released
    /// into the session pool; this only pins that the dims travel with them.
    #[test]
    fn each_pool_brings_its_own_dims() {
        use crate::scout_rx_pool_mcu::ScoutRxPoolMcu;
        use crate::session_rx_pool_mcu_multicast::SessionRxPoolMcuMulticast;

        std::assert_eq!(<ScoutRxPoolMcu as RxSlots>::SLOT_COUNT, 8);
        std::assert_eq!(<ScoutRxPoolMcu as RxSlots>::SLOT_SIZE, 256);
        std::assert_eq!(<SessionRxPoolMcuMulticast as RxSlots>::SLOT_COUNT, 32);
        std::assert_eq!(<SessionRxPoolMcuMulticast as RxSlots>::SLOT_SIZE, 1536);

        let mut scout = <ScoutRxPoolMcu as RxSlots>::new();
        let s = scout.reserve().expect("scout slot");
        std::assert_eq!(scout.free_count(), 7);
        scout.release(s);
        std::assert_eq!(scout.free_count(), 8);
    }
}
