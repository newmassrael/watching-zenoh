// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ARCHITECTURE section 9.2 on the MCU profile -- the RECEIVE POOL: the slots an
//! Ethernet MAC's receive DMA writes frames into, which lwIP then reads in place.
//!
//! ## What this adds to the loan that came before it
//!
//! A MAC that lends a received frame ([`EthernetMac::receive_loan`]) used to lend
//! a buffer of its own ring, one per descriptor, so a frame the stack held kept
//! its descriptor out of the ring, and no generated lifecycle followed it. This
//! module is the generated pool's receive edges as a MAC's buffers: installed, the
//! MAC arms each receive descriptor with a slot of [`eth_rx_pool_mcu`], lends a
//! received frame in its slot, and re-arms the descriptor with another slot at
//! once, so the ring stays whole while the stack reads.
//!
//! | what happens to the frame | edge of the generated pool |
//! |---|---|
//! | a descriptor is given a slot | `link_arm_rx` (free to dma-armed-rx) |
//! | the descriptor is released to the controller | `dma_start_rx` (to dma-busy-rx) |
//! | the controller reports the frame written | `rx_complete` (to cpu-ref) |
//! | lwIP, and a socket that holds it, read it in place | `read` on the cpu-ref handle |
//! | the last reader lets go | `pool_return` (cpu-ref to free) |
//!
//! The binding is [`PoolRxRing`]; this module adds the pool's storage and its
//! installation.
//!
//! ## Where the pool lives is the firmware's
//!
//! The controller writes a slot behind the CPU's back, so the pool belongs in
//! memory the bus master reaches and the CPU does not cache (the pool's cache
//! policy is `non-cacheable`). Only the firmware knows where that is, so the
//! firmware owns the storage ([`RxPoolStorage`], in a placed `static`) and hands
//! it to [`install`]; and the MAC refuses a pool outside the window its board
//! names for writing received frames. Such a section is commonly not loaded
//! (Zephyr's `.nocache` is `NOLOAD`), so `install` writes the whole pool before
//! using it; a pool of zeroes is a pool of free slots, which a test below pins.
//!
//! [`EthernetMac::receive_loan`]: wz_runtime_core::EthernetMac::receive_loan
//! [`eth_rx_pool_mcu`]: crate::eth_rx_pool_mcu
//! [`PoolRxRing`]: crate::rx_ring::PoolRxRing
//! [`RxPoolStorage`]: crate::mac_rx_pool::RxPoolStorage
//! [`install`]: crate::mac_rx_pool::install

use alloc::boxed::Box;
use core::mem::MaybeUninit;

pub use crate::eth_rx_pool_mcu::SlotState;
use crate::eth_rx_pool_mcu::{EthRxPoolMcu, SLOT_COUNT};
use crate::rx_ring::PoolRxRing;

/// The memory a firmware sets aside for the pool, in a `static` it places where
/// the MAC's DMA reaches and the CPU does not cache. It needs no initial value:
/// [`install`] writes all of it.
pub type RxPoolStorage = MaybeUninit<EthRxPoolMcu>;

/// The installed pool, bound as a MAC's receive buffers.
pub type EthRxRing = PoolRxRing<EthRxPoolMcu, SLOT_COUNT>;

/// Make `storage` a pool of free slots and bind it as a MAC's receive buffers.
///
/// The whole of `storage` is written first, a 32-bit word at a time, because the
/// section a firmware places it in is commonly not loaded and holds whatever the
/// RAM held at reset (and on RAM with ECC, words nothing has written, which a
/// narrower store would read first). Every slot starts free.
///
/// The binding is the caller's to hand to one MAC
/// (`Cyt4bfMac::new_pooled`, which takes it as a `dyn MacRxPool`).
pub fn install(storage: &'static mut RxPoolStorage) -> &'static mut EthRxRing {
    const _: () = assert!(
        SlotState::Free as u8 == 0,
        "a pool of zeroes is a pool of free slots only while free is the state 0"
    );
    const _: () = assert!(core::mem::size_of::<EthRxPoolMcu>() % 4 == 0);
    let words = core::mem::size_of::<EthRxPoolMcu>() / 4;
    let base = storage.as_mut_ptr() as *mut u32;
    for i in 0..words {
        // SAFETY: `i` words into storage this `&'static mut` owns, which is aligned
        // to its slots' alignment (at least 4) and a whole number of words long.
        unsafe { base.add(i).write_volatile(0) };
    }
    // SAFETY: every byte is zero, and an all-zero pool is a valid one: the slot
    // bytes are plain bytes and every slot state reads `Free` (asserted above).
    let pool = unsafe { storage.assume_init_mut() };
    Box::leak(Box::new(PoolRxRing::new(pool)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth_rx_pool_mcu::SLOT_SIZE;
    use wz_runtime_core::MacRxPool;

    fn storage() -> &'static mut RxPoolStorage {
        Box::leak(Box::new(RxPoolStorage::uninit()))
    }

    /// The storage a firmware gives is not trusted to hold anything: a section that
    /// is not loaded holds what the RAM held at reset. Installed over storage full
    /// of ones (a slot state of 0xFF is no state at all), every slot is free, the
    /// span is the slots on their declared alignment, and the dims are the SSOT's.
    #[test]
    fn a_pool_installed_over_garbage_is_a_pool_of_free_slots() {
        let storage = storage();
        // SAFETY: writes bytes into storage this test owns.
        unsafe {
            core::ptr::write_bytes(
                storage.as_mut_ptr() as *mut u8,
                0xFF,
                core::mem::size_of::<EthRxPoolMcu>(),
            )
        };
        let ring = install(storage);
        std::assert_eq!((ring.slot_count(), ring.slot_size()), (16, 1536));
        std::assert_eq!(ring.free_count(), SLOT_COUNT, "every slot is free");
        let (start, len) = ring.span();
        std::assert_eq!(len, SLOT_COUNT * SLOT_SIZE);
        std::assert_eq!(start as usize % 32, 0, "slots on the declared alignment");
        for idx in 0..SLOT_COUNT {
            std::assert_eq!(ring.pool().slot_state(idx), Some(SlotState::Free));
        }
    }

    /// The binding walks the GENERATED lifecycle, read off the emit's own slot
    /// states at every edge, and each address it publishes is the slot the pool
    /// names by it: armed, the bus master's once started, the CPU's to read once
    /// complete, free once released.
    #[test]
    fn the_binding_walks_the_generated_receive_lifecycle() {
        let ring = install(storage());
        let (idx, addr) = ring.arm_rx().expect("a free slot");
        std::assert_eq!(ring.pool().slot_state(idx), Some(SlotState::DmaArmedRx));
        std::assert_eq!(ring.pool().slot_index_of_ptr(addr), Some(idx));
        std::assert_eq!(ring.free_count(), SLOT_COUNT - 1);

        // SAFETY: the test is the bus master; the descriptor is notional.
        std::assert!(unsafe { ring.start_rx(idx) });
        std::assert_eq!(ring.pool().slot_state(idx), Some(SlotState::DmaBusyRx));
        // SAFETY: as above.
        std::assert!(!unsafe { ring.start_rx(idx) }, "started once");

        // The bus master writes through the published address and nothing else.
        let frame = b"written by the controller";
        // SAFETY: `addr` is the slot's first byte, in the bus master's hands.
        unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), addr, frame.len()) };
        // SAFETY: the write above is the completion.
        let read = unsafe { ring.complete_rx(idx) }.expect("in flight");
        std::assert_eq!(
            read,
            addr as *const u8,
            "the CPU reads where it was written"
        );
        std::assert_eq!(ring.pool().slot_state(idx), Some(SlotState::CpuRef));
        // SAFETY: the slot is the CPU's to read, `frame.len()` bytes were written.
        std::assert_eq!(
            unsafe { core::slice::from_raw_parts(read, frame.len()) },
            frame
        );
        // SAFETY: a replayed completion.
        std::assert!(unsafe { ring.complete_rx(idx) }.is_none(), "completed once");

        std::assert!(ring.release_rx(idx));
        std::assert_eq!(ring.pool().slot_state(idx), Some(SlotState::Free));
        std::assert!(!ring.release_rx(idx), "a second return frees nothing");
        std::assert_eq!(ring.free_count(), SLOT_COUNT);
    }

    /// A slot not in the state an edge needs is refused by the edge: an armed slot
    /// cannot be released, a free one cannot be completed, an index past the pool
    /// names nothing.
    #[test]
    fn an_edge_refuses_a_slot_not_in_its_state() {
        let ring = install(storage());
        let (idx, _) = ring.arm_rx().expect("a free slot");
        std::assert!(!ring.release_rx(idx), "armed, not completed");
        // SAFETY: refused before anything is touched.
        std::assert!(
            unsafe { ring.complete_rx(idx) }.is_none(),
            "armed, not started"
        );
        // SAFETY: as above.
        std::assert!(
            unsafe { ring.complete_rx(SLOT_COUNT - 1) }.is_none(),
            "free"
        );
        // SAFETY: as above.
        std::assert!(
            unsafe { ring.complete_rx(SLOT_COUNT) }.is_none(),
            "no such slot"
        );
        std::assert!(!ring.release_rx(SLOT_COUNT + 3));
        std::assert_eq!(ring.pool().slot_state(idx), Some(SlotState::DmaArmedRx));
    }

    /// The pool runs dry after its last slot, and arms nothing more rather than
    /// failing; a slot given back is armed again.
    #[test]
    fn a_dry_pool_arms_nothing_until_a_slot_comes_back() {
        let ring = install(storage());
        let mut out = std::vec::Vec::new();
        for _ in 0..SLOT_COUNT {
            let (idx, _) = ring.arm_rx().expect("a free slot");
            // SAFETY: notional bus master.
            std::assert!(unsafe { ring.start_rx(idx) });
            out.push(idx);
        }
        std::assert!(ring.arm_rx().is_none(), "every slot is out");
        let back = out[5];
        // SAFETY: notional completion.
        std::assert!(unsafe { ring.complete_rx(back) }.is_some());
        std::assert!(ring.release_rx(back));
        std::assert_eq!(ring.arm_rx().map(|(idx, _)| idx), Some(back));
    }
}
