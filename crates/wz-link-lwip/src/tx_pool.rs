// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! ARCHITECTURE section 9.1 on the MCU profile -- the TRANSMIT POOL: the slots a
//! session encodes its outbound frames into, which an Ethernet MAC's DMA then
//! reads where they lie.
//!
//! ## What this adds to the lend that came before it
//!
//! The lwIP driver already lends the session the memory of the pbuf a datagram is
//! sent in ([`LwipUdpSocket::alloc_tx_payload`](crate::LwipUdpSocket::alloc_tx_payload)),
//! and a MAC that gathers in place reads that pbuf without a copy. What governed
//! that buffer was lwIP's heap and the pbuf's reference count; the generated
//! pool's transmit lifecycle (`sources/network/session_tx_pool_mcu.scxml`) had no
//! caller. This module is its caller: with a pool installed, the lend is a slot of
//! the pool, and every step of the frame's life is an edge of that lifecycle.
//!
//! | what happens to the frame | edge of the generated pool |
//! |---|---|
//! | the session is lent a slot | `pool_acquire_for_encode` (free to cpu-mut) |
//! | the frame is sent | `link_arm_tx` (cpu-mut to dma-armed-tx) |
//! | a MAC queues it to be read in place | `dma_start_tx` (to dma-busy-tx) |
//! | the MAC reports it done and lwIP lets go | `tx_complete` (dma-busy-tx to free) |
//! | it left by a copy, or reached no MAC | `un_arm_tx` then `pool_return` |
//! | it was lent and never sent | `pool_return` (cpu-mut to free) |
//!
//! The address a MAC is handed is checked against the pool's own answer
//! (`dma_armed_tx_ptr`), so a slot is started only when a piece of the frame the
//! MAC queued lies inside it.
//!
//! ## How a slot becomes a pbuf
//!
//! A slot is laid out as lwIP lays out a pbuf of its own heap: the custom pbuf
//! record at the start, the room lwIP keeps in front of a transport payload, then
//! the payload (`wz_lwip_tx_slot_pbuf` in `lwip-sys/shim.c`). lwIP writes the UDP,
//! IPv4 and Ethernet headers into that room, so the frame a MAC is handed is ONE
//! piece inside the slot, and the pbuf lwIP frees at the end is the slot's first
//! byte, which is how the free callback names the slot to the pool.
//!
//! ## Where the pool lives is the firmware's
//!
//! A DMA master reads a slot behind the CPU's back, so the pool belongs in memory
//! the bus master reaches and the CPU does not cache (the pool's cache policy is
//! `non-cacheable`). Only the firmware knows where that is, so the firmware owns
//! the storage ([`TxPoolStorage`], in a placed `static`) and hands it to
//! [`install`]. Such a section is commonly not loaded (Zephyr's `.nocache` is
//! `NOLOAD`), so `install` writes the whole pool itself before using it; a pool
//! of zeroes is a pool of free slots, which a test below pins.
//!
//! Without an installed pool nothing here runs and the lend is lwIP's heap pbuf,
//! as before. A dry pool is not an error either: the lend falls back the same way.
//!
//! ## Threading
//!
//! lwIP runs `NO_SYS`, on one thread, and so does everything here: the pool is
//! reached from the lend, the send, the MAC's gather callback and lwIP's free
//! callback, all on that thread and none of them inside another.
//!
//! [`TxPoolStorage`]: crate::tx_pool::TxPoolStorage
//! [`install`]: crate::tx_pool::install

use alloc::boxed::Box;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, Ordering};

use lwip_sys::{pbuf, wz_lwip_tx_slot_capacity, wz_lwip_tx_slot_pbuf};
use wz_runtime_core::TxSegment;

pub use crate::session_tx_pool_mcu::SlotState;
use crate::session_tx_pool_mcu::{CpuMut, SessionTxPoolMcu, Slot, SLOT_COUNT, SLOT_SIZE};

/// The memory a firmware sets aside for the pool, in a `static` it places where
/// the MAC's DMA reaches and the CPU does not cache. It needs no initial value:
/// [`install`] writes all of it.
pub type TxPoolStorage = MaybeUninit<SessionTxPoolMcu>;

/// Where the pool's slots are: the window a board lets its MAC read in place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxPoolSpan {
    /// The first byte of the first slot.
    pub start: *const u8,
    /// The bytes of every slot together.
    pub len: usize,
}

/// What the pool has done since it was installed. A frame is counted once in
/// `lent`, and then once in exactly one of `abandoned`, `completed` and `unarmed`
/// when it is over.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxPoolStats {
    /// Slots lent to a sender.
    pub lent: u32,
    /// Slots lent and given back unsent.
    pub abandoned: u32,
    /// Frames a MAC queued to read in place from a slot.
    pub started: u32,
    /// Of those, the ones whose MAC reported them done and lwIP let go.
    pub completed: u32,
    /// Frames sent from a slot that no MAC read in place: the MAC copied the
    /// frame, refused it, or it never reached a MAC (a loopback, a send lwIP
    /// refused, an address that never resolved).
    pub unarmed: u32,
    /// Slots on the freelist now.
    pub free: u32,
}

struct Installed {
    pool: NonNull<SessionTxPoolMcu>,
    span: TxPoolSpan,
    capacity: u16,
    stats: TxPoolStats,
}

/// The pool lwIP sends from, if one is installed. Written by [`install`], read
/// by the lend, the gather callback and the free callback, all on lwIP's thread.
static INSTALLED: AtomicPtr<Installed> = AtomicPtr::new(core::ptr::null_mut());

/// Run `f` on the installed pool. Every caller is on lwIP's one thread and none
/// calls into lwIP while `f` runs, so no two of these borrows are ever live at
/// once.
fn with<R>(f: impl FnOnce(&mut Installed, &mut SessionTxPoolMcu) -> R) -> Option<R> {
    let installed = INSTALLED.load(Ordering::Acquire);
    // SAFETY: a non-null pointer is a leaked `Installed` that `install` wrote and
    // nothing frees; the threading contract above makes this the only borrow.
    let installed = unsafe { installed.as_mut() }?;
    let mut pool = installed.pool;
    // SAFETY: the pool is the `'static` storage `install` initialised, and the
    // borrow ends with `f`.
    let pool = unsafe { pool.as_mut() };
    Some(f(installed, pool))
}

/// Make `storage` the pool lwIP sends from, and say where its slots are.
///
/// The whole of `storage` is written first, a 32-bit word at a time, because the
/// section a firmware places it in is commonly not loaded and holds whatever the
/// RAM held at reset (and on RAM with ECC, words nothing has written, which a
/// narrower store would read first). Every slot starts free.
///
/// A second call replaces the first pool. A frame still in flight from the old
/// one is then a stranger to this module, and its slot is not touched again.
pub fn install(storage: &'static mut TxPoolStorage) -> TxPoolSpan {
    const _: () = assert!(
        SlotState::Free as u8 == 0,
        "a pool of zeroes is a pool of free slots only while free is the state 0"
    );
    const _: () = assert!(core::mem::size_of::<SessionTxPoolMcu>() % 4 == 0);
    let words = core::mem::size_of::<SessionTxPoolMcu>() / 4;
    let base = storage.as_mut_ptr() as *mut u32;
    for i in 0..words {
        // SAFETY: `i` words into storage this `&'static mut` owns, which is aligned
        // to its slots' alignment (at least 4) and a whole number of words long.
        unsafe { base.add(i).write_volatile(0) };
    }
    // SAFETY: every byte is zero, and an all-zero pool is a valid one: the slot
    // bytes are plain bytes and every slot state reads `Free` (asserted above).
    let pool = unsafe { storage.assume_init_mut() };
    // Where the slots are, from the pool itself: the first slot taken from a pool
    // of free slots is slot 0, and the slots follow it.
    let span = {
        let mut first = pool
            .pool_acquire_for_encode()
            .expect("a pool of free slots has a free slot");
        let start = first.write(pool).as_ptr();
        first.pool_return(pool);
        TxPoolSpan {
            start,
            len: SLOT_SIZE * SLOT_COUNT,
        }
    };
    // SAFETY: reads a constant of the shim.
    let capacity = unsafe { wz_lwip_tx_slot_capacity(SLOT_SIZE as u16) };
    let installed = Box::leak(Box::new(Installed {
        pool: NonNull::from(pool),
        span,
        capacity,
        stats: TxPoolStats::default(),
    }));
    INSTALLED.store(installed, Ordering::Release);
    span
}

/// The installed pool's slots, or `None` when none is installed.
pub fn span() -> Option<TxPoolSpan> {
    with(|installed, _| installed.span)
}

/// What the installed pool has done, or `None` when none is installed.
pub fn stats() -> Option<TxPoolStats> {
    with(|installed, pool| TxPoolStats {
        free: pool.free_count() as u32,
        ..installed.stats
    })
}

/// The slot the byte at `ptr` lies in, with its state, or `None` when it lies in
/// no slot of the installed pool.
pub fn slot_of(ptr: *const u8) -> Option<(usize, SlotState)> {
    with(|installed, pool| {
        let offset = (ptr as usize).checked_sub(installed.span.start as usize)?;
        if offset >= installed.span.len {
            return None;
        }
        let idx = offset / SLOT_SIZE;
        Some((idx, pool.slot_state(idx)?))
    })
    .flatten()
}

/// How many payload bytes a lent slot can carry, or 0 when no pool is installed
/// (or the port cannot wrap a slot in a pbuf).
pub(crate) fn capacity() -> usize {
    with(|installed, _| usize::from(installed.capacity)).unwrap_or(0)
}

/// A slot lent to a sender and not yet sent: the handle the generated pool gave
/// for it, held until it is armed for transmit or given back.
pub(crate) struct Lent {
    slot: Slot<CpuMut>,
}

/// Lend a slot as a pbuf of `len` payload bytes, or `None` when no pool is
/// installed, every slot is out, or `len` does not fit a slot.
pub(crate) fn lend(len: u16) -> Option<(NonNull<pbuf>, Lent)> {
    with(|installed, pool| {
        if len > installed.capacity {
            return None;
        }
        let mut slot = pool.pool_acquire_for_encode()?;
        let memory = slot.write(pool).as_mut_ptr();
        // SAFETY: `memory` is the slot's `SLOT_SIZE` bytes, aligned to the pool's
        // alignment, and this module keeps it for the pbuf until the free
        // callback; the callback is `'static`.
        let p = unsafe {
            wz_lwip_tx_slot_pbuf(
                memory as *mut core::ffi::c_void,
                SLOT_SIZE as u16,
                len,
                Some(slot_freed),
            )
        };
        let Some(p) = NonNull::new(p) else {
            slot.pool_return(pool);
            return None;
        };
        installed.stats.lent += 1;
        Some((p, Lent { slot }))
    })
    .flatten()
}

/// The lent slot is being sent: the CPU is done writing it and it is the link's.
pub(crate) fn arm(lent: Lent) {
    let armed = with(|_, pool| lent.slot.link_arm_tx(pool));
    debug_assert!(armed.is_some(), "a slot was lent from a pool since removed");
}

/// The lent slot goes back unsent. Called after lwIP's own reference is gone.
pub(crate) fn abandon(lent: Lent) {
    let returned = with(|installed, pool| {
        lent.slot.pool_return(pool);
        installed.stats.abandoned += 1;
    });
    debug_assert!(
        returned.is_some(),
        "a slot was lent from a pool since removed"
    );
}

/// A MAC has queued a frame to be read in place from `pieces`: every armed slot a
/// piece lies in is now the bus master's.
///
/// The slot is found by the address the pool itself publishes for an armed slot,
/// so a piece in memory the pool did not arm (a header pbuf from lwIP's heap, a
/// slot of a pool since replaced) starts nothing.
pub(crate) fn on_queued(pieces: &[TxSegment]) {
    with(|installed, pool| {
        for idx in 0..SLOT_COUNT {
            let Some(base) = pool.dma_armed_tx_ptr(idx) else {
                continue;
            };
            let slot = base as usize..base as usize + SLOT_SIZE;
            if pieces
                .iter()
                .any(|piece| slot.contains(&(piece.ptr as usize)))
            {
                // SAFETY: the MAC has just said it will read this slot in place,
                // which is the start of the transfer the edge names.
                if unsafe { pool.dma_start_tx(idx) } {
                    installed.stats.started += 1;
                }
            }
        }
    });
}

/// lwIP's last reference to a slot's pbuf is gone: the slot goes home by the edge
/// its state calls for.
///
/// The pbuf is the slot's first byte, so the pool names the slot from it.
unsafe extern "C" fn slot_freed(p: *mut pbuf) {
    with(|installed, pool| {
        let Some(idx) = pool.slot_index_of_ptr(p as *const u8) else {
            // A slot of a pool since replaced.
            return;
        };
        match pool.slot_state(idx) {
            Some(SlotState::DmaBusyTx) => {
                // SAFETY: lwIP frees the pbuf only once the shim's reference is
                // given back, which is when the MAC reported the frame done.
                if unsafe { pool.tx_complete(idx) } {
                    installed.stats.completed += 1;
                }
            }
            Some(SlotState::DmaArmedTx) => {
                // SAFETY: no MAC was handed the slot to read in place (it would be
                // busy), and lwIP holds no reference any more.
                if let Some(slot) = unsafe { pool.un_arm_tx(idx) } {
                    slot.pool_return(pool);
                    installed.stats.unarmed += 1;
                }
            }
            // Lent and never sent: the holder of the handle gives it back
            // ([`abandon`]) right after this.
            _ => {}
        }
    });
}

/// Take the installed pool away again, for a test that installed one: a pool left
/// behind would change the lend every later test in the process makes.
#[cfg(any(test, feature = "test-support"))]
pub fn uninstall() {
    INSTALLED.store(core::ptr::null_mut(), Ordering::Release);
}

/// A pool installed for the length of a test, and taken away at its end even if
/// the test fails, so no other test lends from it. Hold it under the lwIP test
/// lock, as everything that touches lwIP is.
#[cfg(test)]
pub(crate) struct TestPool;

#[cfg(test)]
impl TestPool {
    pub(crate) fn install() -> Self {
        let storage: &'static mut TxPoolStorage = Box::leak(Box::new(TxPoolStorage::uninit()));
        install(storage);
        Self
    }
}

#[cfg(test)]
impl Drop for TestPool {
    fn drop(&mut self) {
        uninstall();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// The storage a firmware gives is not trusted to hold anything: a section that
    /// is not loaded holds what the RAM held at reset. Installed over storage full
    /// of ones (a slot state of 0xFF is no state at all), every slot is free and the
    /// window is the slots, at the pool's own addresses.
    #[test]
    fn a_pool_installed_over_garbage_is_a_pool_of_free_slots() {
        let (_serial, _link) = crate::lwip_test_link();
        let storage: &'static mut TxPoolStorage = Box::leak(Box::new(TxPoolStorage::uninit()));
        // SAFETY: writes bytes into storage this test owns.
        unsafe {
            core::ptr::write_bytes(
                storage.as_mut_ptr() as *mut u8,
                0xFF,
                core::mem::size_of::<SessionTxPoolMcu>(),
            )
        };
        let span = install(storage);
        let guard = TestPool;
        std::assert_eq!(span.len, SLOT_SIZE * SLOT_COUNT);
        std::assert_eq!(
            span.start as usize % 32,
            0,
            "slots on the declared alignment"
        );
        let free = stats().expect("installed").free;
        std::assert_eq!(free as usize, SLOT_COUNT, "every slot is free");
        for idx in 0..SLOT_COUNT {
            let byte = (span.start as usize + idx * SLOT_SIZE) as *const u8;
            std::assert_eq!(slot_of(byte), Some((idx, SlotState::Free)));
        }
        std::assert_eq!(slot_of((span.start as usize + span.len) as *const u8), None);
        drop(guard);
        std::assert!(stats().is_none(), "and a test's pool does not outlive it");
    }

    /// A slot lent is a pbuf whose payload lies inside the slot, the generated pool
    /// records it as the CPU's, and a slot given back unsent is free again. The
    /// pool runs dry after its last slot, and a dry pool lends nothing rather than
    /// failing.
    #[test]
    fn a_lent_slot_is_the_cpus_until_it_is_given_back_and_the_pool_runs_dry() {
        let (_serial, _link) = crate::lwip_test_link();
        let pool = TestPool::install();
        let cap = capacity() as u16;
        std::assert!(cap > 1400, "a slot carries most of an MTU: {cap}");
        std::assert!(lend(cap + 1).is_none(), "a payload past a slot is not lent");
        std::assert_eq!(stats().expect("installed").free as usize, SLOT_COUNT);
        let mut out = Vec::new();
        for _ in 0..SLOT_COUNT {
            let (p, lent) = lend(cap).expect("a free slot");
            // SAFETY: a live pbuf this test holds.
            let payload = unsafe { (*p.as_ptr()).payload } as *const u8;
            let (idx, state) = slot_of(payload).expect("the payload lies in a slot");
            std::assert_eq!(state, SlotState::CpuMut);
            std::assert_eq!(
                slot_of(p.as_ptr() as *const u8),
                Some((idx, SlotState::CpuMut)),
                "the pbuf record is that slot's first byte"
            );
            out.push((p, lent));
        }
        std::assert!(lend(1).is_none(), "every slot is out");
        for (p, lent) in out {
            // SAFETY: the pbuf is ours; freeing an unsent slot leaves it to the holder.
            unsafe { lwip_sys::pbuf_free(p.as_ptr()) };
            abandon(lent);
        }
        let stats = stats().expect("installed");
        std::assert_eq!(stats.free as usize, SLOT_COUNT);
        std::assert_eq!(
            (stats.lent, stats.abandoned),
            (SLOT_COUNT as u32, SLOT_COUNT as u32)
        );
        drop(pool);
    }
}
