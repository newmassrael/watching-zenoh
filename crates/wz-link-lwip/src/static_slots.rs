// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Round 3277 -- fixed-memory step S7: address-stable storage the link owns
//! without a heap.
//!
//! lwIP keeps raw pointers into what this crate hands it: the `udp_pcb` holds
//! the socket's state as its receive callback's argument, and the netif holds
//! the MAC it transmits through. Both therefore need storage that does not move
//! for as long as lwIP can call back, which until now was a `Pin<Box<..>>` or a
//! `Box::leak`. A [`SlotPool`](crate::static_slots::SlotPool) is the same guarantee without the allocator: a
//! fixed array of cells in a `static`, a claim flag per cell, and a counted
//! refusal when every cell is taken. A cell never moves because a `static`
//! never does.
//!
//! The pool is declared by whoever owns the capacity decision, the image (or,
//! later, the session slot that embeds it), as a `static` of its own, because
//! Rust has no generic statics: this crate cannot declare one pool for every
//! `LwipUdpSocket<N, Q>` an image might name. The constructors that take a pool
//! are `LwipUdpSocket::bind_in`, `PooledUdpRx::bind_in` and
//! `EthernetIf::add_in`, and they exist where this crate is built with
//! `static-link-storage`, which also removes the constructors that allocate.
//!
//! ## Threading
//!
//! lwIP runs `NO_SYS`, on one thread, and so does every caller of this crate. A
//! claim is a compare-exchange where the target has one and a load and a store
//! where it does not (a Cortex-M0 has no read-modify-write instruction), which
//! is exactly as strong as the contract needs and as strong as the target can
//! make it.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// `S` cells of `T` in a `static`, each claimed on its own.
///
/// Every cell starts unclaimed and uninitialised, so the whole pool is zero
/// bytes of the image and `S * size_of::<T>()` bytes of RAM (`.bss`).
pub struct SlotPool<T, const S: usize> {
    cells: [UnsafeCell<MaybeUninit<T>>; S],
    taken: [AtomicBool; S],
    refused: AtomicU32,
}

// SAFETY: a cell is reached only through the `Slot` that claimed it, and a claim
// is exclusive (the flag), so two threads never hold one cell. `T: Send` is what
// moving a `T` into a cell another thread claimed requires.
unsafe impl<T: Send, const S: usize> Sync for SlotPool<T, S> {}

impl<T, const S: usize> SlotPool<T, S> {
    /// An empty pool: every cell free. `const`, so it initialises a `static`.
    pub const fn new() -> Self {
        Self {
            cells: [const { UnsafeCell::new(MaybeUninit::uninit()) }; S],
            taken: [const { AtomicBool::new(false) }; S],
            refused: AtomicU32::new(0),
        }
    }

    /// How many cells the pool has.
    pub const fn capacity(&self) -> usize {
        S
    }

    /// How many cells are claimed now.
    pub fn in_use(&self) -> usize {
        self.taken
            .iter()
            .filter(|flag| flag.load(Ordering::Acquire))
            .count()
    }

    /// How many claims found every cell taken, since boot. The counted refusal:
    /// a claim that cannot be met says so here and in its return, and never
    /// falls back to a heap.
    pub fn refusals(&self) -> u32 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Claim a free cell and put `init()` in it, or `None` when every cell is
    /// taken (counted in [`refusals`](Self::refusals)).
    ///
    /// `init` runs only once a cell is claimed, so a refused claim builds
    /// nothing, and it is written straight into the cell.
    pub fn claim_with(&'static self, init: impl FnOnce() -> T) -> Option<Slot<T>> {
        // SAFETY: the closure writes a whole `T` at the pointer it is given.
        unsafe {
            self.claim_in_place(|at| {
                // By value: the `T` is a value of its own on the stack until it is
                // written, which is what `claim_in_place` exists to avoid for a large one.
                at.write(init());
            })
        }
    }

    /// [`claim_with`](Self::claim_with) for a `T` too large to be a value on the stack:
    /// the cell is claimed and `init` is given a pointer to it, to write the `T` there
    /// field by field. A session socket's state is 24.7 KB, and a node whose stack is
    /// 32 KB cannot build one by value below the frames that already stand.
    ///
    /// # Safety
    ///
    /// `init` must write a valid `T` at the pointer before it returns (it is then read as
    /// one, and dropped as one). The pointer is aligned and the cell is the caller's alone
    /// while `init` runs, holding no value.
    pub unsafe fn claim_in_place(&'static self, init: impl FnOnce(*mut T)) -> Option<Slot<T>> {
        for (cell, flag) in self.cells.iter().zip(self.taken.iter()) {
            if !take(flag) {
                continue;
            }
            let value =
                NonNull::new(cell.get().cast::<T>()).expect("a cell of a static is not null");
            // The flag made this cell ours alone, and a free cell holds no value, so
            // nothing is dropped or aliased by writing it; `init` is the caller's to make
            // whole (this function's contract).
            init(value.as_ptr());
            return Some(Slot { value, taken: flag });
        }
        // Counted with a load and a store: see the module's threading note.
        self.refused.store(
            self.refused.load(Ordering::Relaxed).wrapping_add(1),
            Ordering::Relaxed,
        );
        None
    }
}

impl<T, const S: usize> Default for SlotPool<T, S> {
    fn default() -> Self {
        Self::new()
    }
}

/// Claim `flag` if it is free.
fn take(flag: &AtomicBool) -> bool {
    #[cfg(target_has_atomic = "8")]
    {
        flag.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }
    #[cfg(not(target_has_atomic = "8"))]
    {
        if flag.load(Ordering::Acquire) {
            false
        } else {
            flag.store(true, Ordering::Release);
            true
        }
    }
}

/// A claimed cell of a [`SlotPool`], holding a `T` that has not moved since it
/// was written and will not until the slot drops.
///
/// Dropping it drops the `T` in place and frees the cell for the next claim.
/// [`leak`](Self::leak) keeps the cell for the rest of the program.
pub struct Slot<T> {
    value: NonNull<T>,
    taken: &'static AtomicBool,
}

// SAFETY: a `Slot` is the unique owner of its cell's `T`, as a `Box<T>` is.
unsafe impl<T: Send> Send for Slot<T> {}
// SAFETY: shared access to the slot is shared access to the `T`.
unsafe impl<T: Sync> Sync for Slot<T> {}

impl<T: 'static> Slot<T> {
    /// Keep the cell, and its `T`, for the rest of the program. The cell is never
    /// freed and the `T` never dropped: for a thing lwIP keeps a pointer to and
    /// never removes (a netif).
    pub fn leak(self) -> &'static mut T {
        let value = self.value;
        core::mem::forget(self);
        // SAFETY: the cell is the caller's alone, and now for good, since the flag
        // stays set; the cell lives in a `static`.
        unsafe { &mut *value.as_ptr() }
    }
}

impl<T> Deref for Slot<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the claim wrote a `T` here, which only this slot reaches.
        unsafe { self.value.as_ref() }
    }
}

impl<T> DerefMut for Slot<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as `deref`, and `&mut self` makes this the only borrow.
        unsafe { self.value.as_mut() }
    }
}

impl<T> Drop for Slot<T> {
    fn drop(&mut self) {
        // SAFETY: the claim wrote a `T`, nothing has dropped it, and the cell is
        // still ours until the flag below says otherwise.
        unsafe { core::ptr::drop_in_place(self.value.as_ptr()) };
        self.taken.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicUsize;

    /// Counts drops, to tell a dropped value from a leaked one.
    struct Counted(&'static AtomicUsize, u32);
    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A pool fills to its capacity, refuses the next claim and counts it, and
    /// frees the cell of a dropped slot for the claim after it, with the value in
    /// the cell dropped exactly once and a refused claim building nothing.
    #[test]
    fn a_pool_fills_to_capacity_refuses_the_next_and_reuses_a_released_cell() {
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        static POOL: SlotPool<Counted, 3> = SlotPool::new();

        let a = POOL.claim_with(|| Counted(&DROPS, 1)).expect("first");
        let b = POOL.claim_with(|| Counted(&DROPS, 2)).expect("second");
        let c = POOL.claim_with(|| Counted(&DROPS, 3)).expect("third");
        std::assert_eq!((POOL.capacity(), POOL.in_use()), (3, 3));
        std::assert_eq!((a.1, b.1, c.1), (1, 2, 3), "each cell holds its own value");

        let mut built = false;
        let refused = POOL.claim_with(|| {
            built = true;
            Counted(&DROPS, 4)
        });
        std::assert!(refused.is_none(), "the fourth claim finds no cell");
        std::assert!(!built, "a refused claim builds nothing");
        std::assert_eq!(POOL.refusals(), 1, "and the refusal is counted");

        drop(b);
        std::assert_eq!(
            DROPS.load(Ordering::SeqCst),
            1,
            "its value was dropped once"
        );
        std::assert_eq!(POOL.in_use(), 2);
        let d = POOL
            .claim_with(|| Counted(&DROPS, 5))
            .expect("a freed cell");
        std::assert_eq!(d.1, 5);
        std::assert_eq!(POOL.refusals(), 1, "a claim that succeeds is not a refusal");

        drop((a, c, d));
        std::assert_eq!(DROPS.load(Ordering::SeqCst), 4);
        std::assert_eq!(POOL.in_use(), 0);
    }

    /// A slot's value does not move: the address read while it is held is the
    /// address inside the pool, and a slot claimed again after a release lands in
    /// the same cell. This is the property lwIP's stored pointers need.
    #[test]
    fn a_slot_lives_at_one_address_inside_its_static_pool() {
        static POOL: SlotPool<[u8; 64], 2> = SlotPool::new();
        let first = POOL.claim_with(|| [1; 64]).expect("claim");
        let at = &*first as *const [u8; 64] as usize;
        let pool_start = &POOL as *const SlotPool<[u8; 64], 2> as usize;
        std::assert!(
            at >= pool_start && at < pool_start + core::mem::size_of_val(&POOL),
            "the value is inside the static, not on a heap or a stack"
        );
        let again = &*first as *const [u8; 64] as usize;
        std::assert_eq!(at, again, "it does not move while held");
        drop(first);
        let second = POOL.claim_with(|| [2; 64]).expect("reclaim");
        std::assert_eq!(
            &*second as *const [u8; 64] as usize,
            at,
            "the freed cell is reused"
        );
    }

    /// A leaked slot keeps its cell for good and its value is never dropped.
    #[test]
    fn a_leaked_slot_keeps_its_cell_and_its_value() {
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        static POOL: SlotPool<Counted, 1> = SlotPool::new();
        let kept: &'static mut Counted = POOL
            .claim_with(|| Counted(&DROPS, 7))
            .expect("claim")
            .leak();
        std::assert_eq!(kept.1, 7);
        std::assert_eq!(POOL.in_use(), 1, "the cell stays claimed");
        std::assert!(POOL.claim_with(|| Counted(&DROPS, 8)).is_none());
        std::assert_eq!(
            DROPS.load(Ordering::SeqCst),
            0,
            "and its value is not dropped"
        );
    }

    /// An in-place claim hands `init` the cell's own address and never builds a `T` of
    /// its own, and a refused claim runs nothing.
    #[test]
    fn an_in_place_claim_is_written_through_the_pointer_and_a_refused_one_writes_nothing() {
        static POOL: SlotPool<[u32; 4], 1> = SlotPool::new();
        let mut seen = 0usize;
        // SAFETY: the closure writes the whole array.
        let first = unsafe {
            POOL.claim_in_place(|at| {
                seen = at as usize;
                at.write([7; 4]);
            })
        }
        .expect("claim");
        std::assert_eq!(*first, [7; 4]);
        std::assert_eq!(
            seen,
            &*first as *const [u32; 4] as usize,
            "the pointer init was given is the cell the slot holds"
        );

        let mut ran = false;
        // SAFETY: never runs: the only cell is taken.
        let refused = unsafe {
            POOL.claim_in_place(|at| {
                ran = true;
                at.write([0; 4]);
            })
        };
        std::assert!(refused.is_none());
        std::assert!(!ran, "a refused claim runs no initialiser");
        std::assert_eq!(POOL.refusals(), 1);
    }
}
