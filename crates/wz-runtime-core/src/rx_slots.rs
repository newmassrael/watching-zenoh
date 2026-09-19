// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2737 — the receive-slot seam over an SCE `sce:kind="buffer-pool"` emit.
//!
//! ## Why it lives in the trait-skeleton tier and not where it was born
//!
//! This began in `wz-link-lwip`, which is the only tier that had a link-RX pool
//! to see through it. The AP profile is getting one, and the wrong way to give
//! it one is a second copy of this trait: a variant set copied across a crate
//! boundary is the shape that hides, because neither copy's tests can see the
//! other drifting.
//!
//! The move was NOT to the obvious crate. The protocol tier would have run the
//! layering backwards, because the link tier sits below it and keeps a
//! two-entry dependency list on purpose. This crate is the
//! runtime-services-tier TRAIT SKELETON that declares nothing of its own,
//! which is what lets both the link tier and the tokio host reach it without
//! either reaching the other.
//!
//! ## What the seam deliberately hides
//!
//! A reader asks for the bytes of a received datagram and says when it is done.
//! It does NOT learn how the bytes got into the slot: a CPU copy out of an lwIP
//! `pbuf` and a descriptor-ring peripheral writing them directly end at the
//! same place, a slot holding `len` bytes, borrowed and then returned.

/// A pool of fixed-size receive slots with a borrow-then-return discipline.
///
/// Implemented over each SCE-generated `sce:kind="buffer-pool"` emit by
/// [`impl_rx_slots`](crate::impl_rx_slots). The associated [`Slot`](RxSlots::Slot)
/// is the emit's own phantom-typed handle, so the lifecycle rules the generator
/// encodes — `pool_return` on a slot the peripheral owns is a type error, not a
/// runtime check — survive being seen through this trait.
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

    /// Slots currently on the freelist. The accounting gate: a leaked handle is
    /// otherwise invisible until the pool runs dry somewhere unrelated.
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
///
/// The pool module is a PATH THE CALLER WRITES (`crate::session_rx_pool_ap`),
/// not an ident this macro prefixes with `crate::`. That is the difference
/// between an exported macro that works and one that only looks like it does:
/// `crate::` inside the definition means THIS crate, which holds no pools, and
/// clippy's `crate_in_macro_def` says so. Taking the path moves the decision to
/// the expansion site, where the caller already knows where its emits live.
///
/// The `use ... as` binding is why the path is usable at all — a `path`
/// fragment may be followed by `as` but not by `::`, so binding it once is what
/// lets every reference below spell it.
#[macro_export]
macro_rules! impl_rx_slots {
    ($pool_mod:path, $pool_ty:ident) => {
        const _: () = {
            use $pool_mod as pool;

            impl $crate::rx_slots::RxSlots for pool::$pool_ty {
                const SLOT_COUNT: usize = pool::SLOT_COUNT;
                const SLOT_SIZE: usize = pool::SLOT_SIZE;

                type Slot = pool::Slot<pool::CpuMut>;

                fn new() -> Self {
                    <pool::$pool_ty>::new()
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
                    <pool::$pool_ty>::free_count(self)
                }

                fn slot_idx(slot: &Self::Slot) -> usize {
                    slot.idx()
                }
            }
        };
    };
}
