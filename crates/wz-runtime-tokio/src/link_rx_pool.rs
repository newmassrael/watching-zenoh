// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2739 — the AP host's LINK-RX slot table, seen through the shared
//! `RxSlots` seam.
//!
//! ## Why this is separate from the reassembly arena next door
//!
//! [`crate::zero_copy`] stages REASSEMBLY CHAINS: a chain accumulates one
//! message's fragment payloads, keyed by peer and sequence number, and which
//! chain a payload belongs to is knowable only after the frame carrying it has
//! been decoded. A LINK read is one step earlier and one granularity coarser —
//! it lands a FRAME, which is a batch that may carry several messages, and at
//! the moment the kernel needs a destination no chain has been chosen yet.
//!
//! That ordering is why the two cannot share a pool, and it is the reason
//! `crate::uring`'s `read_fixed_into` reads into a chain slot today: there was
//! no link-RX pool on this profile to read into. The MCU tier has had the
//! separation since its own pools were emitted — `session_rx_pool_mcu` sits
//! beside `reassembly_pool_mcu` in `out/wz-link-lwip` — and the AP tier
//! declared one inline in `deploy/ap_mcu_pair.yaml` that nothing could consume.
//!
//! ## The seam is shared, not copied
//!
//! `RxSlots` and `impl_rx_slots!` live in `wz-runtime-core`, the
//! trait-skeleton tier, precisely so this crate and the lwIP link tier see one
//! trait rather than two that drift. The impl below is the macro's whole job.

use wz_runtime_core::impl_rx_slots;

impl_rx_slots!(crate::session_rx_pool_ap, SessionRxPoolAp);

/// THE DIMENSION THIS POOL EXISTS FOR, enforced at COMPILE time.
///
/// A slot must hold the largest frame the stream reader can present, and that
/// bound is not a deploy preference: the reader refuses a prefix whose
/// `payload_len` exceeds `u16::MAX` and then sizes its buffer `w + payload_len`,
/// where `w` is 2 on the universal path and 4 under `transport-lowlatency`. So
/// the ceiling is 4 + 65535 = 65539, prefix included, because the reader keeps
/// the prefix in the frame for the codec.
///
/// A `const` assertion rather than a `#[test]`, and the difference is the
/// point: a test can be filtered out of a run, while this fails the BUILD of
/// any profile that carries the pool. The inline declaration this pool replaced
/// said 4096 — sixteen times under the 65536-byte batch the same deploy node
/// declares — and 65536 would be three bytes short on the lowlatency arm. Both
/// are the shape `reassembly_pool_ap.scxml` records in its own comment: a
/// dimension taken from something that is not what the link delivers.
const _: () = {
    const MAX_FRAME: usize = 4 + u16::MAX as usize;
    assert!(
        crate::session_rx_pool_ap::SLOT_SIZE >= MAX_FRAME,
        "a link-RX slot must hold prefix + u16::MAX payload"
    );
};

/// ⛔ DO NOT CALL `RxSlots::new` ON THIS POOL — use this instead.
///
/// The seam's constructor returns `Self` BY VALUE, and this arena is
/// `SLOT_COUNT * SLOT_SIZE` = ~4.2 MiB of storage. The value exists on the
/// stack before any move can happen, and a debug build has no optimiser to
/// elide it, so `RxSlots::new()` aborts with a stack overflow here. MEASURED,
/// not predicted: it is how the first cut of this module's tests died.
///
/// That is not a defect of this pool — it is the trait's `fn new() -> Self`
/// meeting a profile it was not shaped for. `RxSlots` was written where every
/// pool is MCU-sized (`session_rx_pool_mcu` is 16 x 1536 = 24 KiB, which fits a
/// stack frame without trouble), so the signature never had to answer this. The
/// AP tier is three orders of magnitude larger and cannot be constructed that
/// way at all.
///
/// The repair is [`crate::zero_copy`]'s, one pool over, and its reasoning
/// carries verbatim: allocate ZEROED and take ownership of the block, so no
/// temporary is ever materialised. The zero pattern is the correct initial
/// value rather than a convenient one — `storage` is `[[u8; _]; _]`, for which
/// all-zero is what `new()` writes, and `slot_states` is `[SlotState; _]` whose
/// `Free` variant carries the explicit discriminant `0` in the emit.
///
/// The `debug_assert` re-establishes that against the constructed pool instead
/// of trusting this paragraph: a regenerated emit that renumbered `SlotState`
/// would leave every slot in a state nobody declared, and this turns that into
/// a failing test rather than a pool that silently refuses every reserve.
pub fn heap_pool() -> Box<crate::session_rx_pool_ap::SessionRxPoolAp> {
    use crate::session_rx_pool_ap::{SessionRxPoolAp, SLOT_COUNT};

    // SAFETY: `alloc_zeroed` returns a block of `Layout::new::<T>()` — correctly
    // sized AND correctly aligned. The all-zero pattern is a valid, intended
    // `SessionRxPoolAp` (see above), so the block holds an initialised value
    // before `from_raw` takes ownership of it.
    let pool = unsafe {
        let layout = core::alloc::Layout::new::<SessionRxPoolAp>();
        let raw = std::alloc::alloc_zeroed(layout) as *mut SessionRxPoolAp;
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
    use super::heap_pool;
    use crate::session_rx_pool_ap::{SLOT_COUNT, SLOT_SIZE};
    use wz_runtime_core::rx_slots::RxSlots;

    // Every test here builds through `heap_pool`, never `RxSlots::new()`. That
    // is not a style choice: the seam's by-value constructor stack-overflows at
    // this arena's size, which is how the first cut of these tests died.

    /// A WHOLE-SLOT fill is legal, which is what makes the const assertion
    /// above a live property rather than arithmetic about a number.
    ///
    /// Writing `SLOT_SIZE` bytes and reading them back proves the slot really
    /// carries the width it declares; a slot that merely NAMED 65600 while its
    /// storage were shorter would pass every accounting test in this file.
    #[test]
    fn the_whole_declared_width_is_writable() {
        let mut pool = heap_pool();
        let mut slot = pool.reserve().expect("a fresh pool has slots");

        let buf = pool.buf(&mut slot);
        assert_eq!(buf.len(), SLOT_SIZE, "buf lends the declared width");
        buf[SLOT_SIZE - 1] = 0xAB;
        assert_eq!(
            pool.bytes(&slot)[SLOT_SIZE - 1],
            0xAB,
            "the last byte is real"
        );

        pool.release(slot);
    }

    /// Reserve, fill, read back, release — and the freelist returns to full.
    ///
    /// `free_count` is the accounting the seam exists for: a reader that drops
    /// a slot instead of releasing it shows up as a freelist that never comes
    /// back, which is otherwise invisible until the pool runs dry somewhere
    /// unrelated.
    #[test]
    fn a_slot_round_trips_and_the_freelist_comes_back() {
        let mut pool = heap_pool();
        assert_eq!(pool.free_count(), SLOT_COUNT);

        let mut slot = pool.reserve().expect("a fresh pool has slots");
        assert_eq!(pool.free_count(), SLOT_COUNT - 1);

        pool.buf(&mut slot)[..5].copy_from_slice(b"frame");
        assert_eq!(&pool.bytes(&slot)[..5], b"frame");

        pool.release(slot);
        assert_eq!(pool.free_count(), SLOT_COUNT, "a released slot returns");
    }

    /// Exhaustion is BACK-PRESSURE, not an error — which is why `slot_count`
    /// is a throughput figure and not a correctness bound. The caller drops the
    /// frame and counts it, exactly as a bounded receive path must.
    #[test]
    fn an_exhausted_pool_refuses_rather_than_failing() {
        let mut pool = heap_pool();
        let mut held = Vec::new();
        for _ in 0..SLOT_COUNT {
            held.push(pool.reserve().expect("within SLOT_COUNT"));
        }
        assert_eq!(pool.free_count(), 0);
        assert!(pool.reserve().is_none(), "past SLOT_COUNT must refuse");

        for slot in held {
            pool.release(slot);
        }
        assert_eq!(pool.free_count(), SLOT_COUNT);
    }
}
