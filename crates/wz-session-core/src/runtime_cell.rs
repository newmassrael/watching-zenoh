// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The flags and words a session's holders write without a lock, in the form the runtime's
//! concurrency asks for (`SessionRuntime::Flag`, `SessionRuntime::Word`): an atomic
//! where the holders are threads, a `Cell` where they are one task.
//!
//! The methods take the atomic's ordering, so code over either form states the ordering its
//! readers rely on once, and a cell, which has no other thread to order against, ignores it.
//! A cell is sound only where the runtime keeps everything that holds it to one thread at a time:
//! a profile whose session handles are not `Send` (the cooperative one) binds it, and the
//! compiler then refuses to move a holder of one to another thread.

use core::cell::Cell;
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_has_atomic = "64")]
use core::sync::atomic::AtomicU64;

/// A `bool` written through a shared reference: `AtomicBool` or `Cell<bool>`.
pub trait FlagCell {
    /// A flag holding `value`.
    fn new(value: bool) -> Self;
    /// The value, read with `order` where the flag is atomic.
    fn load(&self, order: Ordering) -> bool;
    /// Write `value`, with `order` where the flag is atomic.
    fn store(&self, value: bool, order: Ordering);
}

/// A `u64` written through a shared reference: `AtomicU64` or `Cell<u64>`. Additions wrap, as
/// an atomic's do.
pub trait WordCell {
    /// A word holding `value`.
    fn new(value: u64) -> Self;
    /// The value, read with `order` where the word is atomic.
    fn load(&self, order: Ordering) -> u64;
    /// Write `value`, with `order` where the word is atomic.
    fn store(&self, value: u64, order: Ordering);
    /// Add `value` and answer the word as it was before.
    fn fetch_add(&self, value: u64, order: Ordering) -> u64;
    /// Take `value` away and answer the word as it was before.
    fn fetch_sub(&self, value: u64, order: Ordering) -> u64;
}

impl FlagCell for AtomicBool {
    #[inline]
    fn new(value: bool) -> Self {
        AtomicBool::new(value)
    }

    #[inline]
    fn load(&self, order: Ordering) -> bool {
        AtomicBool::load(self, order)
    }

    #[inline]
    fn store(&self, value: bool, order: Ordering) {
        AtomicBool::store(self, value, order);
    }
}

impl FlagCell for Cell<bool> {
    #[inline]
    fn new(value: bool) -> Self {
        Cell::new(value)
    }

    #[inline]
    fn load(&self, _order: Ordering) -> bool {
        self.get()
    }

    #[inline]
    fn store(&self, value: bool, _order: Ordering) {
        self.set(value);
    }
}

#[cfg(target_has_atomic = "64")]
impl WordCell for AtomicU64 {
    #[inline]
    fn new(value: u64) -> Self {
        AtomicU64::new(value)
    }

    #[inline]
    fn load(&self, order: Ordering) -> u64 {
        AtomicU64::load(self, order)
    }

    #[inline]
    fn store(&self, value: u64, order: Ordering) {
        AtomicU64::store(self, value, order);
    }

    #[inline]
    fn fetch_add(&self, value: u64, order: Ordering) -> u64 {
        AtomicU64::fetch_add(self, value, order)
    }

    #[inline]
    fn fetch_sub(&self, value: u64, order: Ordering) -> u64 {
        AtomicU64::fetch_sub(self, value, order)
    }
}

impl WordCell for Cell<u64> {
    #[inline]
    fn new(value: u64) -> Self {
        Cell::new(value)
    }

    #[inline]
    fn load(&self, _order: Ordering) -> u64 {
        self.get()
    }

    #[inline]
    fn store(&self, value: u64, _order: Ordering) {
        self.set(value);
    }

    #[inline]
    fn fetch_add(&self, value: u64, _order: Ordering) -> u64 {
        let before = self.get();
        self.set(before.wrapping_add(value));
        before
    }

    #[inline]
    fn fetch_sub(&self, value: u64, _order: Ordering) -> u64 {
        let before = self.get();
        self.set(before.wrapping_sub(value));
        before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flag_round<F: FlagCell>() {
        let flag = F::new(false);
        assert!(!flag.load(Ordering::Relaxed), "made lowered");
        flag.store(true, Ordering::Release);
        assert!(flag.load(Ordering::Acquire), "raised");
        flag.store(false, Ordering::Relaxed);
        assert!(!flag.load(Ordering::Relaxed), "lowered again");
        assert!(F::new(true).load(Ordering::Relaxed), "made raised");
    }

    fn word_round<W: WordCell>() {
        let word = W::new(7);
        assert_eq!(
            word.fetch_add(1, Ordering::SeqCst),
            7,
            "the add answers the word before"
        );
        assert_eq!(word.load(Ordering::SeqCst), 8);
        assert_eq!(
            word.fetch_sub(1, Ordering::SeqCst),
            8,
            "the take answers the word before"
        );
        assert_eq!(word.load(Ordering::SeqCst), 7);
        word.store(u64::MAX, Ordering::SeqCst);
        assert_eq!(word.fetch_add(1, Ordering::SeqCst), u64::MAX);
        assert_eq!(
            word.load(Ordering::SeqCst),
            0,
            "an add wraps, as the atomic's does"
        );
        assert_eq!(word.fetch_sub(1, Ordering::SeqCst), 0);
        assert_eq!(word.load(Ordering::SeqCst), u64::MAX, "a take wraps too");
    }

    /// The cell answers what the atomic answers, so a profile that binds either sees the same
    /// values from the same writes.
    #[test]
    fn a_cell_flag_reads_as_the_atomic_one() {
        flag_round::<AtomicBool>();
        flag_round::<Cell<bool>>();
    }

    #[test]
    fn a_cell_word_counts_and_wraps_as_the_atomic_one() {
        word_round::<AtomicU64>();
        word_round::<Cell<u64>>();
    }
}
