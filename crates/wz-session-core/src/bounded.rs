// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `BoundedVec<T, N>` — the single capacity-generic backing seam for
//! the application-layer registries.
//!
//! ARCHITECTURE.md §2.4 mandates `static-first, dynamic-opt-in`: one
//! registry implementation that backs onto a heap-free bounded buffer
//! on MCU (`platform.class = mcu`, the no-heap permanent constraint
//! §2.3) and onto an unbounded `alloc::Vec` on AP (a general-purpose
//! machine with none of those constraints, §2.3 note). This type is
//! that seam — registry logic is written once against `BoundedVec`,
//! and only the storage backing swaps with the `alloc` feature:
//!
//! - **`alloc` on (AP profile)** — backed by `alloc::vec::Vec<T>`.
//!   [`push`](BoundedVec::push) never fails; the declared capacity `N`
//!   is advisory (AP is the dynamic-opt-in side and may exceed it).
//! - **`alloc` off (MCU profile)** — backed by `heapless::Vec<T, N>`.
//!   [`push`](BoundedVec::push) returns [`CapacityFull`] when the
//!   declared capacity `N` is full. There is no silent drop — the
//!   caller decides what to do with the rejected value, mirroring
//!   zenoh-pico's table-full reject (and the §2.1 build-time-enforced
//!   bounded declared-subscription table).
//!
//! The fallible-push signature is identical on both backings, so the
//! caller writes one capacity-aware code path; the `alloc` build's
//! `Ok(())` arm is simply never taken on the failure side. `N` is the
//! deploy-declared capacity (the wiring of `N` from `deploy.yaml`
//! lands with the first registry migration; this module only fixes the
//! container contract).

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use core::fmt;
use core::ops::{Deref, DerefMut};

/// Error returned by [`BoundedVec::push`] when a no-alloc backing has
/// reached its declared capacity `N`. Carries the rejected value back
/// to the caller so it can be recovered, retried, or logged — never
/// silently dropped.
pub struct CapacityFull<T>(pub T);

impl<T> fmt::Debug for CapacityFull<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The rejected value `T` is not required to be `Debug`, so the
        // formatter stays value-agnostic.
        f.write_str("CapacityFull")
    }
}

impl<T> fmt::Display for CapacityFull<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded collection at declared capacity")
    }
}

impl<T> core::error::Error for CapacityFull<T> {}

/// Capacity-generic owned sequence. See the [module docs](self) for the
/// AP (`alloc`) vs MCU (no-alloc) backing contract.
#[cfg(feature = "alloc")]
pub struct BoundedVec<T, const N: usize> {
    inner: Vec<T>,
}

/// Capacity-generic owned sequence. See the [module docs](self) for the
/// AP (`alloc`) vs MCU (no-alloc) backing contract.
#[cfg(not(feature = "alloc"))]
pub struct BoundedVec<T, const N: usize> {
    inner: heapless::Vec<T, N>,
}

impl<T, const N: usize> BoundedVec<T, N> {
    /// Construct an empty backing store. `const` on both backings so a
    /// registry may hold a `BoundedVec` in a `const`/`static` slot.
    #[cfg(feature = "alloc")]
    pub const fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Construct an empty backing store. `const` on both backings so a
    /// registry may hold a `BoundedVec` in a `const`/`static` slot.
    #[cfg(not(feature = "alloc"))]
    pub const fn new() -> Self {
        Self {
            inner: heapless::Vec::new(),
        }
    }

    /// The declared logical capacity `N`. Advisory on the `alloc`
    /// backing (AP may exceed it); the hard limit `push` enforces on
    /// the no-alloc backing.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Append `value`. On the `alloc` backing this always returns
    /// `Ok(())`. On the no-alloc backing it returns
    /// `Err(CapacityFull(value))` once `N` entries are present.
    #[cfg(feature = "alloc")]
    pub fn push(&mut self, value: T) -> Result<(), CapacityFull<T>> {
        self.inner.push(value);
        Ok(())
    }

    /// Append `value`. On the `alloc` backing this always returns
    /// `Ok(())`. On the no-alloc backing it returns
    /// `Err(CapacityFull(value))` once `N` entries are present.
    #[cfg(not(feature = "alloc"))]
    pub fn push(&mut self, value: T) -> Result<(), CapacityFull<T>> {
        self.inner.push(value).map_err(CapacityFull)
    }

    /// Retain only the entries for which `keep` returns `true`,
    /// preserving order. The registries use this for `undeclare`
    /// (drop the entry whose id matches).
    pub fn retain<F>(&mut self, keep: F)
    where
        F: FnMut(&T) -> bool,
    {
        self.inner.retain(keep);
    }

    /// Remove all entries, keeping the allocated/declared capacity.
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

impl<T, const N: usize> Default for BoundedVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

// Deref to the element slice gives `len` / `is_empty` / `iter` / `get`
// / indexing / `as_slice` for free on both backings, so the registry
// read paths are backing-agnostic without a hand-forwarded method per
// accessor.
impl<T, const N: usize> Deref for BoundedVec<T, N> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.inner.as_slice()
    }
}

impl<T, const N: usize> DerefMut for BoundedVec<T, N> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.inner.as_mut_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_within_capacity_succeeds_on_both_backings() {
        let mut v: BoundedVec<u32, 4> = BoundedVec::new();
        assert_eq!(v.capacity(), 4);
        assert!(v.is_empty());
        for i in 0..4 {
            assert!(v.push(i).is_ok());
        }
        assert_eq!(v.len(), 4);
        assert_eq!(v.iter().sum::<u32>(), 6);
    }

    #[test]
    fn retain_drops_matching_entries() {
        let mut v: BoundedVec<u32, 4> = BoundedVec::new();
        for i in 0..4 {
            v.push(i).unwrap();
        }
        v.retain(|&x| x % 2 == 0);
        assert_eq!(v.as_ref(), &[0, 2]);
    }

    // Capacity overflow is backing-specific: only the no-alloc backing
    // enforces `N`. On the `alloc` backing push is infinite (AP is the
    // dynamic-opt-in side), so the overflow assertion is gated off it.
    #[cfg(not(feature = "alloc"))]
    #[test]
    fn push_past_capacity_returns_rejected_value_no_alloc() {
        let mut v: BoundedVec<u32, 2> = BoundedVec::new();
        assert!(v.push(10).is_ok());
        assert!(v.push(20).is_ok());
        let rejected = v.push(30);
        assert!(rejected.is_err());
        assert_eq!(rejected.unwrap_err().0, 30);
        assert_eq!(v.len(), 2);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn push_past_declared_capacity_grows_on_alloc() {
        let mut v: BoundedVec<u32, 2> = BoundedVec::new();
        for i in 0..8 {
            assert!(v.push(i).is_ok());
        }
        assert_eq!(v.len(), 8);
        assert_eq!(v.capacity(), 2);
    }
}
