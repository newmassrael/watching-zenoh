// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Capacity-generic backing seams (`BoundedVec<T, N>` +
//! `BoundedString<N>`) for the application-layer registries and the
//! owned-output value modules.
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
use alloc::string::String;
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

    /// Drain the collection by value, partitioning each element by
    /// `extract`: every element for which it returns `true` is moved
    /// into the returned `BoundedVec` (in original order); the rest are
    /// retained in `self`. `extract` receives `&mut T`, so it may mutate
    /// an element before deciding (e.g. decrement a counter and extract
    /// on reaching zero).
    ///
    /// This is the no-alloc *drain-partition-fire* seam the pending-table
    /// registries share (the reply + liveliness-get `sweep_timed_out` /
    /// `fire_final_for` bodies): the borrow checker forbids firing a
    /// captured callback while a `&mut self.pending` iteration is live, so
    /// the caller extracts the to-fire entries here and fires over the
    /// returned vec *after* this call releases the borrow. Extract-then-
    /// fire also means a panicking callback cannot leave a half-swept
    /// entry behind — every fired entry is already out of `self`.
    ///
    /// No-alloc: `self` is taken out via [`core::mem::take`] and rebuilt
    /// from the retained partition; `self` and the returned vec share
    /// capacity `N` (retained + extracted == taken <= N), so neither push
    /// can exceed `N`.
    pub fn drain_partition<F>(&mut self, mut extract: F) -> Self
    where
        F: FnMut(&mut T) -> bool,
    {
        let mut extracted: Self = Self::new();
        let mut keep: Self = Self::new();
        for mut entry in core::mem::take(self) {
            if extract(&mut entry) {
                extracted
                    .push(entry)
                    .expect("drain_partition fits: keep + extracted == taken <= N");
            } else {
                keep.push(entry)
                    .expect("drain_partition fits: keep + extracted == taken <= N");
            }
        }
        *self = keep;
        extracted
    }
}

impl<T, const N: usize> Default for BoundedVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

// By-value `IntoIterator` consumes the backing into an owning iterator on
// both profiles. Registries that must remove-then-fire under a no-alloc
// backing (the reply registry's `fire_final_for` / `sweep_timed_out`
// drain-partition-fire pattern) take the table with `core::mem::take` and
// iterate it by value into bounded `keep` / `fired` partitions — no heap
// temporary on the MCU profile.
#[cfg(feature = "alloc")]
impl<T, const N: usize> IntoIterator for BoundedVec<T, N> {
    type Item = T;
    type IntoIter = alloc::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

#[cfg(not(feature = "alloc"))]
impl<T, const N: usize> IntoIterator for BoundedVec<T, N> {
    type Item = T;
    type IntoIter = <heapless::Vec<T, N> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
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

/// Capacity-generic owned UTF-8 string — the string-shaped sibling of
/// [`BoundedVec`], for the owned-output value modules (canonicalized
/// keyexprs, locator addresses, diagnostic chunks). Same backing
/// contract as [`BoundedVec`]:
///
/// - **`alloc` on (AP)** — backed by `alloc::string::String`;
///   [`push_str`](BoundedString::push_str) never fails, `N` is
///   advisory.
/// - **`alloc` off (MCU)** — backed by `heapless::String<N>`;
///   [`push_str`](BoundedString::push_str) returns [`CapacityFull`]
///   when the append would exceed the declared `N` *bytes*, leaving
///   the buffer unchanged (heapless append is atomic — no partial
///   write). The caller decides; never a silent truncation.
///
/// Implements [`core::fmt::Write`] on both backings, so the value
/// modules can build output with `write!` / `core::fmt` machinery and
/// get the same capacity-failure surface (`fmt::Error` on overflow).
#[cfg(feature = "alloc")]
pub struct BoundedString<const N: usize> {
    inner: String,
}

/// Capacity-generic owned UTF-8 string. See the type docs for the AP
/// (`alloc`) vs MCU (no-alloc) backing contract.
#[cfg(not(feature = "alloc"))]
pub struct BoundedString<const N: usize> {
    inner: heapless::String<N>,
}

impl<const N: usize> BoundedString<N> {
    /// Construct an empty string. `const` on both backings.
    #[cfg(feature = "alloc")]
    pub const fn new() -> Self {
        Self {
            inner: String::new(),
        }
    }

    /// Construct an empty string. `const` on both backings.
    #[cfg(not(feature = "alloc"))]
    pub const fn new() -> Self {
        Self {
            inner: heapless::String::new(),
        }
    }

    /// The declared logical byte capacity `N`. Advisory on the `alloc`
    /// backing; the hard byte limit `push_str` / `push` enforce on the
    /// no-alloc backing.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Append a string slice. `Ok(())` always on the `alloc` backing;
    /// `Err(CapacityFull(()))` on the no-alloc backing when the append
    /// would exceed `N` bytes (buffer left unchanged).
    #[cfg(feature = "alloc")]
    pub fn push_str(&mut self, s: &str) -> Result<(), CapacityFull<()>> {
        self.inner.push_str(s);
        Ok(())
    }

    /// Append a string slice. `Ok(())` always on the `alloc` backing;
    /// `Err(CapacityFull(()))` on the no-alloc backing when the append
    /// would exceed `N` bytes (buffer left unchanged).
    #[cfg(not(feature = "alloc"))]
    pub fn push_str(&mut self, s: &str) -> Result<(), CapacityFull<()>> {
        self.inner.push_str(s).map_err(|_| CapacityFull(()))
    }

    /// Append one `char`. Capacity semantics mirror [`push_str`].
    #[cfg(feature = "alloc")]
    pub fn push(&mut self, c: char) -> Result<(), CapacityFull<char>> {
        self.inner.push(c);
        Ok(())
    }

    /// Append one `char`. Capacity semantics mirror [`push_str`].
    #[cfg(not(feature = "alloc"))]
    pub fn push(&mut self, c: char) -> Result<(), CapacityFull<char>> {
        self.inner.push(c).map_err(|_| CapacityFull(c))
    }

    /// Borrow the contents as a `&str`.
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Remove all bytes, keeping the allocated/declared capacity.
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

impl<const N: usize> Default for BoundedString<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Deref for BoundedString<N> {
    type Target = str;

    fn deref(&self) -> &str {
        &self.inner
    }
}

impl<const N: usize> fmt::Display for BoundedString<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner)
    }
}

impl<const N: usize> fmt::Debug for BoundedString<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.inner.as_str(), f)
    }
}

// Compare against `str` / `&str` literals by content. Lets callers and
// tests write `bounded == "literal"` without reaching for `.as_str()`
// (the canon owned-output modules return `BoundedString` and are
// asserted against literal expectations). Backing-agnostic.
impl<const N: usize> PartialEq<str> for BoundedString<N> {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl<const N: usize> PartialEq<&str> for BoundedString<N> {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

// Content equality between two bounded strings (capacity-independent),
// so a `BoundedString` is usable inside `Result`/`Option` equality
// assertions and as a comparand in registry dedup. Backing-agnostic.
impl<const N: usize, const M: usize> PartialEq<BoundedString<M>> for BoundedString<N> {
    fn eq(&self, other: &BoundedString<M>) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<const N: usize> Eq for BoundedString<N> {}

// `fmt::Write` lets the owned-output modules build a BoundedString with
// `write!` / `core::fmt`; the no-alloc backing surfaces a full buffer
// as `fmt::Error`, the standard `core::fmt` capacity-failure channel.
impl<const N: usize> fmt::Write for BoundedString<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push_str(s).map_err(|_| fmt::Error)
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

    #[test]
    fn drain_partition_extracts_matches_and_retains_rest_in_order() {
        let mut v: BoundedVec<u32, 4> = BoundedVec::new();
        for i in 0..4 {
            v.push(i).unwrap();
        }
        // Extract evens; odds retained, both partitions order-preserving.
        let extracted = v.drain_partition(|x| *x % 2 == 0);
        assert_eq!(extracted.as_ref(), &[0, 2]);
        assert_eq!(v.as_ref(), &[1, 3]);
    }

    #[test]
    fn drain_partition_predicate_may_mutate_before_deciding() {
        let mut v: BoundedVec<u32, 4> = BoundedVec::new();
        for i in 1..=3 {
            v.push(i).unwrap();
        }
        // Decrement each, extract those that reach zero (mirrors the
        // reply registry's remaining_finals counter path).
        let extracted = v.drain_partition(|x| {
            *x -= 1;
            *x == 0
        });
        assert_eq!(extracted.len(), 1); // only the original `1` reaches 0
        assert_eq!(v.as_ref(), &[1, 2]); // 2->1, 3->2 retained, decremented
    }

    #[test]
    fn drain_partition_empty_and_all_match() {
        let mut empty: BoundedVec<u32, 4> = BoundedVec::new();
        assert!(empty.drain_partition(|_| true).is_empty());
        assert!(empty.is_empty());

        let mut all: BoundedVec<u32, 4> = BoundedVec::new();
        all.push(7).unwrap();
        all.push(8).unwrap();
        let extracted = all.drain_partition(|_| true);
        assert_eq!(extracted.len(), 2);
        assert!(all.is_empty());
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

    #[test]
    fn string_push_within_capacity() {
        use core::fmt::Write;
        let mut s: BoundedString<16> = BoundedString::new();
        assert!(s.is_empty());
        assert!(s.push_str("home").is_ok());
        assert!(s.push('/').is_ok());
        write!(s, "temp").unwrap();
        assert_eq!(s.as_str(), "home/temp");
        assert_eq!(&*s, "home/temp");
    }

    // No-alloc backing enforces the byte cap atomically (no partial
    // write). Gated off the alloc backing, which grows past `N`.
    #[cfg(not(feature = "alloc"))]
    #[test]
    fn string_push_past_capacity_rejects_atomically_no_alloc() {
        let mut s: BoundedString<4> = BoundedString::new();
        assert!(s.push_str("abcd").is_ok());
        assert!(s.push_str("e").is_err());
        assert!(s.push('x').is_err());
        // Buffer unchanged by the rejected appends.
        assert_eq!(s.as_str(), "abcd");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn string_grows_past_declared_capacity_on_alloc() {
        let mut s: BoundedString<4> = BoundedString::new();
        assert!(s.push_str("abcdefgh").is_ok());
        assert_eq!(s.as_str(), "abcdefgh");
        assert_eq!(s.capacity(), 4);
    }
}
